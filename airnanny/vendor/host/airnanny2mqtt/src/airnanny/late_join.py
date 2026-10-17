"""Cooperative retained-key recovery of an inactive V33 slot.

Every mutation runs on the existing service owner. No second serial reader,
worker, saved template, command replay or whole-dongle recovery is used.
"""
from collections import deque
from dataclasses import replace
from uuid import uuid4
from .counters import CounterAllocator
from .radio_runtime import restore_devices
from .radio_retry import RetryingCommandDevice
from .radio_service import ServiceBlocked, clean_recovery_loss_safe, response_timeout_retry_safe
from .serial_support import SerialFault


class LateJoinRecovery:
    def __init__(self,session,ledgers,state,*,validate_beacon,bind_fields,leave_check):
        self.session,self.radio,self.ledgers,self.state=session,session.radio,ledgers,state
        if self.radio.firmware_version!=33:
            raise ValueError('V33 late-join capability required')
        self.validate_beacon,self.bind_fields,self.leave_check=validate_beacon,bind_fields,leave_check
        self.phase='BACKOFF';self.due=self.now()+5000;self.slot=None
        self.waiting=False;self.attempt=0;self.guard=None;self.bound_at=0
        self.records=deque(maxlen=4096);self.rx=deque(maxlen=256)
        self.authenticated=set();self.response_revision=None;self.tx_end=None
        self.failure=None;self.failure_records=None;self.secured=False
        self.poll_cursor=0
        original=self.radio.record_observer
        def observed(kind,fields):
            if self.slot is not None:
                self.records.append(dict(kind=kind,fields=fields.copy(),observed=self.now()/1000))
            original(kind,fields)
        self.radio.record_observer=observed
        self.radio.recovery_rx=self.observe_rx

    def now(self):return self.radio.clock.now_ms()

    def observe_rx(self,fields):
        if self.slot is None:return
        row=dict(kind='RX',fields=fields)
        if self.leave_check(row,{self.slot:self.ledgers[self.slot]}):
            raise SerialFault('radio_authenticated_leave')
        if self.phase in ('AWAIT_REJOIN','AWAIT_TIMEOUT') or (
                self.waiting and self.phase in ('REJOIN','TIMEOUT')):
            if len(self.rx)==self.rx.maxlen:
                raise SerialFault('late_join_response_buffer_full')
            self.rx.append(fields.copy())

    def _journal(self):
        self.state.write('ACTIVE',late_join=dict(slot=self.slot,guard=self.guard,
            phase=self.phase,secured=self.secured))

    def _send(self,verb,phase,*,raw=None,**fields):
        if not self.radio.recovery_ready():return False
        self.waiting=True
        def result(kind,reply):
            self.waiting=False
            try:self._result(verb,kind,reply,phase)
            except ServiceBlocked as exc:raise SerialFault(str(exc)) from exc
        self.radio.recovery_submit(verb,self.slot,result,raw=raw,session=1,**fields)
        return True

    def _status_binding(self,f):
        r=self.ledgers[self.slot].read()
        if (f.get('ctx')!=str(self.slot) or int(f['generation'])!=r['generation']
                or f.get('assigned_short')!=f"{self.ledgers[self.slot].identity['short']:04x}"):
            raise ServiceBlocked('late_join_durable_status_binding')

    def _backoff(self):
        self.attempt=min(self.attempt+1,6)
        self.due=self.now()+min(300000,5000*(2**(self.attempt-1)))
        self.phase='BACKOFF';self.slot=None;self.waiting=False
        self.state.write('ACTIVE',late_join=None)
        self.radio.recovery_request=None

    def _result(self,verb,kind,f,next_phase):
        ledger=self.ledgers[self.slot]
        if kind=='STATUS':
            self._status_binding(f)
            if self.phase=='VERIFY':
                if f['recovery']!='STOPPED' or f.get('late_join_restartable')!='1':
                    raise ServiceBlocked('late_join_initial_restart_not_proven')
                ledger.begin_cycle(self.guard)
            elif verb=='BIND':
                if f['recovery']!='BOUND' or f['state']!='RECOVERY':
                    raise ServiceBlocked('late_join_bind_not_bound')
                self.bound_at=self.now();self.scans=0
            elif self.phase=='SCAN_STATUS':
                if f['recovery']=='BOUND' and self.scans<3:
                    self.phase='SCAN';return
                if f['recovery']=='STOPPED' and self.scans==3 and f.get('late_join_restartable')=='1':
                    if ledger.read()['recovery'].get('intents'):
                        raise ServiceBlocked('late_join_empty_scan_has_secured_intent')
                    self._backoff();return
                if f['recovery']!='DISCOVERED':raise ServiceBlocked('late_join_scan_state')
                revision=int(f['beacon_revision'])
                row=next((r for r in reversed(self.records) if r['kind']=='RX'
                          and int(r['fields']['revision'])==revision),None)
                if row is None:raise ServiceBlocked('late_join_beacon_capture_missing')
                # Normalize only the unsigned timer differences for the frozen
                # beacon validator, whose API uses a linear scan-local clock.
                fields=dict(row['fields'])
                fields['time_us']=str((int(fields['time_us'])-self.tx_end)&0xffffffff)
                now=(int(f['time_us'])-self.tx_end)&0xffffffff
                identity=ledger.identity
                self.evidence=self.validate_beacon(bytes.fromhex(fields['mac']),fields,
                    self.radio.boot,self.guard,self.scan_floor,0,now,
                    pan=identity['pan'],tc=identity['tc_ieee'])
            elif self.phase=='CHECK_STOP':
                if f.get('late_join_restartable')!='1' or f['recovery']!='STOPPED':
                    raise ServiceBlocked('late_join_retry_not_proven_by_firmware')
                error=self.failure
                safe=(clean_recovery_loss_safe(error,self.ledgers,self.guard,self.failure_records)
                    or response_timeout_retry_safe(error,self.ledgers,self.guard,self.failure_records))
                if not safe:raise ServiceBlocked('late_join_retry_lifecycle_unknown')
                self._backoff();return
            elif verb=='DISCOVERY_COMMIT' and f['recovery']!='REJOIN_PREPARED':
                raise ServiceBlocked('late_join_discovery_commit_state')
            elif verb=='CURRENT_SHORT_COMMIT' and f['recovery']!='REJOINED':
                raise ServiceBlocked('late_join_short_commit_state')
            elif verb=='PARENT_LINK_ACTIVE':
                if f['recovery']!='PARENT_LINK_ACTIVE':
                    raise ServiceBlocked('late_join_parent_not_active')
                self._activate();return
        else:
            if verb=='ACTIVE_DISCOVERY_BEACON_REQUEST':
                if f['result']!='local_tx_ok':raise ServiceBlocked('late_join_discovery_tx_failed')
                self.tx_end=int(f['time_us']);self.due=self.now()+280
            else:
                kind={'REJOIN_REQUEST':'REJOIN','DEVICE_ANNOUNCE':'ANNOUNCE','END_DEVICE_TIMEOUT':'TIMEOUT'}[verb]
                try:ledger.sent(kind,f['result'],int(f['time_us']))
                except Exception as exc:
                    if (f['cleanup']!='safe' or f['result'] not in ('no_ack','invalid_ack','cca_fail')):
                        raise
                    self.failure=exc;self.failure_records=list(self.records)
                    self.phase='CHECK_STOP';return
                if kind in ('REJOIN','TIMEOUT'):
                    self.due=self.now()+1000
        self.phase=next_phase

    def _secure(self,verb,kind,next_phase):
        if not self.radio.recovery_ready():return
        ledger=self.ledgers[self.slot]
        self.secured=True;self._journal()  # crash marker BEFORE durable reserve
        ledger.reserve(kind)
        raw,fc=ledger.build(kind)
        record=ledger.read();intent=record['recovery']['intents'][kind]
        self._send(verb,next_phase,raw=raw,generation=record['generation'],
            epoch=record['key_epoch_id'],attempt=ledger.identity['attempt'],guard=self.guard,
            fc=fc,hash=intent['sha256'],mac=raw.hex())

    def _responses(self,kind):
        ledger=self.ledgers[self.slot]
        while self.rx:
            fields=self.rx.popleft();raw=bytes.fromhex(fields['mac'])
            result,detail=ledger.authenticate_response(kind,raw,int(fields['revision']),fields)
            if result=='REPLAY_REJECTED' and raw in self.authenticated:continue
            if result not in ('NOT_THIS_CONTEXT','REPLAY_REJECTED'):
                if len(self.authenticated)>=256:raise ServiceBlocked('late_join_auth_history_full')
                self.authenticated.add(raw)
            if result in ('REJOINED','PARENT_LINK_ACTIVE'):
                self.response_revision=int(fields['revision']);self.due=self.now()+25
                self.phase='SHORT' if kind=='REJOIN' else 'ACTIVE'
                self.rx.clear();return
            if result not in ('NOT_THIS_CONTEXT','AUTHENTICATED_NOT_A_RESPONSE'):
                raise ServiceBlocked('late_join_parent_answer:'+result)
        if self.now()>=self.due:
            self.failure=RuntimeError(f'no_authenticated_{kind}_response:ctx={self.slot}')
            self.failure_records=list(self.records);self.phase='CHECK_STOP'

    def _activate(self):
        daemon=self.session.daemon;slots=self.radio.active_slots|{self.slot}
        config,bindings,_,_=restore_devices(self.ledgers,daemon.config.mqtt,
            repeat_commands=True,retry_commands=True,active_slots=slots)
        binding=next(b for b in bindings if b.slot==self.slot)
        registration=next(d for d in config.devices if d.core.context.identity==binding.context_id)
        old=daemon.collection.by_context[binding.context_id]
        adapter=daemon.adapters[old.config.name]
        if old.busy or old.intent is not None or adapter.pending is not None:
            raise ServiceBlocked('late_join_inactive_command_not_empty')
        counters=old.counters
        counters.ledgers[binding.context_id]=self.ledgers[self.slot]
        context=registration.core.context
        context.outgoing[(binding.epoch,binding.key_sequence)]=CounterAllocator(
            counters,binding.context_id,binding.epoch,binding.key_sequence,32)
        device=RetryingCommandDevice(registration.core,old.clock,self.radio,counters,
            rollover_successor=old.rollover_successor)
        daemon.collection.by_context[binding.context_id]=device
        daemon.collection.devices[device.config.name]=device
        adapter.device=device;adapter.cursor=0;adapter.released=device.snapshot()
        adapter.release_block_revision=-1
        daemon.config=replace(daemon.config,devices=tuple(
            registration if d.core.name==device.config.name else d for d in daemon.config.devices))
        remaining=max(0,self.bound_at+60000-self.now())
        self.radio.activate_recovered(binding,ready_after_ms=remaining)
        self.state.write('ACTIVE',late_join=None)
        self.slot=None;self.phase='BACKOFF';self.due=self.now()+5000;self.attempt=0

    def pump(self):
        if not self.radio.connected:return
        if self.waiting:return
        if self.phase=='BACKOFF':
            missing=sorted({0,1}-self.radio.active_slots)
            if not missing or self.now()<self.due or not self.radio.recovery_ready():return
            self.slot=missing[self.poll_cursor%len(missing)];self.poll_cursor+=1
            ledger=self.ledgers[self.slot];q=ledger.read().get('recovery') or {}
            if q.get('leave') or (q.get('intents') and self.slot not in self.radio.active_slots):
                # Clean failed recovery retries were reviewed before _backoff.
                if not self.secured or self.failure is None:
                    raise ServiceBlocked('late_join_prior_secured_state_unreviewed')
            self.guard=uuid4().hex;self.records.clear();self.rx.clear();self.authenticated.clear()
            self.secured=False;self.failure=None;self.phase='VERIFY';self._journal()
        ledger=self.ledgers[self.slot] if self.slot is not None else None
        if self.phase=='VERIFY':self._send('STATUS','BIND')
        elif self.phase=='BIND':
            fields=self.bind_fields(ledger)
            self._send('BIND','SCAN',**fields)
        elif self.phase=='SCAN':
            if not self.radio.recovery_ready():return
            self.scans+=1;self.scan_floor=self.radio._revision if self.radio._revision is not None else -1
            dsn=(ledger.read()['sequences']['dsn']+self.scans)&255
            raw=b'\x03\x08'+bytes([dsn])+b'\xff\xff\xff\xff\x07'
            self._send('ACTIVE_DISCOVERY_BEACON_REQUEST','SCAN_WAIT',raw=raw,
                generation=ledger.read()['generation'],dsn=dsn)
        elif self.phase=='SCAN_WAIT' and self.now()>=self.due:
            self.phase='SCAN_STATUS'
            self._send('STATUS','DISCOVERY')
        elif self.phase=='SCAN_STATUS':self._send('STATUS','DISCOVERY')
        elif self.phase=='DISCOVERY':
            self._send('DISCOVERY_COMMIT','REJOIN',generation=ledger.read()['generation'],
                revision=self.evidence.revision,hash=self.evidence.raw_hash)
        elif self.phase=='REJOIN':self._secure('REJOIN_REQUEST','REJOIN','AWAIT_REJOIN')
        elif self.phase=='AWAIT_REJOIN':self._responses('REJOIN')
        elif self.phase=='SHORT' and self.now()>=self.due:
            self._send('CURRENT_SHORT_COMMIT','ANNOUNCE',generation=ledger.read()['generation'],
                revision=self.response_revision,short=ledger.identity['short'])
        elif self.phase=='ANNOUNCE':self._secure('DEVICE_ANNOUNCE','ANNOUNCE','TIMEOUT')
        elif self.phase=='TIMEOUT':self.rx.clear();self._secure('END_DEVICE_TIMEOUT','TIMEOUT','AWAIT_TIMEOUT')
        elif self.phase=='AWAIT_TIMEOUT':self._responses('TIMEOUT')
        elif self.phase=='ACTIVE' and self.now()>=self.due:
            self._send('PARENT_LINK_ACTIVE','DONE',generation=ledger.read()['generation'],revision=self.response_revision)
        elif self.phase=='CHECK_STOP':self._send('STATUS','BACKOFF')
