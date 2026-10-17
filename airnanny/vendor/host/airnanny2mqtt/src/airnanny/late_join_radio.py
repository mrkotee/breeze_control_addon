"""V33 recovery shares the runtime serial owner, ids, queues and integrity gates."""
from .real_radio import RealRadioTransport
from .radio_wire import number, mac_bytes
from .serial_support import SerialFault


class LateJoinRadioTransport(RealRadioTransport):
    def __init__(self, *args, **kwargs):
        if kwargs.get('firmware_version') != 33:
            raise ValueError('explicit V33 late-join capability required')
        super().__init__(*args, **kwargs)
        self.recovery_ids = {}
        self.automatic = {}
        self.recovery_rx = lambda fields: None
        self.recovery_request = None
        self.config_transition = None
        self.previous_config = None
        self.automatic_seen = set()
        self.readiness_due = {}
        self.readiness_polls = {}

    def context_available(self,context_id):
        b=self.by_context.get(context_id)
        return (super().context_available(context_id) and b is not None
                and self.clock.now_ms()>=self.readiness_due.get(b.slot,0)
                and self.readiness_polls.get(b.slot,40)>=40)

    def application_ready(self,context_id):
        if not super().application_ready(context_id):return False
        slot=self.by_context[context_id].slot
        # An overdue poll is serviced before allocating/encrypting a setter;
        # firmware requires a recent idle poll as well as the startup count.
        return self.clock.now_ms()<self._poll_due[slot]

    def pump(self):
        super().pump()
        if self.connected:
            ready=[slot for slot,due in self.readiness_due.items() if self.clock.now_ms()>=due
                   and self.readiness_polls.get(slot,0)>=40]
            for slot in ready:self.readiness_due.pop(slot)
            if ready:self.health_handler(True,None)

    def recovery_ready(self):
        self._owner_only()
        return (self.connected and not self._pending and not self._commands
                and not self.automatic and self._wire_waiting is None)

    def recovery_submit(self, verb, slot, callback, *, raw=None, **fields):
        if not self.recovery_ready() or slot in self.active_slots or slot not in self.by_slot:
            raise ValueError('idle owned recovery for an inactive slot required')
        identifier=self._send(verb,slot,raw=raw,**fields)
        self.recovery_ids[identifier]=callback
        if verb=='CURRENT_SHORT_COMMIT':
            if self._config_generation==0xffffffff:
                raise SerialFault('radio_config_generation_exhausted')
            self.config_transition=(self._config_generation,self._config_generation+1)
        if verb in ('REJOIN_REQUEST','END_DEVICE_TIMEOUT'):
            self.recovery_request=(slot,identifier)
            self.automatic_seen.clear()
        return identifier

    def activate_recovered(self, binding, *, ready_after_ms=0):
        self._owner_only()
        old=self.by_slot[binding.slot]
        if (binding.slot in self.active_slots or binding.context_id!=old.context_id
                or binding.pan!=old.pan or binding.raw_ieee!=old.raw_ieee
                or binding.epoch!=old.epoch or binding.attempt!=old.attempt
                or binding.key_sequence!=old.key_sequence or binding.generation<=old.generation
                or binding.guard==old.guard or type(ready_after_ms) is not int or not 0<=ready_after_ms<=60000
                or self.automatic or any(p.slot==binding.slot for p in self._pending.values())):
            raise SerialFault('late_join_activation_binding')
        self.by_slot[binding.slot]=binding
        self.by_context[binding.context_id]=binding
        self.by_pan[binding.pan]=binding
        self.bindings=tuple(self.by_slot[s] for s in (0,1))
        self.active_slots=self.active_slots|{binding.slot}
        self._checked.add(binding.slot)
        self._poll_misses[binding.slot]=0
        now=self.clock.now_ms()
        self._poll_due[binding.slot]=now+1250
        self._status_due[binding.slot]=now+10000
        self.readiness_due[binding.slot]=now+ready_after_ms
        self.readiness_polls[binding.slot]=0
        self.recovery_request=None
        self.health_handler(True,None)

    def _status_integrity(self, f):
        if (f.get('boot')!=self.boot or f.get('session')!='1'
                or f.get('application_tx')!=self.application_tx
                or any(f.get(k,'0')!='0' for k in ('rx_drop','out_drop','quarantine',
                    'reboot_required','rx_cutoff_stalled'))):
            raise SerialFault('late_join_status_integrity')
        number(f,'late_join_restartable',1)
        now=number(f,'time_us')
        if self._radio_time is not None and (now-self._radio_time)&0xffffffff>=0x80000000:
            raise SerialFault('radio_session_budget_exhausted')
        self._radio_time=now

    def _auto(self,kind,f):
        if (f.get('boot')!=self.boot or f.get('session')!='1'
                or any(f.get(k,'0')!='0' for k in ('rx_drop','out_drop','reboot_required'))):
            raise SerialFault('late_join_automatic_integrity')
        slot=number(f,'ctx',1);identifier=number(f,'id');poll=number(f,'poll',5)
        if self.recovery_request!=(slot,identifier) or slot in self.active_slots or not poll:
            raise SerialFault('late_join_automatic_binding')
        key=(slot,identifier,poll)
        if kind=='AUTO_ACCEPT':
            raw=mac_bytes(f['mac']);b=self.by_slot[slot]
            if (self.automatic or key in self.automatic_seen or len(raw)!=10 or raw[:2]!=b'\x63\x88'
                    or raw[3:7]!=b.pan.to_bytes(2,'little')+b'\0\0'
                    or raw[7:9]!=b.short.to_bytes(2,'little') or raw[9]!=4
                    or f.get('class')!='MANAGEMENT_POLL' or f.get('retry')!='0'):
                raise SerialFault('late_join_automatic_frame')
            self.automatic[key]=raw
            self.automatic_seen.add(key)
        else:
            raw=self.automatic.pop(key,None)
            if (raw is None or f.get('cleanup')!='safe'
                    or f.get('result') not in ('local_tx_ok','no_ack','invalid_ack','cca_fail')):
                raise SerialFault('late_join_automatic_completion')
            if f['result']=='local_tx_ok' and (f.get('ack_present')!='1'
                    or number(f,'ack_dsn',255)!=raw[2] or number(f,'ack_fcf',65535)&7!=2):
                raise SerialFault('late_join_automatic_ack')

    def _record(self,kind,f):
        if kind in ('AUTO_ACCEPT','AUTO_DONE'):
            self._auto(kind,f)
            return
        if kind=='RX':
            revision=number(f,'revision');actual=number(f,'config_generation')
            allowed={self._config_generation}
            if self.config_transition:allowed.update(self.config_transition)
            if self.previous_config and revision<=self.previous_config[1]:
                allowed.add(self.previous_config[0])
            if self.state!='handshake' and actual not in allowed:
                raise SerialFault('radio_rx_binding_changed')
            before=self._revision
            # The base still owns continuity, boot, CRC, PAN and live routing.
            checked=dict(f,config_generation=str(self._config_generation))
            super()._record(kind,checked)
            if self._revision==revision and before!=revision and self.connected:
                self.recovery_rx(f)
            return
        if kind=='STATUS':
            self._status_integrity(f)
        identifier=number(f,'id') if 'id' in f else None
        callback=self.recovery_ids.get(identifier)
        if callback is None:
            if kind=='STATUS' and number(f,'config_generation')!=self._config_generation:
                raise SerialFault('radio_context_config_changed')
            request=self._pending.get(identifier)
            result=super()._record(kind,f)
            if (kind=='TXDONE' and request is not None and request.verb=='MANAGEMENT_POLL'
                    and request.slot in self.readiness_polls):
                self.readiness_polls[request.slot]=min(40,self.readiness_polls[request.slot]+1)
            return result
        request=self._pending.get(identifier)
        if request is None or f.get('ctx')!=str(request.slot) or f.get('session')!='1':
            raise SerialFault('late_join_wrong_result')
        if kind=='STATUS' and request.raw is None:
            generation=number(f,'config_generation')
            if request.verb=='CURRENT_SHORT_COMMIT':
                if not self.config_transition or generation!=self.config_transition[1]:
                    raise SerialFault('late_join_config_commit')
                self.previous_config=(self.config_transition[0],number(f,'rx_revision'))
                self._config_generation=generation
                self.config_transition=None
            elif generation!=self._config_generation:
                raise SerialFault('late_join_config_binding')
            self._finish(identifier,kind,f)
        else:
            super()._record(kind,f)
            if kind!='TXDONE':return
        self.recovery_ids.pop(identifier)
        callback(kind,f)

    def _disconnect(self,reason,*,retry):
        super()._disconnect(reason,retry=retry)
        self.recovery_ids.clear()
        self.automatic.clear()
        self.config_transition=None
