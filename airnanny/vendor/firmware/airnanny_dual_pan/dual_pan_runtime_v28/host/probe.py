"""Injected-port one-session sequencer. No CLI, COM imports or auto hardware run."""
import time,hashlib
from ledger import *
from discovery import validate,beacon_request
from rejoin_wire import Wire,Fault as WireFault,PREFIX
from observation import Observation

# The firmware refuses ctx on these two: they act on the whole runtime, and a
# ctx accepted there would imply a scope they do not have.
GLOBAL_VERBS=('INFO','END','STATS')

class Probe:
    def __init__(self,port,ledger,clock=time.monotonic):
        self.clock=clock;self.ledger=ledger;self.records=[];self.w=Wire(port,clock,self.records)
        self.w.on_rx=self.on_rx;self.w.on_auto=self.on_auto;self.phase='BASELINE';self.scan_rows=[]
        self.current_request=None;self.auto_accept=None;self.session=0;self.delivery=[];self.ends=None
        self.executed=False
        # The context this run drives, taken from the ledger once it is read.
        # None until then, so a per-context verb issued before the context is
        # known fails loudly instead of being sent unscoped.
        self.ctx=None
    def on_auto(self,row):
        f=row['fields']
        if row['kind']=='AUTO_DONE' and (f.get('cleanup')!='safe' or f.get('reboot_required')!='0'):raise Fault('AUTO_CLEANUP_UNPROVEN')
        if not self.current_request or int(f['id'])!=self.current_request['id']:raise Fault('auto_request_binding')
        if row['kind']=='AUTO_ACCEPT':
            if self.auto_accept or f['class']!='MANAGEMENT_POLL' or f['retry']!='0':raise Fault('auto_duplicate_class')
            self.auto_accept=f
        else:
            a=self.auto_accept
            if not a or f['poll']!=a['poll'] or f['result']!='local_tx_ok' or f['ack_present']!='1':raise Fault('auto_missing_or_failed_receipt')
            raw=bytes.fromhex(a['mac'])
            if int(f['ack_dsn'])!=raw[2] or int(f['ack_fcf']) not in (2,18):raise Fault('auto_ACK_binding')
            queued=int(a['time_us']);started=int(f['rf_start_us']);ended=int(f['time_us'])
            if not queued<=started<=queued+20000 or not started<=ended<=started+20000:raise Fault('poll_RF_timing')
            self.ledger.auto_poll(raw,int(a['poll']),started,int(f['ack_fcf'])==18,raw[2])
            self.auto_accept=None
    def on_rx(self,row,receiver=None):
        f=row['fields'];raw=bytes.fromhex(f['mac'])
        if self.phase=='BASELINE':self.ledger.baseline_receive(raw,self.clock());return
        if self.phase=='SCAN':
            if raw[0]&7==0:self.scan_rows.append(f)
            return # non-beacons discarded by discovery service
        q=self.ledger.read()['recovery'];polls=q['polls']
        if f.get('session')!='1':raise Fault('RX_wrong_session')
        pending=[p for p in polls if p.get('pending_ACK') and p['at']<=int(f['time_us'])/1e6]
        dsn=pending[-1]['dsn'] if pending else None
        result=(receiver or self.ledger.receive)(raw,int(f['revision']),int(f['time_us'])/1e6,f,dsn)
        if result in ('LEAVE_REPEATED','REPLAY_REJECTED','REJECTED','TIMEOUT_REJECTED','KEEPALIVE_METHOD_UNIMPLEMENTED','NO_RESPONSE'):raise Fault(result)
        if result in ('REJOINED','PARENT_LINK_ACTIVE','RAW_ORDINARY'):
            self.delivery.append({'result':result,'revision':int(f['revision']),'time_us':int(f['time_us'])})
    def until(self,predicate,seconds):
        end=self.clock()+seconds
        while self.clock()<end:
            row=self.w.read()
            if row and predicate(row):return row
        raise Fault('bounded_receipt_or_response_timeout')
    def observe(self,seconds):
        end=self.clock()+seconds
        while self.clock()<end:self.w.read()
    def command(self,verb,fields='',raw=None):
        # ctx is appended here rather than at each call site. The firmware now
        # refuses a per-context verb that omits it, and a probe that could
        # forget it on one of ten verbs would fail that verb only in the run
        # that happens to reach it. GLOBAL_VERBS must not carry ctx at all: the
        # firmware refuses a scope those verbs do not have.
        if verb not in GLOBAL_VERBS:
            if self.ctx is None:raise Fault('ctx_unknown_before_bind')
            fields=(fields+' ' if fields else '')+f'ctx={self.ctx}'
        i=self.w.next_id();self.w.send(f'{PREFIX} {verb} id={i}'+(' boot='+self.w.boot if self.w.boot else '')+(' '+fields if fields else ''),raw,verb if raw else None)
        # Which record answers which verb. STATS answers with its own kind, so
        # it has to be named here or awaiting it would never match and the
        # bounded wait would simply time out.
        expect='TXDONE' if raw else {'INFO':'INFO','STATS':'STATS'}.get(verb,'STATUS')
        row=self.until(lambda r:r['kind']==expect and r['fields'].get('id')==str(i),2)
        if raw:
            f=row['fields']
            if f.get('cleanup')!='safe' or f.get('reboot_required')!='0':raise Fault('TX_CLEANUP_UNPROVEN')
            if f['result']!='local_tx_ok':raise Fault('failed_or_unknown_TX_no_retry')
            if raw[0]&0x20 and (f['ack_present']!='1' or int(f['ack_dsn'])!=raw[2] or int(f['ack_fcf']) not in (2,18)):raise Fault('TX_MAC_ACK_binding')
        return row['fields']
    def secured(self,kind,verb):
        raw,fc=self.ledger._build(kind);r=self.ledger.read();q=r['recovery']
        self.ledger.handoff(kind,self.clock());self.current_request={'id':self.w.id+1,'kind':kind}
        fields=f'session=1 generation={r["generation"]} epoch={EPOCH} attempt={ATTEMPT} guard={q["gate"]} fc={fc} hash={hashlib.sha256(raw).hexdigest()} mac={raw.hex()}'
        row=self.command(verb,fields,raw);self.ledger.tx_result(kind,'local_tx_ok',int(row['time_us']))
        return row
    def wait_state(self,state):
        end=self.clock()+.8
        while self.clock()<end:
            if self.ledger.read()['recovery']['state']==state:return
            self.w.read()
        raise Fault('bounded_no_authenticated_response')
    def application_ready(self):
        pass
    def discover_target(self,r,guard):
        dsn=self.ledger.begin_discovery(self.clock());self.phase='SCAN'
        for attempt in range(1,4):
            if attempt>1:
                def reserve(record):
                    q=record['recovery']
                    if q['state']!='DISCOVERING' or q['gate']!=guard or q.get('intents'):raise Fault('discovery_only_retry_binding')
                    q['scan_dsn']=record['sequences']['dsn'];record['sequences']['dsn']=(q['scan_dsn']+1)&255
                r=self.ledger.change(reserve);dsn=r['recovery']['scan_dsn']
            self.scan_rows=[];floor=self.w.rx_revision
            scan=self.command('ACTIVE_DISCOVERY_BEACON_REQUEST',f'session=1 generation={r["generation"]} dsn={dsn}',beacon_request(dsn));start=int(scan['time_us'])
            self.records.append(dict(kind='DISCOVERY_SCAN_ATTEMPT',attempt=attempt,dsn=dsn,observed=self.clock()))
            self.observe(.28);status=self.command('STATUS','session=1')
            if status.get('recovery')=='BOUND' and attempt<3:continue
            if status.get('recovery')!='DISCOVERED':raise Fault('no_target_beacon_after_bounded_scans')
            f=next((row for row in reversed(self.scan_rows) if row['revision']==status['beacon_revision']),None)
            if not f:raise Fault('discovery_RX_missing')
            evidence=validate(bytes.fromhex(f['mac']),f,self.w.boot,guard,floor,start,int(status['time_us']))
            self.ledger.prepare(evidence,int(status['time_us']))
            self.command('DISCOVERY_COMMIT',f'session=1 generation={r["generation"]} revision={evidence.revision} hash={evidence.raw_hash}')
            return
        raise Fault('discovery_scan_bound')
    def execute(self,observe_seconds=60):
        if self.executed:raise Fault('single_session_NO_RERUN')
        if not 1<=observe_seconds<=90:raise Fault('observation_bound')
        self.executed=True
        error=None;ready=False;observation_start=None;observation_stop=None
        try:
            info=self.command('INFO')
            if any(info.get(k)!=v for k,v in {'identity':'airnanny_dual_pan_runtime_v28','version':'28','wire':'10','contexts':'2','channel':'21','application_tx':'typed_fan_once','crypto':'host_only','session':'0','immediate_ack':'0','pending_tx':'0'}.items()):raise Fault('exact_IDLE_V10_required')
            end=self.clock()+10
            while self.clock()<end and not self.ledger.baseline:self.w.read()
            r=self.ledger.read();guard=self.ledger.guard
            self.ctx=int(r["context"]["ctx"])
            self.command('BIND',f'session=1 generation={r["generation"]} epoch={EPOCH} attempt={ATTEMPT} guard={guard} short={r["context"]["short"]}');self.session=1
            self.discover_target(r,guard)
            self.phase='RECOVERY';self.secured('REJOIN','REJOIN_REQUEST');self.wait_state('REJOINED')
            r=self.ledger.read();q=r['recovery'];short=r['context']['short'];generation=r['generation']
            receipt=self.command('CURRENT_SHORT_COMMIT',f'session=1 generation={generation} revision={q["rejoin_response"]["revision"]} short={short}')
            if receipt['assigned_short']!=f'{short:04x}' or receipt['generation']!=str(generation) or receipt['recovery']!='REJOINED':raise Fault('short_install_receipt')
            self.ledger.confirm_short_install(short,generation)
            self.secured('ANNOUNCE','DEVICE_ANNOUNCE');self.secured('TIMEOUT','END_DEVICE_TIMEOUT');self.wait_state('PARENT_LINK_ACTIVE')
            q=self.ledger.read()['recovery'];response=q['lifetime']['response_revision']
            self.command('PARENT_LINK_ACTIVE',f'session=1 generation={generation} revision={response}')
            if observe_seconds!=60:raise Fault('fixed_60s_observation_required')
            observation_start=self.clock();end=observation_start+60;policy=Observation(observation_start)
            while self.clock()<end:
                self.observe(min(1.02,end-self.clock()))
                if self.clock()>=end:break
                raw=self.ledger.reserve_idle_poll(self.clock());receipt=self.command('MANAGEMENT_POLL',f'session=1 generation={generation} dsn={raw[2]}',raw)
                policy.record(self.clock(),raw[2],receipt['result'],receipt.get('_host_validated_preair',False))
                self.ledger.idle_result(raw[2],receipt['result'],receipt)
            observation_stop=self.clock()
            self.ledger.observation_complete(policy.finish(observation_stop))
            ready=self.ledger.ready(True)
            if ready:self.application_ready()
        except Exception as exc:
            if observation_start is not None and observation_stop is None:observation_stop=self.clock()
            error=type(exc).__name__+':'+str(exc)
        finally:
            if self.w.boot:
                # Preserve forensic records; terminal RX may contain another Leave.
                # END must still be attempted even after semantic failure.
                self.w.ending=True
                late_errors=[]
                def terminal_rx(row):
                    try:self.on_rx(row)
                    except Exception as exc:late_errors.append(type(exc).__name__+':'+str(exc))
                self.w.on_rx=terminal_rx
                self.w.on_auto=lambda row:self.records.append({'kind':'AUTO_DURING_END','fields':row['fields']})
                try:
                    self.ends=self.command('END',f'session={self.session}')
                    if self.ends.get('pending')!='0':
                        self.observe(.05);self.ends=self.command('STATUS',f'session={self.session}')
                    if any(self.ends.get(k)!=v for k,v in {'state':'STOPPED','pending':'0','immediate_ack':'0','rx_drop':'0','out_drop':'0'}.items()):raise Fault('END_not_clean')
                    if self.ends.get('quarantine')!='0' or self.ends.get('reboot_required')!='0':raise Fault('END_QUARANTINED')
                    accepts=[x for x in self.records if x['kind'] in ('TXACCEPT','AUTO_ACCEPT')]
                    terminals=[x for x in self.records if x['kind'] in ('TXDONE','AUTO_DONE')]
                    if int(self.ends['accepted_count'])!=int(self.ends['terminal_count']) or int(self.ends['accepted_count'])!=len(accepts) or len(terminals)!=len(accepts):raise Fault('END_OWNERSHIP_COUNT')
                    if accepts and self.ends.get('cleanup')!='1':raise Fault('END_CLEANUP_UNPROVEN')
                    if late_errors:raise Fault('terminal_RX:'+','.join(late_errors))
                except Exception as exc:error=(error+'; ' if error else '')+'END:'+type(exc).__name__+':'+str(exc)
        return {'ready':ready and not error,'error':error,'records':self.records,'delivery':self.delivery,'end':self.ends,'context_scope_diagnostics':dict(self.ledger.scope_counts),
            'observation_timing':{'clock':'host_monotonic_seconds','start':observation_start,'stop':observation_stop,
                'duration_seconds':None if observation_start is None or observation_stop is None else observation_stop-observation_start,
                'required_seconds':60,'completed':bool(self.ledger.read()['recovery'].get('observation',{}).get('complete'))},
            'public_state':{'short':self.ledger.read()['context']['short'],'next_fc':self.ledger.read()['next_fc'],
            'NWK_floors':self.ledger.read()['nwk_source_floors']},'TYPE07':0,'hardware_acceptance_claim':False}
