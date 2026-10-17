"""Injected single-session host coordinator. No serial/flash/RF entrypoint.

V5 crypto/replay/durable Provision and KeyPhase reused unchanged. All writes
require explicit caller-owned run root, never the historical seed path.
"""
import time, hashlib
from core import *
from bindings import OwnedSecret
from current_a7_baseline import A7Preconditions, BaselineRejected, diagnostic
from functools import wraps
def fail_closed(method):
    @wraps(method)
    def checked(self,*args,**kwargs):
        try:return method(self,*args,**kwargs)
        except Exception:
            if self.stage!='ANNOUNCE_UNCERTAIN':self.stage='STOP'
            raise
    return checked

class SingleBoot:
    def __init__(self, root, seed, backend, tc_key, permit_key, clock=time.monotonic):
        if not isinstance(tc_key,OwnedSecret) or not isinstance(permit_key,OwnedSecret):raise Stop('explicit_ctx1_secret_provenance_required')
        tc_key.require('tc_link');permit_key.require('permit_candidate')
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)
        self.provision=Provision(self.root/'association')
        if self.provision.path.exists() or (self.root/'key/security/epoch.json').exists():raise Stop('existing_run_no_restart')
        self.seed=dict(seed);self.backend=backend;self.tc_key=tc_key;self.permit_key=permit_key;self.clock=clock
        self.stage='PASSIVE';self.boot=None;self.session=None;self.pre=None;self.baseline=None;self.permit=None;self.kp=None
        self.revision=0;self.request_floor=None;self.request_ok=False;self.request_used=False;self.pending_kind=None
        self.response=None;self.assoc_response_at=None;self.first_poll_at=None;self.transport_key_at=None;self.trace=[]
        self.key_state_acknowledged=False;self.baseline_at=None
        self.association_polls=0;self.cca_retry_after=None;self.association_start=None;self.association_last_poll=None
    @fail_closed
    def attach(self, info):
        if self.boot is not None:raise Stop('one_boot_only')
        expected={'identity':'airnanny_ctx1_commission_v7','version':'7','channel':'21','session':'0',
                  'immediate_ack':'0','pending_tx':'0','rx_drop':'0','out_drop':'0','crypto':'host_only','application_tx':'locked'}
        if any(info.get(k)!=v for k,v in expected.items()):raise Stop('INFO_context')
        self.boot=info['boot'];self.revision=int(info['rx_revision'])
        p=permit_module.PermitValidator(boot=self.boot,pan=0x0b7a,coordinator=TC,key=self.permit_key.value,
            key_sequence=0,key_epoch=self.permit_key.epoch,generation=3,ctx=1,revision_floor=self.revision)
        self.pre=A7Preconditions(p,self.permit_key)
    def _ready(self, stage):
        if self.stage!=stage or self.boot is None:raise Stop('host_stage_'+self.stage)
    @fail_closed
    def receive(self, raw, revision, ack=None, observed=None):
        if self.boot is None or revision<=self.revision:raise Stop('old_RX_revision')
        self.revision=revision;now=self.clock();observed=now if observed is None else observed
        if self.stage in ('PASSIVE','BASELINE_READY'):
            # Pre-arm ZDO0036 is NOT an ordinary baseline or an authorization.
            try:m=permit_module.codec.Mac.parse(raw)
            except ValueError:return False
            if len(m.payload)<8 or m.payload[2:4]==bytes.fromhex('fcff'):
                self.trace.append({'revision':revision,'baseline_current_a7':False,'reason':'pre_arm_not_ordinary_TYPE06'})
                return False
            try:e=self.pre.validate_current_a7_baseline(raw=raw,boot=self.boot,revision=revision,observed=observed,now=now,generation=3)
            except BaselineRejected as exc:
                self.trace.append(exc.diagnostic)
                if str(exc).endswith('_STOP'):self.stage='STOP';raise Stop(str(exc))
                return False
            if e.semantic_policy!='captured_A7_TYPE06_unicast':return False
            self.baseline=e;self.baseline_at=observed;self.stage='BASELINE_READY';self.trace.append(dict(diagnostic(e),permit_ready=False));return True
        if self.stage=='ARMED':
            self.pre._context_unchanged()
            try:self.permit=self.pre.validate_pairing_permit(raw=raw,boot=self.boot,revision=revision,observed=observed,now=now,generation=3)
            except Exception:return False
            self.stage='PERMIT_READY';return True
        if self.stage in ('REQUEST_SENT','WAIT_ASSOC_RESPONSE'):
            if raw[:2]!=bytes.fromhex('63cc'):return False
            parsed=plan.validate_response(raw,RAW,TC,revision,self.request_floor)
            if parsed['status']!=0:self.stage='STOP';raise Stop('association_explicit_rejection')
            if ack is None or (ack.get('ack_started'),ack.get('ack_completed'),ack.get('deadline_miss'))!=('1','1','0'):
                self.stage='STOP';raise Stop('response_ACK_not_clean')
            if self.response is not None:raise Stop('immutable_response')
            self.response=(raw,revision,ack);self.assoc_response_at=now;return True
        if self.stage=='WAIT_NETWORK_KEY':
            if now-self.kp.started>=10:raise Stop('key_window_expired_no_install')
            accepted=self.kp.receive(raw,revision)
            if accepted:self.transport_key_at=now;self.stage='KEY_INSTALLED'
            return accepted
        return False
    @fail_closed
    def baseline_line(self, identifier):
        self._ready('BASELINE_READY')
        return f'RADIOV7 BASELINE_READY id={identifier} boot={self.boot} ctx=1 generation=3 baseline_revision={self.baseline.revision}'
    @fail_closed
    def arm_line(self, identifier):
        self._ready('BASELINE_READY')
        if not 0<=self.clock()-self.baseline_at<=10:raise Stop('ordinary_baseline_stale')
        return f'RADIOV7 ARM id={identifier} boot={self.boot} ctx=1 generation=3 baseline_revision={self.baseline.revision}'
    @fail_closed
    def arm_ack(self, status):
        self._ready('BASELINE_READY')
        if status.get('boot')!=self.boot or status.get('state')!='PERMIT_ARMED':raise Stop('arm_not_acknowledged')
        floor=int(status['rx_revision']);p=self.pre.permit
        p.revision_floor=max(p.revision_floor,floor);p.last_revision=max(p.last_revision,floor)
        self.stage='ARMED'
    @fail_closed
    def begin_line(self, identifier):
        self._ready('PERMIT_READY');now=self.clock();self.pre.permit.reserve(self.permit,now)
        self.provision.reserve(self.seed,self.permit)
        self.stage='ASSOC_SELECTED'
        return self.provision.begin(self.permit,identifier).replace('RADIOV3','RADIOV7')
    @fail_closed
    def begin_ack(self, status):
        self._ready('ASSOC_SELECTED')
        if status.get('boot')!=self.boot or status.get('state')!='ASSOCIATION' or int(status['session'])!=1:raise Stop('association_begin_binding')
        self.session=1
    @fail_closed
    def request_line(self, identifier):
        self._ready('ASSOC_SELECTED')
        if self.session!=1 or self.request_used:raise Stop('one_request_only')
        self.association_start=self.clock()
        self.request_used=True;self.request_floor=self.revision;self.pending_kind='request';self.stage='REQUEST_SENT'
        return f'RADIOV7 ASSOC REQUEST id={identifier} boot={self.boot} session={self.session}'
    def association_poll_due(self):
        """Offline scheduling predicate; caller must drain fresh RX before submitting."""
        now=self.clock()
        if self.stage!='WAIT_ASSOC_RESPONSE' or self.response or self.pending_kind or self.association_polls>=2:return False
        if self.association_start is None or now-self.association_start>=10:return False
        if self.cca_retry_after is not None:return now>=self.cca_retry_after
        previous=self.association_last_poll if self.association_last_poll is not None else self.association_start
        return now-previous>=.5
    @fail_closed
    def extended_poll_line(self, identifier):
        self._ready('WAIT_ASSOC_RESPONSE')
        if self.pending_kind or self.response:raise Stop('pending_TX_or_response')
        if self.association_polls>=2:raise Stop('association_poll_budget')
        if self.clock()-self.association_start>=10:raise Stop('association_window_expired')
        if self.cca_retry_after is not None and self.clock()<self.cca_retry_after:raise Stop('cca_recovery_too_soon')
        self.association_polls+=1;self.association_last_poll=self.clock();self.cca_retry_after=None
        self.pending_kind='extended'
        return f'RADIOV7 ASSOC POLL id={identifier} boot={self.boot} session={self.session}'
    @fail_closed
    def local_done(self, result):
        kind=self.pending_kind
        if kind is None:raise Stop('unexpected_completion')
        self.pending_kind=None
        if kind=='announce':self.kp.done(result);self.stage='MANAGEMENT_PENDING';return
        if kind=='extended' and result=='cca_fail' and self.association_polls==1 and self.request_ok and self.stage=='WAIT_ASSOC_RESPONSE':
            self.cca_retry_after=self.clock()+.0032
            return
        if result!='local_tx_ok':self.stage='STOP';raise Stop('local_TX_failed_no_retry')
        if kind=='request':self.request_ok=True;self.stage='WAIT_ASSOC_RESPONSE'
    @fail_closed
    def commit_line(self, identifier):
        self._ready('WAIT_ASSOC_RESPONSE')
        if not self.response or self.pending_kind or not self.request_ok:raise Stop('current_response_and_completion_required')
        raw,revision,ack=self.response;r=self.provision.read()
        r=self.provision.commit_response(r['attempt'],raw,revision,self.request_floor,ack,True)
        self.kp=KeyPhase(self.provision,self.root/'key',self.backend,self.tc_key)
        self.kp.started=self.clock();self.stage='ASSOCIATED_UNKEYED'
        line=bind_line(self.provision,self.boot,identifier,r['generation'],r['assigned_short'])
        return line.replace('RADIOV5 BIND_ASSOCIATED','RADIOV7 ASSOC_COMMIT')+f' session={self.session}'
    @fail_closed
    def commit_ack(self, status):
        self._ready('ASSOCIATED_UNKEYED')
        if status.get('boot')!=self.boot or status.get('session')!=str(self.session) or status.get('state')!='WAIT_NETWORK_KEY' or int(status['generation'])!=self.kp.c.generation or int(status['assigned_short'],16)!=self.kp.c.short:
            raise Stop('durable_short_not_bound')
        self.stage='WAIT_NETWORK_KEY'
    def _binding(self):
        c=self.kp.c
        return f'session={self.session} attempt={c.attempt} raw_ieee={c.raw_ieee} short={c.short:04x} pan=0b7a coordinator={c.tc_ieee}'
    @fail_closed
    def poll_line(self, identifier):
        self._ready('WAIT_NETWORK_KEY')
        if self.pending_kind:raise Stop('pending_TX')
        now=self.clock();line=self.kp.poll_line(self.boot,identifier,now)
        if self.first_poll_at is None:self.first_poll_at=now
        self.pending_kind='key_poll'
        return line.replace('RADIOV5 KEY_POLL','RADIOV7 POST_ASSOC_POLL')+' '+self._binding()
    @fail_closed
    def key_line(self, identifier):
        self._ready('KEY_INSTALLED')
        if self.pending_kind:raise Stop('pending_TX')
        return self.kp.key_line(self.boot,identifier).replace('RADIOV5','RADIOV7')+' '+self._binding()
    @fail_closed
    def key_ack(self, status):
        self._ready('KEY_INSTALLED')
        r=self.kp.epoch.read()
        if status.get('boot')!=self.boot or status.get('session')!=str(self.session) or status.get('state')!='KEY_INSTALLED' or int(status['generation'])!=r['generation'] or int(status['assigned_short'],16)!=self.kp.c.short:
            raise Stop('KEY_STATE_not_acknowledged')
        self.key_state_acknowledged=True
    @fail_closed
    def build(self):
        self._ready('KEY_INSTALLED')
        if self.pending_kind or not self.key_state_acknowledged:raise Stop('KEY_STATE_ack_and_completion_required')
        return self.kp.build(self.boot)
    @fail_closed
    def announce_line(self, identifier):
        self._ready('KEY_INSTALLED')
        line=self.kp.handoff_line(identifier).replace('RADIOV5','RADIOV7')
        self.stage='ANNOUNCE_UNCERTAIN';self.pending_kind='announce'
        return line+f' session={self.session} attempt={self.kp.c.attempt}'
    def timings(self):
        return {'assoc_response_to_first_key_poll_ms':None if self.first_poll_at is None else (self.first_poll_at-self.assoc_response_at)*1000,
                'assoc_response_to_transport_key_ms':None if self.transport_key_at is None else (self.transport_key_at-self.assoc_response_at)*1000}
