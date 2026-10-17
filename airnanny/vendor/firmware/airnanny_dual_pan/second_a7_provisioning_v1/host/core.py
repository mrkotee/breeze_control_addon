"""Offline-testable existing-identity reassociation and strict V4->V5 handoff.
No transport/device imports. Old attempt and frozen V4/V5 implementation untouched.
"""
from pathlib import Path
import sys,uuid,json,hashlib,dataclasses
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'tools'))
from key_announce import Context,Epoch,ProtectedSecrets,Secret,Rx,Sequences,validate_transport,verify_announce,durable,store
from key_announce import load
permit_module=load('gate_v1_permit',R/'tools/permit_validator.py')
plan=load('gate_v1_assoc_plan',R/'tools/attempt_plan.py')
RAW='027a56bb75a41437';TC='00124b0036a1875f';OLD_ATTEMPT='9e96a9c130c44db687c1569b811dcf99'
V4_HASH='9264A4D01C42ADB4B131595BA824C704D2ACB38EA3B72889AC827641EAD8F149'
V5_HASH='56944009448C3BE460E45370BB1723BA390DDA510FB25B7ECF25BEE4FC5A8DCE'
V17_HASH='2FFFE202FC0B8766113CADF92156B76A98942B64A0E4F3D3692513F210575193'
from bindings import OwnedSecret
class Stop(RuntimeError):pass
class Provision:
    """New authoritative successor ledger; old V4 association evidence read-only.
    No IEEE allocation, no old-attempt reuse, no counter/epoch initialization.
    """
    def __init__(self,root):self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.path=self.root/'provision.json'
    def read(self):return json.loads(self.path.read_text(encoding='utf-8'))
    def reserve(self,seed,permit):
        with store.locked(self.root):
            if self.path.exists():raise Stop('one_gate_already_reserved_no_retry')
            if seed.get('raw_ieee')!=RAW or seed.get('state')!='ALLOCATED_UNUSED' or seed.get('generation')!=0 or seed.get('attempt') is not None or seed.get('ctx')!=1 or seed.get('target_pan')!=0x0b7a or seed.get('coordinator_ieee')!=TC or any(k in seed for k in ('next_fc','key_epoch_id','secret_ref')):raise Stop('seed_not_unkeyed_or_identity_changed')
            if permit.ctx!=1 or permit.pan!=0x0b7a or permit.target_coordinator_ieee!=TC:raise Stop('permit_context')
            r=dict(seed);r.update(state='REASSOCIATION_ATTEMPT_RESERVED',generation=3,attempt=uuid.uuid4().hex,previous_attempt=None,previous_generation=0,previous_short=None,permit=dataclasses.asdict(permit),ever_secured_tx=False)
            if r['attempt']==OLD_ATTEMPT:raise Stop('attempt_collision')
            durable(self.path,r);return r
    def begin(self,evidence,identifier):
        r=self.read()
        if r['state']!='REASSOCIATION_ATTEMPT_RESERVED' or r['permit']!=dataclasses.asdict(evidence):raise Stop('new_attempt_required')
        # Frozen V4 wire helper expects ATTEMPT_RESERVED; transient adapter only.
        wire_record=dict(r,state='ATTEMPT_RESERVED')
        return plan.begin_command(evidence,wire_record,identifier)
    def commit_response(self,attempt,raw,revision,request_floor,ack,local_success):
        with store.locked(self.root):
            r=self.read()
            if r['state']!='REASSOCIATION_ATTEMPT_RESERVED' or attempt!=r['attempt'] or attempt==OLD_ATTEMPT:raise Stop('old_or_completed_attempt')
            if not local_success:raise Stop('association_local_outcome_uncertain')
            response=plan.validate_response(raw,RAW,TC,revision,request_floor)
            if response['status']!=0:raise Stop('association_explicit_rejection')
            if (ack.get('ack_started'),ack.get('ack_completed'),ack.get('deadline_miss'))!=('1','1','0'):raise Stop('response_ACK_not_clean')
            r.update(state='ASSOCIATED_UNKEYED',generation=r['generation']+1,assigned_short=response['assigned_short'],response_raw=raw.hex(),response_revision=revision,response_ack=dict(ack))
            durable(self.path,r);return r
    def context(self,expected_generation=None):
        r=self.read()
        if r['state']!='ASSOCIATED_UNKEYED' or r['attempt']==OLD_ATTEMPT or r.get('ever_secured_tx') or r['raw_ieee']!=RAW:raise Stop('current_association_required')
        if expected_generation is not None and expected_generation!=r['generation']:raise Stop('wrong_authoritative_generation')
        return Context(r['attempt'],r['generation'],1,RAW,r['assigned_short'],0x0b7a,TC,21,TC)
def bind_line(provision,boot,identifier,expected_generation,expected_short):
    c=provision.context(expected_generation)
    if c.short!=expected_short:raise Stop('old_short_handoff')
    if len(boot)!=32 or any(x not in '0123456789abcdef' for x in boot):raise Stop('boot')
    return f'RADIOV5 BIND_ASSOCIATED id={identifier} boot={boot} ctx=1 generation={c.generation} raw_ieee={RAW} short={c.short:04x} pan=0b7a coordinator={TC} extpan={TC} attempt={c.attempt} max_key_polls=8 poll_interval_ms=500 total_timeout_ms=10000'
class KeyPhase:
    def __init__(self,provision,root,backend,tc_key):
        if not isinstance(tc_key,OwnedSecret):raise Stop('ctx1_TC_candidate_provenance_required')
        tc_key.require('tc_link')
        self.c=provision.context();self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)
        self.epoch=Epoch(self.root/'security',backend);self.epoch.initialize(self.c)
        self.tc_key=tc_key;self.key=None;self.lease=None;self.raw=None;self.intent=None
        self.polls=0;self.last_poll=None;self.started=None;self.seen_revision=0;self.sent=False
    def poll_line(self,boot,identifier,now):
        if self.started is None:self.started=now
        if self.key or self.polls>=8 or now-self.started>=10 or (self.last_poll is not None and now-self.last_poll<.5):raise Stop('key_poll_bound')
        # Poll domain starts at224; secured epoch MAC DSN starts at0. No collision
        # with the immediately preceding key poll; neither seed is historical.
        dsn=224+self.polls;self.polls+=1;self.last_poll=now
        return f'RADIOV5 KEY_POLL id={identifier} boot={boot} ctx=1 generation={self.c.generation} dsn={dsn}'
    def receive(self,raw,revision):
        if revision<=self.seen_revision:raise Stop('old_RX_revision')
        self.seen_revision=revision
        # Only commissioning candidates: no interpreting ordinary encrypted status.
        from key_announce import oracle
        try:m=oracle.Mac.parse(raw)
        except ValueError:return False
        n=m.payload
        if len(n)<10 or n[:2]!=b'\x48\x00' or n[8]!=0x21:return False
        if self.key:raise Stop('unexpected_second_transport_key')
        a=validate_transport(Rx(1,self.c.attempt,self.c.generation,revision,raw),self.c,self.tc_key,self.epoch.replay())
        self.epoch.install(a);self.key=a
        return True
    def key_line(self,boot,identifier):
        r=self.epoch.read()
        if r['state']!='KEY_INSTALLED' or not self.key:raise Stop('durable_key_required')
        return f'RADIOV5 KEY_STATE id={identifier} boot={boot} ctx=1 generation={r["generation"]} epoch={r["key_epoch_id"]} keyseq={r["keyseq"]}'
    def build(self,boot):
        if self.sent or self.raw is not None:raise Stop('one_build_only')
        self.lease=self.epoch.reserve();self.raw=self.epoch.build(self.lease);r=self.epoch.read()
        meta=verify_announce(self.raw,self.c,self.key.secret,r['keyseq'],self.lease.fc,Sequences(**r['lease_sequences']))
        self.intent=self.epoch.intent(self.lease,self.raw,boot,1)
        return meta
    def handoff_line(self,identifier):
        if self.sent or self.intent is None:raise Stop('one_announce_only')
        # Separate public intent record includes intent generation BEFORE USB.
        durable(self.root/'handoff.json',{'state':'ANNOUNCE_UNCERTAIN','intent':self.intent,'mac':self.raw.hex()})
        self.epoch.handed(self.lease);self.sent=True
        i=self.intent
        return f'RADIOV5 DEVICE_ANNOUNCE id={identifier} boot={i["boot"]} ctx=1 generation={i["provision_generation"]} raw_ieee={RAW} short={self.c.short:04x} pan=0b7a coordinator={TC} epoch={i["key_epoch"]} keyseq={i["keyseq"]} fc={i["fc"]} intent=1 hash={i["mac_hash"]} mac={self.raw.hex()}'
    def done(self,result):
        if not self.sent:raise Stop('unexpected_TXDONE')
        self.epoch.completion(result=='local_tx_ok')
        if result!='local_tx_ok':raise Stop('announce_TX_inconclusive')
def hashes():
    paths={'V4':R.parent/'raw_radio_v4_assoc_permit/build/airnanny_raw_assoc_permit_v4.hex','V5':R/'build/airnanny_raw_key_announce_v5_prep.hex','V17':R.parent.parent/'airnanny_v17/releases/airnanny_status_v17_machine_serial.hex'}
    for name,path in paths.items():
        if hashlib.sha256(path.read_bytes()).hexdigest().upper()!=globals()[name+'_HASH']:raise Stop(name+'_hash_changed')
    return {name:str(path) for name,path in paths.items()}
