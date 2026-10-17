"""Host-owned narrow timeout experiment; no serial import, no generic TX API."""
import sys,json,hashlib,uuid
from pathlib import Path
from functools import reduce
from operator import xor
from cryptography.exceptions import InvalidTag
R=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(R.parent/'second_a7_provisioning_v1/tools'))
from key_announce import oracle,ProtectedSecrets,Secret,durable,store,encrypt
RAW='027a56bb75a41437';TC='00124b0036a1875f';RUN='7dd8634f2c1e491d9601be513519583b'
EPOCH='9985b15dcb574c59b87dc2fb379f317f';ATTEMPT='cbef428849da4e87b48867ac616247d1'
DEP=R.parent/'second_a7_provisioning_v1'
RUN_ROOT=DEP/'.local/hardware_gate_v2/runs'/RUN
CURRENT=RUN_ROOT/'runtime/current/key/security'
def load(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def le(v,n=2):return v.to_bytes(n,'little')
def ieee(v):return bytes.fromhex(v)[::-1]

def decode_nwk(raw,key,keyseq=0,pan=0x0b7a):
    """Authenticate base/extended NWK headers. Other layouts stay explicitly unknown.

    `pan` defaults to ctx1's, which is the value this check carried inline while
    the host had one context, so every V25 caller is unchanged. A dual runtime
    must pass the PAN of the context it is decoding FOR: a decoder that accepts
    only one network cannot tell a ctx0 frame from a malformed one, and would
    report the first as the second."""
    m=oracle.Mac.parse(raw)
    if m.fcf&7!=1 or m.dst_pan!=le(pan):raise ValueError('MAC_context')
    n=m.payload
    if len(n)<8:raise ValueError('short_NWK')
    f=int.from_bytes(n[:2],'little')
    # protocol version2, DATA or CMD; no multicast/source route/reserved bits.
    if f&0xc000 or f&0x0500 or f&3 not in (0,1) or (f>>2)&15!=2 or not f&0x200:raise ValueError('unsupported_NWK_layout')
    h=8+(8 if f&0x800 else 0)+(8 if f&0x1000 else 0)
    if len(n)<h+18 or n[h]!=0x28 or n[h+13]!=keyseq:raise ValueError('security_epoch_or_envelope')
    p,meta=oracle.secured_decode(n[:h],n[h:],key.value,(0x28,))
    meta.update(nwk_fcf=f,nwk_src=int.from_bytes(n[4:6],'little'),nwk_dst=int.from_bytes(n[2:4],'little'),mac_src=m.src[::-1].hex(),mac_dst=m.dst[::-1].hex(),header_length=h)
    return m,p,meta

def describe(raw,key):
    """Read-only description, never returns TK/hash plaintext. No replay mutation."""
    try:m,p,o=decode_nwk(raw,key)
    except (ValueError,InvalidTag,AssertionError) as e:return {'classification':'unknown_or_outside_authenticated_subset','reason':type(e).__name__+':'+str(e) if isinstance(e,ValueError) else type(e).__name__}
    o={k:v for k,v in o.items() if k not in ('nonce','aad')};o['MIC_PASS']=True
    if o['nwk_fcf']&3==1:
        o.update(classification='NWK_command',command_id=p[0] if p else None)
        if len(p)==3 and p[0] in (11,12):o['nonsecret_command_fields']=p[1:].hex()
        return o
    if not p:return dict(o,classification='empty_APS')
    if p[0]&3==1:return dict(o,classification='APS_secured_command_unknown' if p[0]&0x20 else 'APS_command',command_id=None if p[0]&0x20 or len(p)<3 else p[2])
    if p[0]&3 or p[0]&0xa0 or len(p)<8:return dict(o,classification='unsupported_APS')
    cluster=int.from_bytes(p[2:4],'little');profile=int.from_bytes(p[4:6],'little')
    o.update(classification='APS_data',cluster=f'{cluster:04x}',profile=f'{profile:04x}')
    if profile==0 and cluster==0x13 and len(p)==20:o.update(announced_short=int.from_bytes(p[9:11],'little'),announced_ieee=p[11:19][::-1].hex(),capability=p[19])
    if profile==0 and cluster==0x8002 and len(p)>=12:o.update(zdo_status=p[9],descriptor_address=int.from_bytes(p[10:12],'little'))
    if ordinary(p):o['ordinary_TYPE06']=True
    return o

def ordinary(p):
    return (len(p)==34 and p[:7]==bytes.fromhex('00080600040108') and p[8]==0x11 and p[10]==1 and p[11:17]==bytes.fromhex('706500001106') and reduce(xor,p[16:-1],0)==p[-1])

class Ledger:
    """Operate the SAME existing NWK epoch; never initialize/clone/reset it."""
    def __init__(self,root=CURRENT,secrets=None):
        self.root=Path(root);self.path=self.root/'epoch.json';self.secrets=secrets or ProtectedSecrets(RUN_ROOT/'secrets')
        self.check(self.read())
    def read(self):return load(self.path)
    @staticmethod
    def check(r):
        if r.get('management_blocker'):raise ValueError('durable_remote_membership_blocker_no_resume')
        c=r['context']
        if (r['state']!='MANAGEMENT_PENDING' or r['generation']!=6 or not r['announced'] or not r['local_mac_ack'] or r['key_epoch_id']!=EPOCH or r['keyseq']!=0 or r['next_fc']<32 or c['attempt']!=ATTEMPT or c['raw_ieee']!=RAW or c['short']!=0x6c55 or c['pan']!=0x0b7a or c['tc_ieee']!=TC or c['channel']!=21 or c['ctx']!=1):raise ValueError('authoritative_current_epoch_required')
    def key(self):return self.secrets.get(self.read()['secret_ref'])
    def block_leave(self,revision,fc,options):
        with store.locked(self.root):
            r=self.read();self.check(r)
            if r['nwk_source_floors'].get(TC,0)<=fc:raise ValueError('authenticated_leave_floor_required')
            r['management_blocker']={'state':'A7_LEAVE_OBSERVED_APPLICATION_BLOCKED','revision':revision,'source_ieee':TC,'NWK_FC':fc,'leave_options':options,'rejoin_requested':bool(options&0x20),'request':bool(options&0x40),'no_automatic_rejoin':True}
            durable(self.path,r)
    def consume(self,source,fc):
        # Authenticated unknown semantics consume their own source NWK floor too.
        with store.locked(self.root):
            r=self.read();self.check(r)
            floor=r['nwk_source_floors'].get(source,0)
            if fc<floor or fc>=0xffffffff:raise ValueError('NWK_replay_or_exhaustion')
            r['nwk_source_floors'][source]=fc+1;durable(self.path,r)
    def reserve_timeout(self,gate):
        with store.locked(self.root):
            r=self.read();self.check(r)
            if r.get('management_timeout_intent'):raise ValueError('one_timeout_ever_no_retry')
            fc=r['next_fc']
            if fc+31>0xfffffffe:raise ValueError('counter_exhausted')
            seq=dict(r['sequences']);token=uuid.uuid4().hex
            # Durable full block burned BEFORE any encryption or plaintext build.
            r['next_fc']=fc+32;r['sequences']={k:(v+1)&255 for k,v in seq.items()}
            r['management_timeout_intent']={'gate':gate,'token':token,'fc':fc,'phase':'BURNED_BEFORE_CRYPTO','epoch':EPOCH,'sequences':seq,'requested_timeout_enum':8,'configuration':0}
            durable(self.path,r)
        key=self.secrets.get(r['secret_ref'])
        mac=b'\x61\x88'+bytes([seq['dsn']])+le(0x0b7a)+le(0)+le(0x6c55)
        h=b'\x09\x1a'+le(0)+le(0x6c55)+b'\x01'+bytes([seq['nwk']])+ieee(TC)+ieee(RAW)
        aux=b'\x28'+le(fc,4)+ieee(RAW)+b'\x00'
        raw=mac+encrypt(h,aux,b'\x0b\x08\x00',key)
        m,p,meta=decode_nwk(raw,key)
        if len(raw)!=54 or p!=b'\x0b\x08\x00' or meta['source_ieee']!=RAW or meta['counter']!=fc:raise ValueError('self_check')
        with store.locked(self.root):
            r=self.read();i=r['management_timeout_intent']
            if i['token']!=token or i['phase']!='BURNED_BEFORE_CRYPTO':raise ValueError('intent_binding')
            i.update(phase='BUILT_NEVER_RETRY',hash=hashlib.sha256(raw).hexdigest());durable(self.path,r)
        return raw,fc

class Receiver:
    def __init__(self,ledger):self.ledger=ledger;self.key=ledger.key();self.application=[];self.timeout_response=None;self.events=[];self.response_floor=None
    def receive(self,raw,revision,ack=None,observed=0):
        try:m,p,meta=decode_nwk(raw,self.key)
        except (ValueError,InvalidTag,AssertionError):return None
        # Replay is domain NWK/source in current epoch, independent of APS domains.
        try:self.ledger.consume(meta['source_ieee'],meta['counter'])
        except ValueError:return None
        o=describe(raw,self.key);o.update(revision=revision,observed=observed,replay='NEW_DURABLY_CONSUMED');self.events.append(o)
        addressed=(m.fcf==0x8861 and m.src==le(0) and m.dst==le(0x6c55) and meta['nwk_src']==0 and meta['nwk_dst']==0x6c55 and meta['source_ieee']==TC)
        clean=ack is not None and all(ack.get(k)==v for k,v in [('ack_started','1'),('ack_completed','1'),('deadline_miss','0')])
        if addressed and meta['nwk_fcf']==0x1a09 and m.payload[8:16]==ieee(RAW) and m.payload[16:24]==ieee(TC) and len(p)==3 and p[0]==12:
            if self.response_floor is not None and revision>self.response_floor and clean:
                if p[1]!=0 or p[2]&0xf8 or not p[2]&3:raise ValueError('timeout_response_rejected_or_invalid_parent_info')
                self.timeout_response=dict(o,status=0,parent_information=p[2],clean_local_ACK=True)
        if addressed and ordinary(p) and clean:self.application.append(o)
        # Child-evicted leave is a terminal observation, never authorization to rejoin.
        if addressed and meta['nwk_fcf']&3==1 and len(p)==2 and p[0]==4:
            self.ledger.block_leave(revision,meta['counter'],p[1]);raise ValueError('A7_leave_current_membership_lost')
        if addressed and o['classification'] not in ('APS_data','NWK_command'):raise ValueError('unimplemented_addressed_management_requires_reassessment')
        return o
    def ready(self):
        # Two authenticated ordinary addressed TYPE06 deliveries, with fresh FCs,
        # successful local ACKs and >=500ms separation in one continuous session.
        return len(self.application)>=2 and self.application[-1]['observed']-self.application[0]['observed']>=.5
