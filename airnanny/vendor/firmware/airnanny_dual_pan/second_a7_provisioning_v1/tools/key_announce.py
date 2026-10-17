"""Narrow offline commissioning subset. No serial/network dependencies.

Secret objects deliberately have no printable repr. Host is the security authority;
firmware can inspect only outer fields. Not complete commissioning.
"""
from dataclasses import dataclass, field
from pathlib import Path
import importlib.util, sys, os, json, uuid, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
oracle=load('v5_frozen_codec',ROOT.parent/'identity_commissioning_v1/offline_codec.py')
store=load('v5_frozen_durability',ROOT.parent/'raw_radio_v4_assoc_permit/tools/identity_store.py')
MAX_FC=0xfffffffe
def u8(v):
    if type(v)!=int or not 0<=v<=255:raise ValueError('octet')
    return bytes([v])
def le16(v):
    if type(v)!=int or not 0<=v<=65535:raise ValueError('uint16')
    return v.to_bytes(2,'little')
def ieee(v):
    if len(v)!=16 or v.lower()!=v or int(v,16) in (0,2**64-1):raise ValueError('IEEE')
    return bytes.fromhex(v)[::-1]
@dataclass(frozen=True)
class Context:
    attempt:str; generation:int; ctx:int; raw_ieee:str; short:int
    pan:int; extpan:str; channel:int; tc_ieee:str; coordinator_short:int=0; expected_keyseq:int=0
    def __post_init__(self):
        ieee(self.raw_ieee);ieee(self.tc_ieee);ieee(self.extpan)
        if len(self.attempt)!=32 or any(x not in '0123456789abcdef' for x in self.attempt):raise ValueError('attempt')
        if self.generation<1 or self.ctx != 1 or self.pan!=0x0b7a or self.channel!=21 or self.coordinator_short!=0 or not 0<self.short<0xfff8:raise ValueError('context')
        if self.raw_ieee!='027a56bb75a41437' or self.tc_ieee!='00124b0036a1875f' or self.extpan!=self.tc_ieee:raise ValueError('ctx1 identity owner')
        u8(self.expected_keyseq)
@dataclass(frozen=True)
class Secret:
    value:bytes=field(repr=False)
    def __post_init__(self):
        if len(self.value)!=16:raise ValueError('key length')
@dataclass(frozen=True)
class Rx:
    ctx:int; attempt:str; generation:int; revision:int; mac:bytes
@dataclass(frozen=True)
class AcceptedKey:
    context:Context; rx_revision:int; counter:int; keyseq:int
    secret:Secret=field(repr=False)
    source:str=''
class Replay:
    """Floors are NEXT EXPECTED, independently keyed by layer/domain/source."""
    def __init__(self,floors=None,save=None):self.floors=dict(floors or {});self.save=save
    def consume(self,domain,source,fc):
        k=domain+':'+source
        if not 0<=fc<=MAX_FC or fc<self.floors.get(k,0):raise ValueError('replay')
        updated=dict(self.floors);updated[k]=fc+1
        if self.save is not None:self.save(updated)
        self.floors=updated
def validate_transport(rx,c,tc_key,replay):
    if (rx.ctx,rx.attempt,rx.generation)!=(c.ctx,c.attempt,c.generation) or rx.revision<=0:raise ValueError('stale context')
    m=oracle.Mac.parse(rx.mac)
    if m.fcf!=0x8861 or m.dst_pan!=le16(c.pan) or m.dst!=le16(c.short) or m.src!=le16(0):raise ValueError('MAC binding')
    n=m.payload
    if len(n)!=62 or n[:2]!=b'\x48\x00' or n[2:4]!=le16(c.short) or n[4:6]!=le16(0):raise ValueError('NWK subset')
    aps=n[8:]
    # Proven frame154 selector0/control30 only; TC-upgrade selector2 is audit only.
    if aps[0]!=0x21 or aps[2]!=0x30 or aps[7:15]!=ieee(c.tc_ieee):raise ValueError('APS source/control')
    p,meta=oracle.secured_decode(aps[:2],aps[2:],oracle.key_hash(tc_key.value,0),(0x30,))
    # Consume authenticated counter before semantic dispatch (including malformed TK).
    replay.consume('aps_commissioning_selector0',c.tc_ieee,meta['counter'])
    if len(p)!=35 or p[:2]!=b'\x05\x01' or p[18]!=c.expected_keyseq or p[19:27]!=ieee(c.raw_ieee) or p[27:35]!=ieee(c.tc_ieee):raise ValueError('Transport Key binding')
    return AcceptedKey(c,rx.revision,meta['counter'],p[18],Secret(p[2:18]),c.tc_ieee)
def short_poll(c,dsn):
    return b'\x63\x88'+u8(dsn)+le16(c.pan)+le16(c.coordinator_short)+le16(c.short)+b'\x04'
def encrypt(header,aux,plain,key):
    eff=bytes([(aux[0]&~7)|5])+aux[1:]
    nonce=aux[5:13]+aux[1:5]+eff[:1]
    return header+aux+AESCCM(key.value,tag_length=4).encrypt(nonce,plain,header+eff)
def synthetic_transport(c,tc_key,nwk_key,fc=0,dsn=2,aps_counter=0,command=5,keytype=1,dst=None,tc=None,keyseq=None):
    if not 0<=fc<=MAX_FC:raise ValueError('FC')
    p=bytes([command,keytype])+nwk_key.value+u8(c.expected_keyseq if keyseq is None else keyseq)+ieee(dst or c.raw_ieee)+ieee(tc or c.tc_ieee)
    aps=encrypt(b'\x21'+u8(aps_counter),b'\x30'+fc.to_bytes(4,'little')+ieee(c.tc_ieee),p,Secret(oracle.key_hash(tc_key.value,0)))
    return b'\x61\x88'+u8(dsn)+le16(c.pan)+le16(c.short)+le16(0)+b'\x48\x00'+le16(c.short)+le16(0)+b'\x3c\x01'+aps
@dataclass(frozen=True)
class Sequences:
    nwk:int; aps:int; zdo:int; dsn:int
    def __post_init__(self):
        for n in (self.nwk,self.aps,self.zdo,self.dsn):u8(n)
def announce_vector(c,key,keyseq,fc,seq):
    """Explicit historical/synthetic oracle. Runtime must use Epoch.build()."""
    if not 0<=fc<=MAX_FC:raise ValueError('FC exhausted')
    u8(keyseq)
    mac=b'\x61\x88'+u8(seq.dsn)+le16(c.pan)+le16(0)+le16(c.short)
    header=b'\x08\x02\xfd\xff'+le16(c.short)+b'\x3c'+u8(seq.nwk)
    aux=b'\x28'+fc.to_bytes(4,'little')+ieee(c.raw_ieee)+u8(keyseq)
    plain=b'\x08\x00\x13\x00\x00\x00\x00'+u8(seq.aps)+u8(seq.zdo)+le16(c.short)+ieee(c.raw_ieee)+b'\x80'
    return mac+encrypt(header,aux,plain,key)
def verify_announce(raw,c,key,keyseq,fc,seq):
    if raw!=announce_vector(c,key,keyseq,fc,seq):raise ValueError('announce exact binding')
    m=oracle.Mac.parse(raw);p,meta=oracle.secured_decode(m.payload[:8],m.payload[8:],key.value,(0x28,))
    if len(p)!=20 or p[:7]!=b'\x08\x00\x13\x00\x00\x00\x00' or p[9:11]!=le16(c.short) or p[11:19]!=ieee(c.raw_ieee) or p[19]!=0x80:raise ValueError('ZDO shape')
    return meta
def durable(path,r):
    if not store.durable(path,r):raise OSError('readback')
def dpapi(data,decrypt=False):
    """Windows user-bound secret encryption; no plaintext fallback."""
    if os.name!='nt':raise OSError('DPAPI Windows backend required')
    import ctypes
    from ctypes import wintypes
    class Blob(ctypes.Structure):_fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_ubyte))]
    buf=(ctypes.c_ubyte*len(data)).from_buffer_copy(data);src=Blob(len(data),buf);out=Blob()
    lib=ctypes.WinDLL('crypt32',use_last_error=True)
    fn=lib.CryptUnprotectData if decrypt else lib.CryptProtectData
    fn.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
    fn.restype=wintypes.BOOL
    if not fn(ctypes.byref(src),None,None,None,None,1,ctypes.byref(out)):raise ctypes.WinError(ctypes.get_last_error())
    try:return ctypes.string_at(out.pbData,out.cbData)
    finally:
        k=ctypes.WinDLL('kernel32');k.LocalFree.argtypes=[ctypes.c_void_p];k.LocalFree(out.pbData)
class ProtectedSecrets:
    def __init__(self,root,protect=dpapi,unprotect=lambda b:dpapi(b,True)):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.protect=protect;self.unprotect=unprotect
    def put(self,ref,key):
        if len(ref)!=32 or any(x not in '0123456789abcdef' for x in ref):raise ValueError('secret ref')
        p=self.root/(ref+'.json')
        if p.exists():raise ValueError('secret exists')
        # Secret ciphertext is bound to its unique reference, not interchangeable.
        durable(p,{'protected':self.protect(ref.encode('ascii')+key.value).hex()})
        if self.get(ref).value!=key.value:raise OSError('secret readback')
    def get(self,ref):
        if len(ref)!=32 or any(x not in '0123456789abcdef' for x in ref):raise ValueError('secret ref')
        plain=self.unprotect(bytes.fromhex(json.loads((self.root/(ref+'.json')).read_text())['protected']))
        if len(plain)!=48 or plain[:32]!=ref.encode('ascii'):raise ValueError('secret reference binding')
        return Secret(plain[32:])
@dataclass(frozen=True)
class Lease:
    epoch:str; ctx:int; fc:int; token:str
class Epoch:
    """Serialized durable security epoch. Local stores must not be rolled back/copied.

    Every reservation burns a whole block (32) and all four sequence values. No
    lease reuse or in-memory unused-tail recovery. Missing/corrupt state fails closed.
    """
    def __init__(self,root,secrets_backend):
        self.root=Path(root).resolve()
        if not self.root.is_relative_to((ROOT/'.local').resolve()) or not Path(secrets_backend.root).resolve().is_relative_to((ROOT/'.local').resolve()):raise ValueError('ctx1_separate_security_storage_required')
        self.root.mkdir(parents=True,exist_ok=True);self.path=self.root/'epoch.json';self.secrets=secrets_backend
    def read(self):
        r=json.loads(self.path.read_text(encoding='utf-8'))
        Context(**r['context'])
        anchor=json.loads((self.root/'context_anchor.json').read_text(encoding='utf-8'))
        if r['context']!=anchor or r['generation'] not in (anchor['generation'],anchor['generation']+1,anchor['generation']+2):raise ValueError('ctx1 epoch lineage')
        authority_path=self.root/'epoch_anchor.json'
        if authority_path.exists():
            authority=json.loads(authority_path.read_text(encoding='utf-8'))
            if authority!={k:r.get(k) for k in ('context','key_epoch_id','secret_ref','keyseq')}:raise ValueError('ctx1 security epoch owner')
        elif 'key_epoch_id' in r:raise ValueError('missing independent ctx1 epoch anchor')
        return r
    def initialize(self,c):
        with store.locked(self.root):
            if self.path.exists() or (self.root/'context_anchor.json').exists():raise ValueError('never overwrite security epoch')
            Context(**c.__dict__)
            durable(self.root/'context_anchor.json',c.__dict__)
            durable(self.path,{'context':c.__dict__,'state':'ASSOCIATED_UNKEYED','generation':c.generation,'replay':{},'nwk_source_floors':{},'tc_upgrade_floors':{},'next_fc':0,'sequences':{'nwk':0,'aps':0,'zdo':0,'dsn':0},'announced':False})
    def replay(self):
        def save(floors):
            with store.locked(self.root):
                r=self.read()
                if any(floors.get(k,0)<v for k,v in r['replay'].items()):raise ValueError('replay rollback')
                r['replay']=floors;durable(self.path,r)
        return Replay(self.read()['replay'],save)
    def install(self,a,fail=None):
        with store.locked(self.root):
            r=self.read()
            if r['state']!='ASSOCIATED_UNKEYED' or r['context']!=a.context.__dict__ or r['replay'].get('aps_commissioning_selector0:'+a.source,0)!=a.counter+1:raise ValueError('installation binding')
            ref=uuid.uuid4().hex;epoch=uuid.uuid4().hex
            r.update(state='KEY_RECEIVED_PENDING_DURABILITY',secret_ref=ref,key_epoch_id=epoch,keyseq=a.keyseq,transport_rx_revision=a.rx_revision,generation=r['generation']+1)
            durable(self.root/'epoch_anchor.json',{k:r[k] for k in ('context','key_epoch_id','secret_ref','keyseq')})
            durable(self.path,r)
            if fail=='secret':raise OSError('injected secret failure')
            self.secrets.put(ref,a.secret)
            if fail=='public':raise OSError('injected public failure')
            r.update(state='KEY_INSTALLED',generation=r['generation']+1);durable(self.path,r)
    def reconcile(self,expected_epoch,expected_generation):
        with store.locked(self.root):
            r=self.read()
            if r['state']!='KEY_RECEIVED_PENDING_DURABILITY' or (r['key_epoch_id'],r['generation'])!=(expected_epoch,expected_generation):raise ValueError('reconcile exact generation')
            self.secrets.get(r['secret_ref'])
            r.update(state='KEY_INSTALLED',generation=r['generation']+1);durable(self.path,r)
    def reserve(self):
        with store.locked(self.root):
            r=self.read()
            if r['state']!='KEY_INSTALLED' or r['announced'] or r.get('lease'):raise ValueError('reservation state')
            start=r['next_fc'];end=start+31
            if end>MAX_FC:raise ValueError('counter exhausted')
            seq=Sequences(**r['sequences']);token=uuid.uuid4().hex
            r.update(next_fc=end+1,lease={'epoch':r['key_epoch_id'],'ctx':r['context']['ctx'],'fc':start,'token':token},lease_sequences=seq.__dict__,lease_phase='reserved')
            r['sequences']={k:(v+1)&255 for k,v in seq.__dict__.items()};durable(self.path,r)
            return Lease(**r['lease'])
    def build(self,lease):
        with store.locked(self.root):
            r=self.read()
            if r['state']!='KEY_INSTALLED' or r.get('lease')!=lease.__dict__ or r['lease_phase']!='reserved':raise ValueError('durable lease required/used')
            # Mark used before crypto. Crash/build failure cannot retry same nonce.
            r['lease_phase']='burned';durable(self.path,r)
            raw=announce_vector(Context(**r['context']),self.secrets.get(r['secret_ref']),r['keyseq'],lease.fc,Sequences(**r['lease_sequences']))
            r.update(lease_phase='built',frame_hash=hashlib.sha256(raw).hexdigest());durable(self.path,r)
            return raw
    def intent(self,lease,raw,boot,intent_generation):
        r=self.read()
        if r['lease_phase']!='built' or r['lease']!=lease.__dict__ or r['frame_hash']!=hashlib.sha256(raw).hexdigest():raise ValueError('built lease')
        if len(boot)!=32 or any(x not in '0123456789abcdef' for x in boot) or intent_generation<1:raise ValueError('intent')
        return {'boot':boot,'ctx':lease.ctx,'provision_generation':r['generation'],'raw_ieee':r['context']['raw_ieee'],'short':r['context']['short'],'pan':r['context']['pan'],'coordinator':r['context']['tc_ieee'],'key_epoch':r['key_epoch_id'],'fc':lease.fc,'keyseq':r['keyseq'],'mac_hash':r['frame_hash'],'intent_generation':intent_generation}
    def handed(self,lease):
        with store.locked(self.root):
            r=self.read()
            if r['lease_phase']!='built' or r['lease']!=lease.__dict__:raise ValueError('handed state')
            r.update(state='ANNOUNCE_UNCERTAIN',lease_phase='handed',announced=True);durable(self.path,r)
    def completion(self,success):
        with store.locked(self.root):
            r=self.read()
            if r['state']!='ANNOUNCE_UNCERTAIN':raise ValueError('completion state')
            r.update(state='MANAGEMENT_PENDING' if success else 'ANNOUNCE_UNCERTAIN',local_mac_ack=bool(success));durable(self.path,r)
    def burn_abandoned(self):
        # Explicit crash reconciliation only before handing; reserved block never reclaimed.
        with store.locked(self.root):
            r=self.read()
            if r['state']!='KEY_INSTALLED' or r.get('lease_phase')=='handed':raise ValueError('uncertain TX cannot restart')
            r.pop('lease',None);r.pop('lease_phase',None);durable(self.path,r)
def tc_secret_from_environment():
    value=os.environ.get('AIRNANNY_HISTORICAL_TC_LINK_KEY')
    if value is None:raise ValueError('explicit TC secret environment required')
    return Secret(bytes.fromhex(value))
