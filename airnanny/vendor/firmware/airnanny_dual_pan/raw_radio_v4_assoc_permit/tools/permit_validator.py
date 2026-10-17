"""Read-only Zigbee permit oracle. No device I/O, secrets in evidence, or commissioning."""
from dataclasses import dataclass, asdict
import hashlib, importlib.util, sys
from pathlib import Path
ORACLE=Path(__file__).resolve().parents[2]/'identity_commissioning_v1/offline_codec.py'
spec=importlib.util.spec_from_file_location('readonly_permit_codec',ORACLE)
codec=importlib.util.module_from_spec(spec);sys.modules[spec.name]=codec;spec.loader.exec_module(codec)

@dataclass(frozen=True)
class PermitEvidence:
    boot_id:str
    rx_revision:int
    raw_mac_hash:str
    observed_timestamp:float
    pan:int
    mac_source_short:int
    nwk_source:int
    nwk_destination:int
    authenticated_security_source_ieee:str
    security_frame_counter:int
    key_sequence:int
    key_epoch_context:str
    aps_profile:int
    zdo_cluster:int
    zdo_tsn:int
    permit_duration:int
    tc_significance:int
    target_coordinator_ieee:str
    validation_generation:int
    ctx:int
    aps_counter:int

class PermitValidator:
    def __init__(self,*,boot,pan,coordinator,key,key_sequence,key_epoch,generation,ctx=0,revision_floor=0):
        if len(boot)!=32 or len(coordinator)!=16 or len(key)!=16 or not generation or ctx!=0 or pan!=0xfa9b:
            raise ValueError('invalid experimental context')
        self.boot,self.pan,self.coordinator=boot,pan,coordinator
        self.key,self.key_sequence,self.key_epoch=key,key_sequence,key_epoch
        self.generation,self.ctx,self.revision_floor=generation,ctx,revision_floor
        self.highest_fc=-1
        self.last_revision=revision_floor
        self.used=set()

    def authenticated(self,raw):
        m=codec.Mac.parse(raw)
        if m.fcf not in (0x8841,0x8861) or m.dst_pan!=self.pan.to_bytes(2,'little') or m.src!=b'\0\0':
            raise ValueError('wrong MAC target/source/shape')
        n=m.payload
        if len(n)<26 or int.from_bytes(n[:2],'little')!=0x0208 or n[4:6]!=b'\0\0':
            raise ValueError('wrong NWK security/source/shape')
        plain,meta=codec.secured_decode(n[:8],n[8:],self.key,(0x28,))
        if meta['source_ieee']!=self.coordinator or meta['keyseq']!=self.key_sequence:
            raise ValueError('wrong authenticated source/key epoch')
        return m,n,plain,meta

    def prime_observation(self,raw,revision):
        # Optional ordinary authenticated A7 traffic raises current FC watermark only.
        _,_,_,meta=self.authenticated(raw)
        if revision<=self.last_revision:raise ValueError('old observation revision')
        self.last_revision=revision
        self.highest_fc=max(self.highest_fc,meta['counter'])

    def validate(self,*,raw,boot,revision,observed,now,generation):
        if boot!=self.boot or generation!=self.generation:raise ValueError('old boot/attempt')
        if not self.revision_floor<revision or revision<=self.last_revision:raise ValueError('old RX revision')
        if not 0<=now-observed<=10:raise ValueError('stale/future observation')
        m,n,plain,meta=self.authenticated(raw)
        if m.fcf!=0x8841 or m.dst!=b'\xff\xff' or n[2:4]!=b'\xfc\xff':raise ValueError('wrong permit destination')
        if len(plain)!=11 or plain[:7]!=bytes.fromhex('08003600000000'):
            raise ValueError('not exact APS DATA broadcast/profile0/ZDO0036')
        if plain[9]!=180 or plain[10]!=1:raise ValueError('captured duration180/significance1 policy')
        if meta['counter']<=self.highest_fc:raise ValueError('replayed security frame counter')
        self.highest_fc=meta['counter'];self.last_revision=revision
        return PermitEvidence(self.boot,revision,hashlib.sha256(raw).hexdigest(),observed,self.pan,0,0,0xfffc,
                              meta['source_ieee'],meta['counter'],meta['keyseq'],self.key_epoch,0,0x0036,
                              plain[8],plain[9],plain[10],self.coordinator,self.generation,self.ctx,plain[7])

    def reserve(self,evidence,now):
        if evidence.boot_id!=self.boot or evidence.validation_generation!=self.generation or evidence.ctx!=self.ctx or evidence.target_coordinator_ieee!=self.coordinator or evidence.pan!=self.pan:
            raise ValueError('evidence context changed')
        if not 0<=now-evidence.observed_timestamp<=10:raise ValueError('evidence stale')
        token=(evidence.boot_id,evidence.rx_revision,evidence.raw_mac_hash)
        if token in self.used:raise ValueError('evidence already reserved')
        self.used.add(token)
        return asdict(evidence)
