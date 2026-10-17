"""Read-only admission evidence. No serial, flash, RF, or outgoing counters.

Reuses the frozen authenticated NWK decoder. A permit request is evidence of
an A7 request, not proof of a changed admission state or a received beacon.
"""
import sys
from pathlib import Path
from dataclasses import dataclass

R=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(R/'host'))
from ledger import decode_nwk,TC,le

@dataclass(frozen=True)
class PermitEvidence:
    boot:str
    revision:int
    time_us:int
    source:str
    incoming_fc:int
    duration:int
    significance:int

class PermitObservation:
    def __init__(self,boot,revision_floor,time_floor,source_floor):
        self.boot=boot;self.revision_floor=revision_floor
        self.time_floor=time_floor;self.source_floor=source_floor
        self.evidence=None

    def receive(self,raw,fields,key):
        if (fields.get('boot')!=self.boot or fields.get('session')!='0' or
            fields.get('channel')!='21' or fields.get('fcs_ok')!='1' or
            int(fields.get('revision','0'))<=self.revision_floor or
            int(fields.get('time_us','0'))<=self.time_floor):return None
        try:m,p,meta=decode_nwk(raw,key)
        except Exception:return None
        if (meta['source_ieee']!=TC or meta['nwk_src']!=0 or
            meta['nwk_dst']!=0xfffc or meta['nwk_fcf']&3 or
            m.src!=le(0) or m.dst!=le(0xffff) or
            meta['counter']<=self.source_floor):return None
        # Exact captured APS DATA/broadcast ep0/profile0/cluster0036 shape.
        # APS counter and ZDO transaction byte vary; admission fields do not.
        if len(p)!=11 or p[:7]!=bytes.fromhex('08003600000000') or p[9:]!=b'\xb4\x01':return None
        if self.evidence is not None:return None
        self.evidence=PermitEvidence(self.boot,int(fields['revision']),int(fields['time_us']),
            TC,meta['counter'],180,1)
        return self.evidence

    def current(self,now_us):
        return self.evidence is not None and 0<=now_us-self.evidence.time_us<180000000
