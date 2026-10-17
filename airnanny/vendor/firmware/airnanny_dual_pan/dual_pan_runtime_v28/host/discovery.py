"""Typed legacy A7 evidence. Unauthenticated beacons never prove TC ownership."""
import sys,hashlib
from dataclasses import dataclass,asdict
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(R.parent/'raw_radio_v8_post_announce_management/host'))
from management import oracle,TC,le
SCAN_US=261120
RESPONSE_US=491520
FRESH_US=2000000
class Fault(ValueError):pass
def beacon_request(dsn):
    if type(dsn)!=int or not 0<=dsn<=255:raise Fault('DSN')
    return b'\x03\x08'+bytes([dsn])+b'\xff\xff\xff\xff\x07'
@dataclass(frozen=True)
class DiscoveryEvidence:
    boot:str;session:int;channel:int;revision:int;time_us:int;pan:int;extpan:str
    source_short:int;source_mode:int;permit:bool;coordinator:bool
    router_capacity:bool;end_capacity:bool;protocol:int;version:int;profile:int
    update_id:int;raw_hash:str;validation_generation:int;guard:str
    scan_start_revision:int;scan_tx_end_us:int;scan_deadline_us:int
    def public(self):return asdict(self)
def validate(raw,fields,boot,guard,floor,start_us,now_us,generation=1,pan=0x0b7a,tc=None):
    """`pan` and `tc` default to ctx1's, which is what this check carried
    inline while the host had one context, so every V25 caller is unchanged.
    A dual runtime must pass the PAN and trust centre of the context it is
    discovering FOR: otherwise a perfectly good ctx0 beacon is refused as
    beacon_MAC_context, and the gate reports a coordinator that did not
    answer when in fact it did."""
    if (fields.get('boot')!=boot or fields.get('session')!='1' or fields.get('channel')!='21' or
        fields.get('fcs_ok')!='1' or int(fields['revision'])<=floor):raise Fault('discovery_boot_session_channel_revision')
    t=int(fields['time_us'])
    if not start_us<=t<start_us+SCAN_US or not t<=now_us<=t+FRESH_US:raise Fault('stale_or_outside_scan')
    m=oracle.Mac.parse(raw)
    if m.fcf!=0x8000 or m.src_pan!=le(pan) or m.src!=le(0):raise Fault('beacon_MAC_context')
    p=m.payload
    if len(p)<19:raise Fault('short_beacon')
    sf=int.from_bytes(p[:2],'little')
    if sf&0x2fff!=0x0fff or not sf&0x4000:raise Fault('nonbeacon_coordinator_superframe')
    if p[2]&0x7f or p[3]&0x88:raise Fault('GTS_or_reserved_pending')
    index=4+2*(p[3]&7)+8*((p[3]>>4)&7)
    if index+15!=len(p):raise Fault('Appendix_R23_or_truncated_unsupported')
    z=p[index:]
    if z[:2]!=b'\0\x22' or z[2]&0x7b or not z[2]&0x80 or z[11:14]!=b'\xff'*3:raise Fault('protocol_profile_version_depth_capacity_offset')
    extpan=z[3:11][::-1].hex()
    if extpan!=(TC if tc is None else tc):raise Fault('wrong_configured_extPAN')
    return DiscoveryEvidence(boot,1,21,int(fields['revision']),t,pan,extpan,0,2,
        bool(sf&0x8000),True,bool(z[2]&4),True,0,2,2,z[14],hashlib.sha256(raw).hexdigest(),generation,guard,floor,start_us,start_us+SCAN_US)
