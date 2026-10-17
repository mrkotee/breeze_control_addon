"""Narrow receive scope. No store, secret loading, serial or RF operations."""
from cryptography.exceptions import InvalidTag
from recovery_model import decode_nwk,oracle,le,TC,valid_short
from management import ordinary
def foreign_status(raw,key,keyseq,current_short):
    try:
        mac=oracle.Mac.parse(raw)
        if mac.fcf!=0x8861 or mac.src!=le(0) or len(mac.dst)!=2:return None
        destination=int.from_bytes(mac.dst,'little')
        if not valid_short(destination) or destination==current_short:return None
        m,p,meta=decode_nwk(raw,key,keyseq)
    except (ValueError,AssertionError,InvalidTag):return None
    if (meta['source_ieee']!=TC or meta['nwk_src']!=0 or
        meta['nwk_dst']!=destination or
        not (meta['nwk_fcf']==0x0248 or (meta['nwk_fcf']==0x0208 and destination==0xf59f)) or
        not ordinary(p)):return None
    return {'source_ieee':meta['source_ieee'],'counter':meta['counter']}

PEER='00124b0036a18944'

def foreign_peer_group_control(raw,key,keyseq,current_short):
    """Captured existing peer's group TYPE06 uplink, never RAW delivery.

    Exact APS group 000A/cluster0006/profile0104/endpoint08 and ZCL11/02,
    allowing only APS/ZCL sequence octets to vary. No generic broadcast rule.
    """
    try:
        mac=oracle.Mac.parse(raw)
        if mac.fcf!=0x8861 or mac.dst!=le(0) or len(mac.src)!=2:return None
        _,p,meta=decode_nwk(raw,key,keyseq)
    except (ValueError,AssertionError,InvalidTag):return None
    short=meta['nwk_src']
    if (meta['source_ieee']!=PEER or not valid_short(short) or short==current_short or
        mac.src!=le(short) or meta['nwk_fcf']!=0x2208 or meta['nwk_dst']!=0xfffd or
        len(p)!=12 or p[:8]!=bytes.fromhex('0c0a000600040108') or p[9]!=0x11 or p[11]!=0x02):return None
    return {'source_ieee':meta['source_ieee'],'counter':meta['counter']}
