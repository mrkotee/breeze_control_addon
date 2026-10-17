"""Exact known-peer incoming TYPE07 classification; never proof of RAW delivery.

No COM, keys backend, durable state, outgoing counters or transmission API.
The integrating ledger must consume the incoming floor once and discard stale
copies without baseline, confirmation or readiness credit.
"""
import sys
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(R/'host'))
import application_control
from ledger import decode_nwk,le
from airnanny.aps import APS
from airnanny.zcl import ZCL
from airnanny.application import Type07

PEER='00124b0036a18944'
def foreign_peer_type07(raw,key,keyseq,current_short):
    try:
        m,p,meta=decode_nwk(raw,key,keyseq)
        if (m.fcf!=0x8861 or m.src!=le(0xf59f) or m.dst!=le(0) or
            current_short==0xf59f or meta['source_ieee']!=PEER or
            meta['nwk_src']!=0xf59f or meta['nwk_dst']!=0xfffd or
            meta['nwk_fcf']!=0x2208):return None
        a=APS.parse(p);z=ZCL.parse(a.payload)
        if (a.control,a.group,a.cluster,a.profile,a.source_endpoint,z.control,z.command)!=(12,10,6,0x104,8,0x11,1):return None
        Type07(z.payload) # Frozen magic, length, type and checksum validation.
    except Exception:return None
    return dict(source_ieee=PEER,counter=meta['counter'])
