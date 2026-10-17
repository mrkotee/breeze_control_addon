"""Explicit offline envelope choice, not a proven dongle membership contract."""
from dataclasses import replace
from .application import Type07
from .config import DeviceConfig
from .counters import FrameCounterStore
from .security import SecurityHeader, encrypt
from .nwk import NWK
from .mac import MAC
from .aps import APS
from .zcl import ZCL


def secured_frame(config: DeviceConfig, frame: Type07, store: FrameCounterStore) -> bytes:
    ctx = config.context
    # Reserve first. Failures from this point never roll this counter back.
    counter = ctx.reserve_counter(store)
    zcl = ZCL(0x11, None, ctx.advance("zcl_tsn"), 1, frame.raw)
    aps = APS(12, None, 10, 6, 0x104, 8, ctx.advance("aps_counter"), zcl.serialize())
    nwk = NWK(config.nwk_fcf, config.nwk_destination, ctx.local_short,
              config.radius, ctx.advance("nwk_sequence"), b"")
    header = SecurityHeader(0x28, counter, ctx.local_ieee, ctx.active_key_sequence)
    nwk = replace(nwk, payload=encrypt(nwk, header, aps.serialize(), ctx.keys))
    return MAC(0x8861, ctx.advance("mac_dsn"), ctx.pan, config.mac_destination,
               ctx.pan, ctx.local_short, nwk.serialize()).serialize()
