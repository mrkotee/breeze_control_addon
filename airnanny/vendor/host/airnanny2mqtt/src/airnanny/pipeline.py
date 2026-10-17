from dataclasses import dataclass
from .binary import CodecError
from .mac import MAC
from .nwk import NWK
from .security import decrypt, SecurityHeader
from .aps import APS
from .zcl import ZCL
from .frames import ApplicationFrame
from .context import ZigbeeContext, route


@dataclass(frozen=True)
class DecodedFrame:
    context: str
    mac: MAC
    nwk: NWK
    security: SecurityHeader
    aps: APS
    zcl: ZCL
    application: ApplicationFrame


def receive(raw: bytes, contexts: list[ZigbeeContext]) -> DecodedFrame:
    mac = MAC.parse(raw)
    context = route(mac, contexts)
    nwk = NWK.parse(mac.payload)
    header, plaintext = decrypt(nwk, context.keys)
    context.accept_authenticated(header)
    aps = APS.parse(plaintext)
    if (aps.cluster, aps.profile, aps.source_endpoint) != (6, 0x104, 8):
        raise CodecError("unsupported application APS envelope")
    if aps.destination_endpoint not in (None, 8) or aps.group not in (None, 10):
        raise CodecError("unsupported application destination")
    zcl = ZCL.parse(aps.payload)
    if zcl.control != 0x11 or zcl.command != 1:
        raise CodecError("unsupported application ZCL envelope")
    application = ApplicationFrame.parse(zcl.payload)
    return DecodedFrame(context.identity, mac, nwk, header, aps, zcl, application)
