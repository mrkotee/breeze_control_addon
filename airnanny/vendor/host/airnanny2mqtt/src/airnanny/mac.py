from dataclasses import dataclass
from .binary import CodecError, Reader, uint


@dataclass(frozen=True)
class MAC:
    fcf: int
    dsn: int
    destination_pan: int
    destination: int
    source_pan: int
    source: int
    payload: bytes

    @property
    def ack_request(self) -> bool:
        return bool(self.fcf & 0x20)

    @property
    def pan_compression(self) -> bool:
        return bool(self.fcf & 0x40)

    @classmethod
    def parse(cls, data: bytes):
        if len(data) > 125:
            raise CodecError("MAC exceeds PSDU bound excluding FCS")
        r = Reader(data)
        fcf, dsn = r.uint(2), r.uint(1)
        if fcf & ~0x70 != 0x8801:
            raise CodecError("unsupported MAC: require legacy DATA, short/short, no security")
        pan, dst = r.uint(2), r.uint(2)
        src_pan = pan if fcf & 0x40 else r.uint(2)
        return cls(fcf, dsn, pan, dst, src_pan, r.uint(2), r.rest())

    def serialize(self) -> bytes:
        if self.pan_compression and self.source_pan != self.destination_pan:
            raise CodecError("compressed PAN mismatch")
        out = uint(self.fcf, 2) + uint(self.dsn, 1) + uint(self.destination_pan, 2) + uint(self.destination, 2)
        if not self.pan_compression:
            out += uint(self.source_pan, 2)
        out += uint(self.source, 2) + self.payload
        self.parse(out)
        return out
