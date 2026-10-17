from dataclasses import dataclass
from .binary import CodecError, Reader, uint


@dataclass(frozen=True)
class ZCL:
    control: int
    manufacturer: int | None
    tsn: int
    command: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes):
        r = Reader(data)
        fc = r.uint(1)
        if fc & 0xe0 or fc & 3 not in (0, 1):
            raise CodecError("unsupported ZCL control")
        return cls(fc, r.uint(2) if fc & 4 else None, r.uint(1), r.uint(1), r.rest())

    def serialize(self) -> bytes:
        if bool(self.control & 4) != (self.manufacturer is not None):
            raise CodecError("manufacturer flag mismatch")
        out = uint(self.control, 1)
        if self.manufacturer is not None:
            out += uint(self.manufacturer, 2)
        out += uint(self.tsn, 1) + uint(self.command, 1) + self.payload
        self.parse(out)
        return out
