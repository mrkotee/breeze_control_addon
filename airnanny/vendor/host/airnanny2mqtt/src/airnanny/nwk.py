from dataclasses import dataclass
from .binary import CodecError, Reader, uint


@dataclass(frozen=True)
class NWK:
    fcf: int
    destination: int
    source: int
    radius: int
    sequence: int
    payload: bytes

    @property
    def security(self) -> bool:
        return bool(self.fcf & 0x200)

    @property
    def header(self) -> bytes:
        if self.fcf not in (0x0248, 0x0208, 0x2208):
            raise CodecError("unsupported NWK FCF/options")
        return (uint(self.fcf, 2) + uint(self.destination, 2) + uint(self.source, 2)
                + uint(self.radius, 1) + uint(self.sequence, 1))

    @classmethod
    def parse(cls, data: bytes):
        r = Reader(data)
        result = cls(r.uint(2), r.uint(2), r.uint(2), r.uint(1), r.uint(1), r.rest())
        result.header
        return result

    def serialize(self) -> bytes:
        return self.header + self.payload
