from dataclasses import dataclass
from .binary import CodecError, Reader, uint


@dataclass(frozen=True)
class APS:
    control: int
    destination_endpoint: int | None
    group: int | None
    cluster: int
    profile: int
    source_endpoint: int
    counter: int
    payload: bytes

    @property
    def security(self) -> bool:
        return bool(self.control & 0x20)

    @classmethod
    def parse(cls, data: bytes):
        r = Reader(data)
        fc = r.uint(1)
        if fc & 0x20:
            raise CodecError("APS security flag set: unsupported")
        if fc not in (0, 12):
            raise CodecError("unsupported APS control")
        dst = r.uint(1) if fc == 0 else None
        group = r.uint(2) if fc == 12 else None
        return cls(fc, dst, group, r.uint(2), r.uint(2), r.uint(1), r.uint(1), r.rest())

    def serialize(self) -> bytes:
        if self.control == 0 and self.group is None:
            address = uint(self.destination_endpoint, 1)
        elif self.control == 12 and self.destination_endpoint is None:
            address = uint(self.group, 2)
        else:
            raise CodecError("invalid APS addressing/control")
        return (uint(self.control, 1) + address + uint(self.cluster, 2) + uint(self.profile, 2)
                + uint(self.source_endpoint, 1) + uint(self.counter, 1) + self.payload)
