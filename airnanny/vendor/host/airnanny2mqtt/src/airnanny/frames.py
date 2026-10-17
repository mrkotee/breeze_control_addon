from dataclasses import dataclass
from functools import reduce
from operator import xor
from .binary import CodecError, uint


@dataclass(frozen=True)
class ApplicationFrame:
    type: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes):
        if len(data) < 7 or data[:4] != b"pe\x00\x00":
            raise CodecError("invalid proprietary prefix/header")
        if data[4] != len(data) - 6:
            raise CodecError("invalid proprietary length")
        if reduce(xor, data[5:], 0):
            raise CodecError("invalid proprietary checksum")
        return cls(data[5], data[6:-1])

    def serialize(self) -> bytes:
        out = b"pe\x00\x00" + uint(len(self.payload) + 1, 1) + uint(self.type, 1) + self.payload
        return out + bytes([reduce(xor, out[5:], 0)])
