class CodecError(ValueError):
    """Malformed or unsupported wire form."""


class Reader:
    def __init__(self, data: bytes):
        self.data = bytes(data)
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise CodecError("truncated frame")
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "little")

    def rest(self) -> bytes:
        return self.take(len(self.data) - self.offset)


def uint(value: int, size: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value < 1 << (8 * size):
        raise CodecError("integer out of range")
    return value.to_bytes(size, "little")
