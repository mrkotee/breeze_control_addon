from dataclasses import dataclass, field
from threading import Lock
from typing import Protocol
from .binary import CodecError, uint

LIMIT = 1 << 32


class FrameCounterStore(Protocol):
    def reserve(self, context: str, epoch: str, key_sequence: int, count: int) -> range:
        """Atomically commit exclusive high-water BEFORE returning a block.

        Production implementations must durably commit and serialize writers.
        epoch is a stable key-material epoch, not merely the wrapping keyseq.
        """
        ...


class MemoryCounterStore:
    """Offline only. Survives allocator restart, NOT loss of this store/process."""
    def __init__(self):
        self._high_water = {}
        self._lock = Lock()

    def reserve(self, context: str, epoch: str, key_sequence: int, count: int) -> range:
        uint(key_sequence, 1)
        if not context or not epoch or not isinstance(count, int) or count <= 0:
            raise CodecError("invalid counter reservation")
        identity = (context, epoch, key_sequence)
        with self._lock:
            start = self._high_water.get(identity, 0)
            if start + count > LIMIT:
                raise CodecError("NWK frame counter exhausted")
            self._high_water[identity] = start + count
            return range(start, start + count)


@dataclass
class CounterAllocator:
    store: FrameCounterStore
    context: str
    epoch: str
    key_sequence: int
    block_size: int = 256
    _next: int = field(default=0, init=False)
    _stop: int = field(default=0, init=False)

    def next(self) -> int:
        if self._next == self._stop:
            block = self.store.reserve(self.context, self.epoch, self.key_sequence, self.block_size)
            self._next, self._stop = block.start, block.stop
        result = self._next
        self._next += 1
        return result
