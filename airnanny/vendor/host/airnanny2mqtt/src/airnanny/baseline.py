from dataclasses import dataclass
from .application import Type06, Type07, checksum


@dataclass
class Baseline:
    frame: Type07 | None = None
    valid: bool = False
    live: bool = False
    source: int | None = None
    generation: int = 0
    remote_pending: bool = False
    status_revision: int = 0
    status_snapshot: Type06 | None = None

    def remote(self, frame: Type07, source: int, local_short: int) -> bool:
        if source in (0, 0xffff, local_short) or frame.fan_raw > 6 or frame.mode_raw > 2:
            return False
        self.frame, self.valid, self.live, self.source = frame, True, True, source
        self.remote_pending = True
        self.generation += 1
        return True

    def observe(self, status: Type06, revision: int):
        if not self.valid or self.frame is None or status.fan_raw > 6 or status.mode_raw > 2:
            return
        if self.remote_pending:
            if self.frame.sequence != status.sequence or not self.frame.known_match(status):
                return
            self.remote_pending = False
        raw = bytearray(self.frame.raw)
        raw[11], raw[12] = status.fan_raw, status.mode_raw
        raw[19] = (raw[19] & ~0x11) | status.power | status.night << 4
        self.frame = Type07(checksum(raw))
        self.status_revision, self.status_snapshot = revision, status

    def commit(self, generation: int, frame: Type07) -> bool:
        if generation != self.generation or not self.valid:
            return False
        self.frame = frame
        self.generation += 1
        return True

    def invalidate(self):
        self.valid = False
        # Prevent a previously started safe transaction from revalidating old data.
        self.generation += 1
