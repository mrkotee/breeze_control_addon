"""Transport contract and deterministic offline fake; no hardware implementation."""
from collections import deque
from dataclasses import dataclass
import heapq
from typing import Callable, Protocol


class Clock(Protocol):
    def now_ms(self) -> int: ...


class FakeClock:
    def __init__(self, now: int = 0): self._now = now
    def now_ms(self) -> int: return self._now
    def advance(self, ms: int):
        if ms < 0: raise ValueError("clock cannot move backwards")
        self._now += ms


class RadioTransport(Protocol):
    def send_frame(self, ctx_id: str, mac_bytes: bytes, tx_id: str,
                   completion: Callable[[str, int], None]) -> bool:
        """Return local submission acceptance. Callback status0 means local completion only."""
        ...


@dataclass(frozen=True)
class LocalTxResult:
    delay_ms: int | None = 0  # None: callback never arrives
    status: int = 0
    submitted: bool = True


class FakeRadioTransport:
    def __init__(self, clock: FakeClock):
        self.clock = clock
        self.scripts = {}
        self.sends = []
        self._events = []
        self._order = 0
        self.tickers = []

    def script(self, ctx_id: str, *results: LocalTxResult):
        self.scripts.setdefault(ctx_id, deque()).extend(results)

    def schedule(self, delay_ms: int, callback: Callable[[], None]):
        if delay_ms < 0: raise ValueError("negative event delay")
        self._order += 1
        heapq.heappush(self._events, (self.clock.now_ms() + delay_ms, self._order, callback))

    def send_frame(self, ctx_id, mac_bytes, tx_id, completion):
        self.sends.append((ctx_id, bytes(mac_bytes), tx_id))
        queue = self.scripts.get(ctx_id)
        result = queue.popleft() if queue else LocalTxResult()
        if result.submitted and result.delay_ms is not None:
            self.schedule(result.delay_ms, lambda: completion(tx_id, result.status))
        return result.submitted

    def incoming(self, delay_ms: int, raw: bytes, receiver: Callable[[bytes], object]):
        self.schedule(delay_ms, lambda: receiver(raw))

    def advance(self, ms: int):
        if ms < 0: raise ValueError("negative event delay")
        target = self.clock.now_ms() + ms
        while self._events and self._events[0][0] <= target:
            when, _, callback = heapq.heappop(self._events)
            self.clock.advance(when - self.clock.now_ms())
            callback()
            for tick in self.tickers: tick()
        self.clock.advance(target - self.clock.now_ms())
        for tick in self.tickers: tick()
