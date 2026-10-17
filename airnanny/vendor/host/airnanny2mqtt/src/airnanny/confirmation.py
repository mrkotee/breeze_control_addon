"""V17 command-specific confirmation, independent of radio/clock implementation."""
from dataclasses import dataclass
from .application import Type06, Type07
from .commands import CommandRequest, FRESH_MS


@dataclass
class Confirmation:
    request: CommandRequest
    tx: Type07
    before: Type07
    generation: int
    rx_baseline: int
    started_ms: int
    window_ms: int
    local_status: int | None = None
    accepted: bool = False
    samples: int = 0
    first_ms: int = 0
    match: Type06 | None = None
    match_revision: int = 0
    match_ms: int = 0
    candidate: Type06 | None = None
    candidate_revision: int = 0
    candidate_ms: int = 0
    latest_ms: int = 0
    latest_revision: int = 0
    confirmed: bool = False
    failure: str | None = None

    def check(self, generation: int, now: int):
        if self.confirmed or self.failure: return
        if generation != self.generation: self.failure = "newer_remote_generation"
        elif now - self.started_ms >= self.window_ms: self.failure = "confirmation_timeout"
        if self.failure: self.match = None

    def _confirm(self):
        if not self.failure and self.local_status == 0 and self.match is not None:
            self.confirmed = True

    def _matched(self, s: Type06, revision: int, now: int):
        self.match, self.match_revision, self.match_ms = s, revision, now
        self._confirm()

    def _power_sample(self, s: Type06, revision: int, now: int):
        if self.failure or self.confirmed: return
        if s.sequence != self.tx.sequence or s.power != self.request.value or revision <= self.rx_baseline:
            return
        b = self.before
        if (s.target_tenths, s.fan_raw, s.mode_raw, s.humidifier_raw, s.night) != (
                b.target_tenths, b.fan_raw, b.mode_raw, b.humidifier_raw, b.night):
            self.failure = "confirmation_mismatch"
            self.match = None
            return
        if self.local_status != 0: return
        self.accepted = True
        if not self.samples:
            self.samples, self.first_ms = 1, now
        elif now - self.first_ms >= 1000:
            self.samples = 2
            self._matched(s, revision, now)

    def observe(self, s: Type06, revision: int, received_ms: int, generation: int, now: int):
        self.check(generation, now)
        if self.failure or self.confirmed: return
        if revision <= max(self.rx_baseline, self.latest_revision) or not 0 <= now - received_ms <= FRESH_MS: return
        self.latest_ms = received_ms
        self.latest_revision = revision
        kind = self.request.kind
        exact = s.sequence == self.tx.sequence
        known = self.tx.known_match(s)
        if kind == "power":
            self.candidate = None
            if exact and s.power == self.request.value:
                self.candidate, self.candidate_revision, self.candidate_ms = s, revision, received_ms
                self._power_sample(s, revision, now)
            else: self.samples = 0
        elif kind == "night":
            self.match = None
            fixed = (s.target_tenths, s.power, s.mode_raw, s.night) == (
                self.before.target_tenths, self.tx.power, self.tx.mode_raw, self.tx.night)
            if fixed and exact: self.accepted = True
            correlated = exact or self.accepted and s.sequence == (self.tx.sequence + 1) & 255
            if not fixed or not correlated or not self.accepted or s.fan_raw != (0 if self.tx.night else self.tx.fan_raw):
                self.samples = 0
                return
            if not self.tx.night:
                if exact: self._matched(s, revision, received_ms)
            else:
                if not self.samples: self.first_ms = now
                self.samples = min(self.samples + 1, 255)
                if self.samples >= 2 and now - self.first_ms >= 1000:
                    self._matched(s, revision, received_ms)
        elif kind in ("temp", "humidifier"):
            if (not exact or not known or s.target_tenths != self.tx.target_tenths
                    or kind == "humidifier" and s.humidifier_raw != self.request.value):
                self.match = None
            else: self._matched(s, revision, received_ms)
        elif exact and known:
            # FAN/MODE retain a provisional match across unrelated later RX (V17).
            self._matched(s, revision, received_ms)

    def complete(self, status: int, generation: int, now: int):
        if self.local_status is not None: return  # callback idempotence
        self.local_status = status
        self.check(generation, now)
        if self.failure or self.confirmed: return
        if status:
            self.failure, self.match = "local_completion", None
            return
        if self.request.kind == "power":
            if self.candidate is not None:
                if now - self.candidate_ms > FRESH_MS: self.failure = "confirmation_mismatch"
                else: self._power_sample(self.candidate, self.candidate_revision, now)
        else:
            # Enforce the requested host freshness boundary even for generic late callbacks.
            if self.match is not None and now - self.match_ms > FRESH_MS: self.match = None
            self._confirm()
