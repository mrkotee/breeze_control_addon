from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from .application import Type06, Type07, MODES, OFF, target_valid, checksum
from .baseline import Baseline

FRESH_MS = 15000
DEFAULT_WINDOW_MS = 20000
TEMP_POWER_WINDOW_MS = 45000


class CommandError(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class CommandRequest:
    kind: str
    value: int

    def __post_init__(self):
        valid = type(self.value) is int and (
            self.kind == "fan" and 1 <= self.value <= 7 or
            self.kind in ("mode", "humidifier") and 0 <= self.value <= 2 or
            self.kind in ("night", "power") and 0 <= self.value <= 1 or
            self.kind == "temp" and target_valid(self.value))
        if not valid:
            raise CommandError("bad_argument")

    @classmethod
    def parse(cls, kind: str, value):
        if kind == "mode":
            if value not in MODES: raise CommandError("bad_argument")
            value = MODES.index(value)
        elif kind in ("night", "power"):
            if value not in ("on", "off"): raise CommandError("bad_argument")
            value = int(value == "on")
        elif kind == "humidifier":
            if value == "off": value = 0
            elif value in ("1", "2"): value = int(value)
            elif type(value) is not int or value not in (1, 2): raise CommandError("bad_argument")
        elif kind == "temp":
            if value == "off": value = OFF
            else:
                try:
                    tenths = Decimal(str(value)) * 10
                    if not tenths.is_finite() or tenths != int(tenths): raise ValueError
                    value = int(tenths)
                except (InvalidOperation, ValueError, OverflowError):
                    raise CommandError("bad_argument") from None
        return cls(kind, value)


def build(request: CommandRequest, baseline: Baseline, status: Type06 | None,
          age_ms: int | None, controller_short: int) -> Type07:
    """Pure application preflight/builder; no counter or baseline side effects."""
    if status is None or age_ms is None or not 0 <= age_ms <= FRESH_MS:
        raise CommandError("stale_status")
    if not baseline.valid or baseline.frame is None: raise CommandError("baseline_invalid")
    if baseline.remote_pending: raise CommandError("remote_pending")
    b, s, kind, value = baseline.frame, status, request.kind, request.value
    if s.fan_raw > 6 or s.mode_raw > 2: raise CommandError("unsupported_state")
    if not b.known_match(s): raise CommandError("state_mismatch")
    if kind in ("humidifier", "night", "power") and not baseline.live:
        raise CommandError("no_live_baseline")
    if kind in ("temp", "humidifier", "night", "power") and b.target_tenths != s.target_tenths:
        raise CommandError("state_mismatch")
    if kind == "temp":
        if not s.power or s.mode_raw != 0 or not target_valid(b.target_tenths):
            raise CommandError("unsupported_state")
    if kind == "humidifier":
        if b.humidifier_raw != s.humidifier_raw: raise CommandError("state_mismatch")
        if not s.power or s.mode_raw != 0 or s.night or b.humidifier_raw > 2:
            raise CommandError("unsupported_state")
    if kind == "night" and (not s.power or b.humidifier_raw != 0):
        raise CommandError("unsupported_state")
    if kind == "power":
        if baseline.source != controller_short: raise CommandError("no_live_baseline")
        if (s.power == value or s.mode_raw != 0 or s.night or b.humidifier_raw != 0
                or s.humidifier_raw != 0 or not target_valid(b.target_tenths, off=False)):
            raise CommandError("unsupported_state")
    raw = bytearray(b.raw)
    if kind == "fan": raw[11] = value - 1
    elif kind == "mode": raw[12] = value
    elif kind == "temp": raw[7:9] = value.to_bytes(2, "little", signed=True)
    elif kind == "humidifier": raw[13] = value
    elif kind == "night": raw[19] = (raw[19] & ~0x10) | value << 4
    elif kind == "power": raw[19] = (raw[19] & ~1) | value
    raw[6] = (s.sequence + 1) & 255
    return Type07(checksum(raw))
