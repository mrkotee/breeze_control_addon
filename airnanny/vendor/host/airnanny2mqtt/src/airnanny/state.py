from dataclasses import asdict, dataclass
from .application import OFF, target_valid


def display_target(value: int):
    return "off" if value == OFF else value / 10 if target_valid(value) else None


@dataclass(frozen=True)
class DeviceStateSnapshot:
    device: str
    status_valid: bool
    status_fresh: bool
    status_age_ms: int | None
    power: int | None
    fan: int | None
    mode: str | None
    target: float | str | None
    night: int | None
    humidifier: int | None
    application_sequence: int | None
    rx_revision: int
    baseline_valid: bool
    baseline_pending: bool
    baseline_generation: int
    baseline_source: str
    baseline_address: int | None
    raw_type06: str | None
    raw_type07: str | None
    pending_transaction: str | None

    def to_dict(self): return asdict(self)
