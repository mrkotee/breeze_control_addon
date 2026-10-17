from dataclasses import dataclass


@dataclass(frozen=True)
class CommandAccepted:
    device: str
    tx_id: str
    kind: str


@dataclass(frozen=True)
class CommandCompleted:
    device: str
    tx_id: str
    rx_revision: int
    application_sequence: int


@dataclass(frozen=True)
class CommandFailed:
    device: str
    tx_id: str | None
    reason: str


@dataclass(frozen=True)
class StateEvent:
    device: str
    rx_revision: int
    application_sequence: int
    power: int
    fan: int | None
    mode: str | None
    target: float | str | None
    night: int
    humidifier: int | None
    baseline_generation: int
    origin: str  # remote-correlated, own-correlated, or unknown; never guess provenance
