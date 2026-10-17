from dataclasses import dataclass, field
import re
from .binary import CodecError, uint
from .context import ZigbeeContext


@dataclass(frozen=True)
class DeviceConfig:
    name: str
    context: ZigbeeContext
    controller_short: int
    key_reference: str  # reference only; key loading remains the caller's responsibility
    nwk_fcf: int = 0x2208
    nwk_destination: int = 0xfffd
    radius: int = 60
    mac_destination: int = 0
    timeout_ms: dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        uint(self.controller_short, 2)
        uint(self.mac_destination, 2)
        uint(self.nwk_destination, 2)
        uint(self.radius, 1)
        if (not self.name or not re.fullmatch(r"env:[A-Za-z_][A-Za-z_0-9]*|file:[^#]+#[A-Za-z_][A-Za-z_0-9]*", self.key_reference) or self.controller_short in
                (0, 0xffff, self.context.local_short) or self.nwk_fcf not in (0x248, 0x208, 0x2208)):
            raise CodecError("invalid offline device configuration")
        if any(k not in ("fan", "mode", "temp", "night", "humidifier", "power") or
               type(v) is not int or v <= 0 for k, v in self.timeout_ms.items()):
            raise CodecError("invalid confirmation window")


@dataclass(frozen=True)
class Configuration:
    devices: tuple[DeviceConfig, ...]

    def __post_init__(self):
        for values in ([d.name for d in self.devices], [d.context.identity for d in self.devices],
                       [(d.context.pan, d.context.local_short) for d in self.devices],
                       [id(d.context.keys) for d in self.devices]):
            if len(set(values)) != len(values): raise CodecError("duplicate/shared device configuration")
