"""Known fields only. Raw bytes remain the authoritative, lossless model."""
from dataclasses import dataclass
from .binary import CodecError
from .frames import ApplicationFrame

MODES = ("intake", "mixed", "recirc")
OFF = -1000


def target_valid(value: int, off: bool = True) -> bool:
    return (off and value == OFF) or 100 <= value <= 300 and value % 5 == 0


def checksum(raw: bytes) -> bytes:
    return ApplicationFrame(raw[5], bytes(raw[6:-1])).serialize()


@dataclass(frozen=True)
class Type06:
    raw: bytes

    def __post_init__(self):
        frame = ApplicationFrame.parse(self.raw)
        if len(self.raw) != 23 or frame.type != 6:
            raise CodecError("expected 23-byte TYPE06")

    def serialize(self) -> bytes:
        return self.raw

    @property
    def sequence(self): return self.raw[6]
    @property
    def target_tenths(self): return int.from_bytes(self.raw[13:15], "little", signed=True)
    @property
    def fan_raw(self): return self.raw[15]
    @property
    def fan(self): return self.fan_raw + 1 if self.fan_raw <= 6 else None
    @property
    def mode_raw(self): return self.raw[16]
    @property
    def mode(self): return MODES[self.mode_raw] if self.mode_raw <= 2 else None
    @property
    def humidity_like_raw(self): return self.raw[17]
    @property
    def humidifier_raw(self): return self.raw[18]
    @property
    def humidifier(self): return self.humidifier_raw if self.humidifier_raw <= 2 else None
    @property
    def flags(self): return self.raw[21]
    @property
    def power(self): return self.flags & 1
    @property
    def night(self): return (self.flags >> 4) & 1

    def known_key(self):
        # air_ctl_changed: unknown target values collapse to one unavailable value.
        return (self.power, self.fan, self.mode, self.night, self.humidifier,
                self.target_tenths if target_valid(self.target_tenths) else None)


@dataclass(frozen=True)
class Type07:
    raw: bytes

    def __post_init__(self):
        frame = ApplicationFrame.parse(self.raw)
        if len(self.raw) != 21 or frame.type != 7:
            raise CodecError("expected 21-byte TYPE07")

    def serialize(self) -> bytes:
        return self.raw

    @property
    def sequence(self): return self.raw[6]
    @property
    def target_tenths(self): return int.from_bytes(self.raw[7:9], "little", signed=True)
    @property
    def remote_temperature_tenths(self): return int.from_bytes(self.raw[9:11], "little", signed=True)
    @property
    def fan_raw(self): return self.raw[11]
    @property
    def mode_raw(self): return self.raw[12]
    @property
    def humidifier_raw(self): return self.raw[13]
    @property
    def time_calendar_raw(self): return self.raw[14:18]
    @property
    def byte18(self): return self.raw[18]
    @property
    def flags(self): return self.raw[19]
    @property
    def power(self): return self.flags & 1
    @property
    def night(self): return (self.flags >> 4) & 1

    def known_match(self, status: Type06) -> bool:
        return (self.fan_raw, self.mode_raw, self.power, self.night) == (
            status.fan_raw, status.mode_raw, status.power, status.night)
