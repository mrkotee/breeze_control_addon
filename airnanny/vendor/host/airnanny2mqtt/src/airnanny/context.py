from dataclasses import dataclass, field
from .binary import CodecError, uint
from .security import KeyStore
from .counters import CounterAllocator, FrameCounterStore


class ReplayError(CodecError):
    pass


@dataclass
class ZigbeeContext:
    identity: str
    pan: int
    extended_pan: int
    channel: int
    local_ieee: int
    local_short: int
    coordinator_ieee: int
    coordinator_short: int = 0
    keys: KeyStore = field(default_factory=KeyStore, repr=False)
    active_key_sequence: int = 0
    key_epochs: dict[int, str] = field(default_factory=lambda: {0: "initial"})
    incoming_high_water: dict[tuple[int, str, int], int] = field(default_factory=dict)
    nwk_sequence: int = 0
    aps_counter: int = 0
    zcl_tsn: int = 0
    mac_dsn: int = 0
    outgoing: dict[tuple[str, int], CounterAllocator] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        for value in (self.pan, self.local_short, self.coordinator_short):
            uint(value, 2)
        for value in (self.extended_pan, self.local_ieee, self.coordinator_ieee):
            uint(value, 8)
        uint(self.active_key_sequence, 1)
        if not self.identity or self.pan == 0xffff or not 11 <= self.channel <= 26:
            raise CodecError("invalid context")

    def advance(self, name: str) -> int:
        if name not in ("nwk_sequence", "aps_counter", "zcl_tsn", "mac_dsn"):
            raise CodecError("unknown sequence")
        value = getattr(self, name)
        uint(value, 1)
        setattr(self, name, (value + 1) & 255)
        return value

    def reserve_counter(self, store: FrameCounterStore, block_size: int = 256) -> int:
        seq = self.active_key_sequence
        self.keys.get(seq)
        if seq not in self.key_epochs:
            raise CodecError("unknown key epoch")
        epoch = self.key_epochs[seq]
        identity = (epoch, seq)
        if identity not in self.outgoing:
            self.outgoing[identity] = CounterAllocator(store, self.identity, epoch, seq, block_size)
        elif self.outgoing[identity].store is not store:
            raise CodecError("cannot switch counter store within an epoch")
        return self.outgoing[identity].next()

    def accept_authenticated(self, header):
        """Internal post-MIC gate: strict high-water, duplicates rejected too."""
        if header.key_sequence not in self.key_epochs:
            raise CodecError("unknown replay epoch")
        identity = (header.source_ieee, self.key_epochs[header.key_sequence], header.key_sequence)
        if header.counter <= self.incoming_high_water.get(identity, -1):
            raise ReplayError("old or duplicate authenticated NWK frame")
        self.incoming_high_water[identity] = header.counter


def route(mac, contexts: list[ZigbeeContext]) -> ZigbeeContext:
    # Broadcast needs a unique PAN. Never trial-decrypt other contexts.
    candidates = [c for c in contexts if mac.destination_pan == c.pan and mac.source_pan == c.pan
                  and mac.destination in (c.local_short, 0xffff)]
    if len(candidates) != 1:
        raise CodecError("unknown or ambiguous MAC context")
    return candidates[0]
