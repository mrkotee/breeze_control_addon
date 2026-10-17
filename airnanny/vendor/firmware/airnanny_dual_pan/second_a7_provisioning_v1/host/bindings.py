"""Explicit ctx1 provenance. Equal key bytes never imply equal authority."""
from dataclasses import dataclass, field
import json
from pathlib import Path

PROFILE = json.loads((Path(__file__).resolve().parents[1]/'profile.json').read_text())


@dataclass(frozen=True)
class OwnedSecret:
    ctx: int
    pan: int
    tc_ieee: str
    role: str
    epoch: str
    value: bytes = field(repr=False)

    def __post_init__(self):
        if len(self.value) != 16 or not self.epoch:
            raise ValueError('secret length or provenance')

    def require(self, role):
        if (self.ctx, self.pan, self.tc_ieee, self.role) != (1, PROFILE['pan'], PROFILE['tc_ieee'], role):
            raise ValueError('cross_context_secret')
        return self


@dataclass(frozen=True)
class ReplayWatermark:
    ctx: int
    pan: int
    tc_ieee: str
    epoch: str
    generation: int
    highest_fc: int


def bind_watermark(validator, watermark):
    expected = (validator.ctx, validator.pan, validator.coordinator,
                validator.key_epoch, validator.generation)
    if not isinstance(watermark, ReplayWatermark) or (
            watermark.ctx, watermark.pan, watermark.tc_ieee,
            watermark.epoch, watermark.generation) != expected:
        raise ValueError('cross_context_replay_watermark')
    if not -1 <= watermark.highest_fc < 0xffffffff or watermark.highest_fc < validator.highest_fc:
        raise ValueError('replay_watermark_rollback')
    validator.highest_fc = watermark.highest_fc
