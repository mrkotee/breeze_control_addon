"""Read the calibrated FILL WATER bit from an authenticated snapshot.

The caller supplies DeviceStateSnapshot.raw_type06 after normal RX validation.
This module does not receive radio frames or change the frozen control codec.
"""
from .application import Type06


def water_empty(raw_type06: str | None) -> bool | None:
    if raw_type06 is None:
        return None
    return bool(Type06(bytes.fromhex(raw_type06)).flags & 0x02)
