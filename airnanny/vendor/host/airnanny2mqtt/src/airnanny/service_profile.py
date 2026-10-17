"""Host defaults for continuous firmware profiles; no hardware or store access."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceProfile:
    firmware_version: int
    rollover_successor: int
    recovery_stock_handoff: bool
    partial_startup: bool


def service_profile(firmware_version=32, *, rollover_successor=None,
                    recovery_stock_handoff=None, partial_startup=None):
    if type(firmware_version) is not int or firmware_version not in (30, 31, 32, 33):
        raise ValueError('continuous firmware profile required')
    if rollover_successor is None:
        rollover_successor = 2 if firmware_version >= 32 else 0
    if recovery_stock_handoff is None:
        recovery_stock_handoff = firmware_version >= 32
    if partial_startup is None:
        partial_startup = firmware_version >= 33
    if (type(rollover_successor) is not int or rollover_successor not in (0, 2)
            or (rollover_successor == 2 and firmware_version < 32)):
        raise ValueError('successor 2 requires V32')
    if type(recovery_stock_handoff) is not bool or (recovery_stock_handoff and firmware_version < 32):
        raise ValueError('recovery stock handoff requires V32')
    if type(partial_startup) is not bool or (partial_startup and firmware_version < 32):
        raise ValueError('partial startup requires V32')
    return ServiceProfile(firmware_version, rollover_successor, recovery_stock_handoff, partial_startup)
