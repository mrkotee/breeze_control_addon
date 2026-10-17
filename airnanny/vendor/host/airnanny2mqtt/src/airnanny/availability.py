from .state import DeviceStateSnapshot


def availability(snapshot: DeviceStateSnapshot, running: bool, context_available: bool) -> str:
    if not running or not context_available or not snapshot.status_valid: return 'unavailable'
    return 'online' if snapshot.status_fresh else 'stale'


def binary_availability(value: str) -> str:
    return 'online' if value == 'online' else 'offline'
