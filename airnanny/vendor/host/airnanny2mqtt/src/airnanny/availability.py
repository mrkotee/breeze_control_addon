from .state import DeviceStateSnapshot

# Reachability and freshness are two questions, and one bound cannot answer
# both. `status_fresh` is the reviewed command-confirmation bound: a status
# older than it may not confirm a setter. It was never a statement about
# whether the appliance is there -- an A7 reports roughly every twenty
# seconds when idle, which is why the confirmation windows beside it are
# twenty and forty-five. Answering Home Assistant from the confirmation bound
# put both devices out of the UI for five seconds of every twenty, between
# two perfectly normal reports.
#
# So a status past the confirmation bound is `stale` -- published, visible in
# diagnostics, and not a lie about reachability -- until silence has lasted
# long enough to mean something. Four missed reports is that line: past it
# the device is reported unavailable, which is the only value Home Assistant
# is told to act on.
REACHABLE_MS = 90000


def availability(snapshot: DeviceStateSnapshot, running: bool, context_available: bool) -> str:
    if not running or not context_available or not snapshot.status_valid: return 'unavailable'
    if snapshot.status_fresh: return 'online'
    age = snapshot.status_age_ms
    return 'stale' if age is not None and 0 <= age <= REACHABLE_MS else 'unavailable'


def binary_availability(value: str) -> str:
    return 'offline' if value == 'unavailable' else 'online'
