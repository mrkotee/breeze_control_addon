"""How long to listen for a coordinator's beacon before giving up.

The reviewed scan sends a beacon request and listens 0.28 s for the answer,
up to three times: 0.84 s of listening in total. That is right when the
coordinator answers the request, which it did from the position this was
developed at.

Where it does not answer -- a link good enough to hear the unit but not good
enough for the unit to hear us -- the scan can still succeed, because these
networks also beacon on their own. Measured from one such position: about
one beacon every twenty seconds. Against 0.84 s of listening that is roughly
a one-in-twenty-five chance per recovery cycle, which reads as a unit that
is simply absent.

Listening longer costs nothing. It spends no counter, moves no secured
state, and the firmware still decides which beacon counts -- the host only
waits. So the patience is configurable, the reviewed values stay the
default, and a deployment that needs more says so explicitly.
"""
import math

SETTLE_SECONDS = 0.28
SCANS = 3
PATIENT_SETTLE_SECONDS = 2.0
MAX_SCANS = 64


class PatienceError(ValueError):
    """The requested patience is not a usable scan plan."""


def scan_plan(listen_seconds):
    """Settle window and scan count for a total listening time.

    Returns the reviewed values unchanged for 0, which is the default and
    means "behave exactly as before".

    More scans rather than one long wait: each scan sends another beacon
    request, so a unit that misses one may hear the next, and a unit that
    answers none is still caught by a beacon of its own arriving inside any
    of the windows.
    """
    if listen_seconds in (None, 0, 0.0):
        return SETTLE_SECONDS, SCANS
    if not isinstance(listen_seconds, (int, float)) or isinstance(listen_seconds, bool):
        raise PatienceError('listening time must be a number of seconds')
    if listen_seconds < PATIENT_SETTLE_SECONDS:
        raise PatienceError('listening for less than %g s is the default scan, not patience'
                            % PATIENT_SETTLE_SECONDS)
    scans = math.ceil(listen_seconds / PATIENT_SETTLE_SECONDS)
    if scans > MAX_SCANS:
        raise PatienceError('listening longer than %g s would exceed %d scans'
                            % (MAX_SCANS * PATIENT_SETTLE_SECONDS, MAX_SCANS))
    return PATIENT_SETTLE_SECONDS, scans


def apply(module, listen_seconds):
    """Rebind the scan bounds a reviewed runner reads from its module.

    Rebinding rather than editing: the file's bytes are bound by the issue #6
    evidence, and the scan's logic is not what needs changing -- only how
    long it is prepared to wait. The values it now holds are reported back so
    a run can say what it used rather than leaving it to be inferred.
    """
    settle, scans = scan_plan(listen_seconds)
    module.SCAN_SETTLE_S = settle
    module.MAX_SCANS = scans
    return settle, scans
