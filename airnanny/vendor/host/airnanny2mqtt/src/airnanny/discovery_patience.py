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

What cannot change is the window itself. The host-side validator binds a
beacon to the request that asked for it: 261 ms, the standard active-scan
duration, with a separate two-second freshness bound. A beacon arriving later
is not an answer to our request, and widening the wait only collects beacons
the validator then refuses as stale -- which is what a first attempt at this
did, turning "no beacon" into "a beacon outside the scan".

So patience buys more scans, not longer ones. Each scan is another request,
and a unit that missed the last one may hear the next. Requests are plaintext:
they spend no counter and move no secured state. If a unit answers none of
them, no amount of patience helps, and that is a finding rather than a
failure -- it means the link carries one way only.
"""
import math

SETTLE_SECONDS = 0.28
SCANS = 3
# The validator's own bound, which the wait must stay inside: 261 ms of
# active scan, and never near the two-second freshness limit.
MAX_SCANS = 256


class PatienceError(ValueError):
    """The requested patience is not a usable scan plan."""


def scan_plan(listen_seconds):
    """Settle window and scan count for a total listening time.

    Returns the reviewed values unchanged for 0, which is the default and
    means "behave exactly as before".

    The window stays at the reviewed value whatever the patience, because
    the validator refuses a beacon that arrived outside it. What grows is
    the number of requests: a unit that missed the last one may hear the
    next.
    """
    if listen_seconds in (None, 0, 0.0):
        return SETTLE_SECONDS, SCANS
    if not isinstance(listen_seconds, (int, float)) or isinstance(listen_seconds, bool):
        raise PatienceError('listening time must be a number of seconds')
    if listen_seconds < SETTLE_SECONDS * (SCANS + 1):
        raise PatienceError('less than %g s is the default scan, not patience'
                            % (SETTLE_SECONDS * (SCANS + 1)))
    scans = math.ceil(listen_seconds / SETTLE_SECONDS)
    if scans > MAX_SCANS:
        raise PatienceError('longer than %g s would exceed %d scans'
                            % (MAX_SCANS * SETTLE_SECONDS, MAX_SCANS))
    return SETTLE_SECONDS, scans


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
