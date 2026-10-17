"""Gate C evaluator: one FAN command per context while the other stays alive.

Pure: records and the adapters' results in, verdict out. No serial, no store.

The plan's row C: "one TYPE07 in ctx0 with ctx1 healthy, then one TYPE07 in
ctx1 with ctx0 healthy. In order, never at once, never retried. Two confirmed
commands, each with a fresh correlated TYPE06; the other context healthy in
both cases." Each sentence is one function below, so a failure names the
sentence that failed.
"""
import gate_b
from gate_a import _int

CONTEXTS = ('ctx0', 'ctx1')
ORDER = ('0', '1')                 # ctx0 first, as in Gate B
# The other context is "healthy" through a command if its parent kept
# acknowledging keepalives across the whole command window: no gap longer
# than this, and at least MIN_PEER_POLLS of them. Keepalives run every 1.25 s,
# so 3 s tolerates one lost poll and nothing more.
MAX_PEER_GAP_US = 3000000
MIN_PEER_POLLS = 3
CONFIRM_WINDOW_US = 20000000
# A TYPE06 can confirm within ~0.3 s of the command (pcaps), which would make
# the window too short to say anything about the peer. It is never shorter.
MIN_WINDOW_US = 5000000


def commands(records):
    """Every TYPE07_FAN the firmware accepted, with its completion, per ctx."""
    out = {c: [] for c in ORDER}
    open_ = {}
    for r in records:
        f = r.get('fields') or {}
        if r.get('kind') == 'TXACCEPT' and f.get('class') == 'TYPE07_FAN':
            entry = {'id': f.get('id'), 'ctx': f.get('ctx'), 'accept_row': f}
            out.setdefault(f.get('ctx'), []).append(entry)
            open_[f.get('id')] = entry
        elif r.get('kind') == 'TXDONE' and f.get('id') in open_:
            e = open_.pop(f['id'])
            e.update(result=f.get('result'), time_us=_int(f, 'time_us'),
                     rf_start_us=_int(f, 'rf_start_us'))
    return out


def one_each(cmds):
    reasons = []
    for c in ORDER:
        n = len(cmds.get(c, []))
        if n != 1:
            reasons.append('ctx%s: %d TYPE07 commands accepted, exactly 1 required '
                           '(never retried, never skipped)' % (c, n))
        elif cmds[c][0].get('result') != 'local_tx_ok':
            reasons.append('ctx%s: the command did not complete locally: %r'
                           % (c, cmds[c][0].get('result')))
    stray = [c for c in cmds if c not in ORDER and cmds[c]]
    if stray:
        reasons.append('TYPE07 accepted on no known context: %r' % stray)
    return reasons


def confirmed(results):
    reasons = []
    for c in ORDER:
        res = (results or {}).get(c) or {}
        if res.get('application_result') != 'CONFIRMED':
            reasons.append('ctx%s: application result %r, CONFIRMED required (a '
                           'fresh TYPE06 matching the command)'
                           % (c, res.get('application_result')))
        elif not res.get('match_revision'):
            reasons.append('ctx%s: confirmed without a recorded matching TYPE06' % c)
    return reasons


def in_order(cmds, results):
    """ctx1's command went on air only after ctx0's was confirmed: its radio
    start is later than the TYPE06 that matched ctx0's command."""
    a = (cmds.get('0') or [None])[0]
    b = (cmds.get('1') or [None])[0]
    if not a or not b or a.get('time_us') is None or b.get('rf_start_us') is None:
        return []                       # one_each has already said why
    first_end = ((results or {}).get('0') or {}).get('match_radio_us') or a['time_us']
    if b['rf_start_us'] <= first_end:
        return ['the two commands overlapped: ctx1 went on air at %d us, before '
                'ctx0 had been confirmed at %d us' % (b['rf_start_us'], first_end)]
    return []

def peer_alive(records, cmds, results):
    """Through each command's window, the OTHER context's parent kept ACKing."""
    polls = gate_b.acked_polls(records)
    reasons, detail = [], {}
    for c in ORDER:
        e = (cmds.get(c) or [None])[0]
        if not e or e.get('rf_start_us') is None:
            continue
        start = e['rf_start_us']
        end = max(((results or {}).get(c) or {}).get('match_radio_us') or start + CONFIRM_WINDOW_US,
                  start + MIN_WINDOW_US)
        other = 'ctx' + ('1' if c == '0' else '0')
        inside = sorted(t for t in polls[other] if start <= t <= end)
        edges = [start] + inside + [end]
        gap = max(b - a for a, b in zip(edges, edges[1:]))
        detail['ctx%s_command' % c] = {'peer': other, 'peer_polls': len(inside),
                                       'max_gap_us': gap, 'window_us': [start, end]}
        if len(inside) < MIN_PEER_POLLS or gap > MAX_PEER_GAP_US:
            reasons.append('%s was not shown alive during ctx%s\'s command: %d ACKed '
                           'polls, longest gap %.1f s' % (other, c, len(inside), gap / 1e6))
    return reasons, detail


def evaluate(records, results, stats=None):
    cmds = commands(records)
    r1 = one_each(cmds)
    r2 = confirmed(results)
    r3 = in_order(cmds, results)
    r4, alive = peer_alive(records, cmds, results)
    attr = gate_b.attribution(records, stats)
    reasons = r1 + r2 + r3 + r4 + list(attr['reasons'])
    return {
        'gate': 'C',
        'commands': {c: [{k: v for k, v in e.items() if k != 'accept_row'} for e in cmds.get(c, [])]
                     for c in ORDER},
        'results': results,
        'peer_alive': alive,
        'attribution': attr,
        'reasons': reasons,
        'passed': not reasons,
    }
