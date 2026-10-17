"""Gate D evaluator: a 60-minute soak with both contexts live.

Pure: the soak's records, its periodic STATUS/STATS snapshots and its
Leave observations in, a verdict out.

The plan's row D: "60 min with both contexts. Both A7s' passive traffic is
enough; no continuous commands. Zero context-crossing safety failures; every
§4 metric collected; a Leave or degradation handled explicitly if it
happened." Each sentence is one check below.

Keepalive is sparse by design (operator's decision, 2026-10-13). The firmware
stops a context on its first failed TX (rejoin_transport.c:106), at roughly 1%
per TX in Gate C's attempts 2-3, so an hour at readiness cadence (~6400 polls)
could not survive. The parent's End Device Timeout is 15360 s, and its
keepalive ceiling is 5120 s, so polling once a minute keeps the link with a
wide margin.

A link is "alive" when the firmware never ended it and no gap between ACKed
polls exceeded MAX_CONSECUTIVE_POLL_MISSES periods (plus slack). That is V27's
own rule: it retries up to two clean misses in a row and ends the context on
the third. The first version of this check demanded >= 90% ACKed polls and no
gap over one period. Those were V26 thresholds, where a miss could not occur
without ending the run, and V27 attempt 2 failed only on them: a full hour,
both contexts PARENT_LINK_ACTIVE in every snapshot, ctx1 with 8 misses of 59
and one 180 s gap. Revised by the operator's decision on 2026-10-13. The miss
rate is reported as a metric, which makes it the measured answer to the plan's
open question about ctx1's RF margin, not a pass threshold.
"""
import gate_a
import gate_b
from gate_a import _int

SOAK_SECONDS = 3600
# include/management.h, V27. Gate D attempt 1 (V26) lost a context to one miss.
MAX_CONSECUTIVE_POLL_MISSES = 3
GAP_SLACK_S = 5.0
# STATS counters that would mean a frame was handled by the wrong context, or
# could not be told apart. Any non-zero value is a context-crossing failure.
CROSSING = ('cross_pair_reject', 'ambiguous', 'routing_error', 'routing_faults',
            'ctx0_tuple_reject', 'ctx1_tuple_reject')
# Plan §4: the metrics a soak must report.
METRICS = ('rx_total', 'ctx0_rx', 'ctx1_rx', 'cross_pair_reject', 'foreign_reject',
           'ctx0_tx_queue', 'ctx1_tx_queue', 'ctx0_tx_accepted', 'ctx1_tx_accepted',
           'ctx0_tx_terminal', 'ctx1_tx_terminal', 'ctx0_tx_failed', 'ctx1_tx_failed',
           'routing_error', 'routing_faults', 'scheduler_starvation', 'starved_polls')


def duration(start_s, end_s):
    soak = end_s - start_s
    if soak < SOAK_SECONDS:
        return ['the soak lasted %.0f s, %d required' % (soak, SOAK_SECONDS)], soak
    return [], soak


POLL_CLASS = 'MANAGEMENT_POLL'


def no_failed_tx(records):
    """No secured or command TX failed, and no context ran out of poll retries.

    V27 retries a clean poll miss with the next poll, so an isolated miss is
    counted and reported but is not a failure. Every other TX that fails ends
    its context in the firmware, and so does the limit-th miss in a row, so
    those are named and not averaged away.
    """
    classes = {}
    out, misses, run = [], {'0': 0, '1': 0}, {'0': 0, '1': 0}
    for r in records:
        f = r.get('fields') or {}
        if r.get('kind') in ('TXACCEPT', 'AUTO_ACCEPT'):
            classes[(r['kind'][:2], f.get('id'), f.get('poll') if r['kind'] == 'AUTO_ACCEPT' else None)] = f.get('class')
            continue
        if r.get('kind') not in ('TXDONE', 'AUTO_DONE'):
            continue
        auto = r['kind'] == 'AUTO_DONE'
        cls = classes.get(('AU' if auto else 'TX', f.get('id'), f.get('poll') if auto else None))
        ctx = f.get('ctx')
        if f.get('result') == 'local_tx_ok':
            if cls == POLL_CLASS and ctx in run:
                run[ctx] = 0
            continue
        if cls == POLL_CLASS and ctx in run:
            misses[ctx] += 1
            run[ctx] += 1
            if run[ctx] >= MAX_CONSECUTIVE_POLL_MISSES:
                out.append('ctx%s: %d keepalive polls in a row missed; the firmware ends '
                           'the context on this' % (ctx, run[ctx]))
            continue
        out.append('ctx%s: a %s TX failed (%s) at %s us; the firmware ends the context '
                   'on this' % (ctx, cls, f.get('result'), f.get('time_us')))
    return out, misses


def links_alive(records, period_s, start_us, end_us):
    polls = gate_b.acked_polls(records)
    reasons, detail = [], {}
    limit_us = (MAX_CONSECUTIVE_POLL_MISSES * period_s + GAP_SLACK_S) * 1e6
    for c in gate_b.CONTEXTS:
        ts = sorted(t for t in polls[c] if start_us <= t <= end_us)
        edges = [start_us] + ts + [end_us]
        gap = max(b - a for a, b in zip(edges, edges[1:]))
        nominal = int((end_us - start_us) / 1e6 / period_s)
        detail[c] = {'acked_polls': len(ts), 'nominal_polls': nominal,
                     'acked_ratio': round(len(ts) / nominal, 3) if nominal else None,
                     'max_gap_s': gap / 1e6, 'gap_limit_s': limit_us / 1e6}
        if gap > limit_us:
            reasons.append('%s: a %.0f s gap without an ACKed poll (limit %.0f s, %d periods)'
                           % (c, gap / 1e6, limit_us / 1e6, MAX_CONSECUTIVE_POLL_MISSES))
    return reasons, detail


def stayed_active(snapshots):
    """Every periodic STATUS saw both contexts PARENT_LINK_ACTIVE."""
    out = []
    for s in snapshots:
        for c in ('0', '1'):
            st = (s.get('status') or {}).get(c) or {}
            if st.get(gate_b.RECOVERY_FIELD) != 'PARENT_LINK_ACTIVE':
                out.append('ctx%s was %r at the %.0f s snapshot'
                           % (c, st.get(gate_b.RECOVERY_FIELD), s.get('at_s', -1)))
    return out


def no_crossing(stats):
    out = []
    for k in CROSSING:
        if k not in (stats or {}):
            out.append('STATS has no %s, so context crossing cannot be ruled out' % k)
        elif _int(stats, k):
            out.append('context-crossing counter %s = %s' % (k, stats[k]))
    return out


def metrics(stats, snapshots):
    missing = [k for k in METRICS if k not in (stats or {})]
    series = [{'at_s': s.get('at_s'), **{k: (s.get('stats') or {}).get(k) for k in METRICS}}
              for s in snapshots]
    reasons = ['metric %s missing from STATS' % k for k in missing]
    return reasons, {'final': {k: (stats or {}).get(k) for k in METRICS}, 'series': series}


def leaves_handled(leaves):
    return ['ctx%s: authenticated Leave at revision %s, handled as a degraded '
            'terminal (floors kept, no rejoin)' % (l['ctx'], l['revision']) for l in leaves]


def evaluate(records, snapshots, stats, start_s, end_s, start_us, end_us, period_s, leaves):
    r1, soak = duration(start_s, end_s)
    r2, misses = no_failed_tx(records)
    r3, alive = links_alive(records, period_s, start_us, end_us)
    r4 = stayed_active(snapshots)
    r5 = no_crossing(stats)
    r6, metric = metrics(stats, snapshots)
    r7 = leaves_handled(leaves)
    attr = gate_b.attribution(records, stats)
    coherence = gate_a.stats_coherent(stats) if stats else {'coherent': False}
    reasons = r1 + r2 + r3 + r4 + r5 + r6 + r7 + list(attr['reasons'])
    if not coherence.get('coherent'):
        reasons.append('the STATS counters do not add up: %r' % coherence)
    return {'gate': 'D', 'soak_seconds': soak, 'period_s': period_s,
            'links': alive, 'poll_misses': misses, 'metrics': metric, 'leaves': leaves,
            'attribution': attr, 'stats_coherence': coherence,
            'reasons': reasons, 'passed': not reasons}
