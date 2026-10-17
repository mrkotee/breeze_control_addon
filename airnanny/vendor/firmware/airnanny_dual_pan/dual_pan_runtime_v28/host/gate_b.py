"""Gate B evaluation: two live contexts, and the immediate ACK of both tuples.

Pure, like gate_a: it takes the records the firmware emitted and returns a
verdict, so every criterion is driven offline before a dongle is on air. The
serial driving belongs to a runner; nothing here opens a port.

What Gate B has to establish, from DUAL_PAN_RUNTIME_PLAN.md section 7 and the
handover recorded in GATE_A_PROCEDURE.md section 0:

  * secured rejoin of BOTH contexts in ONE session. For ctx1 a normal-mode
    rejoin with the stored key was proved in V25; for ctx0 on this firmware it
    is NOT proved, and this is where it is;
  * the order is rejoin -> rejoin -> SHARED readiness, not two complete
    sequential phases. That distinction is the whole point and is checked
    positively below;
  * both TYPE06 streams correctly attributed, zero cross-context rejects;
  * both parent links alive AT THE SAME TIME;
  * the immediate ACK of both tuples, which moved here from Gate A because an
    addressed frame only ever arrives in response to a poll, and the firmware
    will not poll outside R_ACTIVE -- which this gate is what reaches.

Gate A was passive and could be re-run freely. Gate B is not: it transmits, it
spends frame counters and it advances ctx0's store. Everything it claims has
to be legible from the records afterwards, because it cannot simply be run
again to look more closely.
"""
import gate_a
from gate_a import GateAFault as GateBFault, _int, _rx   # same shapes, same faults

# Readiness, once both contexts are active. The plan asks for 60 s with both
# live; the floor below is what makes "both alive at the same time" mean
# something rather than "each was alive at some point".
READINESS_SECONDS = 60
MIN_POLLS_PER_CTX = 10
MIN_OVERLAP_SECONDS = 30
CONTEXTS = ('ctx0', 'ctx1')

# The phases a context passes through, in order. recovery_phase_t in
# include/commission.h; these are the names STATUS reports.
# recovery_name() in src/rejoin_transport.c, verbatim and in its order.
#
# STATUS carries TWO phase fields and they are not the same thing: `state` is
# the commission phase (IDLE / RECOVERY / STOPPED) and `recovery` is the chain
# below. Reading `state` where the chain was meant made a scan that had worked
# look like a failure, because the firmware said RECOVERY while the host was
# waiting to hear DISCOVERED.
REJOIN_CHAIN = ('IDLE', 'BOUND', 'SCANNING', 'DISCOVERED', 'REJOIN_PREPARED',
                'WAIT_REJOIN', 'REJOINED', 'ANNOUNCED', 'WAIT_TIMEOUT',
                'PARENT_LINK_ACTIVE', 'STOPPED')
TERMINAL = 'PARENT_LINK_ACTIVE'
RECOVERY_FIELD = 'recovery'


def _us(row):
    return _int(row['fields'], gate_a.RX_TIME)


def phase_log(records):
    """Every phase a context was observed in, in order, from STATUS records.

    Taken from what the firmware reported rather than from what the host
    believes it asked for: a host that sent the chain correctly and a firmware
    that advanced through it are different claims, and this gate is about the
    second one.
    """
    out = {c: [] for c in CONTEXTS}
    for r in records:
        if r.get('kind') != 'STATUS':
            continue
        f = r['fields']
        ctx = f.get('ctx')
        if ctx not in ('0', '1'):
            continue
        name = 'ctx' + ctx
        state = f.get(RECOVERY_FIELD)
        if state and (not out[name] or out[name][-1]['state'] != state):
            out[name].append({'state': state, 'time_us': _int(f, 'time_us')})
    return out


def rejoined_both(records):
    """Both contexts completed the chain, and ctx0 is the one that was unproved.

    The chain is checked as a SUBSEQUENCE rather than as an exact list: the
    firmware may report a state more than once and the host may observe it at
    any cadence, but it may never reach ACTIVE without having passed REJOINED,
    and it may never go backwards.
    """
    log = phase_log(records)
    out = {'per_context': {}, 'reasons': []}
    for c in CONTEXTS:
        seen = [p['state'] for p in log[c]]
        # STOPPED is the end of a session, not a step backwards, so it is
        # excluded from the monotonicity check rather than failing it.
        order = [REJOIN_CHAIN.index(s) for s in seen
                 if s in REJOIN_CHAIN and s != 'STOPPED']
        monotonic = all(a <= b for a, b in zip(order, order[1:]))
        reached = TERMINAL in seen
        rejoined = 'REJOINED' in seen
        out['per_context'][c] = {
            'states': seen, 'reached_active': reached,
            'passed_rejoined': rejoined, 'monotonic': monotonic,
            'active_at_us': next((p['time_us'] for p in log[c]
                                  if p['state'] == TERMINAL), None),
        }
        if not rejoined:
            out['reasons'].append('%s: never reported REJOINED, so no secured '
                                  'rejoin happened on this context' % c)
        if not reached:
            out['reasons'].append('%s: never reached ACTIVE' % c)
        if not monotonic:
            out['reasons'].append('%s: phases went backwards: %r' % (c, seen))
    out['passed'] = not out['reasons']
    return out


def acked_polls(records):
    """Completion times of the polls a parent actually acknowledged, per ctx.

    A poll is evidence of a live parent link only once the parent has ACKed
    it. AUTO_ACCEPT says the firmware queued a poll; AUTO_DONE says what
    became of it, and only AUTO_DONE carries the result and the ACK. The
    first version counted AUTO_ACCEPT alone (AUTO_DONE has no `class` field,
    so the class filter dropped every completion), which would have passed a
    context whose coordinator had stopped answering. Seen on hardware in
    attempt 10, the first run to emit automatic polls.

    Two kinds of poll exist and both count. The firmware polls by itself only
    inside a response window (AUTO_ACCEPT/AUTO_DONE); once a context is
    PARENT_LINK_ACTIVE the window is closed and every keepalive is a host
    MANAGEMENT_POLL (TXACCEPT/TXDONE). Readiness is made of the second kind.

    The pairing is per context and strict: a DONE counts only against the
    MANAGEMENT_POLL ACCEPT open for the same ctx and the same command.
    """
    polls = {c: [] for c in CONTEXTS}
    open_accept = {}
    for r in records:
        kind = r.get('kind')
        if kind in ('AUTO_ACCEPT', 'AUTO_DONE'):
            family = 'AUTO'
        elif kind in ('TXACCEPT', 'TXDONE'):
            family = 'TX'
        else:
            continue
        f = r['fields']
        ctx = f.get('ctx')
        if ctx not in ('0', '1'):
            continue
        # AUTO polls are numbered within a response window; a host-commanded
        # MANAGEMENT_POLL is one TX, named by its command id alone.
        key = (family, f.get('id'), f.get('poll') if family == 'AUTO' else None)
        if kind.endswith('ACCEPT'):
            open_accept[ctx] = key if f.get('class') == 'MANAGEMENT_POLL' else None
            continue
        if open_accept.pop(ctx, None) != key:
            continue
        if f.get('result') == 'local_tx_ok' and f.get('ack_present') == '1':
            polls['ctx' + ctx].append(_int(f, 'time_us'))
    return polls

def shared_readiness(records):
    """Both parent links alive AT THE SAME TIME, not one after the other.

    This is the criterion the plan is explicit about: rejoin -> rejoin ->
    shared readiness, because two complete sequential phases let the first
    context's parent link go cold while the second one is commissioned, and a
    run shaped that way proves nothing about a dual runtime. So the overlap is
    required positively, from the automatic polls each context emits once it is
    active: the window where BOTH are polling must be long enough and must
    carry enough polls from each.
    """
    polls = acked_polls(records)

    out = {'polls': {c: len(polls[c]) for c in CONTEXTS}, 'reasons': []}
    for c in CONTEXTS:
        if len(polls[c]) < MIN_POLLS_PER_CTX:
            out['reasons'].append(
                '%s: %d polls during readiness, %d required -- that parent '
                'link was not shown to be alive'
                % (c, len(polls[c]), MIN_POLLS_PER_CTX))

    if all(polls[c] for c in CONTEXTS):
        lo = max(min(polls[c]) for c in CONTEXTS)
        hi = min(max(polls[c]) for c in CONTEXTS)
        overlap = max(0, hi - lo) / 1e6
        out['overlap_seconds'] = round(overlap, 1)
        out['overlap_window_us'] = [lo, hi]
        # Polls from each side INSIDE the shared window, so a context that
        # merely started early and stopped early cannot buy overlap with two
        # distant samples.
        out['polls_inside_overlap'] = {
            c: sum(1 for t in polls[c] if lo <= t <= hi) for c in CONTEXTS}
        if overlap < MIN_OVERLAP_SECONDS:
            out['reasons'].append(
                'the two parent links overlapped for %.1f s, %d required: '
                'they were alive one after the other, not at the same time'
                % (overlap, MIN_OVERLAP_SECONDS))
        for c in CONTEXTS:
            if out['polls_inside_overlap'][c] < MIN_POLLS_PER_CTX:
                out['reasons'].append(
                    '%s: only %d of its polls fall inside the shared window'
                    % (c, out['polls_inside_overlap'][c]))
    else:
        out['overlap_seconds'] = 0.0
        out['reasons'].append('at least one context never polled, so there is '
                              'no shared window at all')
    out['passed'] = not out['reasons']
    return out


def attribution(records, stats=None):
    """Every frame went to the context that owns it, and nothing crossed.

    `match` is the firmware's own classification, so this reads what the
    admission layer concluded rather than re-deriving it on the host. A
    cross-pair frame is the isolation failure the whole runtime exists to
    prevent: PAN of one context carrying the short address of the other.
    """
    out = {'matches': {}, 'reasons': []}
    for f in _rx(records):
        m = f.get('match', '?')
        out['matches'][m] = out['matches'].get(m, 0) + 1
        if m == 'ambiguous':
            out['reasons'].append('a frame classified ambiguous: the two '
                                  'contexts were not separable')
            break
    for c in CONTEXTS:
        if not out['matches'].get(c):
            out['reasons'].append('%s: not one frame was attributed to it' % c)

    if stats is not None:
        for counter, why in (
                ('cross_pair_reject', 'a cross-pair frame reached admission'),
                ('ambiguous', 'a frame could not be attributed'),
                ('routing_faults', 'the one-radio scheduler routed a frame to '
                                   'the wrong context')):
            n = _int(stats, counter) if counter in stats else 0
            out[counter] = n
            if n:
                out['reasons'].append('%s=%d: %s' % (counter, n, why))
    out['passed'] = not out['reasons']
    return out


MIN_ADDRESSED_PER_CTX = 2      # the parent's two answers: REJOIN and TIMEOUT


def addressed_ack(records):
    """B4 as revised after attempt 11: EVERY frame addressed to either tuple,
    across the whole run, answered with an immediate ACK inside the envelope,
    at least MIN_ADDRESSED_PER_CTX of them per context, no deadline missed and
    nothing answered that was not ours.

    The plan carried Gate A's >=30 addressed samples per PAN over to here on
    the premise that "an addressed frame arrives in response to a poll".
    Attempt 11 disproved the premise for idle parents. All 92 keepalive polls
    (46 per context) were ACKed with frame-pending clear (ack_fcf=2): neither
    parent had anything queued, so readiness contains no addressed frame to
    answer, and the firmware's typed allowlist gives the host no way to
    provoke 30 answers. What a run does carry is the parents' answers to
    REJOIN and TIMEOUT. Those are the frames whose ACK matters most, since an
    unanswered one is retransmitted and then lost. So the count becomes
    "all of them, and at least those two", over the whole run rather than the
    readiness slice. Simultaneity, which the >=30 interleaved samples also
    stood for, is shown by shared_readiness from ACKed polls.

    The measurement is Gate A's (dual_tuple_ack), unchanged. Only its count and
    interleaving requirements are replaced, and that function stays as it is
    for Gate A.
    """
    # A frame that did not request an ACK (fcf bit 5 clear) is legitimately
    # unanswered and is left out of the count; one that did is held to it.
    population, no_ar = [], 0
    for r in records:
        f = r.get('fields') or {}
        if (r.get('kind') == 'RX' and f.get('match') in gate_a.BOUND_MATCHES
                and f.get('ack_started') == '0' and not _ack_requested(f)):
            no_ar += 1
            continue
        population.append(r)
    d = gate_a.dual_tuple_ack(population)
    reasons = []
    for m in gate_a.BOUND_MATCHES:
        b = d['per_context'][m]
        if b['samples'] < MIN_ADDRESSED_PER_CTX:
            reasons.append('%s: %d addressed frames in the run, %d required'
                           % (m, b['samples'], MIN_ADDRESSED_PER_CTX))
        if b['acked'] != b['samples']:
            reasons.append('%s: %d of %d addressed frames were not ACKed'
                           % (m, b['samples'] - b['acked'], b['samples']))
        if b['acked'] and not b['turnaround_us']:
            reasons.append('%s: ACKs produced but no turnaround computable; the '
                           'capture fields are missing' % m)
        elif b['acked']:
            if not b['turnaround_within_envelope']:
                reasons.append('%s: ACK turnaround outside the %d+/-%d us envelope'
                               % (m, gate_a.ACK_TURNAROUND_US,
                                  gate_a.ACK_TURNAROUND_TOLERANCE_US))
            if not b['ack_duration_plausible']:
                reasons.append('%s: ACK duration implausible' % m)
        if b['capture_order_violations']:
            reasons.append('%s: %d frames with hardware captures out of order'
                           % (m, len(b['capture_order_violations'])))
    if d['deadline_misses']:
        reasons.append('%d missed ACK deadlines' % len(d['deadline_misses']))
    if d['unintended_acks']:
        reasons.append('%d unintended ACKs' % len(d['unintended_acks']))
    out = dict(d, reasons=reasons, passed=not reasons,
               addressed_without_ack_request=no_ar,
               criterion='B4 revised: every addressed frame ACKed, >=%d per ctx'
                         % MIN_ADDRESSED_PER_CTX)
    out.pop('interleaving', None)
    return out


def _ack_requested(fields):
    mac = fields.get('mac') or ''
    try:
        return bool(int(mac[0:2], 16) & 0x20)
    except ValueError:
        return True                # unreadable: held to the stricter rule


def readiness_slice(records):
    """The records from the first keepalive poll on: what keep_alive returned
    to the runner, recoverable from an outcome's records alone."""
    for i, r in enumerate(records):
        if r.get('kind') == 'HOST_COMMAND' and ' MANAGEMENT_POLL ' in r.get('raw', ''):
            return records[i:]
    return []


def evaluate(records, stats=None, ack_records=None):
    """The whole gate.

    `ack_records` is the readiness slice, where both contexts are active. It
    scopes the allowlist-stability check. The ACK criterion reads the whole run:
    see addressed_ack for why that changed after attempt 11.
    """
    a = rejoined_both(records)
    b = shared_readiness(records)
    c = attribution(records, stats)
    d = addressed_ack(records)
    coherence = gate_a.stats_coherent(stats) if stats is not None else None

    reasons = (list(a['reasons']) + list(b['reasons']) + list(c['reasons'])
               + list(d['reasons']))
    if coherence is not None and not coherence['coherent']:
        reasons.append('the STATS counters do not add up, so no number in this '
                       'run can be read: %r' % coherence)
    generations = gate_a.config_generations(
        ack_records if ack_records is not None else records)
    if len(set(generations)) > 1:
        reasons.append('the allowlist changed during readiness: '
                       'config_generation %s' % sorted(set(generations)))
    return {
        'gate': 'B',
        'secured_rejoin': a,
        'shared_readiness': b,
        'attribution': c,
        'dual_tuple_ack': d,
        'stats_coherence': coherence,
        'config_generations': sorted(set(generations)),
        'reasons': reasons,
        'passed': not reasons,
    }
