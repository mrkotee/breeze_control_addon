"""Gate A evaluation: RF margin and dual-tuple immediate ACK.

The evaluator here is pure. It takes the RX records the firmware emitted and
returns a verdict, so every criterion can be tested offline against synthetic
and fixture-generated records rather than only against a radio. The serial
driving lives in launch_gate_a.py; nothing in this module opens a port.

What Gate A has to establish, from DUAL_PAN_RUNTIME_PLAN.md:

  * both contexts' tuples are actually present on air from one dongle position,
    with their RSSI/LQI measured rather than assumed -- this is the ctx1 RF
    margin question from plan section 2.2, which is a stop criterion;
  * with both tuples allow-listed, an immediate ACK is produced for each of
    them without the PIB or the channel being switched between them;
  * zero missed ACK deadlines in the observed set;
  * zero unintended ACKs -- nothing that is not one of the two bound tuples is
    ever answered;
  * RX of both PANs survives throughout.

The one criterion worth stating carefully is interleaving. Thirty samples of
ctx0 followed by thirty of ctx1 would satisfy a naive per-PAN count while
proving nothing about two networks being live at once: that is just two
sequential single-context runs. So concurrency is required positively, by
alternation and by presence in each part of the window, and a run that happens
to be sequential fails even if every other number is perfect.
"""

from dual_store import PINNED as _PINNED

MIN_SAMPLES_PER_CTX = 30
MIN_ALTERNATIONS = 10
WINDOW_PARTS = 3

# The four timestamps in an RX record are hardware captures from TIMER3, not
# software reads:
#
#   time_us        CC[0]  CRCOK     end of the received frame
#   ack_start_us   CC[1]  TXREADY   radio ready to transmit the ACK
#   ack_address_us CC[3]  ADDRESS   during the ACK, after preamble and SFD
#   ack_end_us     CC[2]  PHYEND    end of the ACK on air
#
# IEEE 802.15.4 aTurnaroundTime is 12 symbols, 192 us, measured from the end of
# the received frame to the start of the ACK on air. None of the four captures
# is exactly "ACK start on air": TXREADY precedes it and ADDRESS follows the
# preamble. So asserting CC[1] - CC[0] == 192 +/- a tight tolerance would risk
# failing the gate on a definitional mismatch rather than on a real timing
# fault, which is the worst kind of false negative -- it would send someone
# looking for a radio problem that is not there.
#
# What is asserted instead is in two parts. First, an ORDERING that holds
# whatever the reference points mean and that no correct capture path can
# violate: CRCOK < TXREADY <= ADDRESS < PHYEND. A mis-wired PPI channel or a
# CC clash shows up here immediately, and that is the failure that would
# otherwise corrupt every number in the record silently. Second, a GENEROUS
# envelope on CRCOK -> TXREADY, wide enough that only a real fault leaves it.
# The actual distribution is reported either way, so the hardware defines the
# tight number rather than this file guessing it in advance.
ACK_TURNAROUND_US = 192
ACK_TURNAROUND_TOLERANCE_US = 160          # 32..352 us: a sanity bound
ACK_MAX_DURATION_US = 1000                 # an ACK is 352 us of air at 250 kbps

BOUND_MATCHES = ('ctx0', 'ctx1')

# The firmware's own names, from the RX line in src/main.c -- which is the one
# the dongle actually emits.
#
# There are TWO RX formatters in this tree. src/main.c builds the live line;
# dual_format_rx in src/dual_records.c builds a differently named one
# (`rx_end_us`, `rx_id`, `rx_end_valid`) and is called by nothing except its
# own unit test. Reading the records module and concluding that `time_us` had
# been renamed is a mistake that was actually made here, and it would have
# repointed every timestamp this evaluator reads at a field the dongle does not
# send: _int defaults a missing field to 0, so the window span would collapse,
# the interleaving check could never pass, and every turnaround would have been
# computed against zero -- all without one loud failure.
#
# So the names are taken from main.c, and tests/test_gate_a.py reads that line
# out of the source, checks the fixtures against it, and asserts that the dead
# formatter is still dead. If dual_format_rx ever becomes the live emitter,
# that test fails and these constants are what has to change.
RX_TIME = 'time_us'              # CC[0] CRCOK, end of the received frame
RX_ACK_START = 'ack_start_us'    # CC[1] TXREADY
RX_ACK_ADDRESS = 'ack_address_us'  # CC[3] ADDRESS
RX_ACK_END = 'ack_end_us'        # CC[2] PHYEND

# Each network is identified on air by its PAN id, which every frame in it
# carries whether or not it is addressed to us. See `frame_pan`. Taken from the
# pinned store identities rather than written out again here: two copies of a
# PAN id is one copy too many, and tests/test_gate_a.py checks these against
# DUAL_CTX0_PAN and DUAL_CTX1_PAN in the firmware header as well.
PAN_OF_CTX = {'ctx%d' % ctx: entry['pan'] for ctx, entry in _PINNED.items()}
MIN_SURVEY_SAMPLES_PER_PAN = 30


class GateAFault(RuntimeError):
    pass


def _rx(records):
    return [r['fields'] for r in records if r.get('kind') == 'RX']


def _int(f, key, default=0):
    try:
        return int(f.get(key, default))
    except (TypeError, ValueError):
        raise GateAFault('non_numeric_field:' + key)


def frame_pan(mac_hex):
    """The PAN id a received frame belongs to, from its MAC header bytes.

    This is what makes Gate A possible at all. `match` cannot answer the RF
    margin question: it compares the DESTINATION against our own (PAN, short)
    tuples, so a frame the coordinator sends to one of its other children is
    `foreign` no matter how strong it is, and a frame addressed to US only ever
    arrives after we have joined and polled. The first hardware run saw 248
    addressed frames and classified every one as foreign, with ctx0 and ctx1 at
    zero -- not because the radio or the classifier was wrong, but because a
    passive observer is not addressed by anyone.

    The PAN id, on the other hand, is carried by every frame in a network. A
    coordinator's transmissions are therefore measurable without ever joining,
    which is exactly the measurement section 2.2 of the plan asks for: the RSSI
    and LQI of both coordinators from one dongle position.

    The parse mirrors dual_header_size in src/dual_context.c, and is deliberately
    strict in the same way: an addressing mode the firmware calls malformed or
    unsupported returns None here rather than a guess. With PAN compression the
    source PAN is omitted and equals the destination PAN, which is why the
    destination is preferred and the source is only read when there is no
    destination at all.

    Returns the PAN id, or None if this frame does not carry one legibly.
    """
    try:
        mac = bytes.fromhex(mac_hex or '')
    except ValueError:
        raise GateAFault('non_hex_mac:%r' % mac_hex)
    if len(mac) < 3:
        return None
    fcf = mac[0] | (mac[1] << 8)
    dest = (fcf >> 10) & 3
    src = (fcf >> 14) & 3
    compressed = bool(fcf & 0x40)
    if dest == 1 or src == 1 or (compressed and (dest == 0 or src == 0)):
        return None                      # malformed, as the firmware calls it
    if dest:                             # dest PAN sits right after the seq no
        return int.from_bytes(mac[3:5], 'little') if len(mac) >= 5 else None
    if src and not compressed:           # no destination: the source PAN is it
        return int.from_bytes(mac[3:5], 'little') if len(mac) >= 5 else None
    return None


def survey(records):
    """Gate A, whole. Passive RF margin of both coordinators from one dongle
    position, with the ACK gate shut throughout.

    Scoped by PAN, not by `match`, for the reason set out in frame_pan: no
    allowlist is published during this gate and the dongle transmits nothing,
    so no frame is addressed to us and `match` is `foreign` for all of them.
    What is measured is each coordinator's signal as received here, which is
    the section 2.2 stop criterion and does not require being a member of
    either network.

    Nothing may be answered. The dongle never binds and never transmits in this
    gate, so an ACK observed here means the gate opened on its own, which is a
    firmware fault and not a weak signal.
    """
    out = {'per_context': {}, 'ack_observed': 0, 'total': 0,
           'frames_without_a_legible_pan': 0, 'other_pans': {}}
    samples = []
    for f in _rx(records):
        out['total'] += 1
        if _int(f, 'ack_started'):
            out['ack_observed'] += 1
        pan = frame_pan(f.get('mac'))
        if pan is None:
            out['frames_without_a_legible_pan'] += 1
            continue
        match = next((m for m, p in PAN_OF_CTX.items() if p == pan), None)
        if match is None:
            # Another network on channel 21. Counted, never measured: it says
            # how busy the channel is, which belongs in the record.
            out['other_pans']['%04x' % pan] = out['other_pans'].get('%04x' % pan, 0) + 1
            continue
        bucket = out['per_context'].setdefault(
            match, {'samples': 0, 'rssi': [], 'lqi': []})
        bucket['samples'] += 1
        bucket['rssi'].append(_int(f, 'rssi'))
        bucket['lqi'].append(_int(f, 'lqi'))
        samples.append(dict(match=match, time_us=_int(f, RX_TIME)))

    for match, b in out['per_context'].items():
        b['rssi_min'] = min(b['rssi'])
        b['rssi_max'] = max(b['rssi'])
        b['rssi_mean'] = round(sum(b['rssi']) / len(b['rssi']), 1)
        b['lqi_min'] = min(b['lqi'])
        b['lqi_max'] = max(b['lqi'])
        b['lqi_mean'] = round(sum(b['lqi']) / len(b['lqi']), 1)
    out['pan_of_context'] = {m: '%04x' % p for m, p in PAN_OF_CTX.items()}
    out['both_contexts_present'] = all(
        out['per_context'].get(m, {}).get('samples', 0) >= MIN_SURVEY_SAMPLES_PER_PAN
        for m in BOUND_MATCHES)
    # Both coordinators audible throughout the window rather than one of them
    # only at the start: a network that fades in and out has not been shown to
    # be reachable from this position, whatever its mean RSSI says.
    out['concurrency'] = _interleaved(samples) if samples else {
        'alternations': 0, 'alternations_required': MIN_ALTERNATIONS,
        'window_parts': [], 'both_in_every_part': False, 'passed': False}

    out['reasons'] = []
    for m in BOUND_MATCHES:
        n = out['per_context'].get(m, {}).get('samples', 0)
        if n < MIN_SURVEY_SAMPLES_PER_PAN:
            out['reasons'].append(
                '%s (PAN %04x): %d frames heard from this dongle position, %d '
                'required -- that network is not adequately audible here'
                % (m, PAN_OF_CTX[m], n, MIN_SURVEY_SAMPLES_PER_PAN))
    if not out['concurrency']['both_in_every_part']:
        out['reasons'].append(
            'both PANs were not heard in every part of the window: %r'
            % (out['concurrency']['window_parts'],))
    if out['ack_observed']:
        out['reasons'].append('an ACK was produced while nothing was bound')
    out['passed'] = not out['reasons']
    return out


def _alternations(sequence):
    return sum(1 for a, b in zip(sequence, sequence[1:]) if a != b)


def _interleaved(samples):
    """Positive evidence that both contexts were live at the same time, rather
    than one after the other. Two tests, both required: the match sequence
    alternates often enough that the contexts are genuinely interleaved, and
    each equal part of the observation window contains both contexts."""
    order = [s['match'] for s in samples]
    alternations = _alternations(order)

    times = [s['time_us'] for s in samples]
    span = max(times) - min(times)
    parts_ok = True
    parts = []
    if span <= 0:
        parts_ok = False
    else:
        start = min(times)
        width = span / WINDOW_PARTS
        for p in range(WINDOW_PARTS):
            lo = start + p * width
            hi = start + (p + 1) * width if p < WINDOW_PARTS - 1 else start + span + 1
            present = {s['match'] for s in samples if lo <= s['time_us'] < hi}
            parts.append(sorted(present))
            if not all(m in present for m in BOUND_MATCHES):
                parts_ok = False
    return {
        'alternations': alternations,
        'alternations_required': MIN_ALTERNATIONS,
        'window_parts': parts,
        'both_in_every_part': parts_ok,
        'passed': alternations >= MIN_ALTERNATIONS and parts_ok,
    }


def dual_tuple_ack(records):
    """Phase 2, both tuples allow-listed. Measures the immediate ACK for each
    context and refuses anything answered that is not one of the two."""
    samples = []
    unintended = []
    deadline_misses = []
    per_ctx = {m: {'samples': 0, 'acked': 0, 'turnaround_us': [],
                   'to_address_us': [], 'ack_duration_us': [],
                   'capture_order_violations': [],
                   'rssi': [], 'lqi': []} for m in BOUND_MATCHES}

    for f in _rx(records):
        match = f.get('match')
        started = _int(f, 'ack_started')
        completed = _int(f, 'ack_completed')
        miss = _int(f, 'deadline_miss')
        time_us = _int(f, RX_TIME)

        if miss:
            deadline_misses.append(dict(match=match, time_us=time_us))

        # Anything answered that is not one of the two bound tuples is the
        # failure this gate exists to rule out, and is recorded whole.
        if started and match not in BOUND_MATCHES:
            unintended.append(dict(match=match, time_us=time_us,
                                   mac=f.get('mac', ''), reason=f.get('reason', '')))
            continue
        if match not in BOUND_MATCHES:
            continue

        b = per_ctx[match]
        b['samples'] += 1
        b['rssi'].append(_int(f, 'rssi'))
        b['lqi'].append(_int(f, 'lqi'))
        samples.append(dict(match=match, time_us=time_us))

        if started and completed:
            b['acked'] += 1
            start_us = _int(f, RX_ACK_START)
            addr_us = _int(f, RX_ACK_ADDRESS)
            end_us = _int(f, RX_ACK_END)
            if start_us and time_us:
                b['turnaround_us'].append(start_us - time_us)
            if addr_us and time_us:
                b['to_address_us'].append(addr_us - time_us)
            if end_us and start_us:
                b['ack_duration_us'].append(end_us - start_us)
            # The ordering check. Independent of what the reference points
            # mean, and the one thing a mis-wired capture path cannot satisfy.
            if time_us and start_us and addr_us and end_us:
                if not (time_us < start_us <= addr_us < end_us):
                    b['capture_order_violations'].append(dict(
                        match=match, crcok=time_us, txready=start_us,
                        address=addr_us, phyend=end_us))

    for m, b in per_ctx.items():
        if b['rssi']:
            b['rssi_min'], b['rssi_max'] = min(b['rssi']), max(b['rssi'])
            b['lqi_min'], b['lqi_max'] = min(b['lqi']), max(b['lqi'])
        for name in ('turnaround_us', 'to_address_us', 'ack_duration_us'):
            v = b[name]
            if v:
                b[name.replace('_us', '') + '_min'] = min(v)
                b[name.replace('_us', '') + '_max'] = max(v)
                b[name.replace('_us', '') + '_mean'] = round(sum(v) / len(v), 1)
        if b['turnaround_us']:
            t = b['turnaround_us']
            lo = ACK_TURNAROUND_US - ACK_TURNAROUND_TOLERANCE_US
            hi = ACK_TURNAROUND_US + ACK_TURNAROUND_TOLERANCE_US
            b['turnaround_within_envelope'] = all(lo <= x <= hi for x in t)
            b['turnaround_envelope_us'] = [lo, hi]
        else:
            b['turnaround_within_envelope'] = False
        d = b['ack_duration_us']
        b['ack_duration_plausible'] = bool(d) and all(0 < x <= ACK_MAX_DURATION_US
                                                      for x in d)

    interleaving = _interleaved(samples) if samples else {
        'passed': False, 'alternations': 0,
        'alternations_required': MIN_ALTERNATIONS,
        'window_parts': [], 'both_in_every_part': False}

    reasons = []
    for m in BOUND_MATCHES:
        b = per_ctx[m]
        if b['samples'] < MIN_SAMPLES_PER_CTX:
            reasons.append('%s: %d CRC-valid addressed samples, %d required'
                           % (m, b['samples'], MIN_SAMPLES_PER_CTX))
        if b['acked'] == 0:
            reasons.append('%s: never answered with an immediate ACK' % m)
        elif not b['turnaround_us']:
            # Answered, but not one turnaround could be computed. Saying
            # "outside the envelope" here would send someone looking for a
            # radio fault; the fault is that the timestamps were not readable,
            # which is what a renamed or absent capture field looks like.
            reasons.append('%s: %d ACKs were produced but no turnaround could '
                           'be computed from the records -- the capture fields '
                           'are missing or unreadable, so this run measured '
                           'nothing' % (m, b['acked']))
        else:
            if not b['turnaround_within_envelope']:
                reasons.append('%s: ACK turnaround outside the %d+/-%d us envelope'
                               % (m, ACK_TURNAROUND_US, ACK_TURNAROUND_TOLERANCE_US))
            if not b['ack_duration_plausible']:
                reasons.append('%s: ACK duration implausible, expected 0 to %d us'
                               % (m, ACK_MAX_DURATION_US))
        if b['capture_order_violations']:
            reasons.append('%s: %d frames where the hardware captures are out '
                           'of order (CRCOK < TXREADY <= ADDRESS < PHYEND); the '
                           'capture path itself is suspect, so no timing number '
                           'in this run can be trusted'
                           % (m, len(b['capture_order_violations'])))
    if deadline_misses:
        reasons.append('%d missed ACK deadlines' % len(deadline_misses))
    if unintended:
        reasons.append('%d unintended ACKs' % len(unintended))
    if not interleaving['passed']:
        reasons.append('the two contexts were not shown to be live at the same '
                       'time: %d alternations (%d required), both present in '
                       'every window part: %s'
                       % (interleaving['alternations'],
                          interleaving['alternations_required'],
                          interleaving['both_in_every_part']))

    return {
        'per_context': per_ctx,
        'interleaving': interleaving,
        'deadline_misses': deadline_misses,
        'unintended_acks': unintended,
        'reasons': reasons,
        'passed': not reasons,
    }


# The STATS counters are written at TWO stages of one admission pass, and the
# two stages have different denominators. Reading them as one census is wrong,
# and reading them as a census is how a genuine double-count would be missed,
# so the relationship that does hold is written down and checked here.
#
# dual_admit_part is entered once per BCC round. Round one always has PHR plus
# the two FCF bytes, which is all dual_header_size needs, so the stage-1 verdict
# is reached on the first round and is final:
#
#   stage 1   dual_header_size on the FCF alone. An unsupported or malformed
#             frame increments unsupported_reject or malformed_reject and
#             aborts reception. It never reaches rx_total. A frame that passes
#             may return asking for more bytes, incrementing nothing.
#   stage 2   dual_addr_match on the complete header, on the final round only.
#             rx_total is incremented here, and then exactly one of the six
#             classification counters below.
#
# So the classification counters sum to rx_total exactly, while unsupported and
# malformed also carry their stage-1 totals and sit OUTSIDE that sum. Frames
# presented to the radio is rx_total plus the stage-1 aborts, which is why the
# first hardware run reported rx_total=344 against 792 counter increments:
# 0+0+248+0+96 = 344 on the inside, 447+1 aborted at stage 1. Coherent, not
# double-counted. If a future change ever did make two paths write one counter,
# the identity below is what breaks.
STATS_CLASSIFICATION = ('ctx0_rx', 'ctx1_rx', 'broadcast', 'ambiguous',
                        'foreign_reject', 'cross_pair_reject')


def stats_coherent(stats):
    """The counter identity above, as a predicate on a parsed STATS field set.

    Returned rather than raised: the caller decides what an incoherent counter
    set means. Missing counters are reported as missing rather than defaulted,
    because a zero stood in for an absent field would make the identity hold by
    accident, which is the one outcome this must not produce.
    """
    missing = [k for k in ('rx_total',) + STATS_CLASSIFICATION if k not in stats]
    if missing:
        return {'checked': False, 'missing': missing, 'coherent': False}
    total = _int(stats, 'rx_total')
    parts = {k: _int(stats, k) for k in STATS_CLASSIFICATION}
    classified = sum(parts.values())
    return {'checked': True, 'missing': [], 'rx_total': total,
            'classified_sum': classified, 'parts': parts,
            'stage1_aborts_outside_the_sum': {
                k: _int(stats, k) for k in ('unsupported', 'malformed_reject')
                if k in stats},
            'coherent': classified == total}


def config_generations(records):
    """The config_generation values stamped on the RX records of ONE phase.

    Scoped deliberately. The allowlist is published once per context and must
    not change afterwards, because a changing generation would mean the radio
    was reconfigured mid-measurement and the samples are not comparable. But
    that invariant belongs to the MEASUREMENT window alone: phase 1 runs before
    any config is published and its records legitimately carry generation 0,
    while phase 2 runs after both BINDs and carries generation 2. A session-wide
    collection therefore always holds {0, 2} and always fails -- which is what
    the first hardware run of this gate reported, with the hardware healthy and
    both tuples bound. Deriving the set here, from the phase-2 slice that is
    also the evidence, means the caller cannot hand the check the wrong window.
    """
    return [f['config_generation'] for f in _rx(records)
            if f.get('config_generation') is not None]


def evaluate(records, stats=None):
    """The whole of Gate A: the passive survey, with the counters checked.

    Gate A no longer carries a second phase. Measuring the immediate ACK needs
    frames addressed to us, those arrive only in response to a poll, and the
    firmware will not poll outside R_ACTIVE -- which is reached through the full
    rejoin sequence, the content of Gate B. The ACK measurement therefore moved
    to Gate B, where that traffic has to be generated anyway and no network is
    commissioned twice. `dual_tuple_ack` below is that measurement, kept here
    because it is the same evaluator and Gate B imports it.

    The config_generation check goes with it. Nothing is published during Gate
    A, so every record carries generation 0 and there is no window in which it
    could change.
    """
    a = survey(records)
    reasons = list(a['reasons'])
    coherence = stats_coherent(stats) if stats is not None else None
    if coherence is not None and not coherence['coherent']:
        reasons.append('the STATS counters do not add up, so no number in this '
                       'run can be read: %r' % coherence)
    # What Gate A must establish is that IT published nothing -- not that
    # nothing was ever published on this dongle.
    #
    # The distinction is not academic. A dongle keeps its published allowlist
    # for the life of a boot: END shuts the ACK gate but leaves the config in
    # place. So a Gate A run that follows an earlier run on the same boot finds
    # config_generation already at 2, with immediate_ack at 0. Demanding a zero
    # here failed exactly that run -- a healthy, genuinely passive measurement
    # -- and the only way to satisfy it would have been to make someone unplug
    # the dongle before every attempt, which is the manual step this gate was
    # reshaped to avoid.
    #
    # The real invariant is that the generation does not MOVE while the gate is
    # listening. A published allowlist does not make the survey wrong: it is
    # scoped by PAN, not by `match`, so what each frame classifies as does not
    # enter the measurement at all. What would make it wrong is the radio being
    # reconfigured mid-window, and that is what this catches. Passivity itself
    # is established separately and more directly, by the runner: immediate_ack
    # must read 0 at both ends and ctx*_tx_accepted must be 0.
    generations = config_generations(records)
    if len(set(generations)) > 1:
        reasons.append('the allowlist changed while the gate was listening, so '
                       'the radio was reconfigured mid-measurement: '
                       'config_generation %s' % sorted(set(generations)))
    return {
        'gate': 'A',
        'survey': a,
        'stats_coherence': coherence,
        'config_generations': sorted(set(generations)),
        'reasons': reasons,
        'passed': not reasons,
    }
