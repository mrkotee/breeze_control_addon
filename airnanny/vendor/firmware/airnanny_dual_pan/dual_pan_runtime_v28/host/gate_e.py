"""Gate E evaluator: a host restart, and both durable contexts come back.

Pure: what phase A left, what phase B found and what phase B did, in; a
verdict out.

The plan's row E: "Host restart: both durable contexts load. FC high-water
and replay state preserved, RAW identity not regenerated, security epoch not
silently re-initialised, both contexts back in an observable state." Each
clause is one check.

How a restart looks on this firmware decides the shape. Closing the port
stops both contexts (main.c PORT_CLOSE -> stop_all_loss), and a context binds
once per dongle boot. So a restarted host does not resume a radio session;
it comes back through a new boot and a rejoin from the durable stores. Phase
A ends by dying -- no END, no clean close -- so what is tested is a crash, not
a polite exit; phase B is a new process that must find exactly what A left
and continue from it.
"""
import gate_b

IDENTITY_FIELDS = ('raw_ieee', 'tc_ieee', 'pan', 'short', 'attempt', 'ctx')
EPOCH_FIELDS = ('key_epoch_id', 'keyseq', 'secret_ref')
MIN_ACKED_POLLS = 3


def identity(record):
    """The fields a restart must never regenerate, from one epoch.json."""
    c = record.get('context') or {}
    out = {k: c.get(k) for k in IDENTITY_FIELDS}
    out.update({k: record.get(k) for k in EPOCH_FIELDS})
    return out


def found_what_a_left(a_after, b_before):
    """Phase B, before any frame, sees exactly phase A's last durable state.
    Nothing ran between them, so anything but equality is a store that moved
    on its own, or a restart that rewrote something."""
    out = []
    for c in ('0', '1'):
        if a_after['snapshot'][c] != b_before['snapshot'][c]:
            out.append('ctx%s: the store phase B loaded is not the one phase A left: %r -> %r'
                       % (c, a_after['snapshot'][c], b_before['snapshot'][c]))
    return out


def identity_kept(a_after, b_before, b_after):
    out = []
    for c in ('0', '1'):
        a, b0, b1 = (x['identity'][c] for x in (a_after, b_before, b_after))
        for label, fields in (('RAW identity', IDENTITY_FIELDS), ('security epoch', EPOCH_FIELDS)):
            for f in fields:
                if not (a[f] == b0[f] == b1[f]):
                    out.append('ctx%s: %s field %s changed across the restart: %r -> %r -> %r'
                               % (c, label, f, a[f], b0[f], b1[f]))
    return out


def counters_continue(a_after, b_after):
    """No frame counter of phase B may be below phase A's high-water mark, and
    the allocator itself only rises."""
    out = []
    for c in ('0', '1'):
        hw = a_after['snapshot'][c]['next_fc']
        fcs = sorted(b_after['intent_fcs'][c])
        if not fcs:
            out.append('ctx%s: phase B sent no secured frame, so FC continuity is unshown' % c)
        elif fcs[0] < hw:
            out.append('ctx%s: phase B reused frame counter %d below phase A\'s high-water %d'
                       % (c, fcs[0], hw))
        if b_after['snapshot'][c]['next_fc'] <= hw:
            out.append('ctx%s: next_fc did not advance past phase A (%d -> %d)'
                       % (c, hw, b_after['snapshot'][c]['next_fc']))
    return out


def replay_kept(a_after, b_after):
    out = []
    for c in ('0', '1'):
        before = a_after['snapshot'][c]['nwk_source_floors']
        after = b_after['snapshot'][c]['nwk_source_floors']
        for src, floor in before.items():
            if after.get(src, 0) < floor:
                out.append('ctx%s: replay floor for %s fell across the restart: %d -> %r'
                           % (c, src, floor, after.get(src)))
    return out


def came_back(b_records, b_final_status, a_reached):
    out = []
    polls = gate_b.acked_polls(b_records)
    for c in ('0', '1'):
        if not a_reached.get(c):
            out.append('ctx%s: phase A never reached PARENT_LINK_ACTIVE, so there was '
                       'nothing to come back to' % c)
        st = (b_final_status or {}).get(c) or {}
        if st.get(gate_b.RECOVERY_FIELD) != 'PARENT_LINK_ACTIVE':
            out.append('ctx%s: after the restart it is %r, not PARENT_LINK_ACTIVE'
                       % (c, st.get(gate_b.RECOVERY_FIELD)))
        if len(polls['ctx' + c]) < MIN_ACKED_POLLS:
            out.append('ctx%s: %d ACKed polls after the restart, %d required'
                       % (c, len(polls['ctx' + c]), MIN_ACKED_POLLS))
    return out


def a_died(phase_a):
    """Phase A must have ended without END: that is what makes it a crash."""
    if phase_a.get('ended_cleanly'):
        return ['phase A sent END; the gate needs a host that dies, not one that exits']
    return []


def evaluate(phase_a, b_before, b_after, b_records, b_final_status):
    a_after = phase_a['after']
    a_reached = phase_a.get('reached_active') or {}
    reasons = (a_died(phase_a) + found_what_a_left(a_after, b_before)
               + identity_kept(a_after, b_before, b_after)
               + counters_continue(a_after, b_after) + replay_kept(a_after, b_after)
               + came_back(b_records, b_final_status, a_reached))
    return {'gate': 'E',
            'phase_a_high_water': {c: a_after['snapshot'][c]['next_fc'] for c in ('0', '1')},
            'phase_b_first_fc': {c: (min(b_after['intent_fcs'][c]) if b_after['intent_fcs'][c] else None)
                                 for c in ('0', '1')},
            'reasons': reasons, 'passed': not reasons}
