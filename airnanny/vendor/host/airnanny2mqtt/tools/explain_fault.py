"""Summarise why the service latched, from the trace it kept.

A latched fault asks for a person's judgement, and the design is right to:
an unknown outcome to a secured exchange means nobody can say whether the
device accepted the frame. But asking for judgement while keeping the
evidence inside a volume the operator cannot reach asks for a guess instead.

The retained traces run to tens of thousands of records. This reduces one to
the handful of facts the decision actually turns on: what failed, whether an
application command was in flight, how each transmission terminated, and
whether cleanup was safe. The full trace stays where it is for anyone who
wants it.

Nothing here decides anything. It reads, summarises, and prints.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys

TRACE_GLOB = 'recovery_failure_*.private.json'
TERMINAL_RESULTS = ('local_tx_ok', 'no_ack', 'invalid_ack', 'cca_fail', 'aborted')

# What a transmission was for is carried by its acceptance record, not by its
# completion: TXDONE's `application_tx` names the session's application-TX
# mode, not this frame's purpose. Reading it as a per-frame flag reports an
# application command in flight during recovery that carried none -- the
# exact opposite of the truth, on the one question a review turns on.
# Named positively. An allowlist of recovery classes would quietly call any
# class it had not heard of an application command, which is the error this
# is here to avoid -- and the vocabulary belongs to the firmware, not here.
APPLICATION_CLASSES = frozenset(('TYPE07_FAN',))
# The only transmission that carries no security. Everything else may have
# moved secured state, whatever its result said, so only a trace made up
# entirely of these can be shown to have spent nothing.
PLAINTEXT_CLASSES = frozenset(('ACTIVE_DISCOVERY_BEACON_REQUEST',))
RECOVERY_CLASSES = frozenset(('MANAGEMENT_POLL', 'ACTIVE_DISCOVERY_BEACON_REQUEST',
                              'REJOIN_REQUEST', 'DEVICE_ANNOUNCE', 'END_DEVICE_TIMEOUT'))


def transmission_key(kind, fields):
    """Identify one transmission across its acceptance and its completion.

    Commanded and automatic transmissions number themselves separately, and
    an automatic one is further distinguished by the poll it belongs to.
    """
    family = 'AUTO' if str(kind).startswith('AUTO') else 'TX'
    # Only the automatic family carries `poll` on both halves. A commanded
    # acceptance does not report it at all while its completion does, so
    # including it for TX gives an acceptance and its own completion
    # different keys -- which reads as every frame accepted and none
    # completed, the alarm this is meant to raise only when it is true.
    if family == 'AUTO':
        return family, fields.get('id'), fields.get('poll')
    return family, fields.get('id'), None


def latest_trace(state_dir):
    traces = sorted(Path(state_dir).glob(TRACE_GLOB), key=os.path.getmtime)
    return traces[-1] if traces else None


def summarise(trace):
    """The facts a review turns on, from one retained trace."""
    data = json.loads(Path(trace).read_text(encoding='utf-8'))
    records = data.get('records') or []
    kinds = Counter(r.get('kind') for r in records)

    # Commanded and automatic transmissions number themselves separately, and
    # an automatic one is only distinguished by which poll it belongs to, so
    # the key carries all three. Keyed by id alone, a later commanded frame
    # silently renames an earlier automatic one -- which can relabel a secured
    # management poll as a plaintext beacon.
    accepted = {}
    for record in records:
        kind = record.get('kind')
        if kind in ('TXACCEPT', 'AUTO_ACCEPT'):
            fields = record.get('fields') or {}
            accepted[transmission_key(kind, fields)] = fields.get('class')

    transmissions, application, cleanup, completed = [], 0, Counter(), set()
    for record in records:
        kind = record.get('kind')
        if kind not in ('TXDONE', 'AUTO_DONE'):
            continue
        fields = record.get('fields') or {}
        key = transmission_key(kind, fields)
        completed.add(key)
        purpose = accepted.get(key)
        is_application = purpose in APPLICATION_CLASSES
        transmissions.append({'ctx': fields.get('ctx'), 'result': fields.get('result'),
                              'cleanup': fields.get('cleanup'), 'purpose': purpose,
                              'application': is_application})
        if is_application:
            application += 1
        if fields.get('cleanup'):
            cleanup[fields['cleanup']] += 1

    # A frame the firmware accepted has already had its counter block
    # reserved. If no completion ever arrived, what the device did with it is
    # exactly the thing nobody can determine -- and it contributes no
    # transmission above, so without this it would be invisible.
    unmatched = sorted(purpose or 'unknown' for key, purpose in accepted.items()
                       if key not in completed)

    status = {}
    for record in records:
        if record.get('kind') != 'STATUS':
            continue
        fields = record.get('fields') or {}
        if fields.get('ctx') is not None:
            status[fields['ctx']] = {k: fields.get(k) for k in
                                     ('state', 'recovery', 'association_state', 'key_state',
                                      'generation', 'rx_drop', 'out_drop', 'quarantine',
                                      'reboot_required')}

    return {'error': data.get('error'), 'error_type': data.get('error_type'),
            'records': dict(kinds), 'transmissions': transmissions,
            'accepted_without_completion': unmatched,
            'errors_reported': kinds.get('ERROR', 0),
            'application_transmissions': application,
            'unrecognised_purposes': sorted(
                {t['purpose'] for t in transmissions
                 if t['purpose'] not in APPLICATION_CLASSES | RECOVERY_CLASSES}
                - {None}),
            'cleanup': dict(cleanup), 'last_status': status,
            'state_at_failure': {k: v for k, v in (data.get('state') or {}).items()
                                 if not isinstance(v, (list, dict))}}


def spent_nothing(summary):
    """Does this trace prove the failed recovery moved no secured state?

    A reason string cannot answer this. `retained_recovery_failed_or_unknown`
    is latched for any chain that ended without a classifiable result,
    including ones where secured frames went out and nobody can say whether
    the device took them. The trace can answer it, for the cases where every
    transmission was a plaintext beacon that cleaned up safely.

    Conservative on purpose: an unrecognised purpose, an unrecognised result,
    a transmission that cannot be attributed at all, or any cleanup other
    than safe all mean no.
    """
    transmissions = summary.get('transmissions') or []
    if not transmissions or summary.get('application_transmissions'):
        return False
    if summary.get('unrecognised_purposes'):
        return False
    # Accepted but never completed: the counter block is gone and the outcome
    # is unknowable. This is the case the latch exists for, so it is checked
    # before anything else that could look reassuring.
    if summary.get('accepted_without_completion'):
        return False
    if summary.get('errors_reported'):
        return False
    for transmission in transmissions:
        if transmission.get('purpose') not in PLAINTEXT_CLASSES:
            return False
        if transmission.get('cleanup') != 'safe':
            return False
        if transmission.get('result') not in TERMINAL_RESULTS:
            return False
    # The same signals the existing classifiers refuse on: a dropped receive,
    # a dropped output, a quarantined transfer or a firmware asking to
    # reboot all mean the session lost records, and a trace with holes in it
    # cannot prove anything about what is missing.
    for fields in (summary.get('last_status') or {}).values():
        for name in ('rx_drop', 'out_drop', 'quarantine', 'reboot_required'):
            value = fields.get(name)
            if value not in (None, '0', 0):
                return False
    return True


def evidence_permits_clearing(state_dir):
    """True when the newest trace shows a failure that spent nothing."""
    trace = latest_trace(state_dir)
    if trace is None:
        return False
    try:
        return spent_nothing(summarise(trace))
    except Exception:
        # A trace that cannot be read cannot prove anything, and a safety
        # gate must not be the thing that crashes the recovery it guards:
        # both call sites run while the operator is already trying to get
        # back from a latch.
        return False


def lines(state_dir, limit=8):
    """Readable summary of the newest trace, bounded for a log."""
    trace = latest_trace(state_dir)
    if trace is None:
        return ['  no retained failure trace to review']
    try:
        summary = summarise(trace)
    except (ValueError, OSError) as error:
        return ['  the retained trace could not be read: %s' % error]

    out = ['  trace: %s' % Path(trace).name,
           '  failed with: %s (%s)' % (summary['error'], summary['error_type'])]

    if summary['application_transmissions']:
        out.append('  AN APPLICATION COMMAND WAS IN FLIGHT: %d transmission(s).'
                   % summary['application_transmissions'])
        out.append('  Whether the device acted on it is unknown. Do not assume either way.')
    else:
        out.append('  no application command was in flight; recovery traffic only')
    if summary.get('accepted_without_completion'):
        out.append('  ACCEPTED WITH NO COMPLETION: %s'
                   % ', '.join(summary['accepted_without_completion']))
        out.append('  Their counter blocks are spent and their outcome is unknowable.')
    if summary.get('errors_reported'):
        out.append('  the firmware reported %d error record(s)' % summary['errors_reported'])
    if summary['unrecognised_purposes']:
        # Neither claimed nor dismissed: the firmware's vocabulary is its own,
        # and a class this does not know is a reason to look, not to assume.
        out.append('  transmissions of an unrecognised purpose: %s'
                   % ', '.join(summary['unrecognised_purposes']))

    if summary['cleanup']:
        out.append('  cleanup: %s' % ', '.join('%s=%d' % kv for kv in sorted(summary['cleanup'].items())))

    terminal = [t for t in summary['transmissions'] if t['result']]
    if terminal:
        out.append('  transmissions (newest last):')
        for t in terminal[-limit:]:
            out.append('    ctx%s %-28s %s%s' % (
                t['ctx'], t['purpose'] or 'unknown purpose', t['result'],
                '' if t['cleanup'] is None else ' cleanup=%s' % t['cleanup']))
        unknown = [t for t in terminal if t['result'] not in TERMINAL_RESULTS]
        if unknown:
            out.append('    %d transmission(s) ended with an unrecognised result' % len(unknown))

    if spent_nothing(summary):
        out.append('  every transmission here was a plaintext beacon that cleaned up')
        out.append('  safely: this failure spent no counter and moved no secured state')
    for ctx, fields in sorted(summary['last_status'].items()):
        out.append('  ctx%s last status: %s' % (ctx, ', '.join(
            '%s=%s' % (k, v) for k, v in fields.items() if v is not None)))
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--state-dir', default=os.environ.get('AIRNANNY_STATE_DIR'),
                   help='service state directory; defaults to AIRNANNY_STATE_DIR')
    p.add_argument('--json', action='store_true')
    args = p.parse_args(argv)
    if not args.state_dir:
        p.error('no state directory given and AIRNANNY_STATE_DIR is not set')

    state_file = Path(args.state_dir) / 'state.json'
    if state_file.exists():
        record = json.loads(state_file.read_text(encoding='utf-8'))
        print('service state: %s' % record.get('state'))
        if record.get('reason'):
            print('latched reason: %s' % record['reason'])
        if record.get('review'):
            print('review: %s' % json.dumps(record['review'], ensure_ascii=False, indent=2))

    trace = latest_trace(args.state_dir)
    if args.json:
        print(json.dumps(summarise(trace) if trace else {}, indent=2, sort_keys=True))
        return 0
    print('\n'.join(lines(args.state_dir, limit=20)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
