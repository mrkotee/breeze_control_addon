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

# How much of the conversation to show when it stopped making sense. Bounded
# because this goes to a log on an appliance, and shown at all because the
# reviewed reader refuses an unparsable line without recording it.
LAST_LINES = 4
SERIAL_TAIL_WIDTH = 96
SERIAL_TAIL_ROWS = 3

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

# Host commands that ask the dongle something and change nothing: no frame
# leaves the radio and no durable state moves. Named positively and kept
# short on purpose -- an unknown verb has to mean "cannot say", because the
# firmware's vocabulary is its own and a new command would otherwise be
# assumed harmless the day it is added.
INERT_COMMANDS = frozenset(('INFO', 'STATUS', 'STATS'))

# Host commands the firmware answers out of its own recovery state machine
# and nothing else: each one is a state transition inside the dongle, no
# frame leaves the radio for it and no counter is reserved. Named positively
# for the same reason as the set above -- a command this does not know has to
# mean "cannot say", never "assumed harmless".
CONTROL_COMMANDS = frozenset(('DISCOVERY_COMMIT', 'CURRENT_SHORT_COMMIT',
                              'PARENT_LINK_ACTIVE'))


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


def token_pair(raw):
    """The ` id=N` of a command line, or '' when it carries none."""
    for token in raw.split():
        if token.startswith('id='):
            return ' ' + token
    return ''


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

    # Which commands the host issued, and whether the trace can be trusted to
    # hold all of them. A bounded deque that filled would have dropped the
    # oldest records, and an absence inside a truncated record proves nothing.
    commands = [r for r in records if r.get('kind') == 'HOST_COMMAND'
                and len(r.get('raw', '').split()) > 1]
    host_commands = sorted({r['raw'].split()[1] for r in commands})
    limit = data.get('record_limit')
    complete = (isinstance(limit, int) and limit > 0
                and isinstance(data.get('record_count'), int)
                and data['record_count'] < limit)
    # A second, older proof of the same thing, for traces written before the
    # count was recorded. Command ids start at one and a command is recorded
    # before anything is read, so the record carrying id=1 is the first entry
    # the wire ever appended. A bounded buffer evicts its oldest first, so
    # that entry still being here means nothing was evicted at all.
    complete = complete or any(' id=1' == token_pair(r['raw']) for r in commands)

    # Which of the host's own commands each firmware error answered. An
    # error carrying no id, or one naming a command this trace does not
    # hold, stays unattributed -- and an unattributed error is evidence for
    # nothing. Only the first command with a given id counts: ids are issued
    # in sequence, and a trace that wrapped could hold two.
    commanded = {}
    for record in commands:
        tokens = record['raw'].split()
        for token in tokens:
            if token.startswith('id='):
                commanded.setdefault(token[3:], tokens[1])
                break
    errors = [{'reason': (r.get('fields') or {}).get('reason'),
               'command': commanded.get((r.get('fields') or {}).get('id'))}
              for r in records if r.get('kind') == 'ERROR']

    status = {}
    for record in records:
        if record.get('kind') != 'STATUS':
            continue
        fields = record.get('fields') or {}
        if fields.get('ctx') is not None:
            status[fields['ctx']] = {k: fields.get(k) for k in
                                     ('state', 'recovery', 'association_state', 'key_state',
                                      'generation', 'rx_drop', 'out_drop', 'quarantine',
                                      'reboot_required',
                                      # A clean transmission loss is either an
                                      # unanswered frame or a channel that never
                                      # looked free. These separate the two, and
                                      # an amplified receiver can make an idle
                                      # channel read as busy.
                                      'cca_attempts', 'cca_busy', 'cca_preair')}

    return {'error': data.get('error'), 'error_type': data.get('error_type'),
            'records': dict(kinds), 'transmissions': transmissions,
            'last_firmware_lines': [r['raw'] for r in records[-LAST_LINES:]
                                    if r.get('raw') and r.get('kind') != 'HOST_COMMAND'],
            'last_host_commands': [r['raw'] for r in commands[-LAST_LINES:]],
            'recent_serial': data.get('recent_serial'),
            # Absent key and null value mean different things: one trace was
            # written before the port was watched, the other watched it and
            # read nothing.
            'port_was_watched': 'recent_serial' in data,
            'host_commands': host_commands,
            'complete_record': complete,
            'accepted_without_completion': unmatched,
            'errors_reported': kinds.get('ERROR', 0), 'errors': errors,
            'application_transmissions': application,
            'unrecognised_purposes': sorted(
                {t['purpose'] for t in transmissions
                 if t['purpose'] not in APPLICATION_CLASSES | RECOVERY_CLASSES}
                - {None}),
            'cleanup': dict(cleanup), 'last_status': status,
            'state_at_failure': {k: v for k, v in (data.get('state') or {}).items()
                                 if not isinstance(v, (list, dict))}}


def nothing_was_attempted(summary):
    """Does this trace show a failure that got nowhere near the radio?

    An empty transmission list means one of two opposite things: nothing was
    ever sent, or the trace cannot show what was. They are told apart by
    whether the record is complete -- a bounded buffer that filled dropped
    its oldest entries first, which is exactly where a transmission would be
    -- and by what the host actually asked the dongle to do.

    A failure that could not read the dongle's first line is the case this
    exists for. Nothing was commanded but a query, no frame was accepted, no
    counter was reserved, and latching it forever teaches an operator only
    that the latch is noise.
    """
    if not summary.get('complete_record'):
        return False
    if summary.get('accepted_without_completion') or summary.get('errors_reported'):
        return False
    commands = summary.get('host_commands')
    if not isinstance(commands, list):
        return False  # a trace written before this was recorded cannot say
    return all(command in INERT_COMMANDS for command in commands)


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
    if summary.get('application_transmissions'):
        return False
    if summary.get('unrecognised_purposes'):
        return False
    if not transmissions:
        return nothing_was_attempted(summary)
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
    return session_lost_nothing(summary)


def session_lost_nothing(summary):
    """The signals the existing classifiers refuse on.

    A dropped receive, a dropped output, a quarantined transfer or a firmware
    asking to reboot all mean the session lost records, and a trace with
    holes in it cannot prove anything about what is missing.
    """
    for fields in (summary.get('last_status') or {}).values():
        for name in ('rx_drop', 'out_drop', 'quarantine', 'reboot_required'):
            value = fields.get(name)
            if value not in (None, '0', 0):
                return False
    return True


def answer_unacknowledged(summary):
    """Does this trace show a cycle that ended on an acknowledgement we lost?

    Secured frames did go out, so spent_nothing says no -- correctly, because
    it asks a different question. Spending a counter is not what a review is
    for: these counters are monotonic, and spending one is how they stay that
    way. A review is for an outcome nobody can determine, and this trace has
    none: every frame reached a terminal result, and what ended the cycle was
    the unit answering while this host's own radio failed to acknowledge it.
    The unit said nothing about us. Our radio did.

    The running service now treats that as a new cycle rather than a latch.
    A box already latched on it from an earlier version cannot benefit from
    that -- the latch is on disk and there is no shell to reach it -- so the
    same proof is read back from the retained trace and the fault becomes one
    an operator may acknowledge. It still takes a person.
    """
    if not (summary.get('error') or '').startswith('parent_answer:MAC_ACK_NOT_CLEAN ctx='):
        return False
    if summary.get('application_transmissions') or summary.get('unrecognised_purposes'):
        return False
    if summary.get('accepted_without_completion') or summary.get('errors_reported'):
        return False
    transmissions = summary.get('transmissions') or []
    if not transmissions:
        return False  # the one thing this error cannot be is nothing attempted
    for transmission in transmissions:
        if (transmission.get('purpose') not in RECOVERY_CLASSES
                or transmission.get('cleanup') != 'safe'
                or transmission.get('result') not in TERMINAL_RESULTS):
            return False
    return session_lost_nothing(summary)


def control_command_refused(summary):
    """Did the firmware end this cycle by refusing a command of this host's?

    Secured frames went out, so spent_nothing says no, and an error record
    was reported, so it would say no on that alone. Both are right about the
    questions they ask and neither is the question here.

    A review exists for an outcome nobody can determine: a frame handed to
    the radio whose fate is unknown. What ended this cycle was not an outcome
    at all. The firmware refused one of the host's own state-transition
    commands -- a command that puts no frame on air -- while every frame that
    did go out reached a terminal result and cleaned up safely, and the
    session dropped nothing. There is nothing in that for a person to
    adjudicate.

    The half-established association it leaves behind is not a finding
    either: it is the ordinary starting condition of every recovery cycle,
    and the next one re-establishes it from a fresh guard with counters that
    only ever move forward.

    Conservative in the same way as the rest of this module. Every error must
    be attributed to one of the commands that transmit nothing, the trace
    must be whole -- a buffer that evicted its oldest records could have
    dropped an error about a transmission -- and an error naming no command
    proves nothing.
    """
    errors = summary.get('errors')
    if not errors or not isinstance(errors, list):
        return False  # a trace written before this was recorded cannot say
    if not summary.get('complete_record'):
        return False
    if summary.get('application_transmissions') or summary.get('unrecognised_purposes'):
        return False
    if summary.get('accepted_without_completion'):
        return False
    if any(error.get('command') not in CONTROL_COMMANDS for error in errors):
        return False
    for transmission in summary.get('transmissions') or []:
        if (transmission.get('purpose') not in RECOVERY_CLASSES
                or transmission.get('cleanup') != 'safe'
                or transmission.get('result') not in TERMINAL_RESULTS):
            return False
    return session_lost_nothing(summary)


def evidence_permits_clearing(state_dir, expected_trace=None):
    """True when this fault's own trace shows a failure a person need not
    adjudicate: one that spent nothing, one that ended on an acknowledgement
    this host lost, or one the firmware ended by refusing a command of this
    host's.

    `expected_trace` is the file the fault recorded. Without it this reads
    whatever trace is newest, which for a latch raised while the service was
    already running belongs to some earlier failure -- and clearing one
    fault on another's evidence is exactly the mistake the gate exists to
    prevent. A fault that recorded no trace name proves nothing.
    """
    trace = latest_trace(state_dir)
    if trace is None:
        return False
    if expected_trace is not None and Path(trace).name != expected_trace:
        return False
    try:
        summary = summarise(trace)
        return (spent_nothing(summary) or answer_unacknowledged(summary)
                or control_command_refused(summary))
    except Exception:
        # A trace that cannot be read cannot prove anything, and a safety
        # gate must not be the thing that crashes the recovery it guards:
        # both call sites run while the operator is already trying to get
        # back from a latch.
        return False


def lines(state_dir, limit=8, expected_trace=None):
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
    # Not every latch writes a trace: one raised while the service was
    # already running leaves the newest file belonging to some earlier
    # failure. Summarising it silently invites a reader to treat the two as
    # one event, which is how the wrong thing gets fixed.
    if expected_trace and Path(trace).name != expected_trace:
        out.append('  NOTE: this is not the trace this fault recorded (%s);' % expected_trace)
        out.append('  it is the newest one on the box, from an earlier failure.')

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
        # Which command each one answered is the difference between a refused
        # state transition and an unknown transmission, and that difference
        # is the whole review.
        for error in summary.get('errors') or []:
            out.append('    refused %s: %s' % (error.get('command') or 'an unattributed command',
                                               error.get('reason') or 'no reason given'))
    if summary['unrecognised_purposes']:
        # Neither claimed nor dismissed: the firmware's vocabulary is its own,
        # and a class this does not know is a reason to look, not to assume.
        out.append('  transmissions of an unrecognised purpose: %s'
                   % ', '.join(summary['unrecognised_purposes']))

    if summary['cleanup']:
        out.append('  cleanup: %s' % ', '.join('%s=%d' % kv for kv in sorted(summary['cleanup'].items())))

    # A wire-level failure is about bytes, not transmissions: what the
    # firmware last said, and what arrived that could not be read at all.
    if summary.get('last_host_commands'):
        out.append('  last commands this host sent (newest last):')
        for raw in summary['last_host_commands']:
            out.append('    ' + raw[:SERIAL_TAIL_WIDTH * 2])
    if summary.get('last_firmware_lines'):
        out.append('  last lines the firmware sent (newest last):')
        for raw in summary['last_firmware_lines']:
            out.append('    ' + raw[:SERIAL_TAIL_WIDTH * 2])
    elif summary.get('last_host_commands'):
        out.append('  the firmware sent nothing this host could read')
    tail = summary.get('recent_serial')
    if tail:
        out.append('  last bytes read from the dongle:')
        rows = [tail[i:i + SERIAL_TAIL_WIDTH] for i in range(0, len(tail), SERIAL_TAIL_WIDTH)]
        for row in rows[-SERIAL_TAIL_ROWS:]:
            out.append('    ' + row)
    elif not summary.get('last_firmware_lines'):
        out.append('  nothing readable arrived from the dongle at all'
                   if summary.get('port_was_watched') else
                   '  what did arrive was not kept: this trace predates the port watcher')

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

    if control_command_refused(summary):
        out.append('  what ended this cycle was the firmware refusing a command of this')
        out.append("  host's, which puts no frame on air. Every frame that did go out")
        out.append('  reached a terminal result and cleaned up safely.')
    if spent_nothing(summary):
        if summary.get('transmissions'):
            out.append('  every transmission here was a plaintext beacon that cleaned up')
            out.append('  safely: this failure spent no counter and moved no secured state')
        else:
            # Saying "every transmission" of none reads as a claim about
            # transmissions that were never made.
            out.append('  nothing was transmitted at all: this failure stopped before')
            out.append('  the radio, so it spent no counter and moved no secured state')
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
