"""Gate A launcher. One-shot. Runs on the operator's machine, nowhere else.

Thin by design: the authority lives in gate_a_authority.py, the sequence in
host/gate_a_runner.py and the evaluation in host/gate_a.py, all three of which
are tested offline. What is left here is the part that cannot be tested without
the real machine -- opening the serial port, the one-shot bookkeeping, and
writing the outcome -- and it is kept small for exactly that reason.

The operator flashes the dongle manually, before this runs. This script never
flashes, never erases and never performs a security reset. It writes only
inside its own .local directory and never touches either durable store.

    python launch_gate_a.py --prepare          # make the run id, check nothing else
    python launch_gate_a.py --prepare --supersede 'why'   # a second attempt
    python launch_gate_a.py --run <run-id>     # the gate, once
"""
import argparse
import datetime
import json
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'host'))

import gate_a_authority as authority
import dual_store
from gate_a_runner import GateARunner

GATE = HERE / '.local/gate_a_v1'
BAUD = 115200
# The firmware answers within milliseconds; this is only so a dead port cannot
# hang the run forever.
PORT_TIMEOUT_S = 0.05


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def durable(path, value):
    """Write once, then read back. A record that cannot be read back is not a
    record."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n',
                    encoding='utf-8')
    if json.loads(path.read_text(encoding='utf-8')) != value:
        raise authority.AuthorityFault('durable_readback_failed:%s' % path.name)


def immutable(path, value):
    """One-shot. A guard that can be re-run is not a one-shot guard, and a gate
    that was run twice has no single answer."""
    if path.exists():
        raise authority.AuthorityFault('immutable_NO_RERUN:%s' % path.name)
    durable(path, value)


def serial_modules():
    """The operator's Python has pyserial where the inherited gates found it."""
    sys.path.append('C:/Program Files/Python37/Lib/site-packages')
    import serial
    from serial.tools import list_ports
    return serial, list_ports


def preflight():
    """Everything checkable without the radio, in the order that fails
    cheapest first."""
    report = {'utc': utc()}
    report['software'] = authority.software()
    report['prior_gate'] = {'closed': True}
    authority.prior_closed()
    changed = authority.protected_unchanged()
    if changed:
        raise authority.AuthorityFault('protected_files_changed:%d:%r'
                                       % (len(changed), changed[:5]))
    report['protected_files_unchanged'] = len(authority.protected())
    report['stores_before'] = authority.snapshot()
    return report


def supersede(reason, gate=None):
    """Open a new attempt by archiving the finished one, with a reason.

    The one-shot rule stays: a gate cannot be re-run by accident, and a run
    that happened is never overwritten or deleted. But a gate CAN legitimately
    need a second attempt -- the first one here failed on two defects in the
    host evaluator and on a criterion that could not be met passively at all --
    and the honest way to allow that is an explicit, recorded supersede rather
    than an operator removing a file by hand.

    Everything the previous attempt produced moves under attempts/<n>/ intact,
    and the reason is written beside it. Nothing is discarded.
    """
    gate = GATE if gate is None else gate
    if not (gate / 'milestone.json').exists():
        raise authority.AuthorityFault('nothing_to_supersede')
    attempts = gate / 'attempts'
    n = 1 + sum(1 for p in attempts.glob('*') if p.is_dir()) if attempts.exists() else 1
    dest = attempts / str(n)
    dest.mkdir(parents=True)
    moved = []
    for item in sorted(gate.iterdir()):
        if item.name == 'attempts':
            continue
        item.rename(dest / item.name)
        moved.append(item.name)
    durable(dest / 'superseded.json',
            {'utc': utc(), 'attempt': n, 'reason': reason, 'archived': moved})
    print('superseded attempt %d (%s); archived %r' % (n, reason, moved))
    return n


def prepare(reason=None):
    # preflight first, so a refused prepare leaves nothing behind at all.
    report = preflight()
    GATE.mkdir(parents=True, exist_ok=True)
    if reason:
        report['supersedes_attempt'] = supersede(reason)
        report['supersede_reason'] = reason
        GATE.mkdir(parents=True, exist_ok=True)
    run = uuid.uuid4().hex
    report['run'] = run
    immutable(GATE / 'milestone.json', report)
    print(json.dumps({'run': run,
                      'protected_files_unchanged': report['protected_files_unchanged'],
                      'stores_before': report['stores_before']},
                     indent=2, ensure_ascii=False))
    print('\nprepared. Flash the image manually, then:')
    print('    python launch_gate_a.py --run %s' % run)
    return run


def run(run_id):
    milestone = authority.load(GATE / 'milestone.json')
    if milestone.get('run') != run_id:
        raise authority.AuthorityFault('run_binding')
    run_dir = GATE / 'runs' / run_id

    # Re-checked here and not only in --prepare: the operator flashed in
    # between, and a check made before the thing it guards is not a guard.
    fresh = preflight()
    before = fresh['stores_before']
    if before != milestone['stores_before']:
        raise authority.AuthorityFault('a_store_moved_between_prepare_and_run')

    serial, list_ports = serial_modules()
    device = authority.select_device(list(list_ports.comports()))

    import time
    port = serial.Serial(device['port'], BAUD, timeout=PORT_TIMEOUT_S)
    try:
        outcome = GateARunner(port, time.monotonic,
                              stores=dual_store.read_both()).execute()
    finally:
        port.close()

    after = authority.snapshot()
    violations = authority.gate_a_store_expectation(before, after)
    post_changed = authority.protected_unchanged()

    outcome.update({
        'utc': utc(),
        'gate': 'A',
        'run': run_id,
        'device': device,
        'image_sha256': fresh['software']['image_sha256'],
        'stores_before': before,
        'stores_after': after,
        'store_violations': violations,
        'protected_files_changed_after': post_changed,
        'flashed_by': 'operator, manually, before this run',
        'hardware_pass': bool(outcome.get('passed')) and not violations
                         and not post_changed,
    })
    immutable(run_dir / 'outcome.json', outcome)

    print(json.dumps({k: outcome[k] for k in
                      ('passed', 'hardware_pass', 'error', 'store_violations',
                       'protected_files_changed_after')},
                     indent=2, ensure_ascii=False))
    if outcome.get('verdict'):
        print('\nreasons:')
        for r in outcome['verdict']['reasons'] or ['(none)']:
            print('  -', r)
    print('\noutcome: %s' % (run_dir / 'outcome.json'))
    if not outcome['hardware_pass']:
        print('\nGate A did NOT pass. Do not proceed to Gate B. See '
              'GATE_A_PROCEDURE.md section 5.')
    return outcome


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare', action='store_true')
    g.add_argument('--run', metavar='RUN_ID')
    ap.add_argument('--supersede', metavar='REASON',
                    help='with --prepare: archive the finished attempt under '
                         'attempts/<n>/ with this reason and open a new one. '
                         'Nothing is deleted. Required to prepare a second '
                         'attempt at all, so a re-run is always deliberate '
                         'and always carries a stated reason.')
    args = ap.parse_args()
    try:
        if args.prepare:
            prepare(args.supersede)
        else:
            outcome = run(args.run)
            return 0 if outcome['hardware_pass'] else 1
    except (authority.AuthorityFault, dual_store.StoreFault) as e:
        print('REFUSED: %s: %s' % (type(e).__name__, e), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
