"""Gate D launcher: Gate B's chain, then a 60-minute soak, both contexts live.

THIS GATE TRANSMITS: the rejoin chain on both contexts, then one keepalive
poll per context per period for an hour. No application command is sent.

    python launch_gate_d.py --prepare --operator-health "<operator's words>"
    python launch_gate_d.py --prepare --supersede "<why>" --operator-health "<...>"
    python launch_gate_d.py --run <run-id> [--period 60]

The dongle must be FRESHLY plugged in right before --run: the soak has to
fit under the firmware's 32-bit timer wrap (71.58 min) and its 3900 s
session limit, both counted from boot and BIND.

Starts only after Gate C passed AND the operator stated, after it, that
both pairs work (evidence/gate_c_v1.json, operator_health_after).
"""
import argparse
import json
import sys
import uuid
from pathlib import Path

if sys.version_info < (3, 10):
    sys.exit('launch_gate_d needs Python >= 3.10, like launch_gate_c; this is %s. '
             'Use C:\\Python\\Python310.' % sys.version.split()[0])

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'host'))

import management                                   # noqa: F401  this tree's, first
import launch_gate_b as B
from launch_gate_b import authority, ledgers, immutable, serial_modules, \
    utc, BAUD, PORT_TIMEOUT_S, _supersede
from gate_d_runner import GateDRunner, DEFAULT_PERIOD_S

GATE = HERE / '.local/gate_d_v1'
GATE_C_EVIDENCE = HERE / 'evidence/gate_c_v1.json'


def gate_c_passed():
    if not GATE_C_EVIDENCE.exists():
        raise authority.AuthorityFault('gate_c_has_no_evidence:%s' % GATE_C_EVIDENCE)
    e = authority.load(GATE_C_EVIDENCE)
    if not e.get('hardware_pass'):
        raise authority.AuthorityFault('gate_c_did_not_pass:%s' % e.get('run'))
    after = e.get('operator_health_after')
    if not isinstance(after, dict) or not after.get('statement'):
        raise authority.AuthorityFault('gate_c_has_no_operator_health_after')
    return {'run': e.get('run'), 'utc': e.get('utc'), 'operator_health_after': after}


def prior_runs():
    runs = set()
    for m in [GATE / 'milestone.json'] + sorted((GATE / 'attempts').glob('*/milestone.json')):
        if m.exists() and authority.load(m).get('run'):
            runs.add(authority.load(m)['run'])
    return runs


def lineage(now, left):
    """As Gate C left the stores, or moved since only by Gate D's own
    attempts, checked by the run id each store's cycle carries and by
    transitions() -- the rule launch_gate_c introduced, one gate on."""
    moved = [c for c in ('0', '1') if now[c] != left[c]]
    if not moved:
        return {'from': 'gate_c_stores_after'}
    violations = authority.transitions(left, now, secured_frames_sent=True)
    if violations:
        raise authority.AuthorityFault('store_moved_since_gate_c:%r' % violations)
    runs, by = prior_runs(), {}
    for c in moved:
        guard = B.dual_store.read(int(c))['guard']
        if guard not in runs:
            raise authority.AuthorityFault(
                'store_moved_since_gate_c_by_unknown_run:ctx%s guard=%s' % (c, guard))
        by['ctx' + c] = guard
    return {'from': 'gate_d_attempts', 'moved_by': by}


def preflight():
    report = {'utc': utc()}
    report['software'] = authority.software()
    changed = authority.protected_unchanged(exclude_live_stores=True)
    if changed:
        raise authority.AuthorityFault('protected_files_changed:%d:%r'
                                       % (len(changed), changed[:5]))
    report['gate_c'] = gate_c_passed()
    report['stores_before'] = authority.snapshot()
    left = authority.load(GATE_C_EVIDENCE)['stores_after']
    report['lineage'] = lineage(report['stores_before'], left)
    report['stores_validated'] = sorted(B.dual_store.read_both())
    return report


def prepare(health, reason=None):
    if not health or not health.strip():
        raise authority.AuthorityFault(
            'operator_health_statement_required: both pairs, in the operator\'s words')
    report = preflight()
    report['operator_health'] = {'statement': health.strip(), 'recorded_utc': utc()}
    GATE.mkdir(parents=True, exist_ok=True)
    if reason:
        report['supersedes_attempt'] = _supersede(reason, gate=GATE)
        report['supersede_reason'] = reason
        GATE.mkdir(parents=True, exist_ok=True)
    run = uuid.uuid4().hex
    report['run'] = run
    immutable(GATE / 'milestone.json', report)
    print(json.dumps({'run': run, 'lineage': report['lineage'],
                      'operator_health': report['operator_health']}, indent=2, ensure_ascii=False))
    print('\nprepared. Replug the dongle right before running (the soak must start '
          'from a fresh boot), then:')
    print('    python launch_gate_d.py --run %s' % run)
    return run


def run(run_id, period):
    milestone = authority.load(GATE / 'milestone.json')
    if milestone.get('run') != run_id:
        raise authority.AuthorityFault('run_binding')
    run_dir = GATE / 'runs' / run_id
    fresh = preflight()
    before = fresh['stores_before']
    if before != milestone['stores_before']:
        raise authority.AuthorityFault('a_store_moved_between_prepare_and_run')
    serial, list_ports = serial_modules()
    device = authority.select_device(list(list_ports.comports()))
    import time
    port = serial.Serial(device['port'], BAUD, timeout=PORT_TIMEOUT_S)

    def prompt(text):
        print(text, flush=True)

    try:
        outcome = GateDRunner(port, time.monotonic, ledgers(), guard=run_id,
                              prompt=prompt, period=period).execute()
    finally:
        port.close()
    after = authority.snapshot()
    violations = authority.transitions(before, after, secured_frames_sent=True)
    post_changed = authority.protected_unchanged(exclude_live_stores=True)
    outcome.update({
        'utc': utc(), 'gate': 'D', 'run': run_id, 'device': device,
        'image_sha256': fresh['software']['image_sha256'],
        'gate_c': fresh['gate_c'], 'operator_health': milestone['operator_health'],
        'stores_before': before, 'stores_after': after,
        'store_violations': violations,
        'protected_files_changed_after': post_changed,
        'hardware_pass': bool(outcome.get('passed')) and not violations and not post_changed,
    })
    immutable(run_dir / 'outcome.json', outcome)
    print(json.dumps({k: outcome.get(k) for k in
                      ('passed', 'hardware_pass', 'error', 'stopped', 'leaves', 'polls_sent',
                       'store_violations', 'protected_files_changed_after')},
                     indent=2, ensure_ascii=False))
    for r in (outcome.get('verdict') or {}).get('reasons') or []:
        print('  -', r)
    print('\noutcome: %s' % (run_dir / 'outcome.json'))
    if not outcome['hardware_pass']:
        print('\nGate D did NOT pass. Ask the operator, separately, whether both '
              'pairs work; see HARDWARE_CONTINUATION_POLICY.md.')
    return outcome


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare', action='store_true')
    g.add_argument('--run', metavar='RUN_ID')
    ap.add_argument('--supersede', metavar='REASON')
    ap.add_argument('--operator-health', metavar='STATEMENT')
    ap.add_argument('--period', type=float, default=DEFAULT_PERIOD_S,
                    help='seconds between keepalive polls per context (>= 1.1)')
    args = ap.parse_args()
    if args.prepare:
        prepare(args.operator_health, args.supersede)
        return 0
    if args.period < 1.1:
        raise SystemExit('--period must be >= 1.1 s (the firmware refuses faster polls)')
    outcome = run(args.run, args.period)
    return 0 if outcome['hardware_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
