"""Gate C launcher: Gate B's chain and readiness, then one FAN command per
context, with the operator pressing each network's remote when asked.

THIS GATE TRANSMITS and changes fan speed on both purifiers. The operator
presses the named button on each remote (FAN- by default); the runner then
answers with one step back, so each purifier ends where it started.

    python launch_gate_c.py --prepare --operator-health "<operator's words>"
    python launch_gate_c.py --prepare --supersede "<why>" --operator-health "<...>"
    python launch_gate_c.py --run <run-id>

--operator-health is the operator's own statement that both A7/AirControl
pairs work right now. It is recorded verbatim; it is never inferred.
HARDWARE_CONTINUATION_POLICY.md requires it, and after the 0B7A incident of
2026-10-12/13 it is the precondition for any run that touches ctx1.

Needs Python >= 3.10: the application core (airnanny2mqtt) uses 3.10 syntax.
Everything else here runs on 3.7 as before.
"""
import argparse
import json
import sys
import uuid
from pathlib import Path

if sys.version_info < (3, 10):
    sys.exit('launch_gate_c needs Python >= 3.10 (the airnanny2mqtt control core '
             'does); this is %s. On the operator machine: C:\\Python\\Python310 '
             'with the `cryptography` package.' % sys.version.split()[0])

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'host'))

import management                                   # noqa: F401  this tree's, first
import launch_gate_b as B
from launch_gate_b import authority, ledgers, durable, immutable, serial_modules, \
    utc, BAUD, PORT_TIMEOUT_S, _supersede
from gate_c_runner import GateCRunner

GATE = HERE / '.local/gate_c_v1'
# V27 is V26 with one change (a clean keepalive miss is retried, not terminal),
# so Gate B's evidence is V26's and the stores continue from where V26's last
# run left them: Gate D attempt 1, after which nothing transmitted.
PRIOR_TREE = HERE.parent / 'dual_pan_runtime_v26'
GATE_B_EVIDENCE = PRIOR_TREE / 'evidence/gate_b_v1.json'
LINEAGE_FROM = PRIOR_TREE / '.local/gate_d_v1/runs/14e8a52420314a9881b18e409f67a492/outcome.json'


def gate_b_passed():
    if not GATE_B_EVIDENCE.exists():
        raise authority.AuthorityFault('gate_b_has_no_evidence:%s' % GATE_B_EVIDENCE)
    e = authority.load(GATE_B_EVIDENCE)
    if not e.get('hardware_pass'):
        raise authority.AuthorityFault('gate_b_did_not_pass:%s' % e.get('run'))
    return {'run': e.get('run'), 'utc': e.get('utc')}


def prior_gate_c_runs():
    """Every run id Gate C has ever been prepared with: the current
    milestone and each superseded attempt's archived one."""
    runs = set()
    for m in [GATE / 'milestone.json'] + sorted((GATE / 'attempts').glob('*/milestone.json')):
        if m.exists():
            run = authority.load(m).get('run')
            if run:
                runs.add(run)
    return runs


def lineage(now, left):
    """Where today's stores came from, or a refusal.

    Either exactly as Gate B left them, or moved since then only by Gate C's
    own attempts. That is checkable, not asserted: every store carries the
    guard of the run that last opened its cycle (begin_cycle writes the run id
    there), so each moved store must name a run this gate prepared, and the
    movement itself must obey transitions(). Attempt 1 needed this: a Ctrl-C
    cut it after ctx0 was commissioned and ctx1's cycle opened, and the
    outcome that would have recorded that was never written.
    """
    moved = [c for c in ('0', '1') if now[c] != left[c]]
    if not moved:
        return {'from': 'v26_last_run_stores_after', 'run': LINEAGE_FROM.parent.name}
    violations = authority.transitions(left, now, secured_frames_sent=True)
    if violations:
        raise authority.AuthorityFault('store_moved_since_gate_b:%r' % violations)
    runs = prior_gate_c_runs()
    by = {}
    for c in moved:
        guard = B.dual_store.read(int(c))['guard']
        if guard not in runs:
            raise authority.AuthorityFault(
                'store_moved_since_gate_b_by_unknown_run:ctx%s guard=%s' % (c, guard))
        by['ctx' + c] = guard
    return {'from': 'gate_c_attempts', 'moved_by': by}


def preflight():
    """Gate B's preflight, with the lineage link moved forward one gate.

    Gate B checked that ctx1's store was still the one issue #4 left. Gate B
    itself moved it (secured rejoin, generation 16 -> 17), so that check can
    never hold again and is the wrong one here. The right one is stronger:
    both stores must be exactly what Gate B's evidence says it left behind.
    Anything that moved a store since then has an unexplained history.
    """
    report = {'utc': utc()}
    report['software'] = authority.software()
    changed = authority.protected_unchanged(exclude_live_stores=True)
    if changed:
        raise authority.AuthorityFault('protected_files_changed:%d:%r'
                                       % (len(changed), changed[:5]))
    report['gate_b'] = gate_b_passed()
    report['stores_before'] = authority.snapshot()
    left = authority.load(LINEAGE_FROM)['stores_after']
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
    print(json.dumps({'run': run, 'gate_b': report['gate_b'],
                      'operator_health': report['operator_health'],
                      'stores_before': report['stores_before']}, indent=2, ensure_ascii=False))
    print('\nprepared. Freshly replug the dongle, be at both remotes, then:')
    print('    python launch_gate_c.py --run %s' % run)
    return run


def run(run_id, press):
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
        print('\a' + text, flush=True)

    try:
        outcome = GateCRunner(port, time.monotonic, ledgers(), guard=run_id,
                              prompt=prompt, press=press).execute()
    finally:
        port.close()

    after = authority.snapshot()
    violations = authority.transitions(before, after, secured_frames_sent=True)
    post_changed = authority.protected_unchanged(exclude_live_stores=True)
    outcome.update({
        'utc': utc(), 'gate': 'C', 'run': run_id, 'device': device,
        'image_sha256': fresh['software']['image_sha256'],
        'gate_b': fresh['gate_b'], 'operator_health': milestone['operator_health'],
        'stores_before': before, 'stores_after': after,
        'store_violations': violations,
        'protected_files_changed_after': post_changed,
        'hardware_pass': bool(outcome.get('passed')) and not violations and not post_changed,
    })
    immutable(run_dir / 'outcome.json', outcome)
    print(json.dumps({k: outcome.get(k) for k in
                      ('passed', 'hardware_pass', 'error', 'results', 'store_violations',
                       'protected_files_changed_after')}, indent=2, ensure_ascii=False))
    for name in ('verdict_b', 'verdict'):
        for r in (outcome.get(name) or {}).get('reasons') or []:
            print('  -', name, r)
    print('\noutcome: %s' % (run_dir / 'outcome.json'))
    if not outcome['hardware_pass']:
        print('\nGate C did NOT pass. Ask the operator, separately, whether both '
              'pairs work; see HARDWARE_CONTINUATION_POLICY.md.')
    return outcome


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare', action='store_true')
    g.add_argument('--run', metavar='RUN_ID')
    ap.add_argument('--supersede', metavar='REASON')
    ap.add_argument('--operator-health', metavar='STATEMENT')
    ap.add_argument('--press', default='FAN-',
                    help='the button the operator is asked to press on each remote')
    args = ap.parse_args()
    if args.prepare:
        prepare(args.operator_health, args.supersede)
        return 0
    outcome = run(args.run, args.press)
    return 0 if outcome['hardware_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
