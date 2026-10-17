"""Gate E launcher: a host restart, and both durable contexts come back.

THIS GATE TRANSMITS: the rejoin chain on both contexts, twice, with ~60 s of
keepalive each time. No application command is sent.

    python launch_gate_e.py --prepare --operator-health "<operator's words>"
    python launch_gate_e.py --run-a <run-id>      # freshly plugged dongle; dies at the end
    (operator replugs the dongle)
    python launch_gate_e.py --run-b <run-id>      # a new process on a new boot

Phase A records what it leaves, then exits with os._exit and no END: the
firmware sees the port vanish the way it would if the host crashed. Phase B
must find exactly that, bring both contexts back from it, and never reuse a
frame counter, regenerate an identity or re-initialise an epoch.

Starts only after Gate D passed on V27 with the operator's statement after it.

On V28 (MAC retries for the rejoin chain, after V27's Gate E attempts 1-5
each lost a context to one chain frame), Gate D's evidence is still V27's,
and the stores continue from V27's Gate E attempts: their guards are
recognised here as this gate's own.
"""
import argparse
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path

if sys.version_info < (3, 10):
    sys.exit('launch_gate_e needs Python >= 3.10 (C:\\Python\\Python310); this is %s'
             % sys.version.split()[0])

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'host'))

import management                                   # noqa: F401  this tree's, first
import launch_gate_b as B
from launch_gate_b import authority, ledgers, immutable, serial_modules, \
    utc, BAUD, PORT_TIMEOUT_S, _supersede
import gate_e
from gate_e_runner import GateERunner, phase_b_guard

GATE = HERE / '.local/gate_e_v1'
PRIOR_TREE = HERE.parent / 'dual_pan_runtime_v27'
PRIOR_GATE = PRIOR_TREE / '.local/gate_e_v1'
GATE_D_EVIDENCE = PRIOR_TREE / 'evidence/gate_d_v1.json'


def gate_d_passed():
    if not GATE_D_EVIDENCE.exists():
        raise authority.AuthorityFault('gate_d_has_no_evidence:%s' % GATE_D_EVIDENCE)
    e = authority.load(GATE_D_EVIDENCE)
    if not e.get('hardware_pass'):
        raise authority.AuthorityFault('gate_d_did_not_pass:%s' % e.get('run'))
    after = e.get('operator_health_after')
    if not isinstance(after, dict) or not after.get('statement'):
        raise authority.AuthorityFault('gate_d_has_no_operator_health_after')
    return {'run': e.get('run'), 'utc': e.get('utc'), 'operator_health_after': after}


def prior_guards():
    """Every guard this gate has used, on V27 and here: each run id, and its
    phase-B guard."""
    out = set()
    milestones = []
    for g in (PRIOR_GATE, GATE):
        milestones += [g / 'milestone.json'] + sorted((g / 'attempts').glob('*/milestone.json'))
    for m in milestones:
        if m.exists() and authority.load(m).get('run'):
            run = authority.load(m)['run']
            out.update({run, phase_b_guard(run)})
    return out


def lineage(now, left):
    moved = [c for c in ('0', '1') if now[c] != left[c]]
    if not moved:
        return {'from': 'gate_d_stores_after'}
    violations = authority.transitions(left, now, secured_frames_sent=True)
    if violations:
        raise authority.AuthorityFault('store_moved_since_gate_d:%r' % violations)
    guards, by = prior_guards(), {}
    for c in moved:
        guard = B.dual_store.read(int(c))['guard']
        if guard not in guards:
            raise authority.AuthorityFault(
                'store_moved_since_gate_d_by_unknown_run:ctx%s guard=%s' % (c, guard))
        by['ctx' + c] = guard
    return {'from': 'gate_e_attempts', 'moved_by': by}


def durable_state():
    """What a restart must preserve, read straight from both stores."""
    snap = authority.snapshot()
    ident, fcs = {}, {}
    for c in ('0', '1'):
        r = authority.load(B.dual_store.STORE_PATHS[int(c)])
        ident[c] = gate_e.identity(r)
        q = r.get('recovery') or {}
        fcs[c] = {'gate': q.get('gate'),
                  'fcs': sorted(i['fc'] for i in (q.get('intents') or {}).values() if 'fc' in i)}
    return {'snapshot': snap, 'identity': ident, 'cycle': fcs}


def preflight():
    report = {'utc': utc()}
    report['software'] = authority.software()
    changed = authority.protected_unchanged(exclude_live_stores=True)
    if changed:
        raise authority.AuthorityFault('protected_files_changed:%d:%r' % (len(changed), changed[:5]))
    report['gate_d'] = gate_d_passed()
    report['stores_before'] = authority.snapshot()
    report['lineage'] = lineage(report['stores_before'],
                                authority.load(GATE_D_EVIDENCE)['stores_after'])
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
    print(json.dumps({'run': run, 'lineage': report['lineage']}, indent=2, ensure_ascii=False))
    print('\nprepared. Replug the dongle, then:\n    python launch_gate_e.py --run-a %s' % run)
    return run


def open_port():
    serial, list_ports = serial_modules()
    device = authority.select_device(list(list_ports.comports()))
    import time
    return serial.Serial(device['port'], BAUD, timeout=PORT_TIMEOUT_S), device, time.monotonic


def run_a(run_id):
    milestone = authority.load(GATE / 'milestone.json')
    if milestone.get('run') != run_id:
        raise authority.AuthorityFault('run_binding')
    run_dir = GATE / 'runs' / run_id
    if (run_dir / 'phase_a.json').exists():
        raise authority.AuthorityFault('phase_a_already_ran')
    fresh = preflight()
    if fresh['stores_before'] != milestone['stores_before']:
        raise authority.AuthorityFault('a_store_moved_between_prepare_and_run')
    port, device, clock = open_port()
    out = GateERunner(port, clock, ledgers(), guard=run_id, prompt=lambda t: print(t, flush=True)) \
        .execute_phase(end=False)
    out.update({'phase': 'A', 'run': run_id, 'utc': utc(), 'device': device,
                'image_sha256': fresh['software']['image_sha256'],
                'before': {'snapshot': fresh['stores_before']}, 'after': durable_state(),
                'operator_health': milestone['operator_health']})
    out['store_violations'] = authority.transitions(fresh['stores_before'],
                                                    out['after']['snapshot'], secured_frames_sent=True)
    immutable(run_dir / 'phase_a.json', out)
    print(json.dumps({k: out.get(k) for k in ('error', 'reached_active', 'polls_sent',
                                              'poll_misses', 'store_violations')},
                     indent=2, ensure_ascii=False))
    print('\nphase A recorded; the host now dies WITHOUT END (a crash, by design).')
    print('Replug the dongle, then:\n    python launch_gate_e.py --run-b %s' % run_id, flush=True)
    os._exit(0 if out['error'] is None else 1)


def run_b(run_id):
    milestone = authority.load(GATE / 'milestone.json')
    if milestone.get('run') != run_id:
        raise authority.AuthorityFault('run_binding')
    run_dir = GATE / 'runs' / run_id
    a = authority.load(run_dir / 'phase_a.json')
    if (run_dir / 'outcome.json').exists():
        raise authority.AuthorityFault('phase_b_already_ran')
    software = authority.software()
    b_before = durable_state()
    # Before any frame: phase B must be standing exactly where A fell.
    if b_before['snapshot'] != a['after']['snapshot']:
        raise authority.AuthorityFault('store_is_not_where_phase_a_left_it')
    port, device, clock = open_port()
    try:
        out = GateERunner(port, clock, ledgers(), guard=phase_b_guard(run_id),
                          prompt=lambda t: print(t, flush=True)).execute_phase(end=True)
    finally:
        port.close()
    b_after = durable_state()
    b_after['intent_fcs'] = {c: (b_after['cycle'][c]['fcs']
                                 if b_after['cycle'][c]['gate'] == phase_b_guard(run_id) else [])
                             for c in ('0', '1')}
    verdict = gate_e.evaluate(a, b_before, b_after, out['records'], out.get('final_status'))
    violations = authority.transitions(b_before['snapshot'], b_after['snapshot'],
                                       secured_frames_sent=True)
    post_changed = authority.protected_unchanged(exclude_live_stores=True)
    out.update({'phase': 'B', 'gate': 'E', 'run': run_id, 'utc': utc(), 'device': device,
                'image_sha256': software['image_sha256'],
                'phase_a_sha256': hashlib.sha256((run_dir / 'phase_a.json').read_bytes()).hexdigest(),
                'before': b_before, 'after': b_after, 'verdict': verdict,
                'operator_health': milestone['operator_health'],
                'store_violations': violations, 'protected_files_changed_after': post_changed,
                'passed': verdict['passed'],
                'hardware_pass': verdict['passed'] and out['error'] is None
                and not violations and not post_changed})
    immutable(run_dir / 'outcome.json', out)
    print(json.dumps({k: out.get(k) for k in ('passed', 'hardware_pass', 'error', 'polls_sent',
                                              'poll_misses', 'store_violations')},
                     indent=2, ensure_ascii=False))
    print('high-water A:', verdict['phase_a_high_water'], 'first FC in B:', verdict['phase_b_first_fc'])
    for r in verdict['reasons']:
        print('  -', r)
    print('\noutcome: %s' % (run_dir / 'outcome.json'))
    return out


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare', action='store_true')
    g.add_argument('--run-a', metavar='RUN_ID')
    g.add_argument('--run-b', metavar='RUN_ID')
    ap.add_argument('--supersede', metavar='REASON')
    ap.add_argument('--operator-health', metavar='STATEMENT')
    args = ap.parse_args()
    if args.prepare:
        prepare(args.operator_health, args.supersede)
        return 0
    if args.run_a:
        run_a(args.run_a)
        return 1                       # not reached: run_a exits the process
    return 0 if run_b(args.run_b)['hardware_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
