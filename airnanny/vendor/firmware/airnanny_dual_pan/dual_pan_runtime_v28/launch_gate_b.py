"""Gate B launcher. One-shot. Runs on the operator's machine, nowhere else.

The only component in this tree that constructs a ContextLedger with
hardware=True, which is to say the only one allowed to move a live store.
That is the whole of option 1 (GATE_B_PROCEDURE.md section 3): the inherited
Ledger keeps refusing unconditionally for the twelve offline suites that call
it, and the right to write is concentrated here, where it can be read in one
file.

Windows in practice, not by preference: the keys are DPAPI-protected with no
plaintext fallback, so they can be unwrapped on the operator's machine and
nowhere else.

Unlike Gate A, this gate MOVES state. It transmits, it spends frame counters
and it advances ctx0's store, so the expectation afterwards is not "nothing
changed" but "nothing changed that may not" -- authority.transitions() with
secured_frames_sent=True, rather than Gate A's stricter rule.

    python launch_gate_b.py --prepare                     # mint the run id
    python launch_gate_b.py --prepare --supersede "why"   # a further attempt
    python launch_gate_b.py --run <run-id>                # the gate, once
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
import dual_ledger
import dual_store
from gate_b_runner import GateBRunner
from launch_gate_a import durable, immutable, supersede as _supersede, \
    serial_modules, utc, BAUD, PORT_TIMEOUT_S

GATE = HERE / '.local/gate_b_v1'
PRIOR_GATE = HERE / '.local/gate_a_v1'


def gate_a_passed():
    """Gate B does not start until Gate A has passed on this hardware.

    Gate A is the RF margin, and it is a stop criterion: if ctx1's coordinator
    cannot be heard from where the dongle sits, commissioning both contexts
    would spend frame counters to discover something a passive listen already
    knew. The check reads Gate A's own outcome rather than a note saying it
    passed.
    """
    milestone = PRIOR_GATE / 'milestone.json'
    if not milestone.exists():
        raise authority.AuthorityFault('gate_a_never_ran:%s' % milestone)
    run = authority.load(milestone).get('run')
    outcome_path = PRIOR_GATE / 'runs' / run / 'outcome.json'
    if not outcome_path.exists():
        raise authority.AuthorityFault('gate_a_has_no_outcome:%s' % outcome_path)
    outcome = authority.load(outcome_path)
    if not outcome.get('hardware_pass'):
        raise authority.AuthorityFault(
            'gate_a_did_not_pass:run=%s reasons=%r' %
            (run, (outcome.get('verdict') or {}).get('reasons')))
    survey = (outcome.get('verdict') or {}).get('survey', {})
    return {'run': run, 'utc': outcome.get('utc'),
            'rf_margin': {m: {k: b.get(k) for k in
                              ('samples', 'rssi_mean', 'lqi_mean')}
                          for m, b in (survey.get('per_context') or {}).items()}}


def preflight():
    """Everything checkable without the radio, cheapest refusal first."""
    report = {'utc': utc()}
    report['software'] = authority.software()
    authority.prior_closed()
    report['prior_gate'] = {'closed': True}
    changed = authority.protected_unchanged(exclude_live_stores=True)
    if changed:
        raise authority.AuthorityFault('protected_files_changed:%d:%r'
                                       % (len(changed), changed[:5]))
    report['protected_files_unchanged'] = len(authority.protected(exclude_live_stores=True))
    report['gate_a'] = gate_a_passed()
    report['stores_before'] = authority.snapshot()
    # Both stores must be readable and valid BEFORE anything is keyed: a store
    # that cannot be read after a frame has gone out is a store whose counter
    # state is now unknown.
    report['stores_validated'] = sorted(dual_store.read_both())
    return report


def prepare(reason=None):
    report = preflight()
    GATE.mkdir(parents=True, exist_ok=True)
    if reason:
        report['supersedes_attempt'] = _supersede(reason, gate=GATE)
        report['supersede_reason'] = reason
        GATE.mkdir(parents=True, exist_ok=True)
    run = uuid.uuid4().hex
    report['run'] = run
    immutable(GATE / 'milestone.json', report)
    print(json.dumps({'run': run, 'gate_a': report['gate_a'],
                      'protected_files_unchanged': report['protected_files_unchanged'],
                      'stores_before': report['stores_before']},
                     indent=2, ensure_ascii=False))
    print('\nprepared. The image is already flashed and unchanged; then:')
    print('    python launch_gate_b.py --run %s' % run)
    return run


def ledgers():
    """Both contexts' writers, with their keys unwrapped here and nowhere else.

    Constructed together: a Gate B that commissioned one context and could not
    key the other would have spent counters on a run that cannot finish, so
    both keys are resolved before the first frame.
    """
    from key_announce import ProtectedSecrets
    out = {}
    for ctx in (0, 1):
        secrets = dual_ledger.secrets_root(ctx)
        if not secrets.is_dir():
            raise authority.AuthorityFault('no_secrets_for_ctx%d:%s' % (ctx, secrets))
        record = authority.load(dual_store.STORE_PATHS[ctx])
        ref = record.get('secret_ref')
        if not ref:
            raise authority.AuthorityFault('no_secret_ref_in_ctx%d_store' % ctx)
        out[ctx] = dual_ledger.ContextLedger(
            ctx, ProtectedSecrets(secrets).get(ref), hardware=True)
    if out[0].root == out[1].root:
        raise authority.AuthorityFault('the two contexts share a store root')
    return out


def run(run_id):
    milestone = authority.load(GATE / 'milestone.json')
    if milestone.get('run') != run_id:
        raise authority.AuthorityFault('run_binding')
    run_dir = GATE / 'runs' / run_id

    # Re-checked here, not only in --prepare: a check made before the thing it
    # guards is not a guard.
    fresh = preflight()
    before = fresh['stores_before']
    if before != milestone['stores_before']:
        raise authority.AuthorityFault('a_store_moved_between_prepare_and_run')

    serial, list_ports = serial_modules()
    device = authority.select_device(list(list_ports.comports()))

    import time
    port = serial.Serial(device['port'], BAUD, timeout=PORT_TIMEOUT_S)
    try:
        outcome = GateBRunner(port, time.monotonic, ledgers(),
                              guard=run_id).execute()
    finally:
        port.close()

    after = authority.snapshot()
    # secured_frames_sent=True: this gate spends counters on purpose, so a
    # risen next_fc is expected rather than a finding. Everything else -- the
    # frozen identity fields, the monotonic fields, the replay floors -- is
    # held to the same rule as always.
    violations = authority.transitions(before, after, secured_frames_sent=True)
    post_changed = authority.protected_unchanged(exclude_live_stores=True)

    outcome.update({
        'utc': utc(), 'gate': 'B', 'run': run_id, 'device': device,
        'image_sha256': fresh['software']['image_sha256'],
        'gate_a': fresh['gate_a'],
        'stores_before': before, 'stores_after': after,
        'store_violations': violations,
        'protected_files_changed_after': post_changed,
        'flashed_by': 'operator, manually, before Gate A; unchanged since',
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
        print('\nGate B did NOT pass. Do not proceed to Gate C. Both pairs '
              'must be confirmed healthy separately; see '
              'HARDWARE_CONTINUATION_POLICY.md.')
    return outcome


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare', action='store_true')
    g.add_argument('--run', metavar='RUN_ID')
    ap.add_argument('--supersede', metavar='REASON',
                    help='with --prepare: archive the finished attempt under '
                         'attempts/<n>/ with this reason and open a new one. '
                         'Nothing is deleted.')
    args = ap.parse_args()
    try:
        if args.prepare:
            prepare(args.supersede)
        else:
            outcome = run(args.run)
            return 0 if outcome['hardware_pass'] else 1
    except authority.AuthorityFault as e:
        print('REFUSED: %s' % e, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
