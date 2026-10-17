"""Gate E's evidence, assembled from a run's immutable phase_a.json and outcome.json.

Re-evaluates the restart under the current evaluator and writes
evidence/gate_e_v1.json with the run-time verdict beside it. Every earlier
attempt, on V27 and on V28, is listed with why it was superseded, because the
reason V28 exists is in that list. Nothing here touches the dongle or the
stores.

    python tools/gate_e_evidence.py <run-id> --operator-health-after "<words>"
"""
import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / 'host'))
import gate_b                                                       # noqa: E402
import gate_e                                                       # noqa: E402

GATE = HERE / '.local/gate_e_v1'
PRIOR_GATE = HERE.parent / 'dual_pan_runtime_v27/.local/gate_e_v1'
OUT = HERE / 'evidence/gate_e_v1.json'
REVIEW = HERE / 'evidence/review.json'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def history():
    """Every attempt before this one: its runtime, its run and why it ended."""
    out = []
    for runtime, gate in (('V27', PRIOR_GATE), ('V28', GATE)):
        attempts = gate / 'attempts'
        dirs = sorted((p for p in attempts.iterdir() if p.name.isdigit()),
                      key=lambda p: int(p.name)) if attempts.exists() else []
        for d in dirs:
            out.append({'runtime': runtime, 'attempt': int(d.name),
                        'run': load(d / 'milestone.json').get('run'),
                        'superseded_because': load(d / 'superseded.json')['reason']})
        if runtime == 'V27' and (gate / 'milestone.json').exists():
            # V27's last attempt was not superseded on V27: the gate moved to V28.
            run = load(gate / 'milestone.json')['run']
            a = load(gate / 'runs' / run / 'phase_a.json')
            out.append({'runtime': 'V27', 'attempt': len(dirs) + 1, 'run': run,
                        'superseded_because': 'phase A: %s; the gate moved to V28 '
                                              '(MAC retries for the rejoin chain)' % a['error']})
    return out


def published_identity(identity):
    """The identity as evidence may publish it. secret_ref names the file that
    holds the context's network key under DPAPI; it is not the key, but it has
    no business in a published record, and GitGuardian flagged it as a
    high-entropy secret in da813dd. Only that it did not change matters, and
    the evaluator checked that on the real values, so its digest is enough."""
    out = {}
    for c, ident in identity.items():
        ident = dict(ident)
        ref = ident.pop('secret_ref', None)
        ident['secret_ref_sha256'] = (hashlib.sha256(ref.encode()).hexdigest().upper()
                                      if ref is not None else None)
        out[c] = ident
    return out


def chain_retries(records):
    return [{'ctx': int(r['fields']['ctx']), 'id': int(r['fields']['id']),
             'mac_retries': int(r['fields']['mac_retries']), 'result': r['fields']['result']}
            for r in records if r.get('kind') == 'TXDONE'
            and r['fields'].get('mac_retries', '0') != '0']


def build(run_id, health_after=None):
    run_dir = GATE / 'runs' / run_id
    a, o = load(run_dir / 'phase_a.json'), load(run_dir / 'outcome.json')
    if o.get('run') != run_id or o.get('gate') != 'E' or a.get('run') != run_id:
        raise SystemExit('not a Gate E run %s' % run_id)
    if o['phase_a_sha256'] != sha(run_dir / 'phase_a.json').lower():
        raise SystemExit('phase_a.json is not the one phase B read')
    v = gate_e.evaluate(a, o['before'], o['after'], o['records'], o.get('final_status'))
    clean = (o.get('error') is None and a.get('error') is None
             and not o.get('store_violations') and not a.get('store_violations')
             and not o.get('protected_files_changed_after'))
    acked = {k: len(x) for k, x in gate_b.acked_polls(o['records']).items()}
    retries = {'phase_a': chain_retries(a['records']), 'phase_b': chain_retries(o['records'])}
    past = history()
    head = ('Gate E %s on V28. Phase A brought both contexts to PARENT_LINK_ACTIVE and '
            'died without END; phase B, on a new boot, found the stores exactly as A '
            'left them and brought both back: first FC ctx0 %s / ctx1 %s against A\'s '
            'high-water %s / %s, identity and epoch unchanged, no replay floor fell, '
            'ACKed polls after the restart ctx0 %d, ctx1 %d. Chain frames that needed a '
            'MAC retry: %d. Attempt %d overall (%d before it: %d on V27, %d on V28).'
            % ('PASSED' if v['passed'] and clean else 'did NOT pass',
               v['phase_b_first_fc']['0'], v['phase_b_first_fc']['1'],
               v['phase_a_high_water']['0'], v['phase_a_high_water']['1'],
               acked.get('ctx0', 0), acked.get('ctx1', 0),
               len(retries['phase_a']) + len(retries['phase_b']), len(past) + 1, len(past),
               sum(1 for x in past if x['runtime'] == 'V27'),
               sum(1 for x in past if x['runtime'] == 'V28')))
    return {
        'record': 'gate_e', 'identity': 'airnanny_dual_pan_runtime_v28', 'issue': 5,
        'gate': 'E', 'run': run_id, 'utc_phase_a': a.get('utc'), 'utc_phase_b': o.get('utc'),
        'evaluated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'image_sha256': o.get('image_sha256'), 'device': o.get('device'),
        'boots': {'phase_a': (a.get('info_before') or {}).get('boot'),
                  'phase_b': (o.get('info_before') or {}).get('boot')},
        'passed': bool(v['passed']), 'hardware_pass': bool(v['passed']) and clean,
        'phase_a_sha256': sha(run_dir / 'phase_a.json'),
        'operator_outcome_sha256': sha(run_dir / 'outcome.json'),
        'operator_outcome_path': str((run_dir / 'outcome.json').relative_to(HERE)).replace('\\', '/'),
        'review_sha256': sha(REVIEW) if REVIEW.exists() else None,
        'operator_health_before': o.get('operator_health'),
        'operator_health_after': ({'statement': health_after,
                                   'recorded_utc': datetime.datetime.now(
                                       datetime.timezone.utc).isoformat()}
                                  if health_after else 'NOT YET STATED'),
        'how_a_restart_is_tested': (
            'Closing the port stops both contexts (main.c PORT_CLOSE) and a context binds '
            'once per dongle boot, so a restarted host cannot resume a radio session. '
            'Phase A ends with os._exit and no END -- a crash -- and phase B is a new '
            'process on a new boot that must continue from exactly what A left.'),
        'verdict_at_run_time': {'passed': (o.get('verdict') or {}).get('passed'),
                                'reasons': (o.get('verdict') or {}).get('reasons')},
        'verdict': v,
        'acked_polls_after_restart': acked,
        'poll_misses': {'phase_a': a.get('poll_misses'), 'phase_b': o.get('poll_misses')},
        'chain_mac_retries': retries,
        'phase_a': {'reached_active': a.get('reached_active'), 'ended_cleanly': a.get('ended_cleanly'),
                    'polls_sent': a.get('polls_sent'), 'store_violations': a.get('store_violations')},
        'identity_after': published_identity(o['after']['identity']),
        'stores_after_phase_a': a['after']['snapshot'],
        'stores_after': o['after']['snapshot'],
        'final_status': {c: (s or {}).get(gate_b.RECOVERY_FIELD)
                         for c, s in (o.get('final_status') or {}).items()},
        'stats': o.get('stats'),
        'store_violations': o.get('store_violations'),
        'protected_files_changed_after': o.get('protected_files_changed_after'),
        'earlier_attempts': past,
        'headline': head,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('run')
    ap.add_argument('--operator-health-after')
    args = ap.parse_args()
    e = build(args.run, args.operator_health_after)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(json.dumps(e, indent=2, ensure_ascii=False) + '\n')
    print(e['headline'])
    for r in e['verdict']['reasons'] or []:
        print('  -', r)
    print('wrote %s' % OUT)
    return 0 if e['hardware_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
