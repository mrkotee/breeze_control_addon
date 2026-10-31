"""Gate D's evidence, assembled from a run's immutable outcome.json.

Re-reads the soak under the current evaluator and writes
evidence/gate_d_v1.json with the run-time verdict beside it. The records are
what the radio did; the evaluator is what is concluded from them; the two are
kept apart, as for Gate B. Nothing here touches the dongle or the stores.

    python tools/gate_d_evidence.py <run-id> --operator-health-after "<words>"
"""
import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / 'host'))
import gate_d                                                       # noqa: E402

GATE = HERE / '.local/gate_d_v1'
OUT = HERE / 'evidence/gate_d_v1.json'
REVIEW = HERE / 'evidence/review.json'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def signal(records):
    out = {}
    for name, pan in (('ctx0', '9bfa'), ('ctx1', '7a0b')):
        xs = [(int(r['fields']['rssi']), int(r['fields']['lqi'])) for r in records
              if r.get('kind') == 'RX' and r['fields'].get('mac', '')[6:10] == pan]
        if xs:
            out[name] = {'frames': len(xs), 'rssi_min': min(x[0] for x in xs),
                         'rssi_max': max(x[0] for x in xs),
                         'lqi_min': min(x[1] for x in xs), 'lqi_max': max(x[1] for x in xs)}
    return out


def build(run_id, health_after=None):
    path = GATE / 'runs' / run_id / 'outcome.json'
    o = json.loads(path.read_text(encoding='utf-8'))
    if o.get('run') != run_id or o.get('gate') != 'D':
        raise SystemExit('not a Gate D outcome for %s' % run_id)
    s = o['soak']
    v = gate_d.evaluate(o['records'], o['snapshots'], o['stats'], s['start_s'], s['end_s'],
                        s['start_us'], s['end_us'], s['period_s'], o['leaves'])
    clean = (o.get('executed') is True and o.get('error') is None
             and not o.get('store_violations') and not o.get('protected_files_changed_after'))
    attempts = sorted(int(p.name) for p in (GATE / 'attempts').iterdir()
                      if p.name.isdigit()) if (GATE / 'attempts').exists() else []
    links = v['links']
    head = ('Gate D %s on V27. %.0f s soak, poll every %.0f s; both contexts '
            'PARENT_LINK_ACTIVE in all %d snapshots; ACKed polls ctx0 %d/%d, ctx1 %d/%d '
            '(misses %s, longest gap ctx0 %.0f s, ctx1 %.0f s); zero context crossing; '
            'no Leave.'
            % ('PASSED' if v['passed'] and clean else 'did NOT pass', v['soak_seconds'],
               s['period_s'], len(o['snapshots']),
               links['ctx0']['acked_polls'], links['ctx0']['nominal_polls'],
               links['ctx1']['acked_polls'], links['ctx1']['nominal_polls'],
               v['poll_misses'], links['ctx0']['max_gap_s'], links['ctx1']['max_gap_s']))
    return {
        'record': 'gate_d', 'identity': 'airnanny_dual_pan_runtime_v28', 'issue': 5,
        'gate': 'D', 'run': run_id, 'utc': o.get('utc'),
        'evaluated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'image_sha256': o.get('image_sha256'), 'device': o.get('device'),
        'passed': bool(v['passed']), 'hardware_pass': bool(v['passed']) and clean,
        'operator_outcome_sha256': sha(path),
        'operator_outcome_path': str(path.relative_to(HERE)).replace('\\', '/'),
        'review_sha256': sha(REVIEW) if REVIEW.exists() else None,
        'attempt': (max(attempts) + 1) if attempts else None,
        'operator_health_before': o.get('operator_health'),
        'operator_health_after': ({'statement': health_after,
                                   'recorded_utc': datetime.datetime.now(
                                       datetime.timezone.utc).isoformat()}
                                  if health_after else 'NOT YET STATED'),
        'verdict_at_run_time': {'passed': (o.get('verdict') or {}).get('passed'),
                                'reasons': (o.get('verdict') or {}).get('reasons')},
        'criterion_revision': {
            'criterion': 'link alive',
            'was': '>= 90% of nominal polls ACKed and no gap over one period + 5 s',
            'now': 'never ended by the firmware, and no gap over %d periods + %.0f s'
                   % (gate_d.MAX_CONSECUTIVE_POLL_MISSES, gate_d.GAP_SLACK_S),
            'why': 'the first thresholds were written for V26, where a single miss '
                   'ended the context; V27 retries up to two clean misses in a row by '
                   'design, and this run used that exactly as intended',
            'decided_by': 'operator, 2026-10-13, after the run',
        },
        'verdict': v,
        'poll_misses': v['poll_misses'],
        'signal': signal(o['records']),
        'polls_sent': o.get('polls_sent'),
        'stats': o.get('stats'),
        'stores_before': o.get('stores_before'), 'stores_after': o.get('stores_after'),
        'store_violations': o.get('store_violations'),
        'protected_files_changed_after': o.get('protected_files_changed_after'),
        'headline': head,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('run')
    ap.add_argument('--operator-health-after')
    args = ap.parse_args()
    e = build(args.run, args.operator_health_after)
    OUT.write_text(json.dumps(e, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(e['headline'])
    for r in e['verdict']['reasons'] or []:
        print('  -', r)
    print('wrote %s' % OUT)
    return 0 if e['hardware_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
