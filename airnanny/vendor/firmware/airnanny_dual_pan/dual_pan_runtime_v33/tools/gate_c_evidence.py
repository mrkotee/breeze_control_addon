"""Gate C's evidence, assembled from a run's outcome.json.

Re-reads the records under the current evaluators (Gate B's for the chain and
readiness, Gate C's for the commands) and writes evidence/gate_c_v1.json.
Nothing here touches the dongle, the stores or the run directory.

    python tools/gate_c_evidence.py <run-id> [--operator-health-after "<words>"]

--operator-health-after is the operator's statement, made after the run,
that both pairs still work (HARDWARE_CONTINUATION_POLICY.md). It is recorded
verbatim and never inferred; without it the evidence says it is missing.
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
import gate_c                                                       # noqa: E402

GATE = HERE / '.local/gate_c_v1'
OUT = HERE / 'evidence/gate_c_v1.json'
REVIEW = HERE / 'evidence/review.json'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def signal(records):
    """RSSI/LQI per network, from every frame carrying that PAN."""
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
    if o.get('run') != run_id or o.get('gate') != 'C':
        raise SystemExit('not a Gate C outcome for %s' % run_id)
    records = o['records']
    results = o.get('results') or {}
    vb = gate_b.evaluate(records, o.get('stats'), ack_records=gate_b.readiness_slice(records))
    vc = gate_c.evaluate(records, results, o.get('stats'))
    clean = (o.get('executed') is True and o.get('error') is None
             and not o.get('store_violations') and not o.get('protected_files_changed_after'))
    passed = bool(vb['passed'] and vc['passed'])
    attempts = sorted(int(p.name) for p in (GATE / 'attempts').iterdir()
                      if p.name.isdigit()) if (GATE / 'attempts').exists() else []
    head = ('Gate C %s. One FAN command per context, each confirmed by a fresh '
            'matching TYPE06 while the other context kept ACKing keepalives: %s.'
            % ('PASSED' if passed and clean else 'did NOT pass',
               ', '.join('ctx%s %s FAN %s->%s' % (c, r.get('application_result'),
                                                  r.get('from_fan'), r.get('requested'))
                         for c, r in sorted(results.items()))))
    return {
        'record': 'gate_c', 'identity': 'airnanny_dual_pan_runtime_v28', 'issue': 5,
        'gate': 'C', 'run': run_id, 'utc': o.get('utc'),
        'evaluated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'image_sha256': o.get('image_sha256'), 'device': o.get('device'),
        'passed': passed, 'hardware_pass': passed and clean,
        'operator_outcome_sha256': sha(path),
        'operator_outcome_path': str(path.relative_to(HERE)).replace('\\', '/'),
        'launcher_write': ('outcome.json was written in full, then the launcher\'s '
                           'readback comparison failed on polls_sent having int keys '
                           '(fixed); the file is the run\'s record'
                           if o.get('polls_sent') and run_id == '9643a4eede7f42559512239369b336ca'
                           else 'normal'),
        'review_sha256': sha(REVIEW) if REVIEW.exists() else None,
        'attempt': (max(attempts) + 1) if attempts else None,
        'operator_health_before': o.get('operator_health'),
        'operator_health_after': ({'statement': health_after,
                                   'recorded_utc': datetime.datetime.now(
                                       datetime.timezone.utc).isoformat()}
                                  if health_after else 'NOT YET STATED'),
        'press': 'FAN- on each remote by the operator; the runner answered +1',
        'results': results,
        'verdict_c': vc, 'verdict_b': vb,
        'signal': signal(records),
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
    for name in ('verdict_b', 'verdict_c'):
        for r in e[name]['reasons'] or []:
            print('  -', name, r)
    print('operator health after:', e['operator_health_after'])
    print('wrote %s' % OUT)
    return 0 if e['hardware_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
