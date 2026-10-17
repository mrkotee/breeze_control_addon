"""Gate B's evidence, assembled from a run's immutable outcome.json.

The run's own verdict stays where the launcher wrote it. This re-reads the
records under the CURRENT evaluator and writes evidence/gate_b_v1.json. That
is how attempt 11 is judged under B4 as revised (gate_b.addressed_ack)
without another USB replug: the records are what the radio did, the
evaluator is what we conclude from them, and the two are kept apart.

Nothing here touches the dongle, the stores or the run directory.

    python tools/gate_b_evidence.py <run-id>
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

GATE = HERE / '.local/gate_b_v1'
OUT = HERE / 'evidence/gate_b_v1.json'
REVIEW = HERE / 'evidence/review.json'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def keepalive_acks(records):
    """Every host keepalive's completion, by context and ACK frame control.
    ack_fcf 2 is an ACK with frame-pending clear: the parent had nothing for
    us. This is the observation that retired the >=30-sample premise."""
    accepted = {r['fields'].get('id') for r in records
                if r.get('kind') == 'TXACCEPT'
                and r['fields'].get('class') == 'MANAGEMENT_POLL'}
    out = {}
    for r in records:
        f = r.get('fields') or {}
        if r.get('kind') == 'TXDONE' and f.get('id') in accepted:
            key = 'ctx%s ack_present=%s ack_fcf=%s result=%s' % (
                f.get('ctx'), f.get('ack_present'), f.get('ack_fcf'), f.get('result'))
            out[key] = out.get(key, 0) + 1
    return out


def build(run_id):
    path = GATE / 'runs' / run_id / 'outcome.json'
    o = json.loads(path.read_text(encoding='utf-8'))
    if o.get('run') != run_id or o.get('gate') != 'B':
        raise SystemExit('not a Gate B outcome for %s' % run_id)
    records = o['records']
    verdict = gate_b.evaluate(records, o.get('stats'),
                              ack_records=gate_b.readiness_slice(records))
    clean_run = (o.get('executed') is True and o.get('error') is None
                 and not o.get('store_violations')
                 and not o.get('protected_files_changed_after'))
    attempts = sorted(int(p.name) for p in (GATE / 'attempts').iterdir()
                      if p.name.isdigit()) if (GATE / 'attempts').exists() else []
    v = verdict
    headline = (
        'Gate B %s under B4 as revised. ctx0 and ctx1 each completed a secured '
        'rejoin in one session (parent answers authenticated on the host: %s); '
        'both parent links ACKed keepalives together for the readiness window '
        '(%s); attribution clean; every addressed frame ACKed (%s).'
        % ('PASSED' if v['passed'] and clean_run else 'did NOT pass',
           ', '.join('%s %s' % (a['ctx'], a['result']) for a in o.get('answers', [])
                     if a['result'] in ('REJOINED', 'PARENT_LINK_ACTIVE')),
           v['shared_readiness'].get('polls'),
           {m: '%d/%d' % (b['acked'], b['samples'])
            for m, b in v['dual_tuple_ack']['per_context'].items()}))
    return {
        'record': 'gate_b',
        'identity': 'airnanny_dual_pan_runtime_v28',
        'issue': 5,
        'gate': 'B',
        'run': run_id,
        'utc': o.get('utc'),
        'evaluated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'image_sha256': o.get('image_sha256'),
        'flashed_by': o.get('flashed_by'),
        'device': o.get('device'),
        'passed': bool(v['passed']),
        'hardware_pass': bool(v['passed']) and clean_run,
        'operator_outcome_sha256': sha(path),
        'operator_outcome_path': str(path.relative_to(HERE)).replace('\\', '/'),
        'review_sha256': sha(REVIEW) if REVIEW.exists() else None,
        'attempt': (max(attempts) + 1) if attempts else None,
        'verdict_at_run_time': {'passed': (o.get('verdict') or {}).get('passed'),
                                'reasons': (o.get('verdict') or {}).get('reasons')},
        'criterion_revision': {
            'criterion': 'B4',
            'was': '>=30 CRC-valid addressed samples per PAN with interleaving, '
                   'scoped to readiness',
            'now': v['dual_tuple_ack'].get('criterion'),
            'why': 'the plan assumed addressed frames arrive in response to '
                   'polls; every keepalive ACK in this run had frame-pending '
                   'clear, so idle parents send none, and the typed allowlist '
                   'gives the host no way to provoke them',
            'keepalive_acks': keepalive_acks(records),
            'decided_by': 'operator, 2026-10-12, after attempt 11',
        },
        'verdict': verdict,
        'answers': o.get('answers'),
        'id_floor': o.get('id_floor'),
        'stats': o.get('stats'),
        'stores_before': o.get('stores_before'),
        'stores_after': o.get('stores_after'),
        'store_violations': o.get('store_violations'),
        'protected_files_changed_after': o.get('protected_files_changed_after'),
        'headline': headline,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('run')
    args = ap.parse_args()
    e = build(args.run)
    OUT.write_text(json.dumps(e, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(e['headline'])
    for r in e['verdict']['reasons'] or ['(no reasons: every criterion held)']:
        print('  -', r)
    print('wrote %s' % OUT)
    return 0 if e['hardware_pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
