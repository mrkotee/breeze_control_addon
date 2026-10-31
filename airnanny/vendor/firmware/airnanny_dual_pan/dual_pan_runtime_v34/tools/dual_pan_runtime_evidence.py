"""Issue #5's machine-readable result, derived from the five gates' evidence.

Reads each gate's evidence file, checks it records a hardware pass, and writes
../evidence/dual_pan_runtime_v1.json with the figures DUAL_PAN_RUNTIME_RESULT.md
cites and the SHA256 of every file it read, so the summary can be re-derived
rather than trusted. Nothing here touches the dongle or the stores.

    python tools/dual_pan_runtime_evidence.py
"""
import datetime
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parent
OUT = ROOT / 'evidence/dual_pan_runtime_v1.json'

GATES = {
    'A': ('V26', 'dual_pan_runtime_v26/evidence/gate_a_v1.json'),
    'B': ('V26', 'dual_pan_runtime_v26/evidence/gate_b_v1.json'),
    'C_v26': ('V26', 'dual_pan_runtime_v26/evidence/gate_c_v1.json'),
    'C_v27': ('V27', 'dual_pan_runtime_v27/evidence/gate_c_v1.json'),
    'D': ('V27', 'dual_pan_runtime_v27/evidence/gate_d_v1.json'),
    'E': ('V28', 'dual_pan_runtime_v28/evidence/gate_e_v1.json'),
}
IMAGES = {
    'V26': 'dual_pan_runtime_v26/releases/airnanny_dual_pan_runtime_v26.hex',
    'V27': 'dual_pan_runtime_v27/releases/airnanny_dual_pan_runtime_v27.hex',
    'V28': 'dual_pan_runtime_v28/releases/airnanny_dual_pan_runtime_v28.hex',
}
REVIEWS = {v: 'dual_pan_runtime_%s/evidence/review.json' % v.lower() for v in IMAGES}


def sha(rel):
    return hashlib.sha256((ROOT / rel).read_bytes()).hexdigest().upper()


def load(rel):
    return json.loads((ROOT / rel).read_text(encoding='utf-8'))


def health(h):
    return h.get('statement') if isinstance(h, dict) else h


def summary():
    ev = {k: load(p) for k, (_, p) in GATES.items()}
    failed = [k for k, e in ev.items() if not e.get('hardware_pass')]
    if failed:
        raise SystemExit('gate evidence without a hardware pass: %s' % failed)
    for k, (runtime, _) in GATES.items():
        if ev[k].get('image_sha256', '').upper() != sha(IMAGES[runtime]):
            raise SystemExit('gate %s ran on an image that is not the %s release' % (k, runtime))
    a, b, d, e = ev['A'], ev['B'], ev['D'], ev['E']
    ack = b['verdict']['dual_tuple_ack']['per_context']
    gates = {}
    for k, (runtime, p) in GATES.items():
        x = ev[k]
        gates[k] = {'runtime': runtime, 'run': x.get('run'),
                    'utc': x.get('utc') or x.get('utc_phase_b'),
                    'attempt': (len(x['earlier_attempts']) + 1 if 'earlier_attempts' in x
                                else x.get('attempt')),
                    'hardware_pass': True,
                    'evidence': p, 'evidence_sha256': sha(p),
                    'headline': x.get('headline') if isinstance(x.get('headline'), str) else None,
                    'operator_health_after': health(x.get('operator_health_after'))}
    return {
        'record': 'dual_pan_runtime', 'version': 1, 'issue': 5,
        'state': 'DUAL_PAN_RADIO_RUNTIME_PROVEN',
        'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'contexts': {'ctx0': {'pan': '0xFA9B', 'room': 'second bedroom'},
                     'ctx1': {'pan': '0x0B7A', 'room': 'bedroom'}},
        'channel': 21, 'crypto': 'host_only',
        'runtimes': {
            'V26': {'change': 'dual-PAN RAW runtime', 'image': IMAGES['V26'],
                    'image_sha256': sha(IMAGES['V26'])},
            'V27': {'change': 'a clean MAC-poll miss no longer ends the context; '
                              '3 consecutive misses do',
                    'image': IMAGES['V27'], 'image_sha256': sha(IMAGES['V27'])},
            'V28': {'change': 'a REJOIN/ANNOUNCE/TIMEOUT frame whose ACK is lost is resent '
                              'byte-identical up to 3 times (macMaxFrameRetries)',
                    'image': IMAGES['V28'], 'image_sha256': sha(IMAGES['V28']),
                    'current': True},
        },
        'reviews': {v: {'path': p, 'sha256': sha(p), 'passed': load(p).get('passed')}
                    for v, p in REVIEWS.items()},
        'gates': gates,
        'not_repeated_on_v28': ['A', 'B', 'C', 'D'],
        'measurements': {
            'rf_margin_gate_a': a['headline']['rf_margin_section_2_2'],
            'rf_asymmetry_db': a['headline']['asymmetry_db'],
            'immediate_ack_gate_b': {c: {k: ack[c][k] for k in (
                'samples', 'acked', 'turnaround_us', 'to_address_us', 'ack_duration_us')}
                for c in ack},
            'immediate_ack_envelope_us': ack['ctx0']['turnaround_envelope_us'],
            'deadline_misses': b['verdict']['dual_tuple_ack']['deadline_misses'],
            'unintended_acks': b['verdict']['dual_tuple_ack']['unintended_acks'],
            'readiness_gate_b': b['verdict']['shared_readiness']['polls'],
            'fan_commands': {'V26': ev['C_v26']['results'], 'V27': ev['C_v27']['results']},
            'soak_gate_d': {'seconds': d['verdict']['soak_seconds'],
                            'period_s': d['verdict']['period_s'],
                            'links': d['verdict']['links'],
                            'poll_misses': d['verdict']['poll_misses'],
                            'signal': d['signal'],
                            'final_stats': d['verdict']['metrics']['final']},
            'restart_gate_e': {'phase_a_high_water': e['verdict']['phase_a_high_water'],
                               'phase_b_first_fc': e['verdict']['phase_b_first_fc'],
                               'acked_polls_after_restart': e['acked_polls_after_restart'],
                               'chain_mac_retries': e['chain_mac_retries'],
                               'earlier_attempts': e['earlier_attempts']},
        },
        'isolation': {k: {'cross_pair_reject': ev[k].get('stats', {}).get('cross_pair_reject'),
                          'routing_faults': ev[k].get('stats', {}).get('routing_faults'),
                          'routing_error': ev[k].get('stats', {}).get('routing_error')}
                      for k in GATES},
        'stores_final': e['stores_after'],
        'store_violations': {k: ev[k].get('store_violations') for k in GATES},
        'limitations': [
            'ctx1 RF margin: ~15 dB weaker than ctx0; 13-15 % keepalive misses in the soak; '
            '0B7A beacon not heard on every scan (one Gate E attempt saw none in 3 scans)',
            'a context binds once per dongle boot, so a failed bind costs a replug',
            'TYPE07 is single-shot by design',
            'deep scheduler queue unproven: the protocol holds one frame per context',
            'Gates A-D were not repeated on V28',
            'out of scope: MQTT/HA integration, UI, generic TX (issue #6)',
        ],
        'result_document': 'DUAL_PAN_RUNTIME_RESULT.md',
    }


def main():
    s = summary()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(json.dumps(s, indent=2, ensure_ascii=False) + '\n')
    print('%s: gates %s, all hardware_pass' % (s['state'], ', '.join(s['gates'])))
    print('wrote %s' % OUT)
    return 0


if __name__ == '__main__':
    sys.exit(main())
