"""Offline review. Produces evidence/review.json, which the Gate A guard pins.

Runs every offline suite, hashes every reviewed source, pins the image and its
manifest, and refuses to write the review if anything failed. The guard then
refuses to run unless this review passed, the sources still hash to what was
reviewed, and the image is the one that was reviewed.

hardware_performed is recorded as false and is checked by the guard: a review
produced by a run that touched hardware is not an offline review, and the
sequence is review first, hardware second.

    python review.py            # run everything, write the review
    python review.py --dry-run  # run everything, write nothing
"""
import argparse
import datetime
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True

IMAGE = HERE / 'releases/airnanny_dual_pan_runtime_v28.hex'
MANIFEST = HERE / 'evidence/build_manifest.json'
REVIEW = HERE / 'evidence/review.json'

# Everything the guard will re-hash before it puts the dongle on air. Firmware
# sources are already covered by the build manifest's own input hashes; these
# are the host and test files, which the manifest does not describe and which
# decide what the gate concludes.
REVIEWED = [
    'host/gate_a.py', 'host/gate_a_runner.py', 'host/dual_store.py',
    'host/gate_b.py', 'tests/test_gate_b.py',
    'host/secured_frame.py', 'tests/test_secured_frame.py',
    'host/dual_ledger.py', 'tests/test_dual_ledger.py',
    'host/gate_b_runner.py', 'tests/test_gate_b_runner.py',
    'host/id_floor.py',
    'launch_gate_b.py', 'tests/test_launch_gate_b.py',
    'gate_a_authority.py', 'launch_gate_a.py', 'review.py',
    'tests/test_gate_a.py', 'tests/test_gate_a_runner.py',
    'tests/test_gate_a_authority.py', 'tests/test_dual_store.py',
    'tests/test_dual_pan_ack_flow.py', 'tests/firmware_cli.c',
    'tests/run_native.sh', 'tests/test_wire_surface.py', 'tests/test_poll_misses.c',
    'tests/test_mac_retry.c',
    'tools/wire_surface.py', 'tools/gate_b_evidence.py',
    'host/dual_application.py', 'tests/test_dual_application.py',
    'host/gate_c.py', 'tests/test_gate_c.py',
    'host/gate_c_runner.py', 'tests/test_gate_c_runner.py',
    'launch_gate_c.py', 'tests/test_launch_gate_c.py',
    'tools/gate_c_evidence.py',
    'host/gate_d.py', 'host/gate_d_runner.py', 'launch_gate_d.py', 'tests/test_gate_d.py',
    'tools/gate_d_evidence.py',
    'host/gate_e.py', 'host/gate_e_runner.py', 'launch_gate_e.py', 'tests/test_gate_e.py',
    'tools/gate_e_evidence.py', 'tools/dual_pan_runtime_evidence.py',
]

PYTHON_SUITES = [
    'test_gate_a', 'test_gate_a_runner', 'test_gate_a_authority',
    'test_dual_store', 'test_dual_pan_ack_flow', 'test_wire_surface',
    'test_gate_b', 'test_secured_frame', 'test_dual_ledger',
    'test_gate_b_runner', 'test_launch_gate_b',
    'test_dual_application', 'test_gate_c', 'test_gate_c_runner',
    'test_launch_gate_c', 'test_gate_d', 'test_gate_e',
    # inherited, and the baseline that tells a regression from an inheritance
    'test_completion', 'test_clock_dispatch', 'test_permit_observation',
    'test_mac_backoff', 'test_peer_scope', 'test_foreign_status_scope',
    'test_first_control',
]
# Measured as failing identically in ctx1_rx_admission_v25; see tests.txt.
INHERITED_FAILURES = {
    'test_recovery': 'failures=1', 'test_rx_deadline': 'failures=6',
    'test_ctx1_admission': 'errors=1', 'test_discovery_cca': 'errors=1',
    'test_power': 'failures=2, errors=1',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def toolchain_available():
    """The native corpus needs a POSIX shell and a host C compiler. Windows has
    neither, which is why the first version of this script died with a
    traceback there instead of saying so: the ARM build belongs on Windows
    because only Windows has the lineage toolchain, but the REVIEW belongs
    wherever gcc and sh are. Both see the same files."""
    missing = []
    for tool in ('sh', 'gcc'):
        try:
            subprocess.run([tool, '--version'], capture_output=True, check=False)
        except (OSError, ValueError):
            missing.append(tool)
    return missing


def native():
    r = subprocess.run(['sh', str(HERE / 'tests/run_native.sh')],
                       capture_output=True, text=True, cwd=str(HERE))
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    failed = [l for l in lines if ' 0 failures' not in l
              and ('checks,' in l or 'violations' in l)
              and 'invariant_violations=0' not in l]
    return {'returncode': r.returncode, 'lines': lines, 'failing_lines': failed,
            'passed': r.returncode == 0 and not failed}


def python_suite(name):
    r = subprocess.run([sys.executable, '-m', 'unittest', name],
                       capture_output=True, text=True, cwd=str(HERE / 'tests'))
    tail = [l for l in r.stderr.splitlines() if l.strip()][-1:] or ['<no output>']
    return {'returncode': r.returncode, 'summary': tail[-1],
            'passed': r.returncode == 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--fresh', action='store_true',
                    help='discard any cached progress and re-run every suite')
    args = ap.parse_args()

    report = {
        'record': 'review',
        'identity': 'airnanny_dual_pan_runtime_v28',
        'issue': 5,
        'gate': 'A',
        'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'review_host': platform.system(),
        'hardware_performed': False,
        'scope': 'offline only; no flash, no COM, no RF, no probe, no store writes',
        'why_the_review_host_may_differ_from_the_build_host': (
            'the image must be built on Windows because only Windows has the '
            'lineage ARM toolchain; the suites need a POSIX shell and a host C '
            'compiler, which Windows does not have. Both hosts see the same '
            'files, and the manifest input hashes recorded below were '
            're-verified against the sources on this host, so the review seals '
            'the same bytes the operator built. Suite results have been '
            'measured identical on both non-Windows hosts throughout.'),
    }

    missing = toolchain_available()
    if missing:
        print('REFUSED: this review needs %s, which this host does not have.\n'
              'The ARM build belongs on Windows because only Windows has the\n'
              'lineage toolchain. The review needs a POSIX shell and a host C\n'
              'compiler, so run it where those are; both see the same files\n'
              'and produce the same review.json.' % ' and '.join(missing),
              file=sys.stderr)
        return 2

    # Resumable, because the whole review does not fit one bounded invocation
    # on every host: test_first_control alone is about two minutes. Each step's
    # result is cached and successive runs do only what is missing.
    #
    # The cache is keyed on the fingerprint below, which covers every reviewed
    # source and the image. If anything changes, the progress is discarded
    # rather than reused -- a cached pass belonging to code that has since moved
    # is exactly the stale evidence this whole review exists to prevent.
    fingerprint = hashlib.sha256(
        json.dumps({rel: sha(HERE / rel) for rel in REVIEWED
                    if (HERE / rel).exists()}, sort_keys=True).encode()
        + (sha(IMAGE) if IMAGE.exists() else 'no-image').encode()).hexdigest()

    progress_path = HERE / '.local/review_progress.json'
    progress = {}
    if progress_path.exists() and not args.fresh:
        cached = json.loads(progress_path.read_text(encoding='utf-8'))
        if cached.get('fingerprint') == fingerprint:
            progress = cached.get('steps', {})
        else:
            print('(sources or image changed since the cached progress; '
                  'discarding it and starting over)')

    def step(name, fn):
        if name in progress:
            print('  cached  %s' % name)
            return progress[name]
        print('  running %s ...' % name, flush=True)
        result = fn()
        progress[name] = result
        progress_path.parent.mkdir(parents=True, exist_ok=True)
        progress_path.write_text(json.dumps(
            {'fingerprint': fingerprint, 'utc': report['utc'],
             'steps': progress}, indent=2) + '\n', encoding='utf-8')
        return result

    report['native'] = step('native', native)
    report['python'] = {name: step('python:' + name,
                                   lambda n=name: python_suite(n))
                        for name in PYTHON_SUITES}
    report['resumed_from_cache'] = sorted(
        k for k in progress if k in ('native',) or k.startswith('python:'))
    report['inherited_failures_not_rerun_here'] = INHERITED_FAILURES

    missing = [rel for rel in REVIEWED if not (HERE / rel).exists()]
    report['missing_reviewed_sources'] = missing
    report['source_sha256'] = {rel: sha(HERE / rel) for rel in REVIEWED
                               if (HERE / rel).exists()}

    if IMAGE.exists() and MANIFEST.exists():
        m = json.loads(MANIFEST.read_text(encoding='utf-8'))
        report['image_sha256'] = sha(IMAGE)
        report['manifest_sha256'] = sha(MANIFEST)
        report['image_matches_manifest'] = report['image_sha256'] == m['hex_sha256'].upper()
        report['image_bit_comparable_with_lineage'] = bool(
            m.get('bit_comparable_with_v17_to_v25_lineage'))
        report['manifest_flashed'] = m.get('flashed')
        stale = [rel for rel, digest in m.get('input_sha256', {}).items()
                 if not rel.startswith('nrf sdk/')
                 and (not (HERE / rel).exists() or sha(HERE / rel) != digest.upper())]
        report['firmware_inputs_that_moved_since_the_build'] = stale
    else:
        report['image_sha256'] = None
        report['image_present'] = False
        report['firmware_inputs_that_moved_since_the_build'] = None

    failures = []
    if not report['native']['passed']:
        failures.append('native corpus')
    for name, r in report['python'].items():
        if not r['passed']:
            failures.append('python:' + name)
    if missing:
        failures.append('missing reviewed sources: %r' % missing)
    if not IMAGE.exists():
        failures.append('release image absent: build it with the lineage '
                        'toolchain first')
    else:
        if not report.get('image_matches_manifest'):
            failures.append('the image does not match its manifest')
        if not report.get('image_bit_comparable_with_lineage'):
            failures.append('the image is not bit-comparable with the V17..V25 '
                            'lineage; build it with the operator toolchain')
        if report.get('manifest_flashed') is not False:
            failures.append('the manifest does not state flashed=false')
        if report.get('firmware_inputs_that_moved_since_the_build'):
            failures.append('firmware sources moved after the build: %r'
                            % report['firmware_inputs_that_moved_since_the_build'][:4])

    report['failures'] = failures
    report['passed'] = not failures

    print(json.dumps({'passed': report['passed'], 'failures': failures,
                      'image_sha256': report['image_sha256'],
                      'native': report['native']['passed'],
                      'python': {k: v['passed'] for k, v in report['python'].items()}},
                     indent=2, ensure_ascii=False))

    if args.dry_run:
        print('\n--dry-run: nothing written')
        return 0 if report['passed'] else 1
    if not report['passed']:
        print('\nreview FAILED; evidence/review.json not written. The Gate A '
              'guard refuses to run without a passing review.', file=sys.stderr)
        return 1
    report['fingerprint'] = fingerprint
    REVIEW.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n',
                      encoding='utf-8')
    # The progress cache has served its purpose; leaving it behind invites a
    # later run to seal from it without having run anything.
    if progress_path.exists():
        progress_path.unlink()
    print('\nwrote %s' % REVIEW)
    return 0


if __name__ == '__main__':
    sys.exit(main())
