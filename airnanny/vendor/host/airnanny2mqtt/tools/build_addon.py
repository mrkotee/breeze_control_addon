"""Assemble the add-on's vendor tree from this repository.

The add-on is built by the Supervisor on the target machine, where the build
context is the add-on directory alone. The runtime therefore has to be copied
into that directory, and the copy has to keep the same relative layout: the
frozen firmware host code derives each context's pinned store path from its
own location on disk, so flattening the tree would move the stores.

Only files that git tracks are copied. That is what keeps build artifacts,
durable stores and protected secrets out of a public repository by
construction rather than by a list of exclusions someone has to maintain.

Every copied file is recorded with its SHA-256, and the firmware build
manifests already in the tree are re-checked against the copies, so an
incomplete or stale vendor tree fails here instead of on the Raspberry Pi.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]

# v28 carries the frozen host modules the service imports; v29 is read by the
# inherited preflight; v33 is the firmware actually running. The two milestone
# directories hold the durable stores' pinned parents and key_announce.
VENDOR_PATHS = (
    'host/airnanny2mqtt/src',
    'host/airnanny2mqtt/tools',
    'firmware/airnanny_dual_pan/evidence',
    'firmware/airnanny_dual_pan/dual_pan_runtime_v28',
    'firmware/airnanny_dual_pan/dual_pan_runtime_v29',
    'firmware/airnanny_dual_pan/dual_pan_runtime_v33',
    'firmware/airnanny_dual_pan/hardware_commissioning_v7',
    'firmware/airnanny_dual_pan/second_a7_provisioning_v1',
    # key_announce loads the frozen v5 codec and durability layer from these
    # two by relative path, so they are part of the runtime chain even though
    # nothing imports them by name.
    'firmware/airnanny_dual_pan/identity_commissioning_v1',
    'firmware/airnanny_dual_pan/raw_radio_v4_assoc_permit',
)

IMPORT_CHECK = (
    "import sys; sys.path[:0] = ['src', 'tools']; sys.dont_write_bytecode = True;"
    "from run_radio_daemon import firmware_modules; firmware_modules();"
    "import management, dual_store, dual_ledger, key_announce, gate_a_authority;"
    "from airnanny import addon_keys;"
    "print(dual_store.STORE_PATHS[0]); print(dual_store.STORE_PATHS[1])"
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_names(path, *flags):
    out = subprocess.run(['git', 'ls-files', '-z', *flags, path], cwd=REPO,
                         capture_output=True, check=True)
    return [name for name in out.stdout.decode('utf-8').split('\0') if name]


def tracked(path, include_untracked=False):
    names = git_names(path)
    pending = git_names(path, '--others', '--exclude-standard')
    if pending and not include_untracked:
        raise SystemExit(
            'these files are not committed, so a build from this revision would not\n'
            'reproduce the vendor tree. Commit them, or pass --include-untracked to\n'
            'try a local build:\n  ' + '\n  '.join(sorted(pending)))
    return names + (pending if include_untracked else [])


def copy_tree(vendor, include_untracked=False):
    if vendor.exists():
        shutil.rmtree(vendor)
    manifest, count = {}, 0
    for base in VENDOR_PATHS:
        names = tracked(base, include_untracked)
        if not names:
            raise SystemExit('nothing tracked under %s' % base)
        for name in names:
            source = REPO / name
            if not source.exists():
                raise SystemExit('tracked but missing from the working tree: %s' % name)
            target = vendor / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            manifest[name] = sha256(target)
            count += 1
    return manifest, count


def verify_build_manifests(vendor):
    """Re-check each firmware build manifest against the copies.

    The manifests were written when the images were built, so a source file
    that failed to copy, or copied from a different revision, is caught here
    rather than by a preflight failure on the target machine.
    """
    checked = 0
    for base in VENDOR_PATHS:
        manifest_path = vendor / base / 'evidence/build_manifest.json'
        if not manifest_path.exists():
            continue
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        image_root = vendor / base
        for label, expected in manifest['input_sha256'].items():
            if label.startswith('nrf sdk/'):
                continue
            source = image_root / label
            if not source.exists():
                raise SystemExit('%s: build input missing from vendor tree: %s' % (base, label))
            if sha256(source).upper() != expected.upper():
                raise SystemExit('%s: build input changed after build: %s' % (base, label))
            checked += 1
    if not checked:
        raise SystemExit('no firmware build inputs were verified; the vendor tree looks wrong')
    return checked


def verify_imports(vendor):
    """Load the frozen chain from inside the copy, as the add-on will."""
    result = subprocess.run([sys.executable, '-c', IMPORT_CHECK],
                            cwd=vendor / 'host/airnanny2mqtt',
                            capture_output=True, text=True)
    if result.returncode:
        raise SystemExit('the vendored tree does not import:\n' + result.stderr.strip())
    stores = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    for path in stores:
        if str(vendor) not in path:
            raise SystemExit('a store path escaped the vendor tree: %s' % path)
    return stores


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--include-untracked', action='store_true',
                   help='also copy files git does not track yet; for local builds only')
    p.add_argument('--addon-root', default=str(REPO.parent / 'breeze_control_addon'),
                   help='checkout of the add-on repository')
    args = p.parse_args(argv)

    addon = Path(args.addon_root).resolve()
    if not (addon / 'airnanny/config.yaml').exists():
        raise SystemExit('not an add-on checkout: %s' % addon)

    revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=REPO,
                              capture_output=True, text=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(['git', 'status', '--porcelain'], cwd=REPO,
                                capture_output=True, text=True, check=True).stdout.strip())

    vendor = addon / 'airnanny/vendor'
    manifest, count = copy_tree(vendor, args.include_untracked)
    inputs = verify_build_manifests(vendor)
    stores = verify_imports(vendor)

    record = {'source_revision': revision, 'source_tree_dirty': dirty,
              'files': count, 'build_inputs_verified': inputs,
              'paths': list(VENDOR_PATHS), 'sha256': manifest}
    out = addon / 'airnanny/vendor_manifest.json'
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')

    print('vendored %d files from %s%s' % (count, revision[:12], ' (dirty)' if dirty else ''))
    print('verified %d firmware build inputs' % inputs)
    for path in stores:
        print('store path resolves to %s' % path)
    print('manifest: %s' % out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
