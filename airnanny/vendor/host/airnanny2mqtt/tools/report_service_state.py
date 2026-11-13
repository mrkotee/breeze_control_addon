"""Print a read-only, secret-free snapshot. Does not start the bridge."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT.parents[1] / 'firmware/airnanny_dual_pan'
sys.path[:0] = [str(ROOT / 'src'), str(FIRMWARE / 'dual_pan_runtime_v28/host')]
sys.dont_write_bytecode = True

import dual_store
from airnanny.radio_service import ServiceLock
from airnanny.service_snapshot import snapshot


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--stores-dir', type=Path,
                        help='add-on store volume, containing ctx0 and ctx1')
    args = parser.parse_args(argv)
    paths = dual_store.STORE_PATHS
    if args.stores_dir is not None:
        milestones = {0: 'hardware_commissioning_v7', 1: 'second_a7_provisioning_v1'}
        paths = {slot: args.stores_dir / ('ctx%d' % slot) /
                 path.relative_to(FIRMWARE / milestones[slot] / '.local')
                 for slot, path in paths.items()}
    # Same lock as the bridge: never read a torn multi-store transition.
    # Opening this lock is the only write; JSON state/stores are read-only.
    with ServiceLock(args.state_dir / 'owner.lock'):
        report = snapshot(args.state_dir / 'state.json', paths,
                          validate_store=lambda slot, path: dual_store.read(slot, path=path))
    print('AIRNANNY DIAGNOSTICS ONLY: bridge and radio not started', flush=True)
    print(json.dumps(report, indent=2, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
