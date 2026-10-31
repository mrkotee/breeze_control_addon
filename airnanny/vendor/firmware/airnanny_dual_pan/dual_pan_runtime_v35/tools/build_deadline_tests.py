"""Build actual V18 dispatcher replay and actual gate_events ring tests offline."""
import os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(R/'.local/zig-global'),ZIG_LOCAL_CACHE_DIR=str(R/'.local/zig-local'))
zig=R.parents[3]/'toolchains/zig-windows-x86_64-0.13.0/zig.exe'
subprocess.run([str(zig),'cc','-std=c11','-DASSOC_HOST_TEST','-I'+str(R/'tests'),'-I'+str(R/'include'),'-I'+str(R/'radio_driver'),str(R/'tests/scan_replay.c')]+[str(R/'src'/n) for n in ('assoc.c','key_gate.c','permit_binding.c','rejoin_transport.c','assoc_filter.c')]+['-o',str(R/'build/scan_replay.exe')],env=env,check=True)
subprocess.run([str(zig),'cc','-std=c11','-I'+str(R/'tests/event_mocks'),'-I'+str(R/'include'),str(R/'tests/events_test.c'),'-o',str(R/'build/events_test.exe')],env=env,check=True)
