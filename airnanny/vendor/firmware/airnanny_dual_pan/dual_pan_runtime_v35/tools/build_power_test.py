import os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(R/'.local/zig-global'),ZIG_LOCAL_CACHE_DIR=str(R/'.local/zig-local'))
zig=R.parents[3]/'toolchains/zig-windows-x86_64-0.13.0/zig.exe'
# The source list carried the pre-dual-PAN set until V33 and no longer linked;
# it is now the same set native_build.py and test_runtime.py use, so this test
# builds against the real main.c rather than failing before it runs.
sources=('assoc.c','assoc_protocol.c','key_gate.c','permit_binding.c','rejoin_transport.c',
         'assoc_filter.c','dual_identity.c','dual_context.c','dual_admit.c','dual_sched.c','dual_records.c')
(R/'build').mkdir(exist_ok=True)
subprocess.run([str(zig),'cc','-std=c11','-DASSOC_HOST_TEST','-Itests','-Iinclude','-Iradio_driver','tests/power_test.c']+['src/'+s for s in sources]+['-o','build/power_test.exe'],cwd=R,env=env,check=True)
