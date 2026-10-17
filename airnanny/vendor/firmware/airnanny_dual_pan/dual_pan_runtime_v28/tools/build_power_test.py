import os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(R/'.local/zig-global'),ZIG_LOCAL_CACHE_DIR=str(R/'.local/zig-local'))
zig=R.parents[3]/'toolchains/zig-windows-x86_64-0.13.0/zig.exe'
subprocess.run([str(zig),'cc','-std=c11','-DASSOC_HOST_TEST','-Itests','-Iinclude','-Iradio_driver','tests/power_test.c']+['src/'+s for s in ('assoc.c','key_gate.c','permit_binding.c','rejoin_transport.c','assoc_filter.c')]+['-o','build/power_test.exe'],cwd=R,env=env,check=True)
