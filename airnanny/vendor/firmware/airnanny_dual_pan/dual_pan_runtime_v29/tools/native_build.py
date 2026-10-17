import os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def main():
    (R/'build').mkdir(exist_ok=True)
    zig=R.parents[3]/'toolchains/zig-windows-x86_64-0.13.0/zig.exe'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(R/'.local/zig-global'),ZIG_LOCAL_CACHE_DIR=str(R/'.local/zig-local'))
    sources=('assoc.c','assoc_protocol.c','key_gate.c','permit_binding.c','rejoin_transport.c',
             'assoc_filter.c','dual_identity.c','dual_context.c','dual_admit.c','dual_sched.c','dual_records.c')
    cmd=[str(zig),'cc','-std=c11','-DASSOC_HOST_TEST','-Itests','-Iinclude','-Iradio_driver','tests/firmware_cli.c']+['src/'+s for s in sources]+['-o','build/firmware_cli.exe']
    subprocess.run(cmd,cwd=R,env=env,check=True)
if __name__=='__main__':main()
