"""Offline FakeRadio dispatcher build; no device or serial entry point."""
import os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def run():
    zig=R.parents[3]/'toolchains/zig-windows-x86_64-0.13.0/zig.exe'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(R/'.local/zig-global'),ZIG_LOCAL_CACHE_DIR=str(R/'.local/zig-local'))
    sources=['assoc.c','assoc_protocol.c','permit_binding.c','key_gate.c','commission.c','commission_protocol.c','assoc_filter.c']
    for name,defines in [('firmware_cli',[]),('historical_cli',['-DCOMMISSION_HISTORICAL_ORACLE'])]:
        cmd=[str(zig),'cc','-std=c11','-DASSOC_HOST_TEST','-Itests','-Iinclude','-I../raw_radio_v7_assoc_poll_cca/radio_driver']+defines+['tests/firmware_cli.c']+['src/'+s for s in sources]+['-o','build/'+name+'.exe']
        subprocess.run(cmd,cwd=R,env=env,check=True)
    subprocess.run([str(zig),'cc','-std=c11','-DASSOC_HOST_TEST','-Itests','-Iinclude','-I../raw_radio_v7_assoc_poll_cca/radio_driver','tests/test_dispatcher.c']+['src/'+s for s in sources]+['-o','build/test_dispatcher.exe'],cwd=R,env=env,check=True)
    subprocess.run([str(zig),'cc','-std=c11','-Itests/ring_mocks','-Itests','-Iinclude','-I../raw_radio_v7_assoc_poll_cca/radio_driver','tests/test_ring.c','src/gate_events.c','src/assoc_filter.c','src/assoc.c','-o','build/test_ring.exe'],cwd=R,env=env,check=True)
if __name__=='__main__':run()
