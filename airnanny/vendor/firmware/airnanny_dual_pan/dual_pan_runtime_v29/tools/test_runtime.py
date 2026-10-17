"""Offline Windows native tests of the real V29 predicates and V28 lifecycle."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT.parent/'dual_pan_runtime_v28'


def main():
    zig=ROOT.parents[3]/'toolchains/zig-windows-x86_64-0.13.0/zig.exe'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(ROOT/'.local/zig-global'),
             ZIG_LOCAL_CACHE_DIR=str(ROOT/'.local/zig-local'))
    sources=['src/'+s for s in ('assoc.c','assoc_protocol.c','key_gate.c','permit_binding.c',
              'rejoin_transport.c','assoc_filter.c','dual_identity.c','dual_context.c',
              'dual_admit.c','dual_sched.c','dual_records.c')]
    report=dict(status='OFFLINE_NATIVE_PASS',hardware_performed=False,tests=[])
    for test in ('test_application_repeat','test_mac_retry','test_id_handoff'):
        output=ROOT/'build'/f'{test}.exe'
        cmd=[str(zig),'cc','-std=c11','-DASSOC_HOST_TEST','-Itests','-Iinclude','-Iradio_driver',
             'tests/'+test+'.c']+sources+['-o',str(output)]
        subprocess.run(cmd,cwd=ROOT,env=env,check=True,capture_output=True)
        result=subprocess.run([str(output)],cwd=ROOT,text=True,capture_output=True,check=True)
        summary=result.stdout.strip().splitlines()[-1]
        report['tests'].append(dict(name=test,summary=summary,binary_sha256=hashlib.sha256(output.read_bytes()).hexdigest()))
        print(summary)
    # Constrain the firmware delta, including driver and ACK paths, exactly.
    expected={'src/main.c','src/rejoin_transport.c','src/tx_lifecycle.inc'}
    changed=[]
    for directory in ('src','include','radio_driver'):
        for file in (BASE/directory).rglob('*'):
            if file.is_file():
                relative=file.relative_to(BASE)
                if file.read_bytes()!=(ROOT/relative).read_bytes():
                    changed.append(relative.as_posix())
    assert set(changed)==expected,changed
    for name in ('src/main.c','src/tx_lifecycle.inc'):
        original=(BASE/name).read_text()
        want=original.replace('airnanny_dual_pan_runtime_v28','airnanny_dual_pan_runtime_v29').replace('version=28','version=29').replace('typed_fan_once','typed_type07_repeat')
        assert (ROOT/name).read_text()==want,name
    original=(BASE/'src/rejoin_transport.c').read_text()
    want=original.replace('q->phase!=R_ACTIVE||q->application_once||','q->phase!=R_ACTIVE||').replace('Host authenticates baseline and checks FAN-only plaintext before handoff.','Host authenticates baseline and retains the frozen SAFE setter semantics.')
    assert (ROOT/'src/rejoin_transport.c').read_text()==want
    report['firmware_delta']=changed
    report['unchanged_driver_and_ack_paths']=True
    (ROOT/'evidence/application_repeat_offline.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()
