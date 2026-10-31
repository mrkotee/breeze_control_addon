"""Offline Windows native tests of the real V29 predicates and V28 lifecycle."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT.parent/'dual_pan_runtime_v30'
PREVIOUS=ROOT.parent/'dual_pan_runtime_v33'


def main():
    zig=ROOT.parents[3]/'toolchains/zig-windows-x86_64-0.13.0/zig.exe'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(ROOT/'.local/zig-global'),
             ZIG_LOCAL_CACHE_DIR=str(ROOT/'.local/zig-local'))
    sources=['src/'+s for s in ('assoc.c','assoc_protocol.c','key_gate.c','permit_binding.c',
              'rejoin_transport.c','assoc_filter.c','dual_identity.c','dual_context.c',
              'dual_admit.c','dual_sched.c','dual_records.c')]
    report=dict(status='OFFLINE_NATIVE_PASS',hardware_performed=False,tests=[])
    for test in ('test_application_repeat','test_mac_retry','test_id_handoff','test_persistent','test_poll_reset','test_radio_loss','test_late_join'):
        output=ROOT/'build'/f'{test}.exe'
        cmd=[str(zig),'cc','-std=c11','-DASSOC_HOST_TEST','-Itests','-Iinclude','-Iradio_driver',
             'tests/'+test+'.c']+sources+['-o',str(output)]
        subprocess.run(cmd,cwd=ROOT,env=env,check=True,capture_output=True)
        result=subprocess.run([str(output)],cwd=ROOT,text=True,capture_output=True,check=True)
        summary=result.stdout.strip().splitlines()[-1]
        report['tests'].append(dict(name=test,summary=summary,binary_sha256=hashlib.sha256(output.read_bytes()).hexdigest()))
        print(summary)
    output=ROOT/'build/test_poll_reset_v30.exe'
    baseline_sources=[str(BASE/p) for p in sources]
    subprocess.run([str(zig),'cc','-std=c11','-DASSOC_HOST_TEST','-DV30_REFERENCE',
                    '-Itests','-Iinclude','-Iradio_driver','tests/test_poll_reset.c']+
                   baseline_sources+['-o',str(output)],cwd=ROOT,env=env,check=True,capture_output=True)
    baseline=subprocess.run([str(output)],cwd=ROOT,text=True,capture_output=True,check=True)
    summary=baseline.stdout.strip().splitlines()[-1]
    print(summary)
    report['v30_bug_reproduced']=dict(summary=summary,binary_sha256=hashlib.sha256(output.read_bytes()).hexdigest())
    # Constrain the firmware delta, including driver and ACK paths, exactly.
    #
    # V34 changes the board, not the protocol: main.c arms the dongle's
    # amplifier and asks the SoC for the drive level that board wants, and the
    # two headers say what the board is. radio_driver/ must not appear here --
    # the amplifier is reached through the driver's existing FEM hooks, and the
    # value of that is that every ACK, CCA and admission path carrying hardware
    # proof from V26 onwards is the same code, byte for byte.
    #
    # Added files are compared too. Until V34 this walked the predecessor only,
    # so a new header was invisible to the check that exists to see new things.
    expected={'src/main.c','include/gate_radio_config.h','include/board_fem.h'}
    changed=[]
    for directory in ('src','include','radio_driver'):
        seen=set()
        for file in (PREVIOUS/directory).rglob('*'):
            if file.is_file():
                relative=file.relative_to(PREVIOUS)
                seen.add(relative)
                current=ROOT/relative
                if not current.exists() or file.read_bytes()!=current.read_bytes():
                    changed.append(relative.as_posix())
        for file in (ROOT/directory).rglob('*'):
            if file.is_file() and file.relative_to(ROOT) not in seen:
                changed.append(file.relative_to(ROOT).as_posix())
    assert set(changed)==expected,changed
    report['firmware_delta']=sorted(changed)
    report['unchanged_radio_driver']=True
    (ROOT/'evidence/persistent_offline.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()
