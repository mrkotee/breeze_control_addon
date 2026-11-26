"""Actual V35 C dispatcher: driver refusal stops the active context immediately."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
FW=ROOT.parents[1]/'firmware/airnanny_dual_pan/dual_pan_runtime_v35'


def main():
    exe=FW/'build/firmware_cli.exe'
    assert exe.is_file(),'build the frozen V35 native fixture first'
    commands=[
        'RADIOV10 BIND id=1 boot='+ '1'*32+' ctx=1 session=1 generation=6 short=27733 epoch=9985b15dcb574c59b87dc2fb379f317f attempt=cbef428849da4e87b48867ac616247d1 guard='+ 'a'*32,
        '@ACTIVE',
        'RADIOV10 STATUS id=2 boot='+ '1'*32+' ctx=1 session=1',
        '@DRIVER_FAIL',
        'RADIOV10 MANAGEMENT_POLL id=3 boot='+ '1'*32+' ctx=1 session=1 generation=6 dsn=1',
        'RADIOV10 STATUS id=4 boot='+ '1'*32+' ctx=1 session=1',
    ]
    result=subprocess.run([str(exe)],input='\n'.join(commands)+'\n',text=True,capture_output=True,check=True)
    rows=[]
    for line in result.stdout.splitlines():
        if line.startswith('RADIOV10 '):
            tokens=line.split();rows.append(dict(kind=tokens[1],fields=dict(t.split('=',1) for t in tokens[2:])))
    assert not any(r['kind']=='ERROR' for r in rows),rows
    before=next(r['fields'] for r in rows if r['kind']=='STATUS' and r['fields']['id']=='2')
    done=next(r['fields'] for r in rows if r['kind']=='TXDONE' and r['fields']['id']=='3')
    after=next(r['fields'] for r in rows if r['kind']=='STATUS' and r['fields']['id']=='4')
    assert before['state']=='RECOVERY' and before['recovery']=='PARENT_LINK_ACTIVE',before
    assert done['result']=='error' and done['cleanup']=='safe' and done['rf_start_us']=='0',done
    assert after['state']=='STOPPED' and after['recovery']=='STOPPED',after
    report=dict(status='V35_POLL_DRIVER_REFUSAL_REPRODUCED',hardware_used=False,
        before={k:before[k] for k in ('state','recovery')},
        terminal={k:done[k] for k in ('result','cleanup','rf_start_us')},
        after={k:after[k] for k in ('state','recovery','quarantine','reboot_required')},
        firmware_cli_sha256=hashlib.sha256(exe.read_bytes()).hexdigest())
    (ROOT/'evidence/poll_driver_refusal_20261126.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
