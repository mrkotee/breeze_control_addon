"""Narrow ctx1 specialization of the frozen V8 minimal management pipeline.

No serial access or mutation of the installed epoch. No application command.
"""
import hashlib
import json
import shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parent
SOURCE=ROOT.parent/'raw_radio_v8_post_announce_management'
TARGET=ROOT.parent/'ctx1_management_v1'
RUN='7dd8634f2c1e491d9601be513519583b'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    run=ROOT/'.local/hardware_gate_v2/runs'/RUN
    epoch=run/'runtime/current/key/security/epoch.json'
    before=epoch.read_bytes();r=json.loads(before)
    if json.loads((run/'terminal.json').read_text())['state']!='FINISHED':raise ValueError('closed_recovery_required')
    if (r['context']['ctx'],r['context']['pan'],r['context']['short'],r['key_epoch_id'],r['next_fc'])!=(1,0x0b7a,0x6c55,'9985b15dcb574c59b87dc2fb379f317f',32) or r.get('management_timeout_intent') or r.get('management_blocker'):
        raise ValueError('exact_unused_management_authority_required')
    if (TARGET/'evidence/review.json').exists() or (TARGET/'.local/management_gate_v1/milestone.json').exists():raise ValueError('reviewed_preparation_NO_REGENERATION')
    TARGET.mkdir(exist_ok=True)
    for name in ('build','evidence','releases','host','tools','tests','src','include','.local/tests'):(TARGET/name).mkdir(parents=True,exist_ok=True)
    changes=[('0xfa9b','0x0b7a'),('0xa326','0x6c55'),('0xc9b7','0xf59f'),
             ('e2b0275f4d582069','027a56bb75a41437'),('00124b0036a148e5','00124b0036a1875f'),
             ('1ea30211ee014345a8288337a173a833',r['key_epoch_id']),('5b09cb6bc02746298fbffcfb780844a5',r['context']['attempt']),
             ('airnanny_raw_post_announce_v8','airnanny_ctx1_management_v8'),
             ('0x69,0x20,0x58,0x4d,0x5f,0x27,0xb0,0xe2','0x37,0x14,0xa4,0x75,0xbb,0x56,0x7a,0x02'),
             ('0xe5,0x48,0xa1,0x36,0,0x4b,0x12,0','0x5f,0x87,0xa1,0x36,0,0x4b,0x12,0'),
             ('0x9b,0xfa','0x7a,0x0b'),('0x26,0xa3','0x55,0x6c'),
             ('6388409bfa000026a304','6388407a0b0000556c04'),
             ("c['ctx']!=0","c['ctx']!=1"),("'ctx':0","'ctx':1")]
    files=list((SOURCE/'src').glob('*'))+list((SOURCE/'include').glob('*'))
    files += [SOURCE/'host'/n for n in ('management.py','wire.py','live.py')]
    files += [SOURCE/'tools'/n for n in ('build.py','native_build.py')]
    files += list((SOURCE/'tests').glob('*'))
    provenance={}
    for p in files:
        if not p.is_file():continue
        text=p.read_text()
        for old,new in changes:text=text.replace(old,new)
        if p.name=='management.py':
            text=text.replace('raw_radio_v7_assoc_poll_cca/tools','second_a7_provisioning_v1/tools')
            text=text.replace("RUN='6ad64bba458744b1b085d0ba02bbc388'",f"RUN='{RUN}'")
            text=text.replace("DEP=R.parent/'hardware_commissioning_v7'","DEP=R.parent/'second_a7_provisioning_v1'")
            text=text.replace(".local/hardware_gate_v1/runs",".local/hardware_gate_v2/runs")
        if p.name=='live.py':
            # Only the proven injected Probe is carried forward. Its old COM7
            # CLI and ctx0 audit loader are deliberately not callable here.
            text=text.split('\ndef check_inputs():')[0]+'\n'
        if p.name=='management.c':
            text=text.replace('s->keys.state=K_MANAGEMENT;', 's->association.target.ctx=1;s->keys.ctx=1;s->keys.state=K_MANAGEMENT;')
            text=text.replace('memcpy(s->keys.tc,tc,8);','memcpy(s->keys.tc,tc,8);memcpy(s->keys.extpan,tc,8);')
        q=TARGET/p.relative_to(SOURCE);q.write_text(text)
        provenance[p.relative_to(SOURCE).as_posix()]={'original_sha256':sha(p),'generated_sha256':sha(q)}
    if not (TARGET/'radio_driver').exists():shutil.copytree(SOURCE/'radio_driver',TARGET/'radio_driver')
    (TARGET/'evidence/provenance.json').write_text(json.dumps({'source':str(SOURCE),'target':str(TARGET),'target_context':r['context'],'key_epoch_id':r['key_epoch_id'],'dependency_run':RUN,'installed_epoch_sha256':sha(epoch),'files':provenance,'changes':changes,'hardware_performed':False},indent=2)+'\n')
    if epoch.read_bytes()!=before:raise ValueError('installed_epoch_changed')
    print(json.dumps({'generated':str(TARGET),'installed_epoch_unchanged':True,'serial_opened':False,'TYPE07':'LOCKED'}))

if __name__=='__main__':main()
