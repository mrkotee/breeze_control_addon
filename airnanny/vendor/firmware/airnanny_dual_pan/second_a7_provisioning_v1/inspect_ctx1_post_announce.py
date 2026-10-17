"""Read-only inspection of the sealed ctx1 recording; no serial or replay writes."""
import hashlib
import json
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'host'))
sys.path.insert(0,str(ROOT/'tools'))
from application_adapter import extracted
from key_announce import oracle,ProtectedSecrets
from cryptography.exceptions import InvalidTag

RUN='7dd8634f2c1e491d9601be513519583b'

def main():
    path=ROOT/'.local/hardware_gate_v2/runs'/RUN
    outcome=json.loads((path/'runtime/outcome.json').read_text())
    epoch_path=path/'runtime/current/key/security/epoch.json'
    before=epoch_path.read_bytes();epoch=json.loads(before);c=epoch['context']
    if (c['ctx'],c['pan'],c['raw_ieee'],c['tc_ieee'],c['short'],c['attempt'],epoch['key_epoch_id'])!=(1,0x0b7a,'027a56bb75a41437','00124b0036a1875f',0x6c55,'cbef428849da4e87b48867ac616247d1','9985b15dcb574c59b87dc2fb379f317f'):
        raise ValueError('exact_current_ctx1_authority_required')
    if json.loads((path/'terminal.json').read_text())['state']!='FINISHED':raise ValueError('recovery_closure_required')
    key=ProtectedSecrets(path/'secrets').get(epoch['secret_ref'])
    ns={'oracle':oracle,'le':lambda x,n=2:x.to_bytes(n,'little')}
    source=extracted(ROOT.parent/'raw_radio_v8_post_announce_management/host/management.py',['decode_nwk']).replace('0xfa9b','0x0b7a')
    exec(compile(source,'<ctx1_read_only_decoder>','exec'),ns)
    start=next(x['monotonic'] for x in outcome['phases'] if x['phase']=='PASSIVE_OBSERVE')
    decoded=[];other=0
    for row in outcome['records']:
        if row['kind']!='RX' or row['observed']<start:continue
        raw=bytes.fromhex(row['fields']['mac'])
        try:m,p,meta=ns['decode_nwk'](raw,key,epoch['keyseq'])
        except (ValueError,InvalidTag,AssertionError):other+=1;continue
        item={'revision':int(row['fields']['revision']),'observed':row['observed'],'MIC_PASS':True,
              'security_source_ieee':meta['source_ieee'],'counter':meta['counter'],
              'nwk_src':meta['nwk_src'],'nwk_dst':meta['nwk_dst'],'mac_src':meta['mac_src'],'mac_dst':meta['mac_dst'],
              'ciphertext_sha256':hashlib.sha256(raw).hexdigest()}
        if meta['nwk_fcf']&3==1:
            item.update(classification='NWK_command',command_id=p[0] if p else None)
            if len(p)==2 and p[0]==4:item.update(leave_options=p[1],rejoin_requested=bool(p[1]&0x20))
        elif len(p)>=8 and p[0]&3==0 and not p[0]&0xa0:
            item.update(classification='APS_data',cluster=f'{int.from_bytes(p[2:4],"little"):04x}',profile=f'{int.from_bytes(p[4:6],"little"):04x}')
        else:item['classification']='unknown_APS'
        decoded.append(item)
    if epoch_path.read_bytes()!=before:raise ValueError('read_only_epoch_changed')
    result={'run':RUN,'read_only':True,'serial_opened':False,'replay_mutated':False,'epoch_mutated':False,
            'outcome_sha256':hashlib.sha256((path/'runtime/outcome.json').read_bytes()).hexdigest(),
            'authenticated_post_announce_frames':decoded,'outside_subset_count':other,
            'readiness_proven':False,'TYPE07_sent':False}
    (ROOT/'evidence/ctx1_post_announce_inspection.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__':main()
