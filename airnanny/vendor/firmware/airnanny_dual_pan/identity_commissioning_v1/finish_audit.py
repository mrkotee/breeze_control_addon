from pathlib import Path
import json, hashlib, sys
from capture_audit import R, PROTECTED, inventory
rows=json.loads((R/'evidence/commissioning_frames.json').read_text(encoding='utf-8'))
for r in rows:
    raw=bytes.fromhex(r['mac_no_fcs']);fc=int.from_bytes(raw[:2],'little');dm=(fc>>10)&3;sm=(fc>>14)&3;i=3
    dp=raw[i:i+2].hex() if dm else None;i+=2 if dm else 0
    dst=raw[i:i+({0:0,2:2,3:8}[dm])][::-1].hex() if dm else None;i+={0:0,2:2,3:8}[dm]
    sp=raw[i:i+2].hex() if sm and not fc&0x40 else dp if sm else None;i+=2 if sm and not fc&0x40 else 0
    src=raw[i:i+({0:0,2:2,3:8}[sm])][::-1].hex() if sm else None
    r['wire_addressing']={'destination_mode':dm,'source_mode':sm,'destination':dst,'source':src,'destination_pan_le':dp,'source_pan_le':sp,'pan_compressed':bool(fc&0x40),'note':'tshark src64/dst64 may additionally resolve short addresses; these values come directly from wire'}
(R/'evidence/commissioning_frames.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
results=json.loads((R/'evidence/offline_test_result.json').read_text(encoding='utf-8'))
if not results['crypto'].get('154',{}).get('verified'):raise RuntimeError('Transport Key not authenticated; do not publish ready evidence')
labels={99:'beacon',136:'permit join',137:'beacon',138:'association request',139:'ACK',140:'extended Data Request',141:'ACK',142:'association response',143:'ACK',154:'NWK key Transport',156:'Device Announce',158:'end device timeout request',160:'relay announce',161:'Node Descriptor Request',168:'end device timeout response',172:'Node Descriptor Response',174:'Request TC key',179:'TC link-key Transport',181:'Verify Key',204:'Confirm Key SUCCESS',206:'Permit Join Request',208:'Permit Join relay'}
lines=['# Exact commissioning frame index','', 'All values are capture metadata; absent means not exposed/absent, never a default. Full wire bytes and fields are in commissioning_frames.json. Nested crypto layers: offline_test_result.json. All listed commissioning frames are from airnanny_pairing.pcapng; other selected management captures are in JSON.','', '|Frame|Time(s)|Class|FCF / DSN / AR|MAC source -> destination|PAN source / destination|NWK FCF / src / dst / seq|APS command / counter|','|---|---|---|---|---|---|---|---|']
for r in rows:
    if r['file']!='airnanny_pairing.pcapng':continue
    f=r['fields'];g=lambda k:f.get(k,'—')
    src=r['wire_addressing']['source'] or '—';dst=r['wire_addressing']['destination'] or '—'
    label=labels.get(r['frame'],'ACK' if int(g('wpan.fcf'),16)&7==2 else 'Data Request' if f.get('wpan.cmd')=='0x04' else 'other captured management/application')
    lines.append('|{}|{}|{}|{} / {} / {}|{} -> {}|{} / {}|{} / {} / {} / {}|{} / {}|'.format(r['frame'],r['time_s'],label,g('wpan.fcf'),g('wpan.seq_no'),g('wpan.ack_request'),src,dst,g('wpan.src_pan'),g('wpan.dst_pan'),g('zbee_nwk.fcf'),g('zbee_nwk.src'),g('zbee_nwk.dst'),g('zbee_nwk.seqno'),g('zbee_aps.cmd.id'),g('zbee_aps.counter')))
(R/'CAPTURE_SEQUENCE.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
baseline=json.loads((R/'evidence/protected_baseline.json').read_text(encoding='utf-8'))
checks={}
for k,p in PROTECTED.items():
    actual=inventory(p);expected=baseline[k]
    changed=[n for n in set(actual)|set(expected) if actual.get(n)!=expected.get(n)]
    checks[k]={'files':len(actual),'unchanged':not changed,'changed':changed}
if not all(v['unchanged'] for v in checks.values()):raise RuntimeError('protected source changed')
(R/'evidence/protected_comparison.json').write_text(json.dumps(checks,indent=2)+'\n',encoding='utf-8')
out={'milestone':'DEDICATED RAW IDENTITY COMMISSIONING V1','date':'2026-10-06','verdict':'B DEDICATED IDENTITY VALID, COMMISSIONING PARTIAL','identity_handoff_verdict':'A Separate RAW identities remove V17 counter-handoff requirement','hardware':{'serial_opens':0,'usb_operations':0,'flashes':0,'rf_tx':0,'join':0},'firmware_preparation':{'created':False,'hex':None,'firmware_tests':0,'reason':'minimal fresh-identity commissioning subset and phase enforcement not established'},'capture_frames':len(rows),'capture_files':17,'association_pairs':1,'first_observed_post_association_fc':419511,'first_ever_identity_fc_proven':False,'transport_key_mic_verified':True,'secured_layers_exact_reencrypt':12,'offline_tests':results,'protected':checks,'unsupported':['fresh identity A7 admission','local address admission/conformance','minimal mandatory post-announce exchange','discovery beacon request TX fixture','polling and timeout policy validation','complete state machine and firmware phase allowlist'],'next_gate':'offline resolution first; no hardware authorized; after A separately authorize SINGLE-PAN FRESH RAW IDENTITY PROVISIONING','stop':True}
(R/'evidence/raw_identity_commissioning_v1.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'verdict':out['verdict'],'protected':checks},indent=2))
