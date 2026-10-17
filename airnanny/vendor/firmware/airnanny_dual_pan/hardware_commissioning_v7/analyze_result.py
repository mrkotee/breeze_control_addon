"""Read-only offline analysis; emits metadata only, never decrypted key bytes."""
import json
import runner
from cryptography.exceptions import InvalidTag

RUN='6ad64bba458744b1b085d0ba02bbc388'

def main():
    root=runner.HERE/'.local/hardware_gate_v1/runs'/RUN
    d=runner.load(root/'runtime/outcome.json');e=d['public_epoch']
    key=runner.ProtectedSecrets(root/'secrets').get(e['secret_ref'])
    refs=runner.load(runner.HERE.parent/'raw_radio_v5_key_announce/.local/key_gate_v1/secret_refs.json')
    source=runner.ProtectedSecrets(runner.HERE.parent/'raw_radio_v5_key_announce/.local/key_gate_v1/secrets')
    tc=source.get(refs['tc_link_ref']);permit=source.get(refs['permit_nwk_ref'])
    accepted=next(r for r in d['records'] if r['kind']=='RX' and int(r['fields']['revision'])==e['transport_rx_revision'])
    m=runner.oracle.Mac.parse(bytes.fromhex(accepted['fields']['mac']))
    delivered,tkmeta=runner.oracle.transport_decode(m.payload[8:],tc.value)
    assert delivered==key.value and tkmeta['trust_center_ieee']==runner.TC and tkmeta['destination_ieee']==runner.RAW
    begin=next(p['utc'] for p in d['phases'] if p['phase']=='PASSIVE_OBSERVE')
    end=next(p['utc'] for p in d['phases'] if p['phase']=='END')
    rows=[r for r in d['records'] if r['kind']=='RX' and begin<=r['utc']<end]
    observations=[];categories={k:[] for k in ('relayed_Device_Announce','End_Device_Timeout','Node_Descriptor','Request_Key','TC_link_key_Transport_Key','Verify_Key','Confirm_Key','application_to_RAW')}
    short=d['association']['assigned_short']
    for r in rows:
        f=r['fields'];raw=bytes.fromhex(f['mac']);o={'revision':int(f['revision']),'utc':r['utc']}
        observations.append(o)
        try:m=runner.oracle.Mac.parse(raw)
        except ValueError:o['classification']='unsupported_MAC';continue
        if m.dst_pan!=bytes.fromhex('9bfa'):o['classification']='ACK_or_other_PAN';continue
        o.update(mac_source=m.src[::-1].hex(),mac_destination=m.dst[::-1].hex())
        n=m.payload
        if m.fcf&7!=1 or len(n)<8:o['classification']='MAC_command_or_no_NWK';continue
        fcf=int.from_bytes(n[:2],'little');o['NWK_FCF']=f'{fcf:04x}'
        if fcf&0x1d00 or not fcf&0x200:o['classification']='outside_fixed_secured_NWK_subset';continue
        if len(n)<26 or n[8]!=0x28 or n[21]!=e['keyseq']:o['classification']='security_epoch_or_envelope_mismatch';continue
        try:p,meta=runner.oracle.secured_decode(n[:8],n[8:],key.value,(0x28,))
        except (ValueError,InvalidTag):o['classification']='MIC_or_envelope_rejected';continue
        src=int.from_bytes(n[4:6],'little');dst=int.from_bytes(n[2:4],'little')
        o.update(MIC_PASS=True,security_source=meta['source_ieee'],security_FC=meta['counter'],NWK_source=f'{src:04x}',NWK_destination=f'{dst:04x}')
        if fcf&3==1:
            o['classification']='NWK_command';o['command_id']=p[0] if p else None
            if p and p[0] in (0x0b,0x0c):categories['End_Device_Timeout'].append(o['revision'])
            continue
        if not p:o['classification']='empty_APS';continue
        if p[0]&0x20:o['classification']='APS_secured_not_decoded';continue
        if p[0]&3==1:
            o['classification']='APS_command';o['command_id']=p[2] if len(p)>2 else None
            name={8:'Request_Key',15:'Verify_Key',16:'Confirm_Key'}.get(o['command_id'])
            if name:categories[name].append(o['revision'])
            if len(p)>3 and p[2:4]==bytes([5,4]):categories['TC_link_key_Transport_Key'].append(o['revision'])
            continue
        if p[0]&3 or len(p)<8:o['classification']='unsupported_APS';continue
        cluster=int.from_bytes(p[2:4],'little');profile=int.from_bytes(p[4:6],'little')
        o.update(cluster=f'{cluster:04x}',profile=f'{profile:04x}',classification='APS_data')
        if profile==0 and cluster==0x13 and len(p)==20:
            announced_short=int.from_bytes(p[9:11],'little');announced_ieee=p[11:19][::-1].hex()
            o.update(announced_short=f'{announced_short:04x}',announced_ieee=announced_ieee,capability=p[19])
            if announced_short==short and announced_ieee==runner.RAW and m.src==bytes(2):
                categories['relayed_Device_Announce'].append(o['revision'])
        if profile==0 and cluster in (2,0x8002):categories['Node_Descriptor'].append(o['revision'])
        if profile==0x104 and dst==short:categories['application_to_RAW'].append(o['revision'])
    announce=next(r for r in d['records'] if r['kind']=='TXACCEPT' and r['fields']['class']=='DEVICE_ANNOUNCE')
    done=next(r for r in d['records'] if r['kind']=='TXDONE' and r['fields']['id']==announce['fields']['id'])
    value={'run_uuid':RUN,'Transport_Key':dict(tkmeta,rx_revision=e['transport_rx_revision'],protected_key_matches=True,MIC_PASS=True),
        'Device_Announce':{'encrypted_mac':announce['fields']['mac'],'TXDONE':done['fields'],'self_check':d['self_check'],'used_FC':e['lease']['fc'],'next_fc':e['next_fc']},
        'passive':{'begin_utc':begin,'end_utc':end,'RX_count':len(rows),'categories':{k:{'observed_revisions':v,'result':'OBSERVED' if v else 'NOT_OBSERVED_IN_BOUNDED_WINDOW'} for k,v in categories.items()},'observations':observations,
        'limits':['Observational decode only; does not advance runtime replay floors or authorize TX','No try-all keys: only installed FA9B epoch selected by exact PAN/keyseq','No management/application request or response sent','Not observed in 10s does not prove optionality or application readiness','Unrecognized/encrypted APS semantic remains unknown']}}
    encoded=(json.dumps(value,indent=2)+'\n').encode()
    for secret in (key.value,tc.value,permit.value):
        assert secret not in encoded and secret.hex().encode() not in encoded and secret.hex().upper().encode() not in encoded
    (runner.HERE/'evidence/commissioning_analysis.json').write_bytes(encoded)
    print(json.dumps({'passive_RX':len(rows),'categories':value['passive']['categories'],'Transport_Key_revision':e['transport_rx_revision'],'next_fc':e['next_fc']},indent=2))

if __name__=='__main__':main()
