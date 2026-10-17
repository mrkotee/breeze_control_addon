"""Read-only capture audit. No device APIs. Export explicit non-secret fields only."""
from pathlib import Path
import os, json, hashlib, subprocess
R=Path(__file__).resolve().parent
W=R.parents[3]
T=r'C:\Program Files\Wireshark\tshark.exe'
EX={'.deps','.tmp','.venv','__pycache__','.pytest_cache','.git'}
def inventory(p):
    out={}
    for d,ds,fs in os.walk(p):
        ds[:]=sorted(x for x in ds if x not in EX)
        for n in sorted(fs):
            f=Path(d)/n
            out[f.relative_to(p).as_posix()]=hashlib.sha256(f.read_bytes()).hexdigest()
    return out
PROTECTED={'sdk':W/'nrf sdk','v17':R.parent.parent/'airnanny_v17','python':W/'breeze_control/host/airnanny2mqtt','gate_v1':R.parent/'dual_pan_mac_gate','raw_v2':R.parent/'raw_radio_v2'}
def flat(node):
    out={}
    if isinstance(node,dict):
        for k,v in node.items():
            if isinstance(v,str):out[k]=v
            elif isinstance(v,dict):out.update(flat(v))
    return out
FIELDS='wpan.fcf wpan.seq_no wpan.cmd wpan.dst_pan wpan.src_pan wpan.dst16 wpan.src16 wpan.dst64 wpan.src64 wpan.ack_request wpan.dst_addr_mode wpan.src_addr_mode zbee_nwk.fcf zbee_nwk.src zbee_nwk.dst zbee_nwk.seqno zbee_nwk.security zbee_nwk.radius zbee.sec.field zbee.sec.counter zbee.sec.src64 zbee.sec.key_seqno zbee.sec.key_id zbee_aps.counter zbee_aps.cmd.id zbee_aps.cmd.key_type zbee_aps.cmd.key_seqno zbee_aps.cmd.dst64 zbee_aps.cmd.src64 zbee_aps.security zbee_aps.zdp_cluster zbee_aps.profile wpan-tap.ch_num'.split()
if __name__=='__main__':
    R.mkdir(exist_ok=True);(R/'evidence').mkdir(exist_ok=True);(R/'fixtures').mkdir(exist_ok=True)
    baseline=R/'evidence/protected_baseline.json'
    if not baseline.exists():baseline.write_text(json.dumps({k:inventory(p) for k,p in PROTECTED.items()},indent=2),encoding='utf-8')
    rows=[];counts={}
    for p in sorted((W/'pcaps').glob('*.pcapng')):
        packets=json.loads(subprocess.check_output([T,'-r',str(p),'-T','json','-x']))
        selected=[]
        for pkt in packets:
            l=pkt['_source']['layers'];f=flat(l);num=int(f['frame.number'])
            info=f.get('_ws.col.Info','')
            # Save full metadata of pairing window, plus all management candidates elsewhere.
            if p.name=='airnanny_pairing.pcapng' and (99==num or 136<=num<=213) or 'zbee_aps.cmd.id' in f or f.get('wpan.cmd') in ('0x01','0x02','0x07'):
                raw=l.get('wpan_raw',[None])[0]
                row={'file':p.name,'frame':num,'time_s':f.get('frame.time_relative'),'fields':{k:f[k] for k in FIELDS if k in f},'mac_no_fcs':raw}
                # ONLY wire encrypted or unencrypted MAC bytes. Never decrypted Transport Key plaintext.
                rows.append(row);selected.append(num)
        counts[p.name]={'frames':len(packets),'selected':selected,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    (R/'evidence/commissioning_frames.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
    (R/'evidence/capture_inventory.json').write_text(json.dumps(counts,indent=2),encoding='utf-8')
    print(json.dumps({'selected':len(rows),'files':len(counts),'associations':[{k:r[k] for k in ['file','frame','fields']} for r in rows if r['fields'].get('wpan.cmd') in ('0x01','0x02')]}))
