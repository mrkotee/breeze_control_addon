"""Offline actual-dispatcher tests, protected inventories and public secret scan."""
import sys,subprocess,json,os,re
from pathlib import Path
from runner import HERE,V7,SEED,SEED_HASH,V7_HASH,V17_HASH,load,digest,ProtectedSecrets,oracle

def inventory(root):
    out={}
    for d,ds,fs in os.walk(root):
        ds[:]=[s for s in ds if s not in ('.git','__pycache__','.pytest_cache','.venv','.deps','.tmp')]
        for n in fs:
            p=Path(d)/n;out[p.relative_to(root).as_posix()]=digest(p)
    return out

def main():
    run=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests'],cwd=HERE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    print(run.stdout);run.check_returncode()
    dependency=load(V7/'evidence/association_poll_cca_resilience_v1.json')
    assert dependency['verdict']=='A ASSOCIATION POLL CCA RECOVERY READY'
    checks={}
    for name,old in load(V7/'.local/protected_start.json').items():
        now=inventory(Path(old['root']));changes=sorted(k for k in set(now)|set(old['files']) if now.get(k)!=old['files'].get(k))
        checks[name]={'files':len(now),'changes':changes}
    for name,old in load(HERE/'.local/protected_before.json').items():
        now=inventory(HERE.parent/name);changes=sorted(k for k in set(now)|set(old) if now.get(k)!=old.get(k))
        checks[name]={'files':len(now),'changes':changes}
    assert not any(x['changes'] for x in checks.values()),'Protected tree changed; preserve and diagnose'
    assert digest(SEED)==SEED_HASH and load(SEED)['generation']==2
    assert digest(V7/'build/airnanny_raw_assoc_poll_cca_v7_prep.hex').upper()==V7_HASH
    assert digest(HERE.parent.parent/'airnanny_v17/releases/airnanny_status_v17_machine_serial.hex').upper()==V17_HASH
    provenance=load(V7/'evidence/provenance.json')['files']
    frozen={n:r['sha256'] for n,r in provenance.items()}
    assert all(digest(V7/n)==sha for n,sha in frozen.items())
    v5=HERE.parent/'raw_radio_v5_key_announce';refs=load(v5/'.local/key_gate_v1/secret_refs.json')
    backend=ProtectedSecrets(v5/'.local/key_gate_v1/secrets')
    tc=backend.get(refs['tc_link_ref']);nk=backend.get(refs['permit_nwk_ref'])
    frames=load(HERE.parent/'identity_commissioning_v1/evidence/commissioning_frames.json')
    captured=next(x for x in frames if x['file']=='airnanny_pairing.pcapng' and x['frame']==154)
    delivered,_=oracle.transport_decode(oracle.Mac.parse(bytes.fromhex(captured['mac_no_fcs'])).payload[8:],tc.value)
    for p in HERE.rglob('*'):
        if not p.is_file() or any(s in p.parts for s in ('.local','__pycache__')):continue
        b=p.read_bytes()
        for key in (tc.value,nk.value,delivered):
            assert all(v not in b for v in (key,key.hex().encode(),key.hex().upper().encode(),':'.join(f'{x:02x}' for x in key).encode())), 'Secret scan failed'
    source={p.relative_to(HERE).as_posix():digest(p) for p in HERE.rglob('*.py') if '__pycache__' not in p.parts and '.local' not in p.parts}
    value={'verdict':'A LIVE SINGLE-BOOT RUNNER READY','issue':1,'dependency_verdict':dependency['verdict'],
        'tests':{'count':int(re.search(r'Ran (\d+) tests',run.stdout)[1]),'output':run.stdout,'actual_V7_dispatcher':True,'USB_phase_subcases':len(load(HERE/'evidence/usb_failure_matrix.json'))},
        'runner_source_sha256':source,'v7_source_sha256':frozen,'protected_comparisons':checks,'seed_sha256':SEED_HASH,
        'V7_sha256':V7_HASH,'V17_sha256':V17_HASH,'secret_scan':True,'firmware_changed':False,
        'CCA_policy':'Unmodified V7 SingleBoot.association_poll_due; first completed CCA only; >=3200us after receipt; <=2 polls; one request',
        'hardware':{'COM':0,'flash':0,'RF_TX':0,'new_real_attempt':0,'key_install':0,'FC_lease':0}}
    (HERE/'evidence/part_a.json').write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    target=HERE/'evidence/single_pan_commissioning_result.json'
    if not (HERE/'.local/hardware_gate_v1/milestone.json').exists():
        target.write_text(json.dumps({'Part_A':value,'Part_B':{'state':'NOT_STARTED','performed':False},'PASS':False},indent=2)+'\n',encoding='utf-8')
    print('Offline preparation PASS; real commissioning NOT_STARTED')

if __name__=='__main__':main()
