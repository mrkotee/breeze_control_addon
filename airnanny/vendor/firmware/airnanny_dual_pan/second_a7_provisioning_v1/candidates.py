"""Offline candidate enrollment from locally available captures and key oracle.

A ctx1 Network Key is verified against ctx1 captures before separate DPAPI
storage. Historical captures grant no live freshness, replay floor or membership.
The TC bootstrap remains an UNVERIFIED ctx1 candidate until its Transport Key MIC
and exact ctx1 destination/source binding pass in the live commissioning phase.
"""
import csv
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'host'))
from key_announce import ProtectedSecrets,Secret,oracle,durable,store
from bindings import OwnedSecret,PROFILE


def oracle_keys():
    keys=set()
    path=Path(os.environ['APPDATA'])/'Wireshark/zigbee_pc_keys'
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line or line.startswith('#'):continue
        value=next(csv.reader([line]))[0].replace(':','').replace('-','').replace(' ','')
        try:key=bytes.fromhex(value)
        except ValueError:continue
        if len(key)==16:keys.update((key,key[::-1]))
    return keys


def enroll(root=ROOT/'.local/candidates'):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    with store.locked(root):
        path=root/'refs.json'
        if path.exists():
            refs=json.loads(path.read_text());load_candidates(root)
            return refs['public_evidence']
        keys=oracle_keys()
        captures=json.loads((ROOT.parents[2]/'host/airnanny2mqtt/fixtures/captures.json').read_text())
        matches={}
        for row in captures:
            if row['fields'].get('wpan.dst_pan')!='0x0b7a':continue
            raw=bytes.fromhex(row['mac_raw']);m=oracle.Mac.parse(raw);n=m.payload
            if len(n)<26 or n[8]!=0x28:continue
            for key in keys:
                try:plain,meta=oracle.secured_decode(n[:8],n[8:],key,(0x28,))
                except Exception:continue
                if meta['source_ieee']!=PROFILE['tc_ieee'] or meta['keyseq']!=0:continue
                matches.setdefault(key,[]).append({'file':row['file'],'frame':row['frame'],
                    'ciphertext_sha256':hashlib.sha256(raw).hexdigest(),'MIC_valid':True,
                    'security_source':meta['source_ieee'],'keyseq':meta['keyseq']})
        if len(matches)!=1:raise ValueError('one_independently_verified_ctx1_NWK_candidate_required')
        nwk,proof=next(iter(matches.items()))
        if len(proof)<2:raise ValueError('multiple_ctx1_historical_MIC_proofs_required')
        # Select the historical bootstrap from encrypted APS Transport Key only;
        # never copy a ctx0 epoch/ref/floor, and never mark it proven for ctx1.
        rows=json.loads((ROOT.parent/'identity_commissioning_v1/evidence/commissioning_frames.json').read_text())
        historical=next(r for r in rows if r['file']=='airnanny_pairing.pcapng' and r['frame']==154)
        aps=oracle.Mac.parse(bytes.fromhex(historical['mac_no_fcs'])).payload[8:]
        tc_matches=[]
        for key in keys:
            try:_,meta=oracle.transport_decode(aps,key)
            except Exception:continue
            tc_matches.append(key)
        if len(tc_matches)!=1:raise ValueError('one_historical_TC_bootstrap_candidate_required')
        backend=ProtectedSecrets(root/'secrets')
        refs={'ctx':1,'pan':PROFILE['pan'],'tc_ieee':PROFILE['tc_ieee'],
              'candidate_epoch':uuid.uuid4().hex,'tc_link_ref':uuid.uuid4().hex,'permit_nwk_ref':uuid.uuid4().hex}
        backend.put(refs['tc_link_ref'],Secret(tc_matches[0]));backend.put(refs['permit_nwk_ref'],Secret(nwk))
        public={'hardware_performed':False,'ctx':1,'pan':'0B7A','independent_DPAPI_storage':True,
                'historical_ctx1_NWK_MIC_proofs':proof,'TC_bootstrap':'HISTORICAL_CANDIDATE_UNVERIFIED_ON_CTX1',
                'live_authority':False,'incoming_floor_imported':False,'installed_Network_Key':False,
                'NWK_FC_domain_created':False,'no_ctx0_security_loaded':True}
        refs['public_evidence']=public;durable(path,refs)
        return public


def load_candidates(root=ROOT/'.local/candidates'):
    root=Path(root);refs=json.loads((root/'refs.json').read_text())
    if (refs['ctx'],refs['pan'],refs['tc_ieee'])!=(1,PROFILE['pan'],PROFILE['tc_ieee']):
        raise ValueError('candidate_context_binding')
    backend=ProtectedSecrets(root/'secrets')
    tc=OwnedSecret(1,PROFILE['pan'],PROFILE['tc_ieee'],'tc_link',refs['candidate_epoch'],backend.get(refs['tc_link_ref']).value)
    nwk=OwnedSecret(1,PROFILE['pan'],PROFILE['tc_ieee'],'permit_candidate',refs['candidate_epoch'],backend.get(refs['permit_nwk_ref']).value)
    return tc,nwk


if __name__=='__main__':
    evidence=enroll();(ROOT/'evidence/candidate_provenance.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({'historical_ctx1_MIC_proofs':len(evidence['historical_ctx1_NWK_MIC_proofs']),
                      'TC_bootstrap':evidence['TC_bootstrap'],'hardware_performed':False}))
