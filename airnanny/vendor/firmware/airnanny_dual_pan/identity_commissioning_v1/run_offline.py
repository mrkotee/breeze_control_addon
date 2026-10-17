"""Offline only. Secret from env or explicitly enabled local Wireshark oracle.
Never exports key material or Transport Key plaintext.
"""
from pathlib import Path
import csv, json, os, argparse, sys
from offline_codec import Mac, transport_decode, secured_decode, association_request, association_response, key_hash
from cryptography.exceptions import InvalidTag
R=Path(__file__).resolve().parent
def run():
    ap=argparse.ArgumentParser();ap.add_argument('--local-wireshark-key-oracle',action='store_true');args=ap.parse_args()
    rows=json.loads((R/'evidence/commissioning_frames.json').read_text(encoding='utf-8'))
    frames={r['frame']:r for r in rows if r['file']=='airnanny_pairing.pcapng'}
    keys=[]
    if os.environ.get('AIRNANNY_HISTORICAL_TC_LINK_KEY'):keys.append(bytes.fromhex(os.environ['AIRNANNY_HISTORICAL_TC_LINK_KEY']))
    if args.local_wireshark_key_oracle:
        path=Path(os.environ['APPDATA'])/'Wireshark/zigbee_pc_keys'
        for line in path.read_text(encoding='utf-8').splitlines():
            if not line or line.startswith('#'):continue
            parts=next(csv.reader([line]));v=parts[0].replace(':','').replace('-','').replace(' ','')
            try:k=bytes.fromhex(v)
            except ValueError:continue
            if len(k)==16:keys.extend([k,k[::-1]])
    result={'mac_roundtrip':0,'association_tests':0,'crypto':{},'negative_mic_checks':0,'hardware_access':False}
    for row in rows:
        raw=bytes.fromhex(row['mac_no_fcs']);m=Mac.parse(raw);assert m.serialize()==raw;result['mac_roundtrip']+=1
    for n in (138,142):
        m=Mac.parse(bytes.fromhex(frames[n]['mac_no_fcs']));a=m.association();result['association_tests']+=1
        if n==138:assert a=={'command':1,'capability':0x80}
        else:assert a=={'command':2,'assigned_short':0xc9b7,'status':0}
    ctrl=bytes.fromhex('1f719c36004b1200');coord=bytes.fromhex('e548a136004b1200')
    assert association_request(0xfa9b,0,ctrl,30).serialize().hex()==frames[138]['mac_no_fcs']
    assert association_response(0xfa9b,ctrl,coord,212,0xc9b7,0).serialize().hex()==frames[142]['mac_no_fcs']
    result['association_builder_exact']=2
    result['invalid_inputs_rejected']=0
    for call in (lambda:association_request(0xffff,0,ctrl,30),lambda:association_request(1,0,ctrl,256),lambda:association_request(1,0,b'',0),lambda:association_response(1,ctrl,coord,1,0xffff,0),lambda:association_response(1,ctrl,coord,1,0,3),lambda:Mac.parse(b'\x01'),lambda:Mac.parse(b'\x09\x00\x00'),lambda:Mac.parse(b'\x01\x04\x00')):
        try:call()
        except ValueError:result['invalid_inputs_rejected']+=1
        else:raise AssertionError('invalid input accepted')
    fixtures={str(n):{'file':frames[n]['file'],'frame':n,'mac_no_fcs':frames[n]['mac_no_fcs']} for n in (137,138,140,142,154,156,158,161,174,179,181,204,206)}
    (R/'fixtures/pairing.json').write_text(json.dumps(fixtures,indent=2)+'\n',encoding='utf-8')
    aps=Mac.parse(bytes.fromhex(frames[154]['mac_no_fcs'])).payload[8:]
    tc=None
    for candidate in keys:
        try:nwk,meta=transport_decode(aps,candidate);tc=candidate;break
        except Exception:pass
    if tc is None:
        result['crypto']['154']={'verified':False,'reason':'no matching local TC key'}
    else:
        result['crypto']['154']=dict(meta,verified=True)
        assert meta['delivered_key_type']==1 and meta['delivered_key_sequence']==0
        assert meta['destination_ieee']=='00124b00369c711f' and meta['trust_center_ieee']=='00124b0036a148e5'
        try:transport_decode(aps[:-1]+bytes([aps[-1]^1]),tc)
        except InvalidTag:result['negative_mic_checks']+=1
        else:raise AssertionError('tampered APS accepted')
        for n in (156,158,161,174,179,181,204,206):
            m=Mac.parse(bytes.fromhex(frames[n]['mac_no_fcs']));packet=m.payload
            nhlen=8+(8 if int.from_bytes(packet[:2],'little')&0x0800 else 0)+(8 if int.from_bytes(packet[:2],'little')&0x1000 else 0)
            plain,sec=secured_decode(packet[:nhlen],packet[nhlen:],nwk,(0x28,))
            result['crypto'][str(n)]=dict(sec,verified=True)
            if n==179:
                link,tmeta=transport_decode(plain,tc);result['crypto'][str(n)]['aps_transport']=tmeta
                assert tmeta['delivered_key_type']==4 and tmeta['destination_ieee']=='00124b00369c711f' and tmeta['trust_center_ieee']=='00124b0036a148e5'
            elif n==156:
                assert plain==bytes.fromhex('080013000000000100b7c91f719c36004b120080')
                result['crypto'][str(n)]['device_announce_plaintext']=plain.hex()
            elif n in (158,161,206):result['crypto'][str(n)]['nonsecret_plaintext']=plain.hex()
            elif n==174:
                p,s=secured_decode(plain[:2],plain[2:],tc,(0x20,));assert p==b'\x08\x04'
                result['crypto'][str(n)]['aps_request']=dict(s,command=8,requested_key_type=4,plaintext=p.hex())
            elif n==181:
                assert plain[:4]==bytes.fromhex('01060f04') and len(plain)==28
                assert plain[12:]==key_hash(link,3)
                result['crypto'][str(n)]['verify_key']={'command':15,'key_type':4,'source_ieee':plain[4:12][::-1].hex(),'hash_selector':3,'hash_matches':True}
            elif n==204:
                p,s=secured_decode(plain[:2],plain[2:],link,(0x20,));assert p==bytes.fromhex('1000041f719c36004b1200')
                result['crypto'][str(n)]['aps_confirm']=dict(s,command=p[0],status=p[1],plaintext_length=len(p))
        # NWK authentication tamper rejection, using original captured wire.
        p=Mac.parse(bytes.fromhex(frames[156]['mac_no_fcs'])).payload
        try:secured_decode(p[:8],p[8:-1]+bytes([p[-1]^1]),nwk,(0x28,))
        except InvalidTag:result['negative_mic_checks']+=1
        else:raise AssertionError('tampered NWK accepted')
    # Counter/source nonce collision oracle (same structure as read-only host SecurityHeader).
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(R.parents[3]/'breeze_control/host/airnanny2mqtt/src'))
    from airnanny.security import SecurityHeader
    def nonce(ieee,fc):return ieee.to_bytes(8,'little')+fc.to_bytes(4,'little')+b'\x2d'
    assert nonce(0x0200000000000001,7)==nonce(0x0200000000000001,7)
    assert nonce(0x0200000000000001,7)!=nonce(0x0200000000000002,7)
    assert SecurityHeader(0x28,7,0x0200000000000001,0).nonce==nonce(0x0200000000000001,7)
    result['nonce_domain_checks']=2
    result['readonly_host_codec_oracle_match']=True
    result['secret_scan_files']=0
    secrets=keys+([tc,nwk,link] if tc is not None else [])
    for f in R.rglob('*'):
        if not f.is_file() or '__pycache__' in f.parts or '.local' in f.parts:continue
        text=f.read_text(encoding='utf-8').lower();result['secret_scan_files']+=1
        for key in secrets:
            for rep in (key.hex(),':'.join('{:02x}'.format(b) for b in key)):
                if rep in text:raise AssertionError('secret material found in public artifact')
    (R/'evidence/offline_test_result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
if __name__=='__main__':run()
