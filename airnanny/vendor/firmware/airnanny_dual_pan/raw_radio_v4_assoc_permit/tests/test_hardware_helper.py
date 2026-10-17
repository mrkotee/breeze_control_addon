"""Actual helper with fake serial/clock, temporary synthetic identity store; no COM."""
from pathlib import Path
import contextlib,hashlib,io,json,shutil,sys,types,unittest,uuid
from unittest.mock import patch
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'tools'))
import hardware_once as h
from permit_validator import codec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
# Read-only local fixture oracle setup; never log keys.
import test_permit_validator as oracle
RAW=bytes.fromhex(oracle.fixtures[0][1]);KEY=oracle.key
@contextlib.contextmanager
def synthetic_directory():
    p=R/'.local'/('synthetic-helper-'+uuid.uuid4().hex[:8]);p.mkdir()
    try:yield str(p)
    finally:
        assert p.resolve().parent==(R/'.local').resolve()
        shutil.rmtree(p)
def newer(raw):
    m=codec.Mac.parse(raw);n=m.payload;plain,_=codec.secured_decode(n[:8],n[8:],KEY,(0x28,));aux=bytearray(n[8:22]);fc=int.from_bytes(aux[1:5],'little')+1;aux[1:5]=fc.to_bytes(4,'little')
    effective=bytes([(aux[0]&~7)|5])+bytes(aux[1:]);nonce=bytes(aux[5:13])+bytes(aux[1:5])+effective[:1]
    m.payload=n[:8]+bytes(aux)+AESCCM(KEY,tag_length=4).encrypt(nonce,plain,n[:8]+effective)
    return m.serialize()
class Simulated(unittest.TestCase):
    def scenario(self,outcome):
        (R/'.local').mkdir(exist_ok=True)
        with synthetic_directory() as tmp:
            assert Path(tmp).resolve().parent==(R/'.local').resolve()
            root=Path(tmp)/'firmware/dual/v4';(root/'evidence/hardware_v1').mkdir(parents=True);(root/'build').mkdir()
            image=root/'build/airnanny_raw_assoc_permit_v4.hex';image.write_bytes(b'synthetic image no RF')
            (root/'evidence/software_result.json').write_text(json.dumps({'verdict':'A AUTHENTICATED PERMIT ASSOCIATION SOFTWARE READY','build':{'hex_sha256':hashlib.sha256(image.read_bytes()).hexdigest().upper()}}))
            recovery=root.parent.parent/'airnanny_v17/releases/airnanny_status_v17_machine_serial.hex';recovery.parent.mkdir(parents=True);shutil.copyfile(R.parent.parent/'airnanny_v17/releases/airnanny_status_v17_machine_serial.hex',recovery)
            E=root/'evidence/hardware_v1';(E/'forbidden_identities.json').write_text(json.dumps({'physical_aircontrols':['00124b00369c711f','00124b0036a18944'],'coordinators':['00124b0036a148e5','00124b0036a1875f'],'v17_reference':['f4ce36c0b553e5a8'],'other_raw':[]}))
            state={'clock':0,'queue':bytearray(),'primed':False,'permit_sent':False,'session':0,'identity':None,'polls':0,'commands':[],'rev':10}
            def clock():state['clock']+=.03;return state['clock']
            def enqueue(s):state['queue'].extend((s+'\n').encode())
            def rx(raw,ack=0):
                state['rev']+=1;enqueue(f'RADIOV3 RX boot={"1"*32} session={state["session"]} revision={state["rev"]} channel=21 time_us=100000 rssi=-60 lqi=120 fcs_ok=1 ack_started={ack} ack_completed={ack} deadline_miss=0 mac={raw.hex()}')
            class FakePort:
                dtr=True
                def __init__(self,*a,**kw):pass
                @property
                def in_waiting(self):return len(state['queue'])
                def close(self):pass
                def read(self,n):
                    state['clock']+=.1
                    if not state['queue']:
                        if not state['primed']:state['primed']=True;rx(RAW)
                        elif state['clock']>16 and not state['permit_sent']:
                            (E/'arm.json').write_text('{}')
                            if state['clock']>16.5:state['permit_sent']=True;rx(newer(RAW))
                    data=bytes(state['queue'][:n]);del state['queue'][:n];return data
                def write(self,data):
                    cmd=data.decode().strip();state['commands'].append(cmd);parts=cmd.split();f=dict(s.split('=',1) for s in parts if '=' in s)
                    if parts[1]=='INFO':
                        enqueue(f'RADIOV3 INFO boot={"1"*32} id={f["id"]} identity=airnanny_raw_assoc_permit_v4 version=4 capability=association_only permit_gate=beacon_or_authenticated_zdo commissioning=unkeyed application_tx=locked transport_key=unsupported device_announce=unsupported channel=21 session={state["session"]} immediate_ack=0 pending_tx=0 rx_drop=0 out_drop=0 rx_revision=10')
                    elif parts[2]=='BEGIN_PERMIT_EVIDENCE':
                        state['session']=1;state['identity']=f['raw_ieee'];enqueue(f'RADIOV3 BEGIN boot={"1"*32} id={f["id"]} session=1 admission_evidence=zdo_permit permit_revision={f["permit_revision"]} attempt={f["attempt"]}')
                    elif parts[2] in ('REQUEST','POLL'):
                        if parts[2]=='REQUEST':raw=h.expected_request(state['identity'])
                        else:raw=h.expected_poll(state['identity'],state['polls']);state['polls']+=1
                        enqueue(f'RADIOV3 TXACCEPT boot={"1"*32} id={f["id"]} session=1 retry=0 mac={raw.hex()}')
                        if parts[2]=='POLL' and outcome in ('pass','reject'):
                            response=bytes.fromhex('63cc019bfa')+bytes.fromhex(state['identity'])[::-1]+bytes.fromhex('00124b0036a148e5')[::-1]+bytes([2,0x34,0x12,0 if outcome=='pass' else 1]);rx(response,1)
                        result='no_ack' if outcome=='no_ack' else 'local_tx_ok'
                        enqueue(f'RADIOV3 TXDONE boot={"1"*32} id={f["id"]} session=1 result={result}')
                    elif parts[2]=='END':enqueue(f'RADIOV3 STATUS boot={"1"*32} id={f["id"]} session=1 state=CANCELLED')
                    else:raise AssertionError('unexpected command')
                    return len(data)
            with patch.object(h,'R',root),patch.object(h.time,'monotonic',clock),patch.dict(sys.modules,{'serial':types.SimpleNamespace(Serial=FakePort)}),contextlib.redirect_stdout(io.StringIO()):h.main()
            result=json.loads((E/'attempt.json').read_text())
            self.assertEqual(sum(' ASSOC REQUEST ' in c for c in state['commands']),1)
            self.assertLessEqual(sum(' ASSOC POLL ' in c for c in state['commands']),2)
            self.assertEqual(result['rf_tx_request_count'],1)
            if outcome=='pass':self.assertEqual(result['associated_record']['state'],'ASSOCIATED_UNKEYED')
            if outcome=='reject':self.assertEqual(result['outcome'],'A7_REJECTED_FRESH_IDENTITY')
            if outcome=='no_ack':self.assertEqual(result['outcome'],'TX_ACK_INCONCLUSIVE');self.assertEqual(result['poll_tx_count'],0)
            if outcome=='no_response':self.assertEqual(result['outcome'],'ASSOCIATION_INCONCLUSIVE_NO_RESPONSE');self.assertEqual(result['poll_tx_count'],2)
    def test_success(self):self.scenario('pass')
    def test_rejection(self):self.scenario('reject')
    def test_no_ACK_no_poll_no_retry(self):self.scenario('no_ack')
    def test_no_response_bounded(self):self.scenario('no_response')
if __name__=='__main__':unittest.main()
