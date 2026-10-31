"""Synthetic keys only. New header scope must never grant readiness itself."""
import sys,unittest,copy,uuid,shutil
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'host'));sys.path.insert(0,str(R/'tests'))
import test_first_control as v
import context_scope as scope
from application_control import ApplicationLedger,FirstFanControl

def packet(fc=2462400,dst=0xf59f,fcf=0x0208,source=scope.TC,short=0,pan=0x0b7a,keyseq=0,frame=None):
    raw=v.packet(frame or v.status(),fc,dst=dst,source=source,short=short,pan=0x0b7a,keyseq=keyseq)
    _,plain,_=v.lm.decode_nwk(raw,v.v.old.KEY,keyseq)
    h=v.lm.le(fcf)+v.lm.le(dst)+v.lm.le(short)+b'\x3c\x11'
    return raw[:3]+v.lm.le(pan)+raw[5:9]+v.lm.encrypt(h,b'\x28'+v.lm.le(fc,4)+v.lm.ieee(source)+bytes([keyseq]),plain,v.v.old.KEY)

class ScopeTests(unittest.TestCase):
    def test_new_exact_peer_status_and_old_header(self):
        for fcf in (0x0208,0x0248):
            self.assertEqual(scope.foreign_status(packet(fcf=fcf),v.v.old.KEY,0,0x6c55),dict(source_ieee=scope.TC,counter=2462400))
    def test_new_header_only_known_peer_destination(self):
        for dst in (0x6c55,0xffff,0xfffd,0xc9b8):
            self.assertIsNone(scope.foreign_status(packet(dst=dst),v.v.old.KEY,0,0x6c55))
    def test_bad_MIC_key_PAN_source_short_or_header_rejected(self):
        raw=packet();self.assertIsNone(scope.foreign_status(raw[:-1]+bytes([raw[-1]^1]),v.v.old.KEY,0,0x6c55))
        for kw in (dict(keyseq=1),dict(pan=0x1234),dict(source='00124b0036a148e4'),dict(short=1),dict(fcf=0x0209)):
            self.assertIsNone(scope.foreign_status(packet(**kw),v.v.old.KEY,0,0x6c55))
    def test_TYPE07_not_foreign_status(self):
        self.assertIsNone(scope.foreign_status(packet(frame=v.baseline()),v.v.old.KEY,0,0x6c55))

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.root=R/'.local/tests'/uuid.uuid4().hex;self.root.mkdir(parents=True);self.addCleanup(shutil.rmtree,self.root)
        r=v.v.old.fixture();r.update(generation=13,next_fc=672)
        r['recovery']=dict(gate=v.lm.PREVIOUS,state='FIRST_TYPE07_FAILED_OR_UNKNOWN',proofs=[],polls=[])
        v.lm.durable(self.root/'epoch.json',r)
        self.m=ApplicationLedger(self.root,v.v.old.KEY,v.v.GUARD)
    def test_fresh_floor_once_repeats_no_writes_proofs_or_baseline(self):
        before=copy.deepcopy(self.m.read()['recovery'])
        self.assertEqual(self.m.receive(packet(),1,25),'AUTHENTICATED_OTHER_CONTEXT')
        frozen=(self.root/'epoch.json').read_bytes()
        for rev in (2,3,4):self.assertEqual(self.m.receive(packet(),rev,25.1),'AUTHENTICATED_OTHER_CONTEXT_DUPLICATE')
        self.assertEqual(frozen,(self.root/'epoch.json').read_bytes())
        self.assertEqual(self.m.read()['recovery'],before);self.assertEqual(self.m.read()['next_fc'],672)
        self.assertEqual(self.m.read()['nwk_source_floors'][scope.TC],2462401)
        self.assertIsNone(self.m.baseline);self.assertFalse(self.m.ready(True));self.assertNotIn('application_intent',self.m.read())
        restarted=ApplicationLedger(self.root,v.v.old.KEY,v.v.GUARD)
        self.assertEqual(restarted.receive(packet(),9,26),'AUTHENTICATED_OTHER_CONTEXT_DUPLICATE')
    def test_RAW_addressed_replay_still_rejected(self):
        raw=packet(dst=0x6c55)
        self.m.receive(raw,1,25)
        self.assertEqual(self.m.receive(raw,2,25.1),'REPLAY_REJECTED')
    def app(self):
        r=self.m.read();r['generation']=14
        r['recovery'].update(gate=v.v.GUARD,state='PARENT_LINK_ACTIVE',observation={'complete':True},
            proofs=[{'fc':1,'clean_ack':True},{'fc':2,'clean_ack':True}],readiness_candidate=True,
            firmware_current_short_commit_required=False,last_idle_intent={'at':70,'receipt':{'time_us':'70000000'}})
        v.lm.durable(self.root/'epoch.json',r)
        a=FirstFanControl(self.m,v.v.BOOT,1,70);self.m.app=a
        return a
    def test_application_consumed_copy_stale_fresh_peer_status_accepted(self):
        self.m.receive(packet(),1,25);a=self.app()
        self.assertEqual(self.m.receive(packet(),2,70.1),'APPLICATION_STALE')
        self.assertIsNone(a.status);self.assertFalse(a.baseline.valid)
        self.assertEqual(self.m.receive(packet(fc=2462401),3,70.2),'APPLICATION_AUTHENTICATED')
        self.assertIsNotNone(a.status);self.assertFalse(a.baseline.valid)
        self.assertNotIn('application_intent',self.m.read())
    def test_application_unknown_peer_new_header_cannot_supply_status(self):
        a=self.app();a.receive(packet(dst=0xc9b8),1,70.1)
        self.assertIsNone(a.status);self.assertFalse(a.baseline.valid)

if __name__=='__main__':unittest.main()
