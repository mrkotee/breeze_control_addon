import sys, unittest, json, uuid, shutil, copy
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'host'))
import recovery_model as rm
from recovery_model import *
ACK={'ack_started':'1','ack_completed':'1','deadline_miss':'0'}
BEACON=bytes.fromhex('0080197a0b0000ffcf00000022845f87a136004b1200ffffff00')
KEY=Secret(bytes(range(16)))
def fixture():
    return {'fixture':'SYNTHETIC_ONLY','key_epoch_id':EPOCH,'keyseq':0,'secret_ref':'synthetic',
        'state':'MANAGEMENT_PENDING','generation':6,'context':{'generation':4,'ctx':1,'attempt':ATTEMPT,
        'raw_ieee':RAW,'short':0x6c55,'pan':0x0b7a,'channel':21,'tc_ieee':TC},
        'next_fc':32,'sequences':{'nwk':1,'aps':1,'zdo':1,'dsn':1},
        'nwk_source_floors':{TC:2462211,'00124b0036a18944':463499},
        'replay':{'commissioning_TC_selector0':{TC:1}},'tc_upgrade_floors':{},
        'management_blocker':{'state':'A7_LEAVE_OBSERVED_APPLICATION_BLOCKED',
        'source_ieee':TC,'NWK_FC':2462210,'leave_options':0x60}}
def discovery():
    return dict(legacy_beacon(BEACON),active_scan_completed=True,fresh_current_authenticated_parent=True)
def vector(p,fc=2462212,dst=0x6c55,source=TC,pan=0x0b7a,keyseq=0,fcf=0x1a09,long_dst=RAW,long_src=TC):
    h=le(fcf)+le(dst)+le(0)+b'\x01\x07'
    if fcf&0x800:h+=ieee(long_dst)
    if fcf&0x1000:h+=ieee(long_src)
    return b'\x61\x88\x07'+le(pan)+le(dst)+le(0)+encrypt(h,b'\x28'+le(fc,4)+ieee(source)+bytes([keyseq]),p,KEY)

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        base=R/'.local/tests';base.mkdir(parents=True,exist_ok=True)
        self.root=base/uuid.uuid4().hex;self.root.mkdir()
        self.path=self.root/'epoch.json';durable(self.path,fixture());self.m=Model(self.root,KEY)
    def tearDown(self):
        self.assertTrue(self.root.resolve().is_relative_to((R/'.local/tests').resolve()));shutil.rmtree(self.root)
    def prepare(self): self.m.prepare(discovery(),'1'*32)
    def request(self):
        self.prepare();raw,fc=self.m.build_rejoin();self.m.handoff('REJOIN',0);self.m.tx_result('REJOIN','local_tx_ok',.01)
        self.poll=self.m.poll(.05)[2];return raw,fc
    def joined(self,short=0x4321):
        self.request();self.assertEqual(self.m.receive(vector(b'\x07'+le(short)+b'\0'),1,.08,ACK,self.poll),'REJOINED')
        self.m.confirm_short_install(short,self.m.read()['generation'])
    def timeout(self,short=0x4321):
        self.joined(short);self.m.build_announce();self.m.handoff('ANNOUNCE',.1);self.m.tx_result('ANNOUNCE','local_tx_ok',.11)
        raw,fc=self.m.build_timeout();self.m.handoff('TIMEOUT',.12);self.m.tx_result('TIMEOUT','local_tx_ok',.13)
        self.poll=self.m.poll(.16)[2];return raw,fc
    def active(self):
        self.timeout();self.assertEqual(self.m.receive(vector(b'\x0c\0\x01',2462213,0x4321),2,.18,ACK,self.poll),'PARENT_LINK_ACTIVE')
    def test_no_access_to_real_epoch(self):
        before=(CURRENT/'epoch.json').read_bytes()
        with self.assertRaisesRegex(Fault,'NO_REAL_AUTHORITY'):Model(CURRENT,KEY)
        self.assertEqual(before,(CURRENT/'epoch.json').read_bytes())
    def test_fixture_marker_required(self):
        r=fixture();r.pop('fixture');durable(self.path,r)
        with self.assertRaises(Fault):Model(self.root,KEY)
    def test_beacon_legacy(self):self.assertFalse(legacy_beacon(BEACON)['appendix_present'])
    def test_beacon_appendix_refuses_unimplemented_R23(self):
        with self.assertRaises(Fault):legacy_beacon(BEACON+b'\x46\x01\0\0')
    def test_wrong_beacon_context(self):
        for offset in (0,3,5,11,14):
            raw=bytearray(BEACON);raw[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(Fault):legacy_beacon(bytes(raw))
    def test_historical_beacon_not_fresh_discovery(self):
        with self.assertRaises(Fault):self.m.prepare(legacy_beacon(BEACON),'1'*32)
        self.assertNotIn('recovery',self.m.read())
    def test_no_recovery_without_consumed_Leave(self):
        r=fixture();r['nwk_source_floors'][TC]=2462210;durable(self.path,r)
        with self.assertRaises(Fault):self.prepare()
    def test_prepare_preserves_original_blocker_domains_and_key(self):
        old=self.m.read();self.prepare();r=self.m.read()
        for key in old:self.assertEqual(old[key],r[key],key)
    def test_request_shape_FC32_reserved_before_crypto(self):
        raw,fc=self.request();m,p,meta=decode_nwk(raw,KEY)
        self.assertEqual((len(raw),p,fc,meta['counter']),(53,b'\x06\x80',32,32))
        self.assertEqual((m.src,m.dst,meta['nwk_fcf']),(le(0x6c55),le(0),0x1a09))
        self.assertEqual(self.m.read()['next_fc'],64)
    def test_read_high_water_not_hardcoded(self):
        r=fixture();r['next_fc']=1024;durable(self.path,r);self.prepare()
        self.assertEqual(self.m.build_rejoin()[1],1024);self.assertEqual(self.m.read()['next_fc'],1056)
    def test_crash_after_reservation_no_retry(self):
        self.prepare()
        with patch.object(rm,'encrypt',side_effect=RuntimeError('synthetic_crash')):
            with self.assertRaises(RuntimeError):self.m.build_rejoin()
        self.assertEqual(self.m.read()['next_fc'],64)
        restarted=Model(self.root,KEY)
        with self.assertRaises(Fault):restarted.build_rejoin()
    def test_unknown_secured_TX_burns_FC(self):
        self.prepare();self.m.build_rejoin();self.m.handoff('REJOIN',0);self.m.tx_result('REJOIN','unknown',.01)
        self.assertEqual(self.m.read()['next_fc'],64)
        with self.assertRaises(Fault):self.m.build_rejoin()
    def test_duplicate_handoff_denied(self):
        self.request()
        with self.assertRaises(Fault):self.m.handoff('REJOIN',.01)
    def test_MAC_ACK_is_not_rejoin_success(self):self.request();self.assertEqual(self.m.read()['recovery']['state'],'REJOIN_REQUEST_SENT')
    def test_rejoin_success_changed_short_atomic_and_preserves_domains(self):
        before=self.m.read();self.joined();r=self.m.read()
        self.assertEqual(r['context']['short'],0x4321);self.assertEqual(r['generation'],7)
        for key in ('key_epoch_id','keyseq','secret_ref','replay','tc_upgrade_floors','management_blocker'):
            self.assertEqual(r[key],before[key])
        self.assertEqual(r['nwk_source_floors'][TC],2462213)
    def test_rejoin_same_short_success(self):self.joined(0x6c55);self.assertEqual(self.m.read()['context']['short'],0x6c55)
    def test_rejoin_rejection(self):
        self.request();self.assertEqual(self.m.receive(vector(b'\x07\xff\xff\x02'),1,.08,ACK,self.poll),'REJECTED')
        self.assertEqual(self.m.read()['context']['short'],0x6c55)
        with self.assertRaises(Fault):self.m.poll(.15)
    def test_success_invalid_short_rejected(self):
        self.request()
        for short in (0,0xfff8,0xffff):
            with self.subTest(short=short),self.assertRaises(Fault):
                self.m.receive(vector(b'\x07'+le(short)+b'\0',fc=2462212+short),1,.08,ACK,self.poll)
        self.assertEqual(self.m.read()['context']['short'],0x6c55)
    def test_no_response_is_terminal(self):
        self.request();self.m.expire(RESPONSE_WAIT_SECONDS)
        self.assertEqual(self.m.read()['recovery']['state'],'NO_RESPONSE')
        with self.assertRaises(Fault):self.m.build_rejoin()
    def test_500ms_poll_is_too_late(self):
        self.request()
        with self.assertRaisesRegex(Fault,'window_expired'):self.m.poll(.5)
    def test_durable_short_commit_failure_stops_all_TX(self):
        self.request();real=self.m.save
        def failure(path,r):
            if r['context']['short']==0x4321:raise OSError('injected_atomic_commit_failure')
            return real(path,r)
        self.m.save=failure
        with self.assertRaisesRegex(Fault,'DURABILITY_FAIL'):self.m.receive(vector(b'\x07\x21\x43\0'),1,.08,ACK,self.poll)
        self.assertEqual(self.m.read()['context']['short'],0x6c55)
        self.assertEqual(self.m.read()['nwk_source_floors'][TC],2462213)
        with self.assertRaises(Fault):self.m.build_announce()
    def test_timeout_current_short_and_FC_not_zero(self):
        raw,fc=self.timeout();m,p,meta=decode_nwk(raw,KEY)
        self.assertEqual((len(raw),p,fc),(54,b'\x0b\x08\0',96))
        self.assertEqual((m.src,meta['nwk_src']),(le(0x4321),0x4321));self.assertEqual(self.m.read()['next_fc'],128)
    def test_announce_current_short(self):
        self.joined();raw,fc=self.m.build_announce();m,p,meta=decode_nwk(raw,KEY)
        self.assertEqual(fc,64);self.assertEqual((p[9:11],p[11:19],p[19]),(le(0x4321),ieee(RAW),0x80))
        self.assertEqual(meta['nwk_dst'],0xfffd)
    def test_timeout_before_announce_denied(self):
        self.joined()
        with self.assertRaises(Fault):self.m.build_timeout()
    def test_timeout_response_success_known_lifetime(self):
        self.active();q=self.m.read()['recovery'];self.assertEqual(q['lifetime']['seconds'],15360)
        self.assertEqual(q['lifetime']['parent_information'],1)
    def test_timeout_failure_status(self):
        self.timeout();self.assertEqual(self.m.receive(vector(b'\x0c\x01\x01',2462213,0x4321),2,.18,ACK,self.poll),'TIMEOUT_REJECTED')
    def test_timeout_invalid_parent_information(self):
        self.timeout();self.assertEqual(self.m.receive(vector(b'\x0c\0\x80',2462213,0x4321),2,.18,ACK,self.poll),'TIMEOUT_REJECTED')
    def test_bit1_only_cannot_fake_poll_keepalive(self):
        self.timeout();self.assertEqual(self.m.receive(vector(b'\x0c\0\x02',2462213,0x4321),2,.18,ACK,self.poll),'KEEPALIVE_METHOD_UNIMPLEMENTED')
        with self.assertRaises(Fault):self.m.ready(True)
    def test_wrong_source_is_not_response_and_does_not_merge_domains(self):
        self.request();r=self.m.read()
        self.assertEqual(self.m.receive(vector(b'\x07\x21\x43\0',source=RAW),1,.08,ACK,self.poll),'AUTHENTICATED_OTHER_CONTEXT')
        self.assertEqual(self.m.read()['replay'],r['replay']);self.assertEqual(self.m.read()['recovery']['state'],'REJOIN_REQUEST_SENT')
    def test_wrong_PAN_and_keyseq_no_floor(self):
        self.request();before=self.m.read()
        for raw in (vector(b'\x07\x21\x43\0',pan=0x1234),vector(b'\x07\x21\x43\0',keyseq=1)):
            self.assertEqual(self.m.receive(raw,1,.08,ACK,self.poll),'AUTH_REJECTED')
        self.assertEqual(self.m.read(),before)
    def test_bad_MIC_no_floor(self):
        self.request();raw=vector(b'\x07\x21\x43\0');raw=raw[:-1]+bytes([raw[-1]^1]);before=self.m.read()
        self.assertEqual(self.m.receive(raw,1,.08,ACK,self.poll),'AUTH_REJECTED');self.assertEqual(before,self.m.read())
    def test_wrong_extended_destination(self):
        self.request();self.assertEqual(self.m.receive(vector(b'\x07\x21\x43\0',long_dst=TC),1,.08,ACK,self.poll),'UNIMPLEMENTED_AUTHENTICATED_TRAFFIC')
    def test_repeated_Leave_replay_preserved(self):
        self.assertEqual(self.m.receive(vector(b'\x04\x60',2462210,fcf=0x1209),90,0),'REPLAY_REJECTED')
        self.assertEqual(self.m.read()['nwk_source_floors'][TC],2462211)
    def test_new_Leave_blocks_recovery(self):
        self.request();self.assertEqual(self.m.receive(vector(b'\x04\x60',fcf=0x1209),2,.08,ACK,self.poll),'LEAVE_REPEATED')
        with self.assertRaises(Fault):self.m.poll(.15)
    def test_poll_retrieves_queued_response_only_with_proof(self):
        self.request()
        with self.assertRaisesRegex(Fault,'current_poll_proof'):self.m.receive(vector(b'\x07\x21\x43\0'),1,.08,ACK,None)
    def test_clean_ACK_required(self):
        self.request()
        with self.assertRaisesRegex(Fault,'ACK_not_clean'):self.m.receive(vector(b'\x07\x21\x43\0'),1,.08,None,self.poll)
    def test_current_short_used_by_poll_no_old_fallback(self):
        self.joined();self.assertEqual(self.m.poll(.16)[7:9],le(0x4321))
    def test_idle_transition_and_no_500ms_forever(self):
        self.active()
        with self.assertRaisesRegex(Fault,'rate_bound'):self.m.poll(.66)
        self.m.poll(1.16);self.assertEqual(self.m.read()['recovery']['polls'][-1]['period'],1)
    def test_stronger_indirect_proof_ready_only_after_firmware_commit(self):
        self.active();self.assertFalse(self.m.ready());self.assertFalse(self.m.ready(True,drops=1))
        self.assertFalse(self.m.ready(True,unauthorized_tx=1));self.assertTrue(self.m.ready(True))
    def test_no_TYPE07_or_generic_path(self):
        self.prepare()
        for name in ('TYPE07','DATA','NODE_DESCRIPTOR','REQUEST_KEY','VERIFY_KEY','CONFIRM_KEY'):
            with self.subTest(name=name),self.assertRaisesRegex(Fault,'NO_TYPE07'):self.m._build(name)
    def test_session_bounded(self):
        self.active()
        with self.assertRaisesRegex(Fault,'bounded_session'):self.m.poll(120)
    def test_FC_exhaustion(self):
        r=fixture();r['next_fc']=0xfffffffe;durable(self.path,r);self.prepare()
        with self.assertRaises(Fault):self.m.build_rejoin()
    def test_no_announce_before_short_installed_receipt(self):
        self.request();self.m.receive(vector(b'\x07\x21\x43\0'),1,.08,ACK,self.poll)
        with self.assertRaisesRegex(Fault,'short_receipt_required'):self.m.build_announce()
        self.assertEqual(self.m.read()['next_fc'],64)
        with self.assertRaises(Fault):self.m.confirm_short_install(0x6c55,7)
        self.m.confirm_short_install(0x4321,7);self.assertEqual(self.m.build_announce()[1],64)
    def test_crash_after_short_commit_no_resume_or_old_short_fallback(self):
        self.joined();restarted=Model(self.root,KEY)
        self.assertEqual(restarted.read()['context']['short'],0x4321)
        with self.assertRaises(Fault):restarted.build_announce()

if __name__=='__main__':unittest.main()
