"""Real observer/dispatch with deliberately different host and radio clocks."""
import sys,unittest,uuid,shutil
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'host'));sys.path.insert(0,str(R/'tests'))
import test_first_control as v
from application_control import ApplicationLedger,ApplicationProbe,FirstFanControl

class Tests(unittest.TestCase):
    def setUp(self):
        self.root=R/'.local/tests'/uuid.uuid4().hex;self.root.mkdir(parents=True);self.addCleanup(shutil.rmtree,self.root)
        r=v.v.old.fixture();r.update(generation=13,next_fc=672)
        r['recovery']=dict(gate=v.lm.PREVIOUS,state='FIRST_TYPE07_FAILED_OR_UNKNOWN',proofs=[],polls=[])
        v.lm.durable(self.root/'epoch.json',r);self.m=ApplicationLedger(self.root,v.v.old.KEY,v.v.GUARD)
        self.now=561334.0
        r=self.m.read();r['generation']=14
        r['recovery'].update(gate=v.v.GUARD,state='PARENT_LINK_ACTIVE',observation={'complete':True},
            proofs=[{'fc':1,'clean_ack':True},{'fc':2,'clean_ack':True}],readiness_candidate=True,
            firmware_current_short_commit_required=False,last_idle_intent={'at':self.now,'phase':'LOCAL_MAC_ACK','receipt':{'time_us':'106000000'}})
        v.lm.durable(self.root/'epoch.json',r)
        self.app=FirstFanControl(self.m,v.v.BOOT,1,self.now);self.m.app=self.app
        self.probe=ApplicationProbe(object(),self.m,lambda:self.now+.01);self.probe.phase='ACTIVE';self.probe.session=1
    def row(self,raw,radio_us=106695761,revision=290,session='1'):
        return dict(kind='RX',fields=dict(session=session,revision=str(revision),time_us=str(radio_us),mac=raw.hex()))
    def unknown(self):return v.packet(v.status(),3000000,short=1)
    def test_unsupported_scope_observed_once_management_gets_radio_seconds(self):
        with patch.object(self.app,'receive',wraps=self.app.receive) as observer,patch.object(self.m,'receive_management',wraps=self.m.receive_management) as management:
            self.probe.on_rx(self.row(self.unknown()))
            self.assertEqual(observer.call_count,1)
            self.assertAlmostEqual(observer.call_args.args[2],self.now+.01)
            self.assertEqual(observer.call_args.args[3],106695761)
            self.assertEqual(management.call_count,1)
            self.assertAlmostEqual(management.call_args.args[2],106.695761)
        self.assertIsNone(self.app.status);self.assertFalse(self.app.baseline.valid)
        self.assertNotIn('application_intent',self.m.read())
    def test_supported_status_uses_host_time_and_never_management(self):
        with patch.object(self.app,'receive',wraps=self.app.receive) as observer,patch.object(self.m,'receive_management') as management:
            self.probe.on_rx(self.row(v.packet(v.status(),3000000)))
            self.assertEqual(observer.call_count,1);management.assert_not_called()
        self.assertIsNotNone(self.app.status);self.assertAlmostEqual(self.app.status_at,self.now+.01)
    def test_pre_readiness_radio_status_stays_stale(self):
        with patch.object(self.m,'receive_management') as management:
            self.probe.on_rx(self.row(v.packet(v.status(),3000000),radio_us=105999999))
            management.assert_not_called()
        self.assertIsNone(self.app.status);self.assertNotIn('application_intent',self.m.read())
    def test_inflight_idle_poll_unknown_scope_does_not_lose_terminal_path(self):
        raw=self.m.reserve_idle_poll(self.now+.005)
        self.probe.on_rx(self.row(self.unknown()))
        self.assertEqual(self.m.read()['recovery']['last_idle_intent']['phase'],'HANDED_NO_RETRY')
        receipt=dict(ack_present='1',ack_dsn=str(raw[2]),ack_fcf='2',time_us='106718170',rf_start_us='106717134',cleanup='safe',reboot_required='0')
        self.m.idle_result(raw[2],'local_tx_ok',receipt)
        self.assertEqual(self.m.read()['recovery']['last_idle_intent']['phase'],'LOCAL_MAC_ACK')
    def test_wrong_session_still_stops(self):
        with self.assertRaises(v.lm.Fault):self.probe.on_rx(self.row(self.unknown(),session='2'))
    def test_changed_generation_still_stops(self):
        r=self.m.read();r['generation']+=1;v.lm.durable(self.root/'epoch.json',r)
        with self.assertRaises(v.lm.Fault):self.probe.on_rx(self.row(v.packet(v.status(),3000000)))
    def test_old_idle_proof_still_stops(self):
        self.now+=3
        with self.assertRaises(v.lm.Fault):self.probe.on_rx(self.row(v.packet(v.status(),3000000)))
    def test_management_before_application_uses_unchanged_radio_clock(self):
        self.m.app=None
        with patch.object(self.m,'receive',wraps=self.m.receive) as management:
            self.probe.on_rx(self.row(self.unknown()))
            self.assertAlmostEqual(management.call_args.args[2],106.695761)

if __name__=='__main__':unittest.main()
