"""FakePort -> actual V7 dispatcher, synthetic stores, no serial/device import."""
import sys,json,unittest,shutil
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE))
import runner
sys.path.insert(0,str(runner.V7/'tests'))
from test_single_boot import Harness
from key_announce import synthetic_transport
class FakePort:
    def __init__(self,h,scenario='normal',key_poll=1):
        self.h=h;self.t=.1;self.buf=b'';self.is_open=True;self.scenario=scenario;self.key_poll=key_poll;self.polls=0;self.runner=None;self.lines=[]
    @property
    def in_waiting(self):return len(self.buf)
    def enqueue(self,rows):self.buf+=''.join(r['raw']+'\n' for r in rows).encode('ascii')
    def packet(self,p):self.enqueue(self.h.send('@RX '+p.hex()))
    def marker(self,message):
        if message.startswith('PERMIT_ARMED') and self.scenario!='no_permit':self.packet(self.h.permit_packet())
    def read(self,n):
        if not self.is_open:raise OSError('injected USB disconnect')
        if self.buf:data=self.buf[:n];self.buf=self.buf[n:];return data
        self.t+=.01;self.h.send('@TIME '+str(round(self.t*1e6)));return b''
    def write(self,p):
        if not self.is_open:raise OSError('injected USB disconnect')
        s=p.decode().strip();self.lines.append(s)
        if self.scenario=='timeout' and s.startswith('RADIOV7 INFO'):return len(p)
        if 'DEVICE_ANNOUNCE ' in s and self.scenario=='no_ack':self.h.send('@NOACK')
        if 'ASSOC REQUEST ' in s and self.scenario=='request_cca':self.h.send('@CCA')
        if 'ASSOC POLL ' in s:
            self.assoc_polls=getattr(self,'assoc_polls',0)+1
            if self.scenario in ('cca_then_response','cca_twice','cca_response_between') and (self.assoc_polls==1 or self.scenario=='cca_twice'):self.h.send('@CCA')
            if self.scenario=='poll_no_ack':self.h.send('@NOACK')
        rows=self.h.send(s)
        if self.scenario=='wrong_short' and 'ASSOC_COMMIT ' in s:
            for row in rows:row['raw']=row['raw'].replace('assigned_short=1234','assigned_short=8b0b')
        if self.scenario=='boot_change' and 'ARM ' in s:
            for row in rows:row['raw']=row['raw'].replace('1'*32,'2'*32)
        self.enqueue(rows)
        if self.scenario=='duplicate_receipt' and 'ASSOC REQUEST ' in s:
            self.enqueue([r for r in rows if r['kind']=='TXDONE'])
        if 'INFO ' in s and self.scenario!='no_baseline':self.packet(self.h.baseline_packet())
        if 'ASSOC REQUEST ' in s and self.scenario not in ('no_response','cca_then_response','cca_twice','cca_response_between','poll_no_ack'):self.packet(self.h.response())
        if 'ASSOC POLL ' in s and ((self.scenario=='cca_then_response' and self.assoc_polls==2) or self.scenario=='cca_response_between'):self.packet(self.h.response())
        if 'POST_ASSOC_POLL ' in s:
            self.polls+=1;c=self.runner.h.kp.c
            if self.scenario=='bad_then_good' and self.polls==1:
                bad=synthetic_transport(c,self.h.tc,self.h.nk,fc=7);self.packet(bad[:-1]+bytes([bad[-1]^1]))
            elif self.scenario=='bad_semantic_then_good' and self.polls==1:self.packet(synthetic_transport(c,self.h.tc,self.h.nk,fc=7,keytype=4))
            elif self.scenario=='all_bad':
                bad=synthetic_transport(c,self.h.tc,self.h.nk,fc=7);self.packet(bad[:-1]+bytes([bad[-1]^1]))
            elif self.polls>=self.key_poll and self.scenario not in ('no_key','all_bad'):
                fc=8 if self.scenario=='bad_semantic_then_good' else 7
                self.packet(synthetic_transport(c,self.h.tc,self.h.nk,fc=fc))
        if 'KEY_STATE ' in s and self.scenario=='duplicate_key':self.packet(synthetic_transport(self.runner.h.kp.c,self.h.tc,self.h.nk,fc=7))
        return len(p)
class Tests(unittest.TestCase):
    def setUp(self):self.h=Harness();self.p=FakePort(self.h)
    def tearDown(self):self.h.close()
    def make(self,scenario='normal',key_poll=1):
        self.p.scenario=scenario;self.p.key_poll=key_poll
        r=runner.Runner(self.p,self.h.root/'live',self.h.seed,self.h.backend,self.h.tc,self.h.nk,clock=lambda:self.p.t,marker=self.p.marker);self.p.runner=r;return r
    def test_normal_actual_dispatcher_single_boot_immediate_poll(self):
        r=self.make();d=r.execute();self.assertTrue(d['primary'].startswith('A '),d)
        self.assertEqual(d['tx_counts'],{'ASSOCIATION_REQUEST':1,'POST_ASSOC_KEY_POLL':1,'DEVICE_ANNOUNCE':1})
        self.assertEqual(d['public_epoch']['next_fc'],32);self.assertEqual(d['timings']['assoc_response_to_first_key_poll_ms'],0)
        self.assertEqual(d['terminal_STATUS']['pending'],'0');self.assertEqual(d['terminal_STATUS']['immediate_ack'],'0')
        self.assertEqual({x['fields']['boot'] for x in d['records'] if 'fields' in x},{'1'*32})
        self.assertEqual(d['association']['assigned_short'],0x1234)
        self.assertNotIn(self.h.tc.value.hex(),json.dumps(d));self.assertNotIn(self.h.nk.value.hex(),json.dumps(d))
        runner.durable(HERE/'evidence/fakeport_normal.json',dict(d,hardware=False,RF_TX=0,COM=0))
    def test_key_after_two_polls_cancels_remaining(self):
        d=self.make(key_poll=2).execute();self.assertTrue(d['primary'].startswith('A '));self.assertEqual(self.p.polls,2)
    def test_valid_key_before_next_poll_no_queued_poll(self):
        d=self.make().execute();self.assertEqual(self.p.polls,1);self.assertEqual(d['public_epoch']['generation'],6)
    def test_invalid_MIC_does_not_cancel_future_valid_poll(self):
        d=self.make('bad_then_good',2).execute();self.assertTrue(d['primary'].startswith('A '));self.assertEqual(self.p.polls,2);self.assertEqual(len(d['candidate_rejections']),1)
    def test_authenticated_invalid_semantics_persists_floor(self):
        d=self.make('bad_semantic_then_good',2).execute();self.assertTrue(d['primary'].startswith('A '));self.assertEqual(next(iter(d['public_epoch']['replay'].values())),9)
    def test_duplicate_key_no_second_install(self):
        d=self.make('duplicate_key').execute();self.assertTrue(d['primary'].startswith('A '));self.assertEqual(d['public_epoch']['generation'],6);self.assertEqual(self.p.polls,1)
    def test_missing_key_exact_budget(self):
        d=self.make('no_key').execute();self.assertTrue(d['primary'].startswith('B '));self.assertEqual(self.p.polls,8);self.assertNotIn('DEVICE_ANNOUNCE',d['tx_counts'])
    def test_rejected_keys_report_C_at_bound(self):
        d=self.make('all_bad').execute();self.assertTrue(d['primary'].startswith('C '));self.assertEqual(self.p.polls,8)
    def test_short_substitution_rejected(self):
        d=self.make('wrong_short').execute();self.assertTrue(d['primary'].startswith('F '));self.assertEqual(self.p.polls,0)
    def test_duplicate_receipt_safety_fail(self):
        d=self.make('duplicate_receipt').execute();self.assertTrue(d['primary'].startswith('H '));self.assertEqual(self.p.polls,0)
    def test_boot_change_safety_fail(self):
        d=self.make('boot_change').execute();self.assertTrue(d['primary'].startswith('H '));self.assertEqual(self.p.polls,0)
    def test_serial_timeout(self):
        d=self.make('timeout').execute();self.assertEqual(d['failure']['code'],'SERIAL_TIMEOUT');self.assertEqual(self.p.polls,0)
    def test_no_baseline_no_ARM(self):
        d=self.make('no_baseline').execute();self.assertTrue(d['primary'].startswith('G '));self.assertFalse(any(' ARM ' in s for s in self.p.lines))
    def test_no_permit_no_attempt(self):
        r=self.make('no_permit');d=r.execute();self.assertTrue(d['primary'].startswith('G '));self.assertFalse(r.h.provision.path.exists())
    def test_no_response_two_polls_no_key_phase(self):
        d=self.make('no_response').execute();self.assertTrue(d['primary'].startswith('F '));self.assertEqual(d['tx_counts'].get('ASSOCIATION_EXT_POLL'),2);self.assertEqual(self.p.polls,0)
    def test_no_ack_no_announce_retry(self):
        d=self.make('no_ack').execute();self.assertTrue(d['primary'].startswith('E '));self.assertEqual(d['tx_counts']['DEVICE_ANNOUNCE'],1);self.assertEqual(d['public_epoch']['next_fc'],32)
    def test_durable_short_failure_no_poll(self):
        r=self.make()
        with patch.object(r.h.provision,'commit_response',side_effect=OSError('injected')):d=r.execute()
        self.assertTrue(d['primary'].startswith('F '));self.assertEqual(self.p.polls,0)
    def test_key_secret_failure_no_KEY_STATE_or_secured_TX(self):
        r=self.make()
        with patch.object(self.h.backend,'put',side_effect=OSError('injected')):d=r.execute()
        self.assertTrue(d['primary'].startswith('D '));self.assertFalse(any('KEY_STATE' in s or 'DEVICE_ANNOUNCE' in s for s in self.p.lines))
    def test_USB_loss_every_phase_still_requests_manual_recovery(self):
        phases=['PRECHECK','BASELINE','ARM','PERMIT','REASSOCIATION','SHORT_COMMIT','KEY_POLL','KEY_VALIDATE','KEY_DURABILITY','FC_RESERVE','ANNOUNCE_BUILD','ANNOUNCE_HANDOFF','PASSIVE_OBSERVE','END']
        evidence=[]
        for target in phases:
            with self.subTest(phase=target):
                h=Harness();p=FakePort(h);root=h.root/'live';r=runner.Runner(p,root,h.seed,h.backend,h.tc,h.nk,clock=lambda:p.t,marker=p.marker);p.runner=r
                original=r.phase_set
                def fail(name):
                    original(name)
                    if name==target:p.is_open=False
                r.phase_set=fail
                if target=='PRECHECK':p.is_open=False
                try:
                    d=r.execute();self.assertTrue(d['recovery_required']);self.assertEqual(d['phases'][-1]['phase'],'RECOVERY')
                    self.assertLessEqual(d['tx_counts'].get('DEVICE_ANNOUNCE',0),1)
                    evidence.append({'phase':target,'recovery_required':True,'primary':d['primary'],'RF_TX':0})
                finally:h.close()
        runner.durable(HERE/'evidence/usb_failure_matrix.json',evidence)
    def test_outer_guard_started_and_finished_both_prevent_second_gate(self):
        g=runner.Guard(self.h.root/'guard');path=g.start({'both_healthy':True,'automation_paused':True,'no_check_case':True,'current_data':True,'settings_confirmed':True})
        self.assertTrue((path/'000_NOT_STARTED.json').exists());g.claim(path.name)
        with self.assertRaises(runner.Fault):g.claim(path.name)
        with self.assertRaises(runner.Fault):runner.Guard(g.root).start({'both_healthy':True,'automation_paused':True,'no_check_case':True,'current_data':True,'settings_confirmed':True})
        g.reconcile('FAILED',reason='test')
        with self.assertRaises(runner.Fault):runner.Guard(g.root).start({'both_healthy':True,'automation_paused':True,'no_check_case':True,'current_data':True,'settings_confirmed':True})
    def test_different_RAW_rejected(self):
        seed=dict(self.h.seed,raw_ieee='e2b0275f4d58206a')
        with self.assertRaises(runner.Fault):runner.Runner(self.p,self.h.root/'live',seed,self.h.backend,self.h.tc,self.h.nk)
    def test_late_key_after_window_not_installed(self):
        r=self.make('no_key');d=r.execute();before=r.h.kp.epoch.read();r.phase='RECOVERY'
        r.rx({'fields':{'mac':synthetic_transport(r.h.kp.c,self.h.tc,self.h.nk).hex(),'revision':'999'},'observed':self.p.t})
        self.assertEqual(r.h.kp.epoch.read(),before);self.assertNotIn('secret_ref',before)
    def test_recovery_INFO_fake_after_failures(self):
        from recovery import inspect
        class Port:
            in_waiting=1
            def __init__(self):self.t=0;self.once=True;self.writes=[]
            def write(self,p):self.writes.append(p);return len(p)
            def read(self,n):
                self.t+=1
                if not self.once:return b''
                self.once=False;return b'AIRV1 INFO id=20000006 firmware=airnanny_status_v17_machine_serial protocol=1 safe_checks=64445 safe_failed=0 serial_checks=3612 serial_failed=0\nAIRV1 DONE id=20000006 cmd=info result=ok\n'
        p=Port();value=inspect(p,lambda:p.t);self.assertTrue(value['verified']);self.assertEqual(len(p.writes),1);self.assertEqual(value['RF_TX'],0)
    def test_outer_guard_crash_after_index_commit_blocks_rerun(self):
        g=runner.Guard(self.h.root/'guard');original=runner.durable
        def crash(path,value):
            original(path,value)
            if path.name=='milestone.json':raise OSError('simulated death after STARTED commit')
        with patch.object(runner,'durable',crash):
            with self.assertRaises(OSError):g.start({'both_healthy':True,'automation_paused':True,'no_check_case':True,'current_data':True,'settings_confirmed':True})
        with self.assertRaises(runner.Fault):runner.Guard(g.root).start({'both_healthy':True,'automation_paused':True,'no_check_case':True,'current_data':True,'settings_confirmed':True})
    def test_outcome_journal_failure_cannot_prevent_recovery_marker(self):
        r=self.make();messages=[];original=r.marker;r.marker=lambda s:(messages.append(s),original(s));writer=runner.durable
        def fail(path,value):
            if path.name=='outcome.json':raise OSError('injected outcome failure')
            return writer(path,value)
        with patch.object(runner,'durable',fail):d=r.execute()
        self.assertIn('journal_failure',d);self.assertTrue(any('RESTORE_V17' in s for s in messages))
    def test_buffered_ingress_age_not_retimestamped(self):
        r=self.make();self.p.buf=b'RADIOV7 INFO boot='+b'1'*32+b' id=1 session=0\nRADIOV7 STATUS boot='+b'1'*32+b' id=2 session=0\n'
        a=r.w.read();self.p.t+=11;b=r.w.read();self.assertEqual(a['observed'],b['observed']);self.assertLess(b['observed'],self.p.t-10)
if __name__=='__main__':unittest.main()
