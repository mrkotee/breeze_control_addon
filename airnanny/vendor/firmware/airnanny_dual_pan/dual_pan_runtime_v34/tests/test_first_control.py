"""Synthetic keys and disposable authority only; actual native C dispatcher."""
import sys
import unittest
import uuid
import shutil
import copy
import subprocess
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
import support as v
import ledger as lm
from application_control import ApplicationLedger, FirstFanControl, ApplicationProbe
from airnanny.application import Type07
from airnanny.mac import MAC
from airnanny.nwk import NWK
from airnanny.security import decrypt
from airnanny.aps import APS
from airnanny.zcl import ZCL
sys.path.insert(0,str(v.R.parents[2]/'host/airnanny2mqtt/tests'))
from control_support import baseline, status
import sys as _sys,os as _os
_sys.path.insert(0,_os.path.join(_os.path.dirname(_os.path.abspath(__file__)),'..','host'))
from rejoin_wire import PREFIX

def packet(frame, fc, dst=0x6c55, source=lm.TC, short=0, pan=0x0b7a, keyseq=0):
    group=isinstance(frame,Type07)
    aps=APS(12 if group else 0, None if group else 8, 10 if group else None,
        6,0x104,8,22,ZCL(0x11,None,99,1,frame.raw).serialize()).serialize()
    nwk_dst=0xfffd if group else dst
    h=lm.le(0x2208 if group else 0x0248)+lm.le(nwk_dst)+lm.le(short)+b'\x3c\x11'
    return b'\x61\x88\x12'+lm.le(pan)+lm.le(0 if group else dst)+lm.le(short)+lm.encrypt(
        h,b'\x28'+lm.le(fc,4)+lm.ieee(source)+bytes([keyseq]),aps,v.old.KEY)

class UnitTests(unittest.TestCase):
    def setUp(self):
        self.root=v.R/'.local/tests'/uuid.uuid4().hex
        self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree,self.root)
        r=v.old.fixture();r.update(generation=13,next_fc=672)
        r['recovery']={'gate':lm.PREVIOUS,'state':'APPLICATION_TEST_READY','proofs':[],'polls':[]}
        lm.durable(self.root/'epoch.json',r)
        self.m=ApplicationLedger(self.root,v.old.KEY,v.GUARD)
        # Unit fixture only. Integration below establishes these via real C dispatch.
        r['generation']=14
        r['recovery'].update(gate=v.GUARD,state='PARENT_LINK_ACTIVE',
            observation={'complete':True},proofs=[{'fc':1,'clean_ack':True},{'fc':2,'clean_ack':True}],
            firmware_current_short_commit_required=False,
            last_idle_intent={'at':70,'receipt':{'time_us':'70000000'}})
        lm.durable(self.root/'epoch.json',r)
        self.a=FirstFanControl(self.m,v.BOOT,1,70);self.m.app=self.a
        self.fc=3000000;self.rev=0;self.now=70.1
    def rx(self,frame=None,**kw):
        self.rev+=1;self.fc+=1;self.now+=.01
        return self.a.receive(packet(frame or status(),self.fc,**kw),self.rev,self.now)
    def ready(self):
        self.rx(baseline(),source='00124b0036a18944',short=0xf59f)
        self.rx(status())
    def prepare(self):
        self.ready();return self.a.prepare(self.now+.01)
    def desired(self,**kw):
        tx=self.a.confirmation.tx
        args=dict(seq=tx.sequence,fan=tx.fan_raw+1);args.update(kw)
        return status(**args)
    def test_one_build_reserves_current_FC_before_crypto(self):
        self.m.change(lambda r:r.update(next_fc=8192))
        self.ready()
        from airnanny import outgoing
        original=outgoing.encrypt
        def check(*args):
            r=self.m.read();self.assertEqual(r['next_fc'],8224)
            self.assertEqual(r['application_intent']['phase'],'BURNED_BEFORE_CRYPTO')
            return original(*args)
        with patch.object(outgoing,'encrypt',side_effect=check):self.a.prepare(self.now+.01)
        self.assertEqual(self.m.read()['application_intent']['fc'],8192)
    def test_exact_reviewed_APS_ZCL_and_FAN_mutation(self):
        raw=self.prepare();self.assertEqual(len(raw),68)
        mac=MAC.parse(raw);self.assertEqual(mac.fcf,0x8861)
        nwk=NWK.parse(mac.payload);self.assertEqual((nwk.fcf,nwk.destination,nwk.source),(0x2208,0xfffd,0x6c55))
        _,plain,meta=lm.decode_nwk(raw,v.old.KEY)
        aps=APS.parse(plain);zcl=ZCL.parse(aps.payload)
        self.assertEqual((aps.control,aps.group,aps.cluster,aps.profile,aps.source_endpoint),(12,10,6,0x104,8))
        self.assertEqual((zcl.control,zcl.command),(0x11,1))
        self.assertEqual([i for i,(x,y) in enumerate(zip(baseline().raw,zcl.payload)) if x!=y],[6,11,20])
        self.assertEqual(zcl.payload[11],4)
    def test_wire_matches_authoritative_FAN_capture(self):
        vectors=json.loads((v.R.parents[2]/'host/airnanny2mqtt/fixtures/captures.json').read_text())
        captured=next(x for x in vectors if x['type']==7 and x['file']=='remote_speed_3_to_4.pcapng')
        aps=APS.parse(bytes.fromhex(captured['aps_decrypted_raw']));zcl=ZCL.parse(aps.payload)
        self.assertEqual((aps.control,aps.group,aps.cluster,aps.profile,aps.source_endpoint),(12,10,6,0x104,8))
        self.assertEqual((zcl.control,zcl.command),(0x11,1))
        self.assertEqual(captured['fields']['wpan.fcf'],'0x8861')
        self.assertEqual(captured['fields']['zbee_nwk.fcf'],'0x2208')
    def test_stale_parent_poll_rejects_TX_with_fresh_baseline(self):
        self.ready()
        with self.assertRaises(ValueError):self.a.prepare(73)
        self.assertEqual(self.m.read()['next_fc'],672)
    def test_no_status_or_baseline_rejected_without_counter(self):
        with self.assertRaises(ValueError):self.a.prepare(70.2)
        self.rx(status())
        with self.assertRaises(ValueError):self.a.prepare(70.3)
        self.assertEqual(self.m.read()['next_fc'],672)
    def test_old_persisted_readiness_cannot_attach(self):
        self.m.restart_radio()
        self.m.change(lambda r:r['recovery'].update(state='APPLICATION_TEST_READY'))
        with self.assertRaises(ValueError):FirstFanControl(self.m,v.BOOT,1,70)
    def test_radio_restart_invalidates_live_baseline(self):
        self.ready();self.m.restart_radio()
        with self.assertRaises(ValueError):self.a.prepare(70.2)
    def test_context_epoch_keyseq_short_generation_each_rejected(self):
        for field,value in [('key_epoch_id','wrong'),('keyseq',1),('generation',15),('short',0x1234),('pan',0x1234),('channel',22)]:
            original=self.m.read();r=copy.deepcopy(original)
            if field in ('short','pan','channel'):r['context'][field]=value
            else:r[field]=value
            lm.durable(self.m.path,r)
            with self.assertRaises(ValueError):self.a.prepare(70.2)
            lm.durable(self.m.path,original)
    def test_wrong_key_material_and_session_rejected(self):
        self.ready();self.m.key=lm.Secret(bytes(reversed(range(16))))
        with self.assertRaises(ValueError):self.a.prepare(self.now+.01)
        self.m.key=v.old.KEY;self.m.radio_session=2
        with self.assertRaises(ValueError):self.a.prepare(self.now+.01)
    def test_stale_status_rejected(self):
        self.ready();self.m.change(lambda r:r['recovery']['last_idle_intent'].update(at=90))
        with self.assertRaises(ValueError):self.a.prepare(90)
    def test_no_op_nonadjacent_and_prohibited_requests_rejected(self):
        self.ready()
        for value in (4,7,0,'night','power'):
            with self.assertRaises(ValueError):self.a.prepare(self.now+.01,value)
        self.assertEqual(self.m.read()['next_fc'],672)
    def test_night_poweroff_and_mode_rejected(self):
        for kw in ({'flags':0x11},{'flags':0},{'mode':1}):
            self.a.baseline.invalidate()
            self.rx(baseline(**kw),source='00124b0036a18944',short=0xf59f)
            self.rx(status(**kw))
            with self.assertRaises(ValueError):self.a.prepare(self.now+.01)
    def test_unknown_baseline_bytes_preserved(self):
        from airnanny.application import checksum
        b=bytearray(baseline().raw);b[18]=0xa7;b[19]|=0x80
        self.rx(Type07(checksum(b)),source='00124b0036a18944',short=0xf59f);self.rx(status())
        self.a.prepare(self.now+.01)
        self.assertEqual(self.a.confirmation.tx.raw[18:20],bytes(b[18:20]))
    def test_fresh_status_confirms_only_after_local_callback(self):
        self.prepare();self.a.handoff(self.now+.01);self.rx(self.desired())
        self.assertIsNone(self.a.result)
        self.a.complete(0,self.now+.01);self.assertEqual(self.a.result,'CONFIRMED')
    def test_callback_alone_never_confirms(self):
        self.prepare();self.a.handoff(self.now+.01);self.a.complete(0,self.now+.02)
        self.assertIsNone(self.a.result)
        self.rx(status(seq=99,fan=5));self.assertIsNone(self.a.result)
    def test_matching_RX_after_STATUS_but_before_RF_start_never_confirms(self):
        self.prepare();self.a.handoff(self.now+.01)
        self.rx(self.desired());self.assertIsNotNone(self.a.confirmation.match)
        self.a.complete(0,self.now+.01,int((self.now+.005)*1e6))
        self.assertIsNone(self.a.result);self.assertIsNone(self.a.confirmation.match)
    def test_changed_baseline_between_build_and_handoff_is_rejected(self):
        self.prepare()
        self.rx(baseline(seq=77,fan=3),source='00124b0036a18944',short=0xf59f)
        with self.assertRaises(ValueError):self.a.handoff(self.now+.01)
    def test_replayed_and_precommand_TYPE06_never_confirms(self):
        self.prepare();self.a.handoff(self.now+.01);self.a.complete(0,self.now+.02)
        self.assertEqual(self.a.receive(packet(self.desired(),1),99,self.now+.03),'APPLICATION_STALE')
        self.a.command_radio_floor=80000000
        self.rx(self.desired());self.assertIsNone(self.a.result)
    def test_wrong_source_or_second_PAN_never_confirms(self):
        self.prepare();self.a.handoff(self.now+.01);self.a.complete(0,self.now+.02)
        for kw in ({'source':'00124b0036a18944'},{'pan':0x1234},{'keyseq':1},{'dst':0x1234}):
            try:self.rx(self.desired(),**kw)
            except ValueError:pass
            self.assertIsNone(self.a.result)
    def test_physical_controller_addressed_and_broadcast_TYPE06_allowed(self):
        self.prepare();self.a.handoff(self.now+.01);self.a.complete(0,self.now+.02)
        self.rx(self.desired(),dst=0xf59f);self.assertEqual(self.a.result,'CONFIRMED')
    def test_broadcast_TYPE06_confirmation(self):
        self.prepare();self.a.handoff(self.now+.01);self.a.complete(0,self.now+.02)
        self.rx(self.desired(),dst=0xffff);self.assertEqual(self.a.result,'CONFIRMED')
    def test_bad_MIC_does_not_confirm(self):
        self.prepare();raw=bytearray(packet(self.desired(),self.fc+1));raw[-1]^=1
        with self.assertRaises(Exception):self.a.receive(bytes(raw),99,self.now+.1)
        self.assertIsNone(self.a.result)
    def test_confirmation_timeout_is_failed_unknown(self):
        self.prepare();self.a.handoff(self.now+.01);self.a.complete(0,self.now+.02)
        self.a.tick(91);self.assertEqual(self.a.result,'FAILED_OR_UNKNOWN')
    def test_unknown_completion_and_retries_burn_counter(self):
        self.prepare();self.a.handoff(self.now+.01)
        for action in (lambda:self.a.prepare(self.now+.02),lambda:self.a.handoff(self.now+.02)):
            with self.assertRaises(ValueError):action()
        self.assertEqual(self.m.read()['next_fc'],704)
        self.assertEqual(self.m.read()['application_intent']['phase'],'HANDED_UNKNOWN_NO_RETRY')
    def test_crash_after_reservation_before_crypto_never_reuses(self):
        self.ready()
        from airnanny import outgoing
        with patch.object(outgoing,'encrypt',side_effect=RuntimeError('synthetic crash')):
            with self.assertRaises(RuntimeError):self.a.prepare(self.now+.01)
        self.assertEqual(self.m.read()['next_fc'],704)
        with self.assertRaises(ValueError):self.a.prepare(self.now+.02)
        restarted=ApplicationLedger(self.root,v.old.KEY,v.GUARD)
        self.assertTrue(restarted.failed)
    def test_crash_after_handoff_restart_has_no_live_credit(self):
        self.prepare();self.a.handoff(self.now+.01)
        restarted=ApplicationLedger(self.root,v.old.KEY,v.GUARD)
        with self.assertRaises(ValueError):FirstFanControl(restarted,v.BOOT,1,self.now+.02)
    def test_durability_failure_before_reservation_stops_TX(self):
        self.ready()
        with patch.object(self.m,'save',side_effect=OSError('synthetic crash')):
            with self.assertRaises(ValueError):self.a.prepare(self.now+.01)
        self.assertTrue(self.m.failed)
    def test_new_physical_command_generation_invalidates_confirmation(self):
        self.prepare();self.a.handoff(self.now+.01);self.a.complete(0,self.now+.02)
        self.rx(baseline(seq=11,fan=3),source='00124b0036a18944',short=0xf59f)
        self.assertEqual(self.a.result,'FAILED_OR_UNKNOWN')

class NativeTests(UnitTests):
    # Don't inherit tests twice; unittest loader below restricts this class.
    def cli(self):
        p=subprocess.Popen([str(v.R/'build/firmware_cli.exe')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        self.addCleanup(lambda:(p.stdin.close(),p.wait(timeout=3),p.stdout.close()))
        self.i=0
        def feed(line):
            p.stdin.write(line+'\n');p.stdin.flush();rows=[]
            while True:
                row=p.stdout.readline().strip()
                if row.startswith('@END'):self.debug=row;return rows
                if not row:raise RuntimeError('C dispatcher EOF')
                rows.append(row)
        self.feed=feed
        feed(f'{PREFIX} INFO id=1');self.i=1
    # This harness drives ctx1 (short 0x6c55 = 27733); ctx is appended centrally.
    CTX=1
    def command(self,verb,extra=''):
        self.i+=1
        if verb not in ('INFO','END'):
            extra=(extra+' ' if extra.strip() else '')+f'ctx={self.CTX}'
        return self.feed(f'{PREFIX} {verb} id={self.i} boot={v.BOOT} session=1 '+extra)
    def bind(self):
        return self.command('BIND',f'generation=13 epoch={lm.EPOCH} attempt={lm.ATTEMPT} guard={v.GUARD} short=27733')
    def appcommand(self,raw,generation=13,**overrides):
        f=dict(generation=generation,epoch=lm.EPOCH,attempt=lm.ATTEMPT,guard=v.GUARD,
            fc=int.from_bytes(raw[18:22],'little'),hash=hashlib.sha256(raw).hexdigest(),mac=raw.hex())
        f.update(overrides)
        return self.command('TYPE07_FAN',' '.join(f'{k}={val}' for k,val in f.items()))
    def native_test_TYPE07_before_live_parent_rejected(self):
        self.cli();self.bind();raw=self.prepare()
        rows=self.appcommand(raw);self.assertTrue(any('ERROR' in x for x in rows));self.assertIn('tx=0 ',self.debug)
    def native_test_restart_boot_and_wrong_PAN_short_rejected(self):
        self.cli();self.bind();raw=self.prepare()
        self.feed('@APPLICATION_READY_UNIT_FIXTURE')
        raw=bytearray(raw);raw[3]^=1
        self.assertTrue(any('application_context' in x for x in self.appcommand(bytes(raw))))
    def native_test_actual_dispatch_one_command_then_keepalive(self):
        self.cli();self.bind();raw=self.prepare()
        self.feed('@APPLICATION_READY_UNIT_FIXTURE')
        rows=self.appcommand(raw);self.assertTrue(any('TXACCEPT' in x for x in rows),rows)
        self.assertTrue(any('TXDONE' in x and 'local_tx_ok' in x for x in rows),rows)
        self.feed('@TIME 62300001')
        rows=self.command('MANAGEMENT_POLL','generation=13 dsn=55')
        self.assertTrue(any('TXACCEPT' in x for x in rows),rows)
        rows=self.appcommand(raw);self.assertTrue(any('ERROR' in x for x in rows))
        self.assertIn('tx=2 ',self.debug)
    def native_test_FC_below_last_management_block_rejected(self):
        self.cli();self.bind();raw=self.prepare();self.feed('@APPLICATION_READY_UNIT_FIXTURE')
        self.feed('@LAST_FC 672')
        self.assertTrue(any('intent_binding' in x for x in self.appcommand(raw)))
    def native_test_wrong_boot_rejected(self):
        self.cli();self.bind();self.feed('@APPLICATION_READY_UNIT_FIXTURE')
        rows=self.feed(f'{PREFIX} STATUS id=99 boot='+('3'*32)+' session=1')
        self.assertTrue(any('boot_mismatch' in x for x in rows))
    def native_test_generic_or_prohibited_classes_rejected(self):
        self.cli();self.bind()
        rows=self.command('TYPE07_NIGHT','payload=00')
        self.assertTrue(any('reason=verb' in x for x in rows));self.assertIn('tx=0 ',self.debug)
    def native_test_unknown_callback_one_handoff_watchdog_no_retry(self):
        self.cli();self.bind();raw=self.prepare();self.feed('@APPLICATION_READY_UNIT_FIXTURE')
        self.feed('@HOLD');rows=self.appcommand(raw)
        self.assertTrue(any('TXACCEPT' in x for x in rows))
        rows=self.feed('@TIME 63500000')
        self.assertTrue(any('tx_watchdog_abort' in x for x in rows),rows)
        self.assertIn('tx=1 ',self.debug)
        rows=self.appcommand(raw);self.assertTrue(any('ERROR' in x for x in rows));self.assertIn('tx=1 ',self.debug)

class IntegrationTests(unittest.TestCase):
    def run_session(self,confirm=True,current_start=False):
        root=v.R/'.local/tests'/uuid.uuid4().hex;root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree,root)
        r=v.old.fixture();r.update(generation=13,next_fc=672)
        r['recovery']={'gate':lm.PREVIOUS,'state':'APPLICATION_TEST_READY','proofs':[],'polls':[]}
        if current_start:
            r.update(generation=6,next_fc=32);r.pop('recovery')
        lm.durable(root/'epoch.json',r);m=ApplicationLedger(root,v.old.KEY,v.GUARD,**({'initial_generation':6,'initial_min_fc':32} if current_start else {}))
        clock=v.Clock()
        class Port(v.Port):
            waiting=False;sent_baseline=False;confirmation_due=None;app_tx=None
            def write(self,data):
                result=super().write(data)
                if b'TYPE07_FAN ' in data:
                    raw=bytes.fromhex(dict(x.split('=',1) for x in data.decode().split() if '=' in x)['mac'])
                    _,plain,_=lm.decode_nwk(raw,v.old.KEY)
                    self.app_tx=Type07(ZCL.parse(APS.parse(plain).payload).payload)
                    self.confirmation_due=clock.now+3
                return result
            def read(self,n):
                data=super().read(n)
                if self.waiting and not self.sent_baseline:
                    self.sent_baseline=True
                    self.inject(packet(baseline(),500000,dst=self.short,source='00124b0036a18944',short=0xf59f))
                    self.inject(packet(status(),self.fc,dst=self.short));self.fc+=1
                if confirm and self.confirmation_due and clock.now>=self.confirmation_due:
                    self.confirmation_due=None
                    self.inject(packet(status(seq=self.app_tx.sequence,fan=self.app_tx.fan_raw+1),self.fc,dst=0xf59f));self.fc+=1
                return data
        port=Port(clock);self.addCleanup(port.close)
        class Probe(ApplicationProbe):
            def application_ready(self):
                port.waiting=True
                super().application_ready()
        probe=Probe(port,m,clock)
        result=probe.execute()
        summary=dict(synthetic_only=True,actual_C_dispatcher=True,hardware_performed=False,
            ready=result['ready'],application_result=result['application_result'],
            TYPE07=result['TYPE07'],next_fc=m.read()['next_fc'],
            application_intent=m.read().get('application_intent'),
            observation=m.read()['recovery'].get('observation'),END=result['end'],
            command_order=[x['raw'].split()[1] for x in probe.records if x['kind']=='HOST_COMMAND'])
        (v.R/'evidence'/('synthetic_first_fan_'+('confirmed' if confirm else 'timeout')+'.json')).write_text(json.dumps(summary,indent=2)+'\n')
        return result,m,probe
    def test_full_discovery_rejoin_readiness_baseline_one_FAN_confirmation_END(self):
        out,m,p=self.run_session()
        self.assertTrue(out['ready'],out['error'])
        self.assertEqual(m.app.result,'CONFIRMED')
        self.assertEqual(m.read()['application_intent']['fc'],768)
        self.assertEqual(m.read()['next_fc'],800)
        commands=[r['raw'].split()[1] for r in p.records if r['kind']=='HOST_COMMAND']
        self.assertEqual(commands.count('TYPE07_FAN'),1)
        tx=commands.index('TYPE07_FAN');end=commands.index('END')
        self.assertGreater(commands[tx+1:end].count('MANAGEMENT_POLL'),1)
        self.assertEqual(commands[-1],'END')
        self.assertEqual(out['end']['accepted_count'],out['end']['terminal_count'])
    def test_full_session_missing_confirmation_timeout_no_retry(self):
        out,m,p=self.run_session(False)
        self.assertFalse(out['ready']);self.assertEqual(m.app.result,'FAILED_OR_UNKNOWN')
        self.assertEqual(sum(' TYPE07_FAN ' in x['raw'] for x in p.records if x['kind']=='HOST_COMMAND'),1)
        self.assertEqual(out['end']['pending'],'0')

    def test_generation6_retained_Leave_full_path_no_counter_reset(self):
        out,m,p=self.run_session(True,True)
        self.assertTrue(out['ready'],out['error']);self.assertEqual(m.app.result,'CONFIRMED')
        self.assertEqual(m.read()['application_intent']['fc'],128);self.assertEqual(m.read()['next_fc'],160)
        self.assertEqual(m.read()['generation'],7);self.assertEqual(m.read()['context']['short'],0x4321)
        self.assertEqual(m.read()['management_blocker']['NWK_FC'],2462210)
        self.assertEqual(m.read()['recovery_history'][0]['state'],'SEALED_AUTHENTICATED_LEAVE')
        self.assertEqual(sum(' TYPE07_FAN ' in x['raw'] for x in p.records if x['kind']=='HOST_COMMAND'),1)

def suite():
    result=unittest.TestSuite()
    result.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(UnitTests))
    for name in dir(NativeTests):
        if name.startswith('native_test_'):result.addTest(NativeTests(name))
    result.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(IntegrationTests))
    return result

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(suite())
    raise SystemExit(not result.wasSuccessful())
