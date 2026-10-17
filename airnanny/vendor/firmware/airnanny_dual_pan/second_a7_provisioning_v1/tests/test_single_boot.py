"""Fresh RAW, synthetic secrets, real compiled dispatcher via offline pipes."""
import sys,json,uuid,shutil,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'host'));sys.path.insert(0,str(R/'tools'))
from single_boot import *
from bindings import OwnedSecret
from key_announce import encrypt,ieee,le16,synthetic_transport,short_poll,oracle,store

class Harness:
    def __init__(self, executable='firmware_cli.exe'):
        self.root=R/'.local'/('test-'+uuid.uuid4().hex);self.root.mkdir(parents=True)
        self.tc=OwnedSecret(1,0x0b7a,TC,'tc_link','synthetic-ctx1-tc',bytes(range(16)));self.nk=OwnedSecret(1,0x0b7a,TC,'permit_candidate','synthetic-ctx1-candidate',bytes(range(16,32)))
        self.seed={'raw_ieee':RAW,'ctx':1,'state':'ALLOCATED_UNUSED','generation':0,'attempt':None,'target_pan':0x0b7a,'coordinator_ieee':TC,'assigned_short':0x8b0b,'policy':'local_experimental_v1','forbidden_inventory':[TC,'00124b00369c711f','00124b0036a18944']}
        self.clock=.1;self.backend=ProtectedSecrets(self.root/'secrets')
        self.host=SingleBoot(self.root/'run',self.seed,self.backend,self.tc,self.nk,lambda:self.clock)
        self.process=subprocess.Popen([str(R/'build'/executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        self.id=0;self.revision=0;self.records=[];self.commands=[];self.last_tx=0;self.boot='1'*32
        self.host.attach(self.send('RADIOV7 INFO id=0')[-1]['fields'])
    def close(self):
        self.process.stdin.close();self.process.wait(timeout=5);self.process.stdout.close();self.process.stderr.close()
        assert self.root.resolve().parent==(R/'.local').resolve();shutil.rmtree(self.root)
    def ident(self):self.id+=1;return self.id
    def send(self,line):
        self.commands.append(line)
        self.process.stdin.write(line+'\n');self.process.stdin.flush();rows=[]
        while True:
            text=self.process.stdout.readline()
            if not text:raise AssertionError('Fake firmware exited: '+self.process.stderr.read())
            text=text.strip()
            if text.startswith('@END '):self.last_tx=int(text.split()[1].split('=')[1]);break
            fields=dict(x.split('=',1) for x in text.split() if '=' in x)
            row={'raw':text,'kind':text.split()[1],'fields':fields};rows.append(row);self.records.append(row)
        return rows
    def advance(self,seconds):self.clock+=seconds;self.send('@TIME '+str(round(self.clock*1000000)))
    def rx(self,packet):
        rows=self.send('@RX '+packet.hex());row=next(x for x in rows if x['kind']=='RX')
        f=row['fields'];self.revision=int(f['revision']);self.host.receive(packet,self.revision,f)
        return rows
    def baseline_packet(self,fc=10,keyseq=0):
        h=bytes.fromhex('4802b7c900003c01');a=b'\x28'+fc.to_bytes(4,'little')+ieee(TC)+bytes([keyseq])
        status=bytearray(bytes.fromhex('706500001106')+bytes(17));status[13:15]=bytes.fromhex('18fc');status[19]=2;status[21]=1
        from functools import reduce
        from operator import xor
        status[-1]=reduce(xor,status[5:-1],0)
        p=bytes.fromhex('0008060004010801110101')+status
        return bytes.fromhex('6188017a0bb7c90000')+encrypt(h,a,p,self.nk)
    def permit_packet(self,fc=11):
        h=bytes.fromhex('0802fcff00003c02');a=b'\x28'+fc.to_bytes(4,'little')+ieee(TC)+b'\0'
        return bytes.fromhex('4188027a0bffff0000')+encrypt(h,a,bytes.fromhex('080036000000000002b401'),self.nk)
    def prepare(self):
        self.rx(self.baseline_packet());self.send(self.host.baseline_line(self.ident()))
        rows=self.send(self.host.arm_line(self.ident()));self.host.arm_ack(rows[-1]['fields'])
        self.rx(self.permit_packet());rows=self.send(self.host.begin_line(self.ident()));self.host.begin_ack(rows[-1]['fields'])
    def request(self):
        rows=self.send(self.host.request_line(self.ident()))
        self.assert_tx(rows,plan.expected_request(RAW),'ASSOCIATION_REQUEST')
        self.host.local_done(rows[-1]['fields']['result'])
    def assert_tx(self,rows,raw,cls):
        a=next(x for x in rows if x['kind']=='TXACCEPT')
        assert a['fields']['mac']==raw.hex() and a['fields']['class']==cls and a['fields']['retry']=='0'
    def response(self,short=0x1234,status=0):
        return bytes.fromhex('63cc937a0b')+ieee(RAW)+ieee(TC)+b'\x02'+le16(short)+bytes([status])
    def associated(self):
        self.prepare();self.request();self.advance(.5)
        rows=self.send(self.host.extended_poll_line(self.ident()));self.assert_tx(rows,plan.expected_poll(RAW,0),'ASSOCIATION_EXT_POLL');self.host.local_done(rows[-1]['fields']['result'])
        self.rx(self.response());rows=self.send(self.host.commit_line(self.ident()));self.host.commit_ack(rows[-1]['fields'])
    def poll(self):
        line=self.host.poll_line(self.ident());rows=self.send(line)
        self.assert_tx(rows,short_poll(self.host.kp.c,224+self.host.kp.polls-1),'POST_ASSOC_KEY_POLL')
        self.host.local_done(rows[-1]['fields']['result'])
    def installed(self):
        self.associated();self.poll();self.advance(.05)
        self.rx(synthetic_transport(self.host.kp.c,self.tc,self.nk,fc=7))
        rows=self.send(self.host.key_line(self.ident()));self.host.key_ack(rows[-1]['fields'])
    def announce(self):
        meta=self.host.build();rows=self.send(self.host.announce_line(self.ident()))
        self.assert_tx(rows,self.host.kp.raw,'DEVICE_ANNOUNCE');self.host.local_done(rows[-1]['fields']['result'])
        return meta

class Tests(unittest.TestCase):
    def setUp(self):self.h=Harness()
    def tearDown(self):self.h.close()
    def test_fresh_RAW_complete_single_boot_actual_dispatcher(self):
        h=self.h;h.installed();meta=h.announce()
        self.assertEqual(h.host.stage,'MANAGEMENT_PENDING');self.assertEqual(h.host.kp.epoch.read()['next_fc'],32)
        self.assertEqual(h.host.kp.c.short,0x1234);self.assertEqual(h.host.kp.c.raw_ieee,RAW)
        self.assertEqual(h.last_tx,4);self.assertTrue(meta)
        self.assertEqual({r['fields']['boot'] for r in h.records},{h.boot})
        self.assertEqual({r['fields']['session'] for r in h.records if 'session' in r['fields'] and r['fields']['session']!='0'},{'1'})
        self.assertEqual(h.host.timings()['assoc_response_to_first_key_poll_ms'],0)
        self.assertFalse(any('END ' in r['raw'] for r in h.records))
        evidence={'synthetic_only':True,'real_RF_TX':0,'actual_dispatcher':True,'one_boot':h.boot,'same_RAW':RAW,
                  'returned_short':'1234','final_state':h.host.stage,'host_next_fc':32,'used_fc':h.host.kp.lease.fc,
                  'self_check':meta,'timings':h.host.timings(),'records':h.records,'intent':h.host.kp.intent}
        durable(R/'evidence/fresh_raw_integration.json',evidence)
    def test_pre_arm_permit_not_baseline_or_authorization(self):
        h=self.h;h.rx(h.permit_packet());self.assertEqual(h.host.stage,'PASSIVE');self.assertFalse(h.host.provision.path.exists());self.assertEqual(h.last_tx,0)
    def test_baseline_absent(self):
        with self.assertRaises(Stop):self.h.host.arm_line(self.h.ident())
        self.assertEqual(self.h.last_tx,0)
    def test_stale_baseline_cannot_ARM(self):
        h=self.h;h.rx(h.baseline_packet());h.advance(11)
        with self.assertRaises(Stop):h.host.arm_line(h.ident())
        self.assertEqual(h.host.stage,'STOP')
    def test_late_transport_no_secret_install(self):
        h=self.h;h.associated();h.poll();h.advance(10)
        with self.assertRaises(Stop):h.rx(synthetic_transport(h.host.kp.c,h.tc,h.nk,fc=7))
        self.assertEqual(h.host.kp.epoch.read()['state'],'ASSOCIATED_UNKEYED')
    def test_wrong_baseline_keyseq_STOP(self):
        with self.assertRaises(Stop):self.h.rx(self.h.baseline_packet(keyseq=1))
        self.assertEqual(self.h.last_tx,0)
    def test_permit_replay_rejected(self):
        h=self.h;h.rx(h.baseline_packet());h.send(h.host.baseline_line(h.ident()));h.host.arm_ack(h.send(h.host.arm_line(h.ident()))[-1]['fields'])
        h.rx(h.permit_packet(fc=10));self.assertEqual(h.host.stage,'ARMED');self.assertFalse(h.host.provision.path.exists())
    def test_association_no_ACK_STOP(self):
        h=self.h;h.prepare();h.send('@NOACK');rows=h.send(h.host.request_line(h.ident()))
        with self.assertRaises(Stop):h.host.local_done(rows[-1]['fields']['result'])
        self.assertEqual(h.host.stage,'STOP');self.assertEqual(h.last_tx,1)
    def test_association_response_failure(self):
        h=self.h;h.prepare();h.request()
        with self.assertRaises(Stop):h.rx(h.response(0xffff,1))
        self.assertEqual(h.host.stage,'STOP')
    def test_durable_short_commit_failure_no_key_poll(self):
        h=self.h;h.prepare();h.request();h.rx(h.response())
        with patch('core.durable',side_effect=OSError('injected')):
            with self.assertRaises(OSError):h.host.commit_line(h.ident())
        self.assertEqual(h.host.stage,'STOP');self.assertEqual(h.last_tx,1)
        with self.assertRaises(Stop):h.host.poll_line(h.ident())
    def test_short_substitution_rejected_firmware(self):
        h=self.h;h.prepare();h.request();h.rx(h.response());line=h.host.commit_line(h.ident()).replace('short=1234','short=8b0b')
        self.assertEqual(h.send(line)[-1]['fields']['reason'],'association_commit_binding');self.assertEqual(h.last_tx,1)
    def test_old_session_commit_rejected(self):
        h=self.h;h.prepare();h.request();h.rx(h.response());line=h.host.commit_line(h.ident()).replace('session=1','session=2')
        self.assertEqual(h.send(line)[-1]['fields']['reason'],'association_commit_binding')
    def test_key_poll_queue_failure_no_retry(self):
        h=self.h;h.associated();h.send('@DRIVER_FAIL');rows=h.send(h.host.poll_line(h.ident()))
        with self.assertRaises(Stop):h.host.local_done(rows[-1]['fields']['result'])
        self.assertEqual(h.last_tx,2)
        with self.assertRaises(Stop):h.host.poll_line(h.ident())
    def test_key_not_received_bounds(self):
        h=self.h;h.associated()
        for i in range(8):
            if i:h.advance(.501)
            h.poll()
        with self.assertRaises(Stop):h.host.poll_line(h.ident())
        self.assertEqual(h.last_tx,10)
    def test_invalid_Transport_Key_MIC(self):
        h=self.h;h.associated();h.poll();p=bytearray(synthetic_transport(h.host.kp.c,h.tc,h.nk,fc=7));p[-1]^=1
        with self.assertRaises(Exception):h.rx(bytes(p))
        self.assertEqual(h.host.stage,'STOP');self.assertEqual(h.host.kp.epoch.read()['state'],'ASSOCIATED_UNKEYED')
    def test_replayed_Transport_Key(self):
        h=self.h;h.associated();h.poll();packet=synthetic_transport(h.host.kp.c,h.tc,h.nk,fc=7)
        h.rx(packet)
        with self.assertRaises(ValueError):validate_transport(Rx(1,h.host.kp.c.attempt,4,h.revision+1,packet),h.host.kp.c,h.tc,h.host.kp.epoch.replay())
    def test_secret_save_failure(self):
        h=self.h;h.associated();h.poll()
        with patch.object(h.backend,'put',side_effect=OSError('injected')):
            with self.assertRaises(OSError):h.rx(synthetic_transport(h.host.kp.c,h.tc,h.nk,fc=7))
        self.assertEqual(h.host.stage,'STOP');self.assertEqual(h.last_tx,3)
    def test_public_epoch_commit_failure(self):
        h=self.h;h.associated();h.poll()
        with patch('key_announce.durable',side_effect=OSError('injected')):
            with self.assertRaises(OSError):h.rx(synthetic_transport(h.host.kp.c,h.tc,h.nk,fc=7))
        self.assertEqual(h.host.stage,'STOP');self.assertEqual(h.last_tx,3)
    def test_FC_reservation_failure(self):
        h=self.h;h.installed()
        with patch('key_announce.durable',side_effect=OSError('injected')):
            with self.assertRaises(OSError):h.host.build()
        self.assertEqual(h.last_tx,3)
    def test_announce_build_failure_burns_lease(self):
        h=self.h;h.installed()
        with patch('key_announce.announce_vector',side_effect=ValueError('injected')):
            with self.assertRaises(ValueError):h.host.build()
        self.assertEqual(h.host.kp.epoch.read()['next_fc'],32);self.assertEqual(h.last_tx,3)
    def test_self_check_failure_burns_lease(self):
        h=self.h;h.installed()
        with patch('core.verify_announce',side_effect=ValueError('injected')):
            with self.assertRaises(ValueError):h.host.build()
        self.assertEqual(h.host.kp.epoch.read()['next_fc'],32);self.assertEqual(h.last_tx,3)
    def test_USB_handoff_unknown_no_resend(self):
        h=self.h;h.installed();h.host.build();h.host.announce_line(h.ident())
        self.assertEqual(h.host.kp.epoch.read()['state'],'ANNOUNCE_UNCERTAIN')
        with self.assertRaises(Stop):h.host.announce_line(h.ident())
        self.assertEqual(h.last_tx,3)
    def test_announce_no_ACK_no_retry(self):
        h=self.h;h.installed();h.host.build();h.send('@NOACK');rows=h.send(h.host.announce_line(h.ident()))
        with self.assertRaises(Stop):h.host.local_done(rows[-1]['fields']['result'])
        self.assertEqual(h.host.kp.epoch.read()['state'],'ANNOUNCE_UNCERTAIN');self.assertEqual(h.last_tx,4)
    def test_no_generic_TX_or_beacon_BEGIN(self):
        for verb in ('TX','TYPE07','SET','BEACON_REQUEST','REQUEST_KEY','VERIFY_KEY','NODE_DESCRIPTOR','END_DEVICE_TIMEOUT'):
            rows=self.h.send('RADIOV7 '+verb+' id='+str(self.h.ident()));self.assertEqual(rows[-1]['kind'],'ERROR')
        self.assertEqual(self.h.last_tx,0)
    def test_no_announce_before_KEY_STATE_ack(self):
        h=self.h;h.associated();h.poll();h.rx(synthetic_transport(h.host.kp.c,h.tc,h.nk,fc=7))
        with self.assertRaises(Stop):h.host.build()
        self.assertEqual(h.host.kp.epoch.read()['next_fc'],0)
    def test_KEY_STATE_old_short_rejected(self):
        h=self.h;h.associated();h.poll();h.rx(synthetic_transport(h.host.kp.c,h.tc,h.nk,fc=7))
        rows=h.send(h.host.key_line(h.ident()).replace('short=1234','short=8b0b'))
        self.assertEqual(rows[-1]['fields']['reason'],'key_lineage')
    def test_KEY_STATE_stale_generation_rejected(self):
        h=self.h;h.associated();h.poll();h.rx(synthetic_transport(h.host.kp.c,h.tc,h.nk,fc=7))
        rows=h.send(h.host.key_line(h.ident()).replace('generation=6','generation=4'))
        self.assertEqual(rows[-1]['fields']['reason'],'key_lineage')
    def test_capture_loss_blocks_TX(self):
        h=self.h;h.associated();h.send('@DROP');rows=h.send(h.host.poll_line(h.ident()))
        self.assertEqual(rows[-1]['fields']['reason'],'capture_loss_requires_reboot');self.assertEqual(h.last_tx,2)
    def test_response_ACK_deadline_miss_STOP(self):
        h=self.h;h.prepare();h.request();h.send('@BADACK')
        with self.assertRaises(Stop):h.rx(h.response())
        self.assertEqual(h.host.stage,'STOP');self.assertEqual(h.last_tx,1)
    def test_radio_setup_failure_consumes_one_attempt(self):
        h=self.h;h.rx(h.baseline_packet());h.send(h.host.baseline_line(h.ident()));h.host.arm_ack(h.send(h.host.arm_line(h.ident()))[-1]['fields'])
        h.rx(h.permit_packet());h.send('@SLEEPFAIL');rows=h.send(h.host.begin_line(h.ident()))
        self.assertEqual(rows[-1]['fields']['reason'],'radio_busy_no_retry')
        with self.assertRaises(Stop):h.host.begin_ack(rows[-1]['fields'])
        self.assertEqual(h.last_tx,0)

if __name__=='__main__':unittest.main()
