"""Synthetic material only. Exercise the real commissioning and C admission."""
import copy
import dataclasses
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'host'))
sys.path.insert(0, str(ROOT/'tools'))
from test_single_boot import Harness
from bindings import OwnedSecret, ReplayWatermark, bind_watermark
from core import Provision, Stop, RAW, TC, durable
from single_boot import SingleBoot
from key_announce import Context, Epoch, Rx, Secret, synthetic_transport, validate_transport


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.addCleanup(self.h.close)

    def test_ctx0_key_even_equal_material_fails_before_state_creation(self):
        bad = OwnedSecret(0,0xfa9b,'00124b0036a148e5','permit_candidate','ctx0-epoch',self.h.nk.value)
        root=self.h.root/'must-not-exist'
        with self.assertRaises(ValueError):
            SingleBoot(root,self.h.seed,self.h.backend,self.h.tc,bad)
        self.assertFalse(root.exists())

    def test_unscoped_key_cannot_enter_commissioning(self):
        with self.assertRaises(Stop):
            SingleBoot(self.h.root/'reject',self.h.seed,self.h.backend,Secret(self.h.tc.value),self.h.nk)

    def test_ctx0_tc_key_rejected(self):
        bad=dataclasses.replace(self.h.tc,ctx=0,pan=0xfa9b)
        with self.assertRaises(ValueError):
            SingleBoot(self.h.root/'reject',self.h.seed,self.h.backend,bad,self.h.nk)

    def test_ctx0_replay_watermark_fails_without_floor_change(self):
        p=self.h.host.pre.permit
        bad=ReplayWatermark(0,0xfa9b,'00124b0036a148e5','ctx0-epoch',19,9999999)
        with self.assertRaises(ValueError):bind_watermark(p,bad)
        self.assertEqual(p.highest_fc,-1)

    def test_wrong_epoch_or_generation_watermark_rejected(self):
        p=self.h.host.pre.permit
        for change in ({'epoch':'ctx0-epoch'},{'generation':19},{'ctx':0},{'pan':0xfa9b}):
            w=ReplayWatermark(1,p.pan,p.coordinator,p.key_epoch,p.generation,42)
            with self.subTest(change=change),self.assertRaises(ValueError):
                bind_watermark(p,dataclasses.replace(w,**change))
        self.assertEqual(p.highest_fc,-1)

    def test_ctx1_watermark_monotonic_and_separate(self):
        p=self.h.host.pre.permit
        w=ReplayWatermark(1,p.pan,p.coordinator,p.key_epoch,p.generation,42)
        bind_watermark(p,w)
        with self.assertRaises(ValueError):bind_watermark(p,dataclasses.replace(w,highest_fc=41))
        self.assertEqual(p.highest_fc,42)

    def test_ctx0_RAW_seed_rejected_no_association_intent(self):
        h=self.h;h.rx(h.baseline_packet());h.send(h.host.baseline_line(h.ident()));h.host.arm_ack(h.send(h.host.arm_line(h.ident()))[-1]['fields']);h.rx(h.permit_packet())
        h.host.seed['raw_ieee']='e2b0275f4d582069'
        with self.assertRaises(Stop):h.host.begin_line(h.ident())
        self.assertFalse(h.host.provision.path.exists());self.assertEqual(h.last_tx,0)

    def test_ctx0_RAW_firmware_rejected(self):
        h=self.h;h.rx(h.baseline_packet());h.send(h.host.baseline_line(h.ident()));h.host.arm_ack(h.send(h.host.arm_line(h.ident()))[-1]['fields']);h.rx(h.permit_packet())
        line=h.host.begin_line(h.ident()).replace(RAW,'e2b0275f4d582069')
        self.assertEqual(h.send(line)[-1]['kind'],'ERROR');self.assertEqual(h.last_tx,0)

    def test_ctx0_short_firmware_rejected(self):
        h=self.h;h.prepare();h.request();h.rx(h.response())
        line=h.host.commit_line(h.ident()).replace('short=1234','short=a326')
        self.assertEqual(h.send(line)[-1]['kind'],'ERROR');self.assertEqual(h.last_tx,1)

    def test_ctx0_epoch_record_rejected_before_counter_reservation(self):
        h=self.h;h.installed();epoch=h.host.kp.epoch;before=epoch.read()
        r=copy.deepcopy(before);r['context'].update(ctx=0,pan=0xfa9b,raw_ieee='e2b0275f4d582069',tc_ieee='00124b0036a148e5')
        durable(epoch.path,r)
        with self.assertRaises(ValueError):epoch.reserve()
        self.assertEqual(json.loads(epoch.path.read_text())['next_fc'],0)

    def test_ctx0_generation_transplant_rejected(self):
        h=self.h;h.installed();epoch=h.host.kp.epoch;r=epoch.read();r['generation']=19;durable(epoch.path,r)
        with self.assertRaises(ValueError):epoch.reserve()

    def test_ctx0_epoch_identifier_only_transplant_rejected(self):
        h=self.h;h.installed();epoch=h.host.kp.epoch;r=epoch.read()
        r['key_epoch_id']='1ea30211ee014345a8288337a173a833';durable(epoch.path,r)
        with self.assertRaises(ValueError):epoch.reserve()

    def test_ctx0_secret_backend_cannot_own_ctx1_epoch(self):
        h=self.h
        wrong=type('OtherBackend',(),{'root':ROOT.parent/'raw_radio_v7_assoc_poll_cca/.local/secrets'})()
        with self.assertRaises(ValueError):Epoch(h.root/'reject',wrong)
        self.assertFalse((h.root/'reject').exists())

    def test_transport_key_ctx0_envelope_rejected(self):
        h=self.h;h.associated();c=h.host.kp.c
        raw=synthetic_transport(c,h.tc,h.nk,fc=7)
        with self.assertRaises(ValueError):validate_transport(Rx(0,c.attempt,c.generation,999,raw),c,h.tc,h.host.kp.epoch.replay())
        self.assertEqual(h.host.kp.epoch.read()['replay'],{})

    def test_cross_PAN_baseline_equal_key_rejected_before_MIC(self):
        h=self.h;raw=bytearray(h.baseline_packet());raw[3:5]=bytes.fromhex('9bfa')
        with patch.object(h.host.pre.permit,'authenticated',side_effect=AssertionError('must not route')):
            self.assertFalse(h.host.receive(bytes(raw),1))
        self.assertEqual(h.host.stage,'PASSIVE');self.assertEqual(h.host.pre.permit.highest_fc,-1)

    def test_cross_PAN_transport_equal_key_rejected_before_replay(self):
        h=self.h;h.associated();epoch=h.host.kp.epoch;raw=bytearray(synthetic_transport(h.host.kp.c,h.tc,h.nk,fc=7));raw[3:5]=bytes.fromhex('9bfa')
        with self.assertRaises(ValueError):h.rx(bytes(raw))
        self.assertEqual(epoch.read()['replay'],{});self.assertEqual(epoch.read()['next_fc'],0)

    def test_replay_key_and_epoch_no_restart_or_overwrite(self):
        h=self.h;h.installed();epoch=h.host.kp.epoch
        with self.assertRaises(ValueError):epoch.initialize(h.host.kp.c)
        ref=epoch.read()['secret_ref']
        with self.assertRaises(ValueError):h.backend.put(ref,h.nk)

    def test_crash_after_lease_burn_does_not_reuse_FC(self):
        h=self.h;h.installed();e=h.host.kp.epoch;lease=e.reserve()
        restarted=Epoch(e.root,h.backend)
        self.assertEqual(restarted.read()['next_fc'],32)
        restarted.burn_abandoned();new=restarted.reserve()
        self.assertEqual(new.fc,32);self.assertNotEqual(lease.token,new.token)


if __name__ == '__main__':unittest.main()
