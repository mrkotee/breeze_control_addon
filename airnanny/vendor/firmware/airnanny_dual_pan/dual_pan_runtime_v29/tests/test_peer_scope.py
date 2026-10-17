"""Synthetic fixtures only; unchanged authoritative Type07 parser and builder."""
import sys
import unittest
import uuid,shutil,copy
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'host'))
import peer_type07_scope as scope
sys.path.insert(0,str(R/'tests'))
import test_first_control as v
from airnanny.application import Type07,checksum

def packet(frame=None,**kw):
    values=dict(fc=473064,source=scope.PEER,short=0xf59f,dst=0x6c55);values.update(kw)
    return v.packet(frame or v.baseline(),**values)

class Tests(unittest.TestCase):
    def test_exact_authenticated_peer_TYPE07(self):
        self.assertEqual(scope.foreign_peer_type07(packet(),v.v.old.KEY,0,0x6c55),dict(source_ieee=scope.PEER,counter=473064))
    def test_duplicate_classification_does_not_mutate_or_grant_readiness(self):
        first=scope.foreign_peer_type07(packet(),v.v.old.KEY,0,0x6c55)
        self.assertEqual(first,scope.foreign_peer_type07(packet(),v.v.old.KEY,0,0x6c55))
        self.assertEqual(set(first),{'source_ieee','counter'})
    def test_bad_MIC_rejected(self):
        raw=packet();raw=raw[:-1]+bytes([raw[-1]^1])
        self.assertIsNone(scope.foreign_peer_type07(raw,v.v.old.KEY,0,0x6c55))
    def test_other_peer_short_key_and_PAN_rejected(self):
        for kw in (dict(source='00124b00369c7000'),dict(short=0xc9b8),dict(keyseq=1),dict(pan=0xfa9b)):
            self.assertIsNone(scope.foreign_peer_type07(packet(**kw),v.v.old.KEY,0,0x6c55))
    def test_RAW_or_controller_status_is_not_foreign_TYPE07(self):
        self.assertIsNone(scope.foreign_peer_type07(v.packet(v.status(),473064),v.v.old.KEY,0,0x6c55))
        self.assertIsNone(scope.foreign_peer_type07(packet(),v.v.old.KEY,0,0xf59f))
    def test_only_fixed_group_transport(self):
        raw=bytearray(packet());raw[5:7]=scope.le(0xffff)
        self.assertIsNone(scope.foreign_peer_type07(bytes(raw),v.v.old.KEY,0,0x6c55))
    def test_incoming_values_are_lossless_not_local_command_policy(self):
        raw=bytearray(v.baseline().raw);raw[19]^=0x10
        frame=Type07(checksum(bytes(raw)))
        self.assertIsNotNone(scope.foreign_peer_type07(packet(frame),v.v.old.KEY,0,0x6c55))

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.root=R/'.local/tests'/uuid.uuid4().hex;self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree,self.root)
        r=v.v.old.fixture();r.update(generation=13,next_fc=672)
        r['recovery']=dict(gate=v.lm.PREVIOUS,state='FIRST_TYPE07_FAILED_OR_UNKNOWN',proofs=[],polls=[])
        v.lm.durable(self.root/'epoch.json',r)
        self.m=v.ApplicationLedger(self.root,v.v.old.KEY,v.v.GUARD)
    def test_incoming_floor_durable_once_duplicates_do_not_write_or_prove(self):
        r=self.m.read();before_q=copy.deepcopy(r['recovery'])
        self.assertEqual(self.m.receive(packet(),1,25),'AUTHENTICATED_OTHER_CONTEXT')
        raw=(self.root/'epoch.json').read_bytes()
        for revision in range(2,6):
            self.assertEqual(self.m.receive(packet(),revision,25.1),'AUTHENTICATED_OTHER_CONTEXT_DUPLICATE')
        self.assertEqual((self.root/'epoch.json').read_bytes(),raw)
        after=self.m.read();self.assertEqual(after['nwk_source_floors'][scope.PEER],473065)
        self.assertEqual(after['next_fc'],672);self.assertEqual(after['recovery'],before_q)
        self.assertIsNone(self.m.baseline);self.assertIsNone(self.m.app)
        self.assertFalse(self.m.ready(True));self.assertNotIn('application_intent',after)
        restart=v.ApplicationLedger(self.root,v.v.old.KEY,v.v.GUARD)
        self.assertEqual(restart.receive(packet(),9,26),'AUTHENTICATED_OTHER_CONTEXT_DUPLICATE')
    def test_bad_MIC_and_unrecognized_replay_still_fail_closed(self):
        raw=packet();bad=raw[:-1]+bytes([raw[-1]^1]);before=self.m.read()
        self.assertEqual(self.m.receive(bad,1,25),'AUTH_REJECTED');self.assertEqual(self.m.read(),before)
        other=packet(source='00124b00369c7000')
        self.m.receive(other,2,25)
        self.assertEqual(self.m.receive(other,3,25),'REPLAY_REJECTED')
        self.assertEqual(self.m.scope_counts['foreign_peer_control_fresh'],0)
    def test_application_phase_discards_consumed_peer_copy_then_accepts_fresh(self):
        self.m.receive(packet(),1,25)
        r=self.m.read();r['generation']=14
        r['recovery'].update(gate=v.v.GUARD,state='PARENT_LINK_ACTIVE',observation={'complete':True},
            proofs=[{'fc':1,'clean_ack':True},{'fc':2,'clean_ack':True}],
            firmware_current_short_commit_required=False,last_idle_intent={'at':70,'receipt':{'time_us':'70000000'}})
        v.lm.durable(self.root/'epoch.json',r)
        app=v.FirstFanControl(self.m,v.v.BOOT,1,70);self.m.app=app
        self.assertEqual(self.m.receive(packet(),2,70.1),'APPLICATION_STALE')
        self.assertFalse(app.baseline.valid)
        self.assertEqual(self.m.receive(packet(fc=473065),3,70.2),'APPLICATION_AUTHENTICATED')
        self.assertTrue(app.baseline.remote_pending)
        self.assertNotIn('application_intent',self.m.read())

if __name__=='__main__':unittest.main()
