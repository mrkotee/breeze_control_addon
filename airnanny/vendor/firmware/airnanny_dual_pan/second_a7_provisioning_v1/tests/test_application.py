"""Reviewed V22 FAN code, ctx1 binding, durable disposable synthetic ledger."""
import copy
import dataclasses
import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'host'));sys.path.insert(0,str(ROOT/'tools'))
from application_adapter import ApplicationBinding,adapter
from bindings import PROFILE,OwnedSecret
from key_announce import durable,encrypt,ieee,le16,oracle
sys.path.insert(0,str(ROOT.parents[2]/'host/airnanny2mqtt/tests'))
from control_support import baseline,status
from airnanny.application import Type07
from airnanny.mac import MAC
from airnanny.nwk import NWK
from airnanny.security import KeyStore,decrypt
from airnanny.aps import APS
from airnanny.zcl import ZCL


class SyntheticLedger:
    def __init__(self,root,binding):
        self.root=root;self.path=root/'epoch.json';self.binding=binding;self.guard='3'*32
        self.key=OwnedSecret(1,PROFILE['pan'],PROFILE['tc_ieee'],'installed_nwk',binding.epoch,bytes(range(32,48)))
        self.boot=self.radio_session=None
        self.state={'key_epoch_id':binding.epoch,'keyseq':0,'generation':6,'next_fc':32,
            'context':{'ctx':1,'pan':binding.pan,'channel':21,'raw_ieee':binding.raw_ieee,
                       'tc_ieee':binding.tc_ieee,'attempt':binding.attempt,'short':0x1234},
            'sequences':{'dsn':0,'nwk':0,'aps':0,'zdo':0},'nwk_source_floors':{},
            'recovery':{'gate':self.guard,'state':'PARENT_LINK_ACTIVE','readiness_candidate':True,
                        'last_idle_intent':{'at':70,'receipt':{'time_us':'70000000'}}}}
        durable(self.path,self.state)
    def read(self):return json.loads(self.path.read_text())
    def usable(self):
        r=self.read();self.key.require('installed_nwk');return r
    def ready(self,*args):return True  # Explicit SYNTHETIC readiness, no hardware claim.
    def change(self,fn):
        r=self.usable();fn(r);durable(self.path,r);return r
    def consume(self,source,fc):
        def save(r):
            if fc<r['nwk_source_floors'].get(source,0):raise ValueError('NWK_replay')
            r['nwk_source_floors'][source]=fc+1
        self.change(save)


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.root=ROOT/'.local/tests'/uuid.uuid4().hex;self.root.mkdir(parents=True)
        self.addCleanup(shutil.rmtree,self.root)
        self.binding=ApplicationBinding(1,PROFILE['pan'],PROFILE['raw_ieee'],PROFILE['tc_ieee'],'a'*32,'b'*32,0xf59f)
        self.ledger=SyntheticLedger(self.root,self.binding)
        self.app=adapter(self.binding)(self.ledger,'c'*32,1,70)
        self.rev=0;self.fc=100;self.now=70.1
    def packet(self,frame,pan=None,source=None,short=None):
        group=isinstance(frame,Type07)
        source=source or (PROFILE['physical_aircontrol_ieee'] if group else PROFILE['tc_ieee'])
        short=(self.binding.peer_short if group else 0) if short is None else short
        aps=APS(12 if group else 0,None if group else 8,10 if group else None,6,0x104,8,22,ZCL(0x11,None,99,1,frame.raw).serialize()).serialize()
        h=le16(0x2208 if group else 0x0248)+le16(0xfffd if group else 0x1234)+le16(short)+b'\x3c\x11'
        return b'\x61\x88\x12'+le16(self.binding.pan if pan is None else pan)+le16(0 if group else 0x1234)+le16(short)+encrypt(h,b'\x28'+self.fc.to_bytes(4,'little')+ieee(source)+b'\0',aps,self.ledger.key)
    def rx(self,frame=None,**kw):
        self.rev+=1;self.fc+=1;self.now+=.01
        return self.app.receive(self.packet(frame or status(),**kw),self.rev,self.now)
    def ready(self):self.rx(baseline());self.rx(status())
    def test_confirmed_FAN_ctx1_exact_wire_and_one_field(self):
        self.ready();raw=self.app.prepare(self.now+.01);mac=MAC.parse(raw);nwk=NWK.parse(mac.payload)
        keys=KeyStore();keys.put(0,self.ledger.key.value);header,plain=decrypt(nwk,keys);zcl=ZCL.parse(APS.parse(plain).payload)
        self.assertEqual((mac.destination_pan,nwk.source,header.source_ieee,header.counter),(0x0b7a,0x1234,int(PROFILE['raw_ieee'],16),32))
        self.assertEqual([i for i,(x,y) in enumerate(zip(baseline().raw,zcl.payload)) if x!=y],[6,11,20])
        self.assertEqual(self.ledger.read()['next_fc'],64)
        self.app.handoff(self.now+.01);self.app.complete(0,self.now+.02,70140000)
        self.now+=.04
        self.rx(status(seq=self.app.confirmation.tx.sequence,fan=self.app.confirmation.tx.fan_raw+1))
        self.assertEqual(self.app.result,'CONFIRMED')
        durable(ROOT/'evidence/synthetic_ctx1_fan.json',{'synthetic_only':True,'hardware_performed':False,'RF_TX':0,'pan':'0B7A','raw_ieee':PROFILE['raw_ieee'],'short':'1234','counter':header.counter,'next_fc':64,'mutated_offsets':[6,11,20],'confirmation':'CONFIRMED'})
    def test_second_FAN_build_never_retries(self):
        self.ready();self.app.prepare(self.now+.01)
        with self.assertRaises(ValueError):self.app.prepare(self.now+.02)
        self.assertEqual(self.ledger.read()['next_fc'],64)
    def test_without_live_lossless_baseline_no_counter(self):
        self.rx(status())
        with self.assertRaises(ValueError):self.app.prepare(self.now+.01)
        self.assertEqual(self.ledger.read()['next_fc'],32)
    def test_stale_readiness_no_counter(self):
        self.ready()
        with self.assertRaises(ValueError):self.app.prepare(73)
        self.assertEqual(self.ledger.read()['next_fc'],32)
    def test_ctx0_key_after_binding_fails(self):
        self.ready();self.ledger.key=dataclasses.replace(self.ledger.key,ctx=0,pan=0xfa9b)
        with self.assertRaises(ValueError):self.app.prepare(self.now+.01)
    def test_wrong_epoch_or_generation_or_short_fails(self):
        self.ready();before=self.ledger.read()
        for field,value in [('key_epoch_id','1ea30211ee014345a8288337a173a833'),('generation',19),('short',0xa326),('pan',0xfa9b),('raw_ieee','e2b0275f4d582069')]:
            r=copy.deepcopy(before)
            if field in r:r[field]=value
            else:r['context'][field]=value
            durable(self.ledger.path,r)
            with self.subTest(field=field),self.assertRaises(ValueError):self.app.prepare(self.now+.01)
            durable(self.ledger.path,before)
    def test_cross_PAN_even_equal_key_cannot_update_replay(self):
        self.assertIsNone(self.rx(pan=0xfa9b));self.assertEqual(self.ledger.read()['nwk_source_floors'],{})
    def test_ctx0_peer_cannot_supply_baseline(self):
        self.assertIsNone(self.rx(baseline(),source='00124b00369c711f',short=0xc9b7));self.assertFalse(self.app.baseline.valid)
    def test_no_confirmation_without_fresh_matching_TYPE06(self):
        self.ready();self.app.prepare(self.now+.01);self.app.handoff(self.now+.01);self.app.complete(0,self.now+.02,70140000)
        self.rx(status());self.assertIsNone(self.app.result)
        self.app.tick(91);self.assertEqual(self.app.result,'FAILED_OR_UNKNOWN');self.assertEqual(self.ledger.read()['next_fc'],64)


if __name__=='__main__':unittest.main()
