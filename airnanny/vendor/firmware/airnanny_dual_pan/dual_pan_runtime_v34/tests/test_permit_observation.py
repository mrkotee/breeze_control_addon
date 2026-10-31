"""Synthetic keys only; no hardware or current-authority mutation."""
import sys
import unittest
import copy
from pathlib import Path

R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'host'))
import permit_observation as p
sys.path.insert(0,str(R/'tests'))
import test_recovery as v
from ledger import encrypt,ieee

BOOT='1'*32
def packet(payload=bytes.fromhex('080036000000006e02b401'),fc=3000000,source=p.TC,src=0,dst=0xfffc):
    header=p.le(0x0208)+p.le(dst)+p.le(src)+b'\x3c\xb4'
    return b'\x41\x88\x07'+p.le(0x0b7a)+p.le(0xffff)+p.le(src)+encrypt(
        header,b'\x28'+p.le(fc,4)+ieee(source)+b'\0',payload,v.KEY)

class Tests(unittest.TestCase):
    def setUp(self):
        self.o=p.PermitObservation(BOOT,10,100,2999999)
        self.f=dict(boot=BOOT,session='0',channel='21',fcs_ok='1',revision='11',time_us='101')
    def test_fresh_authenticated_exact_target_permit(self):
        e=self.o.receive(packet(),self.f,v.KEY)
        self.assertEqual((e.source,e.duration,e.significance),(p.TC,180,1))
        self.assertTrue(self.o.current(101));self.assertFalse(self.o.current(180000101))
    def test_duplicate_cannot_replace_evidence(self):
        e=self.o.receive(packet(),self.f,v.KEY)
        self.assertIsNone(self.o.receive(packet(fc=3000001),self.f,v.KEY))
        self.assertEqual(self.o.evidence,e)
    def test_bad_MIC_rejected(self):
        raw=packet();raw=raw[:-1]+bytes([raw[-1]^1])
        self.assertIsNone(self.o.receive(raw,self.f,v.KEY))
    def test_controller_origin_rejected(self):
        self.assertIsNone(self.o.receive(packet(source='00124b0036a18944',src=0xf59f),self.f,v.KEY))
    def test_stale_NWK_floor_rejected(self):
        self.assertIsNone(self.o.receive(packet(fc=2999999),self.f,v.KEY))
    def test_wrong_capture_context_rejected(self):
        for k,value in (('boot','2'*32),('session','1'),('channel','20'),('fcs_ok','0'),('revision','10'),('time_us','100')):
            f=copy.deepcopy(self.f);f[k]=value
            self.assertIsNone(self.o.receive(packet(),f,v.KEY))
    def test_close_network_wrong_duration_and_unknown_flags_rejected(self):
        for tail in (b'\0\x01',b'\xb4\0',b'\xff\x01',b'\xb4\x02'):
            payload=bytes.fromhex('080036000000006e02')+tail
            self.assertIsNone(self.o.receive(packet(payload),self.f,v.KEY))
    def test_wrong_ZDO_transport_rejected(self):
        for index in (0,1,2,3,4,5,6):
            payload=bytearray.fromhex('080036000000006e02b401');payload[index]^=1
            self.assertIsNone(self.o.receive(packet(bytes(payload)),self.f,v.KEY))
    def test_wrong_NWK_destination_rejected(self):
        self.assertIsNone(self.o.receive(packet(dst=0x6c55),self.f,v.KEY))
    def test_counter_and_transaction_bytes_may_vary(self):
        payload=bytearray.fromhex('080036000000006e02b401');payload[7:9]=b'\x99\x88'
        self.assertIsNotNone(self.o.receive(packet(bytes(payload)),self.f,v.KEY))
    def test_ordinary_status_is_not_pairing_evidence(self):
        self.assertIsNone(self.o.receive(packet(b'\0'*34),self.f,v.KEY))

if __name__=='__main__':unittest.main()
