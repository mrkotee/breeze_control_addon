from pathlib import Path
import sys,unittest
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'tools'))
from attempt_plan import *
from permit_validator import PermitEvidence
class Plan(unittest.TestCase):
    def setUp(self):
        self.e=PermitEvidence('1'*32,655,'a'*64,100,0xfa9b,0,0,0xfffc,'00124b0036a148e5',1,0,'epoch',0,0x36,2,180,1,'00124b0036a148e5',1,0,110)
        self.r={'ctx':0,'raw_ieee':'0200000000000001','state':'ATTEMPT_RESERVED','forbidden_inventory':['00124b0036a148e5'],'policy':'local_experimental_v1','attempt':'2'*32}
    def test_command_bound(self):
        s=begin_command(self.e,self.r,2);self.assertLess(len(s),512);self.assertIn('BEGIN_PERMIT_EVIDENCE',s)
    def test_captured_request_shape(self):
        b=expected_request(self.r['raw_ieee']);self.assertEqual(b.hex(),'23c81e9bfa0000ffff01000000000000020180')
    def test_polls_bounded(self):
        self.assertEqual(len(expected_poll(self.r['raw_ieee'],0)),16)
        with self.assertRaises(ValueError):expected_poll(self.r['raw_ieee'],2)
    def test_no_forbidden_identity(self):
        self.r['raw_ieee']='00124b0036a148e5'
        with self.assertRaises(ValueError):begin_command(self.e,self.r,2)
    def test_strict_response(self):
        b=bytes.fromhex('63cc019bfa')+bytes.fromhex(self.r['raw_ieee'])[::-1]+bytes.fromhex(self.e.target_coordinator_ieee)[::-1]+bytes.fromhex('02341200')
        self.assertEqual(validate_response(b,self.r['raw_ieee'],self.e.target_coordinator_ieee,12,11)['assigned_short'],0x1234)
        for i in (0,3,5,13,21,24):
            q=bytearray(b);q[i]^=0xff
            with self.subTest(i=i),self.assertRaises(ValueError):validate_response(bytes(q),self.r['raw_ieee'],self.e.target_coordinator_ieee,12,11)
        with self.assertRaises(ValueError):validate_response(b,self.r['raw_ieee'],self.e.target_coordinator_ieee,11,11)
if __name__=='__main__':unittest.main()
