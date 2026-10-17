"""Synthetic ignored local test state only; no production identities allocated."""
from pathlib import Path
import sys, tempfile, json, unittest
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'tools'))
from identity_store import allocate, attempt, save_associated, wire
class Identity(unittest.TestCase):
    def setUp(self):
        (R/'.local').mkdir(exist_ok=True);self.tmp=tempfile.TemporaryDirectory(prefix='synthetic-test-',dir=str(R/'.local'));self.p=Path(self.tmp.name);self.forbidden=['00124b0000000001','00124b0000000002','00124b0000000003']
    def tearDown(self):self.tmp.cleanup()
    def test_stable(self):
        r=allocate(self.p,0,self.forbidden,candidate='0200000000000011');self.assertEqual(allocate(self.p,0,self.forbidden),r);self.assertEqual(r['wire_ieee_le'],'1100000000000002');self.assertEqual(r['state'],'ALLOCATED_UNUSED')
    def test_two_contexts_distinct(self):
        allocate(self.p,0,self.forbidden,candidate='0200000000000011')
        with self.assertRaises(ValueError):allocate(self.p,1,self.forbidden,candidate='0200000000000011')
        a=allocate(self.p,1,self.forbidden,candidate='0200000000000012');self.assertEqual(a['raw_ieee'],'0200000000000012')
    def test_forbidden(self):
        for value in self.forbidden:
            with self.assertRaises(ValueError):allocate(self.p,0,self.forbidden,'allocated_eui_v1',value)
    def test_bad_identities(self):
        for a in ['0000000000000000','ffffffffffffffff','0300000000000001','ABCDEF0123456789','short']:
            with self.assertRaises(ValueError):wire(a)
    def test_policy(self):
        with self.assertRaises(ValueError):allocate(self.p,0,self.forbidden,'allocated_eui_v1')
        with self.assertRaises(ValueError):allocate(self.p,0,self.forbidden,candidate='00124b0000000009')
        with self.assertRaises(ValueError):allocate(self.p,0,[],candidate='0200000000000011')
    def test_attempt_reserved_before_tx(self):
        allocate(self.p,0,self.forbidden,candidate='0200000000000011');r=attempt(self.p,0,self.forbidden);self.assertEqual(r['state'],'ATTEMPT_RESERVED');self.assertEqual(len(r['attempt']),32)
        with self.assertRaises(ValueError):attempt(self.p,0,self.forbidden)
        self.assertEqual(json.loads((self.p/'ctx0.json').read_text(encoding='utf-8')),r)
    def test_associated_only(self):
        allocate(self.p,0,self.forbidden,candidate='0200000000000011');r=attempt(self.p,0,self.forbidden)
        with self.assertRaises(ValueError):save_associated(self.p,0,'old-attempt',0x1234,'00124b0000000001',0x1234)
        a=save_associated(self.p,0,r['attempt'],0x1234,'00124b0000000001',0x1234);self.assertEqual(a['state'],'ASSOCIATED_UNKEYED');self.assertFalse(any('key' in k or 'counter' in k for k in a))
        with self.assertRaises(ValueError):attempt(self.p,0,self.forbidden)
    def test_lock_fail_closed(self):
        (self.p/'owner.lock').write_text('synthetic stale lock',encoding='utf-8')
        with self.assertRaises(FileExistsError):allocate(self.p,0,self.forbidden,candidate='0200000000000011')
    def test_corrupt_store_fail_closed(self):
        (self.p/'ctx0.json').write_text('corrupt',encoding='utf-8')
        with self.assertRaises(ValueError):allocate(self.p,0,self.forbidden)
    def test_existing_conflict(self):
        allocate(self.p,0,self.forbidden,candidate='0200000000000011')
        with self.assertRaises(ValueError):allocate(self.p,0,self.forbidden+['0200000000000011'])
if __name__=='__main__':unittest.main()
