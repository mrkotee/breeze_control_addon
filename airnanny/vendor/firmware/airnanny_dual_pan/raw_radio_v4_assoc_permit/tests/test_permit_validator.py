"""Offline real encrypted fixtures; keys loaded locally, never written or printed."""
from pathlib import Path
import csv, json, os, sys, unittest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
R=Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'tools'))
from permit_validator import PermitValidator,codec
P=R.parent
f=json.loads((P/'evidence/pairing_pre_association_forensics_v1.json').read_text(encoding='utf-8'))
fixtures=[('historical136',f['focus_frames']['136']['mac_no_fcs'])]
fixtures.extend(('hardwareV1_'+str(x['revision']),x['mac']) for x in f['hardware_decoded_permit_messages'])
v2=json.loads((P/'evidence/pairing_trigger_observation_v2.json').read_text(encoding='utf-8'))
fixtures.extend(('hardwareV2_'+str(x['revision']),x['mac']) for x in v2['permit_messages'])
keys=[]
for line in (Path(os.environ['APPDATA'])/'Wireshark/zigbee_pc_keys').read_text().splitlines():
    if not line or line.startswith('#'):continue
    a=bytes.fromhex(next(csv.reader([line]))[0].replace(':','').replace('-','').replace(' ',''));keys.extend([a,a[::-1]])
key=None
for candidate in keys:
    try:
        m=codec.Mac.parse(bytes.fromhex(fixtures[0][1]));codec.secured_decode(m.payload[:8],m.payload[8:],candidate,(0x28,));key=candidate;break
    except Exception:pass
if key is None:raise RuntimeError('Local oracle key unavailable; no software READY claim')
del keys,candidate
class PermitTests(unittest.TestCase):
    def setUp(self):
        self.raw=bytes.fromhex(fixtures[0][1]);self.v=self.validator()
    def validator(self,**changes):
        args=dict(boot='1'*32,pan=0xfa9b,coordinator='00124b0036a148e5',key=key,key_sequence=0,key_epoch='selected_live_nwk_epoch0',generation=1,revision_floor=10)
        args.update(changes);return PermitValidator(**args)
    def validate(self,**changes):
        args=dict(raw=self.raw,boot='1'*32,revision=11,observed=100,now=101,generation=1);args.update(changes)
        return self.v.validate(**args)
    def rewritten(self,header=None,plain=None,aux=None):
        m=codec.Mac.parse(self.raw);n=m.payload;original,meta=codec.secured_decode(n[:8],n[8:],key,(0x28,))
        h=header or n[:8];a=aux or n[8:22];p=plain or original
        effective=bytes([(a[0]&~7)|5])+a[1:]
        nonce=a[5:13]+a[1:5]+effective[:1]
        m.payload=h+a+AESCCM(key,tag_length=4).encrypt(nonce,p,h+effective)
        return m.serialize()
    def test_all_four_positive_real_fixtures(self):
        self.assertEqual(len(fixtures),4)
        for name,raw in fixtures:
            with self.subTest(name=name):
                self.v=self.validator();e=self.validate(raw=bytes.fromhex(raw));self.assertEqual(e.permit_duration,180);self.assertEqual(e.tc_significance,1);self.v.reserve(e,101)
    def test_corrupted_MIC(self):
        b=bytearray(self.raw);b[-1]^=1
        with self.assertRaises(Exception):self.validate(raw=bytes(b))
    def test_wrong_pan(self):
        b=bytearray(self.raw);b[3:5]=bytes.fromhex('7a0b')
        with self.assertRaises(ValueError):self.validate(raw=bytes(b))
    def test_other_coordinator(self):
        self.v=self.validator(coordinator='00124b0036a1875f')
        with self.assertRaises(ValueError):self.validate()
    def test_nwk_source(self):
        n=bytearray(codec.Mac.parse(self.raw).payload[:8]);n[4]=1
        with self.assertRaises(ValueError):self.validate(raw=self.rewritten(header=bytes(n)))
    def test_nwk_destination(self):
        n=bytearray(codec.Mac.parse(self.raw).payload[:8]);n[2]=0xff
        with self.assertRaises(ValueError):self.validate(raw=self.rewritten(header=bytes(n)))
    def test_wrong_cluster_profile_duration_significance(self):
        m=codec.Mac.parse(self.raw);p,_=codec.secured_decode(m.payload[:8],m.payload[8:],key,(0x28,))
        for offset,value in ((2,0x35),(4,1),(9,0),(9,179),(10,0),(0,0)):
            q=bytearray(p);q[offset]=value
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):self.validate(raw=self.rewritten(plain=bytes(q)))
    def test_stale_revision_boot_attempt(self):
        for args in ({'revision':10},{'boot':'2'*32},{'generation':2},{'now':111},{'now':99}):
            with self.subTest(args=args),self.assertRaises(ValueError):self.validate(**args)
    def test_replay_FC(self):
        e=self.validate()
        with self.assertRaises(ValueError):self.validate(revision=12)
        self.assertGreater(e.security_frame_counter,0)
    def test_used_evidence(self):
        e=self.validate();self.v.reserve(e,101)
        with self.assertRaises(ValueError):self.v.reserve(e,102)
    def test_old_key_epoch(self):
        self.v=self.validator(key_sequence=1)
        with self.assertRaises(ValueError):self.validate()
    def test_arbitrary_secured_broadcast_TYPE06(self):
        # Valid MIC over non-permit plaintext must never authorize.
        for p in (b'ordinaryTYPE06status',b'arbitrarybroadcast'):
            with self.assertRaises(ValueError):self.validate(raw=self.rewritten(plain=p))
    def test_prime_current_FC(self):
        self.v.prime_observation(self.raw,11)
        with self.assertRaises(ValueError):self.validate(revision=12)
    def test_evidence_not_valid_after_context_change(self):
        e=self.validate()
        with self.assertRaises(ValueError):self.validator(boot='2'*32).reserve(e,101)
        with self.assertRaises(ValueError):self.validator(generation=2).reserve(e,101)
        with self.assertRaises(ValueError):self.v.reserve(e,111)
if __name__=='__main__':unittest.main()
