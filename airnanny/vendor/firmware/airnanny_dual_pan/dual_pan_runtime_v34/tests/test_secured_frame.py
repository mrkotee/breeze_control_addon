"""Offline tests for secured frame building. No COM, no RF, no hardware.

Two things are established here. First, that the extraction from Ledger._build
is faithful: for ctx1's tuple the bytes are IDENTICAL to what the inherited
model produces, so nothing was changed while moving it. Second, that the PAN
is now genuinely per-context -- the constant 0x0b7a that V25 could afford is
the one thing a dual runtime cannot.
"""
import os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'host'))
sys.path.insert(0, HERE)
import secured_frame
from recovery_model import RAW, TC, Secret, Fault
import dual_store

KEY = Secret(bytes(range(16)))
SEQ = {'nwk': 11, 'dsn': 22, 'aps': 33, 'zdo': 44}
CTX1_PAN = dual_store.PINNED[1]['pan']
CTX0_PAN = dual_store.PINNED[0]['pan']


def build(kind, pan=CTX1_PAN, short=0x6c55, fc=2000, **kw):
    kw.setdefault('raw_ieee', RAW)
    kw.setdefault('tc_ieee', TC)
    return secured_frame.build_secured(
        kind, pan=pan, short=short, fc=fc, sequences=SEQ, key=KEY, **kw)


class TheExtractionIsFaithful(unittest.TestCase):
    def test_every_kind_builds_at_its_measured_length(self):
        for kind, n in secured_frame.LENGTH.items():
            raw, _ = build(kind)
            self.assertEqual(len(raw), n, kind)

    def test_the_bytes_match_the_inherited_construction(self):
        """Rebuilt here exactly as Ledger._build wrote it, including the
        hardcoded ctx1 PAN. If the extraction drifted, these differ."""
        from management import le, ieee
        from recovery_model import encrypt
        for kind in secured_frame.KINDS:
            mac = b'\x61\x88' + bytes([SEQ['dsn']]) + le(0x0b7a) + le(0) + le(0x6c55)
            if kind == 'ANNOUNCE':
                h = b'\x08\x02' + le(0xfffd) + le(0x6c55) + b'\x3c' + bytes([SEQ['nwk']])
                p = (b'\x08\0\x13\0\0\0\0' + bytes([SEQ['aps'], SEQ['zdo']])
                     + le(0x6c55) + ieee(RAW) + b'\x80')
            else:
                h = (b'\x09\x1a' + le(0) + le(0x6c55) + b'\x01' + bytes([SEQ['nwk']])
                     + ieee(TC) + ieee(RAW))
                p = b'\x06\x80' if kind == 'REJOIN' else b'\x0b\x08\0'
            want = mac + encrypt(h, b'\x28' + le(2000, 4) + ieee(RAW) + b'\0', p, KEY)
            self.assertEqual(build(kind)[0], want, kind)

    def test_the_dsn_steps_are_carried_over_unchanged(self):
        self.assertEqual(secured_frame.dsn_step('REJOIN'), 6)
        self.assertEqual(secured_frame.dsn_step('TIMEOUT'), 6)
        self.assertEqual(secured_frame.dsn_step('ANNOUNCE'), 1)

    def test_advance_returns_rather_than_mutates(self):
        """The caller owns the store, so it decides when a counter becomes
        durable. A function that mutated in place would make that decision."""
        before = dict(SEQ)
        after = secured_frame.advance(SEQ, 'ANNOUNCE')
        self.assertEqual(SEQ, before)
        self.assertEqual(after['nwk'], 12)
        self.assertEqual(after['dsn'], 23)
        self.assertEqual((after['aps'], after['zdo']), (34, 45))

    def test_the_sequence_counters_wrap_at_a_byte(self):
        after = secured_frame.advance({'nwk': 255, 'dsn': 252, 'aps': 255,
                                       'zdo': 255}, 'REJOIN')
        self.assertEqual(after['nwk'], 0)
        self.assertEqual(after['dsn'], 2)


class ThePanIsPerContext(unittest.TestCase):
    def test_the_pan_reaches_the_wire(self):
        """The literal 0x0b7a in Ledger._build is ctx1's PAN. A dual runtime
        that kept it would address ctx0's frames to ctx1's network while
        encrypting them with ctx0's key."""
        raw, _ = build('REJOIN', pan=CTX0_PAN, short=dual_store.PINNED[0]['short'])
        self.assertEqual(int.from_bytes(raw[3:5], 'little'), CTX0_PAN)
        self.assertNotEqual(CTX0_PAN, CTX1_PAN)

    def test_the_two_contexts_build_different_frames(self):
        a, _ = build('REJOIN', pan=CTX0_PAN, short=dual_store.PINNED[0]['short'])
        b, _ = build('REJOIN', pan=CTX1_PAN, short=dual_store.PINNED[1]['short'])
        self.assertNotEqual(a, b)
        self.assertNotEqual(a[3:5], b[3:5])          # destination PAN
        # [5:7] is the destination short, zero in both: these frames go to the
        # coordinator. The SOURCE short at [7:9] is what differs per context.
        self.assertEqual(a[5:7], b[5:7])
        self.assertNotEqual(a[7:9], b[7:9])

    def test_an_implausible_tuple_is_refused(self):
        for pan, short in ((CTX0_PAN, 0), (CTX0_PAN, 0xfff8), (0xffff, 0x1234)):
            with self.assertRaises(Fault):
                build('REJOIN', pan=pan, short=short)


class TheSelfCheckRefusesBeforeAnythingIsSpent(unittest.TestCase):
    """A frame counter spent on a bad frame can never be reused, and a frame
    addressed wrongly can reach the other network. So the check happens before
    the bytes are returned, not after they are on air."""

    def test_a_decode_under_the_wrong_key_would_not_pass(self):
        raw, _ = build('REJOIN')
        from management import decode_nwk
        with self.assertRaises(Exception):
            decode_nwk(raw, Secret(bytes(16)))

    def test_an_exhausted_frame_counter_is_refused(self):
        with self.assertRaises(Fault) as e:
            build('REJOIN', fc=0xffffffe0)
        self.assertIn('FC_exhaustion', str(e.exception))

    def test_an_unknown_kind_is_refused(self):
        for kind in ('TYPE07', 'POLL', ''):
            with self.assertRaises(Fault):
                build(kind)

    def test_the_digest_is_of_the_bytes_returned(self):
        import hashlib
        raw, digest = build('ANNOUNCE')
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())


class ItHasNoAuthority(unittest.TestCase):
    def test_the_module_cannot_reach_a_store_or_a_port(self):
        """The point of the extraction: the launcher may write a real store,
        this may not. Imports are the cheapest place to prove that."""
        with open(os.path.join(HERE, '..', 'host', 'secured_frame.py'),
                  encoding='utf-8') as fh:
            src = fh.read()
        # Code only: the prose above explains WHY it may not write a store, so
        # scanning the whole file would fail on its own explanation.
        code = []
        in_doc = False
        for line in src.splitlines():
            if line.strip().startswith('"""') or line.strip().endswith('"""'):
                in_doc = not in_doc if line.count('"""') == 1 else in_doc
                continue
            if not in_doc and not line.strip().startswith('#'):
                code.append(line)
        code = '\n'.join(code)
        for forbidden in ('import serial', 'open(', 'Path(', 'durable',
                          'store', 'write_text', 'ledger', 'json'):
            self.assertNotIn(forbidden, code, forbidden)


if __name__ == '__main__':
    unittest.main()
