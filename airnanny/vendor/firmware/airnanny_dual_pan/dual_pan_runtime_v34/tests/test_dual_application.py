"""Gate C's per-context FAN adapter, offline. No COM, no RF, no real keys.

Real ledgers over disposable stores, real encryption under each context's
synthetic key, the frozen airnanny2mqtt control core underneath. What is
driven: that each context accepts only its own status and its own remote's
baseline, that the frame it builds is the envelope the firmware accepts
(rejoin_transport.c:81-85), and that one command is all there ever is.
"""
import json, shutil, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'host'))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[3] / 'host/airnanny2mqtt/tests'))
import dual_ledger
import dual_store
import test_dual_ledger as T
from dual_application import ContextFanControl, REMOTES, target_fan, TYPE07_LENGTH
from recovery_model import Fault
from management import decode_nwk, encrypt, ieee, le
from airnanny.application import Type07
from airnanny.aps import APS
from airnanny.zcl import ZCL
from control_support import baseline, status

GUARD = 'c' * 32
BOOT = 'a' * 32


def frame(ctx, app, fc, key=None, pan=None, remote_short=None):
    """An encrypted TYPE06 from this context's A7 to its remote, or a TYPE07
    from this context's remote, as the networks carry them (shapes as in the
    inherited test_first_control.packet, identities per context)."""
    p = dual_store.PINNED[ctx]
    remote = dict(REMOTES[ctx])
    if remote_short is not None:
        remote['short'] = remote_short
    group = isinstance(app, Type07)
    aps = APS(12 if group else 0, None if group else 8, 10 if group else None,
              6, 0x104, 8, 22, ZCL(0x11, None, 99, 1, app.raw).serialize()).serialize()
    src = remote['short'] if group else 0
    nwk_dst = 0xfffd if group else remote['short']
    mac_dst = 0 if group else remote['short']
    source = remote['ieee'] if group else p['tc_ieee']
    h = le(0x2208 if group else 0x0208) + le(nwk_dst) + le(src) + b'\x3c\x11'
    pan = p['pan'] if pan is None else pan
    return (b'\x61\x88\x12' + le(pan) + le(mac_dst) + le(src)
            + encrypt(h, b'\x28' + le(fc, 4) + ieee(source) + b'\x00', aps,
                      key or T.KEYS[ctx]))


class Rig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dual_ledger.SIMULATION_ROOT.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=str(dual_ledger.SIMULATION_ROOT)))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        roots = {}
        for ctx in (0, 1):
            d = self.tmp / ('ctx%d' % ctx)
            d.mkdir()
            rec = T.record(ctx)
            rec['sequences']['zcl'] = 5
            pin = dual_store.PINNED[ctx]
            rec['context'].update(ctx=ctx, raw_ieee=pin['raw_ieee'], tc_ieee=pin['tc_ieee'],
                                  attempt=pin['attempt'])
            rec.update(keyseq=pin['keyseq'], key_epoch_id=pin['epoch'])
            rec['recovery'] = {'state': 'PARENT_LINK_ACTIVE', 'gate': GUARD, 'intents': {}}
            (d / 'epoch.json').write_text(json.dumps(rec), encoding='utf-8')
            roots[ctx] = d
        self.ledgers = dual_ledger.pair(T.KEYS, roots=roots)
        self.fc, self.rev, self.now, self.us = 3000000, 100, 70.0, 70000000

    def adapter(self, ctx=0):
        a = ContextFanControl(self.ledgers[ctx], BOOT, self.now)
        a.radio_floor = self.us
        return a

    def rx(self, a, app, ctx=None, **kw):
        ctx = a.ctx if ctx is None else ctx
        self.fc += 1; self.rev += 1; self.now += 0.01; self.us += 10000
        return a.receive(frame(ctx, app, self.fc, **kw), self.rev, self.now, self.us)

    def ready(self, a, fan=4, seq=10):
        self.assertEqual(self.rx(a, baseline(seq=seq, fan=fan)), 'APPLICATION_AUTHENTICATED')
        self.assertEqual(self.rx(a, status(seq=seq, fan=fan)), 'APPLICATION_AUTHENTICATED')
        self.assertTrue(a.ready())


class TheDirectionRule(unittest.TestCase):
    def test_plus_one_below_the_top_minus_one_at_it(self):
        self.assertEqual([target_fan(f) for f in range(1, 8)], [2, 3, 4, 5, 6, 7, 6])


class EachContextHearsOnlyItsOwn(Rig):
    def test_its_own_status_and_its_own_remote(self):
        for ctx in (0, 1):
            a = self.adapter(ctx)
            self.assertEqual(a.classify(frame(ctx, status(), 1))[0], 'status')
            self.assertEqual(a.classify(frame(ctx, baseline(), 2))[0], 'remote')

    def test_the_other_networks_frames_are_not_ours(self):
        a = self.adapter(0)
        self.assertIsNone(a.classify(frame(1, status(), 1)))
        self.assertIsNone(a.classify(frame(1, baseline(), 2)))

    def test_our_key_on_the_other_pan_is_not_ours(self):
        a = self.adapter(0)
        self.assertIsNone(a.classify(frame(0, status(), 1, pan=dual_store.PINNED[1]['pan'])))

    def test_nothing_before_the_radio_floor_counts(self):
        a = self.adapter(0)
        a.radio_floor = 10 ** 12
        self.assertEqual(self.rx(a, status()), 'APPLICATION_STALE')
        self.assertIsNone(a.status)

    def test_a_replayed_frame_is_stale(self):
        a = self.adapter(0)
        raw = frame(0, status(), 5000000)
        self.assertEqual(a.receive(raw, 1, 71, 80000000), 'APPLICATION_AUTHENTICATED')
        self.assertEqual(a.receive(raw, 2, 72, 80000001), 'APPLICATION_STALE')


class OneCommand(Rig):
    def test_no_baseline_no_command_and_no_counter(self):
        a = self.adapter(0)
        self.rx(a, status())
        fc = self.ledgers[0].read()['next_fc']
        with self.assertRaises(Fault):
            a.prepare(self.now)
        self.assertEqual(self.ledgers[0].read()['next_fc'], fc)

    def test_the_frame_is_the_envelope_the_firmware_accepts(self):
        for ctx in (0, 1):
            with self.subTest(ctx=ctx):
                a = self.adapter(ctx)
                self.ready(a)
                fc = self.ledgers[ctx].read()['next_fc']
                raw, intent = a.prepare(self.now)
                p = dual_store.PINNED[ctx]
                u16 = lambda i: raw[i] | raw[i + 1] << 8
                self.assertEqual(len(raw), TYPE07_LENGTH)
                self.assertEqual((u16(0), u16(3), u16(5), u16(7)), (0x8861, p['pan'], 0, p['short']))
                self.assertEqual((u16(9), u16(11), u16(13), raw[15]), (0x2208, 0xfffd, p['short'], 60))
                aux = raw[17:]
                self.assertEqual(aux[0], 0x28)
                self.assertEqual(int.from_bytes(aux[1:5], 'little'), fc)
                self.assertEqual(aux[5:13], ieee(p['raw_ieee']))
                self.assertEqual(intent['fc'], fc)
                _, plain, _ = decode_nwk(raw, T.KEYS[ctx], 0, pan=p['pan'])
                payload = ZCL.parse(APS.parse(plain).payload).payload
                self.assertEqual([i for i, (x, y) in enumerate(zip(baseline().raw, payload))
                                  if x != y], [6, 11, 20])
                self.assertEqual(payload[11], 4)        # FAN 4 -> 5, raw = level-1

    def test_the_counter_is_spent_before_the_frame_and_recorded(self):
        a = self.adapter(0)
        self.ready(a)
        before = self.ledgers[0].read()['next_fc']
        raw, _ = a.prepare(self.now)
        r = self.ledgers[0].read()
        i = r['recovery']['intents']['TYPE07']
        self.assertEqual(r['next_fc'], before + 32)
        self.assertEqual(i['phase'], 'BUILT_NEVER_RETRY')
        import hashlib
        self.assertEqual(i['sha256'], hashlib.sha256(raw).hexdigest())

    def test_never_a_second_command_not_even_from_a_new_adapter(self):
        a = self.adapter(0)
        self.ready(a)
        a.prepare(self.now)
        with self.assertRaises(Fault):
            a.prepare(self.now)
        b = self.adapter(0)
        self.ready(b, seq=11)
        with self.assertRaises(Fault) as e:
            b.prepare(self.now)
        self.assertIn('one_command_NO_RETRY', str(e.exception))

    def test_at_the_top_level_it_steps_down(self):
        a = self.adapter(1)
        self.ready(a, fan=7)
        raw, intent = a.prepare(self.now)
        self.assertEqual((intent['from_fan'], intent['requested']), (7, 6))

    def test_only_on_a_live_parent_link(self):
        r = self.ledgers[0].read()
        r['recovery']['state'] = 'REJOINED'
        self.ledgers[0]._write(r)
        with self.assertRaises(Fault):
            ContextFanControl(self.ledgers[0], BOOT, self.now)


class Confirmation(Rig):
    def sent(self, ctx=0):
        a = self.adapter(ctx)
        self.ready(a)
        a.prepare(self.now)
        a.handoff(self.now)
        a.complete(True, self.now, self.us + 1)
        return a

    def test_a_matching_status_after_the_radio_start_confirms(self):
        a = self.sent(0)
        tx = a.confirmation.tx
        self.rx(a, status(seq=tx.sequence, fan=tx.fan_raw + 1))
        a.tick(self.now)
        self.assertEqual(a.result, 'CONFIRMED')
        i = self.ledgers[0].read()['recovery']['intents']['TYPE07']
        self.assertEqual((i['phase'], i['application_result']), ('CONCLUDED', 'CONFIRMED'))

    def test_no_matching_status_in_the_window_is_failed_or_unknown(self):
        a = self.sent(1)
        a.tick(self.now + 21)
        self.assertEqual(a.result, 'FAILED_OR_UNKNOWN')
        self.assertEqual(self.ledgers[1].read()['recovery']['intents']['TYPE07']
                         ['application_result'], 'FAILED_OR_UNKNOWN')

    def test_a_failed_local_send_never_confirms(self):
        a = self.adapter(0)
        self.ready(a)
        a.prepare(self.now); a.handoff(self.now)
        a.complete(False, self.now, self.us + 1)
        tx = a.confirmation.tx
        self.rx(a, status(seq=tx.sequence, fan=tx.fan_raw + 1))
        a.tick(self.now + 21)
        self.assertEqual(a.result, 'FAILED_OR_UNKNOWN')

    def test_the_other_contexts_status_cannot_confirm(self):
        a = self.sent(0)
        tx = a.confirmation.tx
        self.assertIsNone(self.rx(a, status(seq=tx.sequence, fan=tx.fan_raw + 1), ctx=1))
        a.tick(self.now + 21)
        self.assertEqual(a.result, 'FAILED_OR_UNKNOWN')

    def test_one_context_command_leaves_the_other_store_alone(self):
        before = self.ledgers[1].read()
        self.sent(0)
        self.assertEqual(self.ledgers[1].read(), before)


class AReparedRemoteIsKnownByItsIeee(Rig):
    """0B7A's remote was re-paired on 2026-10-13, so its short may be new.
    Its IEEE cannot change, and that is what the adapter holds it to."""

    def test_the_new_short_is_learned_from_the_remotes_own_frame(self):
        a = self.adapter(1)
        self.assertEqual(self.rx(a, baseline(), remote_short=0x1234), 'APPLICATION_AUTHENTICATED')
        self.assertEqual(a.remote['short'], 0x1234)
        self.assertEqual(self.rx(a, status(), remote_short=0x1234), 'APPLICATION_AUTHENTICATED')
        self.assertTrue(a.ready())
        self.assertEqual(REMOTES[1]['short'], 0xF59F)      # the pin itself is untouched

    def test_another_device_with_that_short_is_not_the_remote(self):
        a = self.adapter(1)
        raw = frame(1, baseline(), 4000000, remote_short=0x1234)
        other = dict(REMOTES[1], ieee='00124b0000000001')
        a.remote = other
        self.assertIsNone(a.classify(raw))


class TheRemotesAreTheOnesTheStoresKnow(unittest.TestCase):
    def test_each_remote_ieee_is_a_replay_floor_in_its_own_store(self):
        for ctx in (0, 1):
            path = dual_store.STORE_PATHS[ctx]
            if not Path(path).exists():
                self.skipTest('live stores not on this host')
            floors = json.loads(Path(path).read_text(encoding='utf-8'))['nwk_source_floors']
            self.assertIn(REMOTES[ctx]['ieee'], floors, ctx)
            self.assertNotIn(REMOTES[1 - ctx]['ieee'], floors, ctx)


if __name__ == '__main__':
    unittest.main()
