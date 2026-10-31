"""Gate D: evaluator, soak runner against a scripted firmware, Leave
handling, launcher refusals. No COM, no RF, no real keys."""
import json, sys, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'host'))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))
import gate_d
import gate_d_runner
from gate_d_runner import GateDRunner
import test_dual_application as A
import dual_store
from management import encrypt, ieee, le
from test_gate_b import polls

SEC = 1000000
GOOD_STATS = {'rx_total': '7', 'ctx0_rx': '2', 'ctx1_rx': '2', 'foreign_reject': '1',
              'cross_pair_reject': '0', 'malformed_reject': '0', 'unsupported': '3',
              'broadcast': '2', 'ambiguous': '0', 'routing_error': '0', 'routing_faults': '0',
              'ctx0_tuple_reject': '0', 'ctx1_tuple_reject': '0',
              'ctx0_tx_queue': '0', 'ctx1_tx_queue': '0', 'ctx0_tx_accepted': '70',
              'ctx1_tx_accepted': '70', 'ctx0_tx_terminal': '70', 'ctx1_tx_terminal': '70',
              'ctx0_tx_failed': '0', 'ctx1_tx_failed': '0', 'scheduler_starvation': '0',
              'starved_polls': '0', 'deep_reject': '0', 'ack_suppressed_scanning': '0',
              'ack_suppressed_disabled': '0'}


def leave(ctx, fc=5000000):
    """An authenticated NWK Leave from this context's TC to its device."""
    p = dual_store.PINNED[ctx]
    h = le(0x0209) + le(p['short']) + le(0) + b'\x1e\x11'
    return (b'\x61\x88\x12' + le(p['pan']) + le(p['short']) + le(0)
            + encrypt(h, b'\x28' + le(fc, 4) + ieee(p['tc_ieee']) + b'\x00',
                      b'\x04\x00', A.T.KEYS[ctx]))


class Evaluator(unittest.TestCase):
    def rows(self, gap_ctx=None):
        out = []
        for ctx in (0, 1):
            ts = [i * 60 * SEC + ctx * 30 * SEC for i in range(0, 61)]
            if ctx == gap_ctx:
                ts = [t for t in ts if not 20 * 60 * SEC <= t <= 30 * 60 * SEC]
            out += polls(ctx, ts)
        from test_gate_a import rx
        out += [rx(match=c, time_us=t * SEC) for t in (1, 2) for c in ('ctx0', 'ctx1')]
        return out

    def snaps(self, bad=None):
        return [{'at_s': t, 'stats': GOOD_STATS, 'status': {
            c: {'recovery': 'STOPPED' if (bad == c and t > 1800) else 'PARENT_LINK_ACTIVE'}
            for c in ('0', '1')}} for t in range(0, 3601, 300)]

    def ev(self, rows=None, snaps=None, stats=GOOD_STATS, end=3600, leaves=()):
        return gate_d.evaluate(rows if rows is not None else self.rows(),
                               snaps if snaps is not None else self.snaps(), stats,
                               0, end, 0, 3630 * SEC, 60.0, list(leaves))

    def test_a_clean_hour_passes(self):
        v = self.ev()
        self.assertTrue(v['passed'], v['reasons'])

    def test_a_short_soak_fails(self):
        self.assertTrue(any('lasted' in r for r in self.ev(end=1800)['reasons']))

    def drop(self, ctx, minutes):
        """rows() without the given minutes' polls of one context."""
        keep = []
        for r in self.rows():
            f = r.get('fields') or {}
            t = int(f.get('time_us', 0) or 0)
            if f.get('ctx') == str(ctx) and r['kind'] in ('AUTO_ACCEPT', 'AUTO_DONE') \
                    and any(abs(t - (m * 60 + ctx * 30) * SEC) < SEC for m in minutes):
                continue
            keep.append(r)
        return keep

    def test_two_misses_in_a_row_are_within_v27s_rule(self):
        """Attempt 2's shape: a 180 s gap, two polls missed and the third ACKed."""
        v = self.ev(rows=self.drop(1, (20, 21)))
        self.assertTrue(v['passed'], v['reasons'])
        self.assertEqual(v['links']['ctx1']['max_gap_s'], 180)

    def test_three_missed_periods_are_beyond_it(self):
        v = self.ev(rows=self.drop(1, (20, 21, 22)))
        self.assertTrue(any('ctx1' in r and '240 s gap' in r for r in v['reasons']), v['reasons'])

    def test_the_miss_rate_is_reported_not_judged(self):
        v = self.ev(rows=self.drop(1, (5, 15, 25, 35, 45, 55)))
        self.assertTrue(v['passed'], v['reasons'])
        self.assertLess(v['links']['ctx1']['acked_ratio'], 0.95)

    def test_v27_attempt_2_reevaluates_as_passed(self):
        p = ROOT / '.local/gate_d_v1/runs/7ff4895d8f23471c914731663f569c4f/outcome.json'
        if not p.exists():
            self.skipTest('the hardware outcome is not on this host')
        o = json.loads(p.read_text(encoding='utf-8'))
        s = o['soak']
        v = gate_d.evaluate(o['records'], o['snapshots'], o['stats'], s['start_s'], s['end_s'],
                            s['start_us'], s['end_us'], s['period_s'], o['leaves'])
        self.assertTrue(v['passed'], v['reasons'])
        self.assertEqual(v['poll_misses'], {'0': 0, '1': 8})

    def test_a_ten_minute_silence_fails_and_is_named(self):
        v = self.ev(rows=self.rows(gap_ctx=1))
        self.assertTrue(any('ctx1' in r and 'gap' in r for r in v['reasons']), v['reasons'])

    def test_a_context_that_stopped_mid_soak_fails(self):
        v = self.ev(snaps=self.snaps(bad='0'))
        self.assertTrue(any("ctx0 was 'STOPPED'" in r for r in v['reasons']))

    def test_any_crossing_counter_fails(self):
        for k in gate_d.CROSSING:
            with self.subTest(k):
                self.assertFalse(self.ev(stats=dict(GOOD_STATS, **{k: '1'}))['passed'])

    def test_a_missing_metric_fails(self):
        stats = {k: v for k, v in GOOD_STATS.items() if k != 'starved_polls'}
        self.assertTrue(any('starved_polls' in r for r in self.ev(stats=stats)['reasons']))

    def test_a_leave_is_reported_as_handled_degradation(self):
        v = self.ev(leaves=[{'ctx': 1, 'revision': 9, 'time_us': 1}])
        self.assertTrue(any('Leave' in r and 'degraded' in r for r in v['reasons']))

    def tx(self, ctx, cid, cls, result):
        return [{'kind': 'TXACCEPT', 'fields': {'ctx': str(ctx), 'id': str(cid), 'class': cls}},
                {'kind': 'TXDONE', 'fields': {'ctx': str(ctx), 'id': str(cid), 'result': result,
                                             'time_us': '1', 'poll': '0'}}]

    def test_a_failed_secured_tx_is_named(self):
        rows = self.rows() + self.tx(1, 9, 'END_DEVICE_TIMEOUT', 'no_ack')
        self.assertTrue(any('ctx1: a END_DEVICE_TIMEOUT TX failed (no_ack)' in r
                            for r in self.ev(rows=rows)['reasons']), self.ev(rows=rows)['reasons'])

    def test_an_isolated_poll_miss_is_counted_not_failed(self):
        rows = self.tx(1, 9, 'MANAGEMENT_POLL', 'no_ack') + self.rows()
        v = self.ev(rows=rows)
        self.assertTrue(v['passed'], v['reasons'])
        self.assertEqual(v['poll_misses'], {'0': 0, '1': 1})

    def test_three_poll_misses_in_a_row_fail(self):
        rows = sum((self.tx(1, 900 + i, 'MANAGEMENT_POLL', 'invalid_ack') for i in range(3)), [])
        v = self.ev(rows=rows + self.rows())
        self.assertTrue(any('3 keepalive polls in a row missed' in r for r in v['reasons']))

    def test_a_good_poll_between_misses_resets_the_run(self):
        rows = (self.tx(1, 901, 'MANAGEMENT_POLL', 'no_ack') + self.tx(1, 902, 'MANAGEMENT_POLL', 'no_ack')
                + self.tx(1, 903, 'MANAGEMENT_POLL', 'local_tx_ok') + self.tx(1, 904, 'MANAGEMENT_POLL', 'no_ack'))
        v = self.ev(rows=rows + self.rows())
        self.assertFalse([r for r in v['reasons'] if 'in a row' in r], v['reasons'])


class LeaveIsAnExplicitDegradation(A.Rig):
    def test_a_leave_from_this_contexts_parent_degrades_it(self):
        L = self.ledgers[1]
        self.assertEqual(L.observe_addressed(leave(1), 50), 'LEAVE')
        q = L.read()['recovery']
        self.assertEqual(q['state'], 'DEGRADED_LEAVE')
        self.assertEqual(q['leave']['revision'], 50)

    def test_the_other_contexts_leave_is_not_ours(self):
        before = self.ledgers[0].read()
        self.assertEqual(self.ledgers[0].observe_addressed(leave(1), 50), 'NOT_THIS_CONTEXT')
        self.assertEqual(self.ledgers[0].read(), before)

    def test_a_replayed_leave_changes_nothing(self):
        L = self.ledgers[0]
        L.observe_addressed(leave(0, fc=7000000), 1)
        r = L.read()
        r['recovery']['state'] = 'PARENT_LINK_ACTIVE'
        L._write(r)
        self.assertEqual(L.observe_addressed(leave(0, fc=7000000), 2), 'REPLAY_REJECTED')
        self.assertEqual(L.read()['recovery']['state'], 'PARENT_LINK_ACTIVE')


class SoakFirmware:
    """An hour of firmware: polls ACKed (or one failing on cue), STATUS and
    STATS over USB, and a Leave on cue."""

    def __init__(self, runner, fail_poll_at=None, leave_at=None, misses=1):
        self.r, self.t, self.cid = runner, 100.0, 0
        self.last = {0: 0.0, 1: 0.0}
        self.stopped = set()
        self.fail_poll_at, self.leave_at = fail_poll_at, leave_at
        self.left = False
        self.polls = {0: [], 1: []}
        self.misses_left = misses        # how many ctx1 polls miss from fail_poll_at on
        self.run = 0

    def clock(self):
        self.t += 0.05
        return self.t

    def read(self):
        if self.leave_at and not self.left and self.t >= self.leave_at:
            self.left = True
            self.r.records.append({'kind': 'RX', 'fields': {
                'match': 'ctx1', 'mac': leave(1).hex(), 'revision': '7777',
                'time_us': str(int(self.t * 1e6))}})

    def command(self, verb, ctx=None, fields='', raw=None, kind=None):
        self.cid += 1
        us = str(int(self.t * 1e6))
        if verb == 'STATUS':
            return {'recovery': 'STOPPED' if ctx in self.stopped else 'PARENT_LINK_ACTIVE',
                    'time_us': us}
        if verb == 'STATS':
            return dict(GOOD_STATS)
        if verb == 'MANAGEMENT_POLL':
            assert ctx not in self.stopped, 'polled a stopped context'
            assert self.t - self.last[ctx] >= 1.0, 'idle_poll_bound'
            self.last[ctx] = self.t
            self.polls[ctx].append(self.t)
            ok = not (self.fail_poll_at and ctx == 1 and self.t >= self.fail_poll_at
                      and self.misses_left > 0)
            if not ok:
                self.misses_left -= 1
                self.run += 1
                if self.run >= gate_d.MAX_CONSECUTIVE_POLL_MISSES:   # V27's rule
                    self.stopped.add(1)
            elif ctx == 1:
                self.run = 0
            done = {'ctx': str(ctx), 'id': str(self.cid), 'poll': '0', 'time_us': us,
                    'result': 'local_tx_ok' if ok else 'no_ack', 'ack_present': '1' if ok else '0'}
            self.r.records += [{'kind': 'TXACCEPT', 'fields': {'ctx': str(ctx), 'id': str(self.cid),
                                                               'class': 'MANAGEMENT_POLL'}},
                               {'kind': 'TXDONE', 'fields': done}]
            return done
        raise AssertionError(verb)


class Soak(A.Rig):
    def runner(self, **kw):
        r = GateDRunner.__new__(GateDRunner)
        r.ledgers = self.ledgers
        r.records, r.answers, r.sent_order, r.authenticated = [], [], [], set()
        r.adapters, r.prompted_at, r.fed = {}, {}, 0
        r.last_poll = {0: None, 1: None}
        r.polls_sent = {0: 0, 1: 0}
        r.period, r.stopped, r.leaves, r.snapshots = 60.0, {}, [], []
        r.misses_in_a_row, r.misses_total = {0: 0, 1: 0}, {0: 0, 1: 0}
        fw = SoakFirmware(r, **kw)
        r.clock, r.command = fw.clock, fw.command
        r.w = type('W', (), {'boot': A.BOOT, 'read': staticmethod(fw.read)})()
        r.prompt = lambda text: None
        return r, fw

    def test_an_hour_at_one_poll_a_minute_per_context(self):
        r, fw = self.runner()
        t0, t1, us0, us1 = r.soak(3600, fw.t)
        self.assertGreaterEqual(t1 - t0, 3600)
        for ctx in (0, 1):
            self.assertTrue(59 <= len(fw.polls[ctx]) <= 61, len(fw.polls[ctx]))
        self.assertEqual(len(r.snapshots), 13)       # start, 11 inside the hour, end
        v = gate_d.evaluate(r.records + [__import__('test_gate_a').rx(match=c, time_us=1)
                                         for c in ('ctx0', 'ctx1')],
                            r.snapshots, r.snapshots[-1]['stats'], t0, t1, us0, us1, 60.0, r.leaves)
        self.assertTrue(v['passed'], v['reasons'])

    def test_it_stops_before_the_firmware_session_limit(self):
        r, fw = self.runner()
        t0, t1, _, _ = r.soak(3600, fw.t - 300)       # BIND was 5 min before the soak
        self.assertLessEqual(t1 - (t0 - 300), gate_d_runner.SESSION_LIMIT_S)

    def test_one_missed_poll_is_survived_by_v27(self):
        r, fw = self.runner(fail_poll_at=1200, misses=1)
        r.soak(3600, fw.t)
        self.assertNotIn(1, r.stopped)
        self.assertEqual(r.misses_total[1], 1)
        self.assertGreater(len(fw.polls[1]), 55)

    def test_three_in_a_row_stop_that_context_and_the_other_carries_on(self):
        r, fw = self.runner(fail_poll_at=1200, misses=3)
        r.soak(3600, fw.t)
        self.assertEqual(r.stopped.get(1), 'poll_misses_in_a_row:3')
        self.assertGreater(len(fw.polls[0]), 55)
        self.assertLess(len(fw.polls[1]), 25)

    def test_a_leave_degrades_that_context_and_polling_stops(self):
        r, fw = self.runner(leave_at=900)
        r.soak(3600, fw.t)
        self.assertEqual(r.stopped.get(1), 'leave')
        self.assertEqual(self.ledgers[1].read()['recovery']['state'], 'DEGRADED_LEAVE')
        self.assertTrue(all(t <= 900 + 61 for t in fw.polls[1]))


class LauncherRefusals(unittest.TestCase):
    def test_no_health_statement_no_prepare(self):
        import launch_gate_d as D
        with self.assertRaises(D.authority.AuthorityFault):
            D.prepare('  ')

    def test_gate_c_must_carry_the_operators_after_statement(self):
        src = (ROOT / 'launch_gate_d.py').read_text(encoding='utf-8')
        self.assertIn('gate_c_has_no_operator_health_after', src)

    def test_too_fast_a_period_is_refused(self):
        src = (ROOT / 'launch_gate_d.py').read_text(encoding='utf-8')
        self.assertIn('args.period < 1.1', src)


if __name__ == '__main__':
    unittest.main()
