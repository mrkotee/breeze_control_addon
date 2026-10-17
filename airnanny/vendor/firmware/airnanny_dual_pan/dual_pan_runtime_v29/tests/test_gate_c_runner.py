"""GateCRunner.command_fan against a scripted firmware. No COM, no RF.

Real ledgers over disposable stores and real encrypted frames from
test_dual_application; the firmware is a function that applies the rules
rejoin_transport.c applies (poll spacing, the 2 s freshness, one TYPE07) and
plays the remote and the A7. The press arrives only after the prompt, as it
would from a person.
"""
import sys, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'host'))
sys.path.insert(0, str(HERE))
import gate_c_runner
from gate_c_runner import GateCRunner
from rejoin_wire import Fault
import test_dual_application as A
from control_support import baseline, status


class Firmware:
    def __init__(self, rig, runner, press_after_prompt=True, confirm=True):
        self.rig, self.r = rig, runner
        self.t = 100.0                       # host seconds; radio us = t * 1e6
        self.last_poll = {0: 90.0, 1: 90.0}
        self.type07 = {0: 0, 1: 0}
        self.prompted = None
        self.prompted_at = 0.0
        self.press_delay = 10
        self.press = press_after_prompt
        self.confirm = confirm
        self.rev = 1000
        self.fc = 4000000
        self.pending_rx = []
        self.fan = {0: 4, 1: 4}
        self.seq = {0: 10, 1: 10}
        self.cid = 0

    def clock(self):
        self.t += 0.01
        return self.t

    def rx(self, ctx, app, delay=0.05):
        self.fc += 1
        self.pending_rx.append((self.t + delay, A.frame(ctx, app, self.fc)))

    def read(self):
        for item in list(self.pending_rx):
            at, raw = item
            if self.t >= at:
                self.pending_rx.remove(item)
                self.rev += 1
                self.r.records.append({'kind': 'RX', 'fields': {
                    'mac': raw.hex(), 'revision': str(self.rev),
                    'time_us': str(int(self.t * 1e6))}})
                return
        if self.prompted is not None and self.press and self.t >= self.prompted_at + self.press_delay:
            ctx = self.prompted
            self.prompted = None
            self.fan[ctx] -= 1                       # the operator pressed FAN-
            self.seq[ctx] += 1
            self.rx(ctx, baseline(seq=self.seq[ctx], fan=self.fan[ctx]))
            self.rx(ctx, status(seq=self.seq[ctx], fan=self.fan[ctx]), delay=0.35)

    def command(self, verb, ctx=None, fields='', raw=None, kind=None):
        self.cid += 1
        f = dict(x.split('=', 1) for x in fields.split() if '=' in x)
        us = str(int(self.t * 1e6))
        if verb == 'STATUS':
            return {'recovery': 'PARENT_LINK_ACTIVE', 'pending': '0', 'time_us': us}
        if verb == 'MANAGEMENT_POLL':
            assert self.t - self.last_poll[ctx] >= 1.0, 'idle_poll_bound ctx%d' % ctx
            self.last_poll[ctx] = self.t
            done = {'ctx': str(ctx), 'id': str(self.cid), 'result': 'local_tx_ok',
                    'ack_present': '1', 'time_us': us, 'poll': '0'}
            self.r.records += [{'kind': 'TXACCEPT', 'fields': {'ctx': str(ctx), 'id': str(self.cid),
                                                               'class': 'MANAGEMENT_POLL'}},
                               {'kind': 'TXDONE', 'fields': done}]
            return done
        if verb == 'TYPE07_FAN':
            assert self.t - self.last_poll[ctx] <= 2.0, 'application_live_readiness'
            assert len(raw) == 68
            self.type07[ctx] += 1
            assert self.type07[ctx] == 1, 'application_once'
            done = {'ctx': str(ctx), 'id': str(self.cid), 'result': 'local_tx_ok',
                    'time_us': us, 'rf_start_us': str(int(self.t * 1e6) - 500)}
            self.r.records += [{'kind': 'TXACCEPT', 'fields': {'ctx': str(ctx), 'id': str(self.cid),
                                                               'class': 'TYPE07_FAN'}},
                               {'kind': 'TXDONE', 'fields': done}]
            if self.confirm:
                a = self.r.adapters[ctx]
                tx = a.confirmation.tx
                self.rx(ctx, status(seq=tx.sequence, fan=tx.fan_raw + 1), delay=0.3)
            return done
        raise AssertionError('unexpected verb %s' % verb)


class Drive(A.Rig):
    def runner(self, **kw):
        r = GateCRunner.__new__(GateCRunner)
        r.ledgers = self.ledgers
        r.records, r.answers, r.sent_order, r.authenticated = [], [], [], set()
        r.adapters, r.fed = {}, 0
        r.prompted_at = {}
        r.last_poll = {0: None, 1: None}
        r.polls_sent = {0: 40, 1: 40}          # readiness already done
        r.press = 'FAN-'
        fw = Firmware(self, r, **kw)
        lines = []

        def prompt(text):
            lines.append(text)
            if 'Нажмите' in text:
                fw.prompted = int(text.split('(ctx')[1][0])
                fw.prompted_at = fw.t                # a person takes ~10 s to press
        r.prompt = prompt
        r.clock = fw.clock
        r.command = fw.command
        r.w = type('W', (), {'boot': A.BOOT, 'read': staticmethod(fw.read)})()
        r.start_keepalive(gate_c_runner.SPARSE_PERIOD_S)
        return r, fw, lines

    def test_both_commands_confirm_and_return_each_fan_to_where_it_was(self):
        r, fw, lines = self.runner()
        for ctx in (0, 1):
            res = r.command_fan(ctx)
            self.assertEqual(res['application_result'], 'CONFIRMED', lines)
            self.assertEqual((res['from_fan'], res['requested']), (3, 4))   # pressed 4->3, we 3->4
        self.assertEqual(fw.type07, {0: 1, 1: 1})

    def test_no_press_means_nothing_is_spent(self):
        r, fw, lines = self.runner(press_after_prompt=False)
        gate_c_runner.BASELINE_WAIT_S, saved = 5, gate_c_runner.BASELINE_WAIT_S
        try:
            fc = self.ledgers[0].read()['next_fc']
            with self.assertRaises(Fault) as e:
                r.command_fan(0)
            self.assertIn('nothing was spent', str(e.exception))
            self.assertEqual(self.ledgers[0].read()['next_fc'], fc)
            self.assertEqual(fw.type07, {0: 0, 1: 0})
        finally:
            gate_c_runner.BASELINE_WAIT_S = saved

    def test_no_confirmation_is_failed_or_unknown_and_never_resent(self):
        r, fw, lines = self.runner(confirm=False)
        res = r.command_fan(0)
        self.assertEqual(res['application_result'], 'FAILED_OR_UNKNOWN')
        self.assertEqual(fw.type07[0], 1)

    def test_the_other_context_is_polled_all_the_way_through(self):
        r, fw, lines = self.runner()
        r.command_fan(0)
        polls1 = [float(x['fields']['time_us']) / 1e6 for x in r.records
                  if x['kind'] == 'TXDONE' and x['fields'].get('ctx') == '1'
                  and x['fields'].get('poll') == '0']
        gaps = [b - a for a, b in zip(polls1, polls1[1:])]
        self.assertGreater(len(polls1), 3)
        self.assertLess(max(gaps), 3.0)

    def test_the_prompt_names_the_network_and_the_button(self):
        r, fw, lines = self.runner()
        r.command_fan(1)
        self.assertTrue(any('FAN-' in l and '0B7A' in l for l in lines), lines)


class SpendAsFewAsTheFirmwareAllows(Drive):
    """Attempts 2 and 3 each died on one failed TX (a lost ACK, then an ACK
    with a bad CRC), because the firmware stops a context on the first. So
    the runner sends only what the firmware requires."""

    def polls(self, r, ctx, after=0.0, before=1e9):
        return [float(x['fields']['time_us']) / 1e6 for x in r.records
                if x['kind'] == 'TXDONE' and x['fields'].get('ctx') == str(ctx)
                and x['fields'].get('poll') == '0' and after <= float(x['fields']['time_us']) / 1e6 <= before]

    def test_readiness_is_forty_polls_per_context_and_prompts_near_its_end(self):
        r, fw, lines = self.runner()
        r.polls_sent = {0: 0, 1: 0}
        t0 = fw.t
        r.readiness(60)
        self.assertGreaterEqual(min(r.polls_sent.values()), gate_c_runner.MIN_POLLS)
        self.assertLessEqual(max(r.polls_sent.values()), gate_c_runner.MIN_POLLS + 1)
        self.assertIn(0, r.adapters)
        self.assertAlmostEqual(r.prompted_at[0] - t0, 45, delta=1)

    def test_waiting_for_a_press_is_sparse(self):
        r, fw, lines = self.runner()
        fw.press_delay = 60
        start = fw.t
        r.command_fan(0)
        waiting = self.polls(r, 1, start, start + 55)
        self.assertLessEqual(len(waiting), 7)          # ~every 10 s, not every 1.25

    def test_the_command_is_surrounded_by_dense_peer_polls(self):
        r, fw, lines = self.runner()
        res = r.command_fan(0)
        sent = next(float(x['fields']['rf_start_us']) / 1e6 for x in r.records
                    if x['kind'] == 'TXDONE' and x['fields'].get('id') and
                    any(y['kind'] == 'TXACCEPT' and y['fields'].get('class') == 'TYPE07_FAN'
                        and y['fields']['id'] == x['fields']['id'] for y in r.records))
        around = self.polls(r, 1, sent, sent + 5)
        self.assertGreaterEqual(len(around), 3)

    def test_the_whole_run_shape_passes_both_evaluators(self):
        import gate_b, gate_c
        r, fw, lines = self.runner()
        r.polls_sent = {0: 0, 1: 0}
        readiness = r.readiness(60)
        r.set_period(gate_c_runner.SPARSE_PERIOD_S)
        res = {'0': r.fire(0)}
        r.arm(1)
        res['1'] = r.fire(1)
        self.assertTrue(gate_b.shared_readiness(readiness)['passed'])
        v = gate_c.evaluate(r.records, res)
        self.assertEqual([x for x in v['reasons'] if 'attributed' not in x], [], v['reasons'])


class TheOutcomeSurvivesItsOwnReadback(Drive):
    """launch_gate_a.durable writes JSON and compares what it reads back.
    Attempt 4 passed on air and then failed that comparison, because
    polls_sent had int keys."""

    def test_the_parts_the_runner_adds_round_trip_through_json(self):
        import json
        r, fw, lines = self.runner()
        part = {'polls_sent': r.polls_record(), 'results': {'0': r.command_fan(0)},
                'answers': r.answers}
        self.assertEqual(json.loads(json.dumps(part)), part)

    def test_execute_records_polls_through_the_string_keyed_form(self):
        import inspect
        src = inspect.getsource(gate_c_runner.GateCRunner.execute)
        self.assertNotIn('dict(self.polls_sent)', src)
        self.assertEqual(src.count('self.polls_record()'), 2)


if __name__ == '__main__':
    unittest.main()
