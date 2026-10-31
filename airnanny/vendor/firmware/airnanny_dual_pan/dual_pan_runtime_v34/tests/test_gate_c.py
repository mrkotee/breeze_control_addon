"""Gate C evaluator, offline. Every way of failing is driven here first."""
import os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'host'))
sys.path.insert(0, HERE)
import gate_c
from test_gate_b import polls, SEC
from test_gate_a import rx

T0 = 100 * SEC                 # ctx0's command
T1 = 130 * SEC                 # ctx1's command
CONFIRM = 3 * SEC              # TYPE06 arrives this long after the command


def command(ctx, rf_start, cid, result='local_tx_ok'):
    return [{'kind': 'TXACCEPT', 'fields': {'ctx': str(ctx), 'id': str(cid),
                                            'class': 'TYPE07_FAN'}},
            {'kind': 'TXDONE', 'fields': {'ctx': str(ctx), 'id': str(cid), 'result': result,
                                          'time_us': str(rf_start + 2000),
                                          'rf_start_us': str(rf_start)}}]


def keepalive(ctx, start=90 * SEC, end=160 * SEC, every=int(1.25 * SEC)):
    return polls(ctx, list(range(start + ctx * 600000, end, every)))


def results(r0='CONFIRMED', r1='CONFIRMED'):
    return {'0': {'application_result': r0, 'match_revision': 10 if r0 == 'CONFIRMED' else None,
                  'match_radio_us': T0 + CONFIRM},
            '1': {'application_result': r1, 'match_revision': 20 if r1 == 'CONFIRMED' else None,
                  'match_radio_us': T1 + CONFIRM}}


def addressed():
    return [rx(match=c, time_us=t * SEC) for t in (95, 96) for c in ('ctx0', 'ctx1')]


def good():
    return (addressed() + keepalive(0) + keepalive(1)
            + command(0, T0, 501) + command(1, T1, 502))


class GateC(unittest.TestCase):
    def test_a_clean_run_passes(self):
        v = gate_c.evaluate(good(), results())
        self.assertTrue(v['passed'], v['reasons'])
        self.assertEqual(v['peer_alive']['ctx0_command']['peer'], 'ctx1')

    def test_a_missing_command_fails_and_is_named(self):
        rows = addressed() + keepalive(0) + keepalive(1) + command(0, T0, 501)
        v = gate_c.evaluate(rows, results())
        self.assertFalse(v['passed'])
        self.assertTrue(any('ctx1: 0 TYPE07' in x for x in v['reasons']), v['reasons'])

    def test_a_retry_fails(self):
        rows = good() + command(0, T0 + 5 * SEC, 503)
        v = gate_c.evaluate(rows, results())
        self.assertTrue(any('ctx0: 2 TYPE07' in x for x in v['reasons']))

    def test_an_unconfirmed_command_fails(self):
        v = gate_c.evaluate(good(), results(r1='FAILED_OR_UNKNOWN'))
        self.assertFalse(v['passed'])
        self.assertTrue(any('ctx1: application result' in x for x in v['reasons']))

    def test_a_local_send_failure_fails(self):
        rows = keepalive(0) + keepalive(1) + command(0, T0, 501, result='timeout') + command(1, T1, 502)
        self.assertFalse(gate_c.evaluate(rows, results())['passed'])

    def test_overlapping_commands_fail(self):
        rows = keepalive(0) + keepalive(1) + command(0, T0, 501) + command(1, T0 + SEC, 502)
        v = gate_c.evaluate(rows, results())
        self.assertTrue(any('overlapped' in x for x in v['reasons']), v['reasons'])

    def test_a_peer_that_went_quiet_during_the_command_fails(self):
        quiet = polls(1, [t for t in range(90 * SEC, 160 * SEC, int(1.25 * SEC))
                          if not T0 - SEC <= t <= T0 + 10 * SEC])
        rows = addressed() + keepalive(0) + quiet + command(0, T0, 501) + command(1, T1, 502)
        v = gate_c.evaluate(rows, results())
        self.assertTrue(any('ctx1 was not shown alive during ctx0' in x for x in v['reasons']),
                        v['reasons'])

    def test_unacked_peer_polls_do_not_count_as_alive(self):
        rows = keepalive(0) + polls(1, list(range(90 * SEC, 160 * SEC, int(1.25 * SEC))), ack='0') \
            + command(0, T0, 501) + command(1, T1, 502)
        v = gate_c.evaluate(rows, results())
        self.assertTrue(any('ctx1 was not shown alive' in x for x in v['reasons']))


if __name__ == '__main__':
    unittest.main()
