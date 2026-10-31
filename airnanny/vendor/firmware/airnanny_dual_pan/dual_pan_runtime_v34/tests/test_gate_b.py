"""Offline tests for the Gate B evaluator. No COM, no RF, no hardware.

Gate B cannot be re-run casually: it transmits, spends frame counters and
advances ctx0's store. So every criterion -- and in particular every way of
FAILING -- is driven here first, against synthetic records, before a dongle
is on air.
"""
import os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'host'))
sys.path.insert(0, HERE)
import gate_a
import gate_b
from test_gate_a import rx, interleaved, HARDWARE_STATS, pan_frame

SEC = 1000000
# Intra-PAN DATA, short addresses, ACK request bit CLEAR (0x8841): a frame
# that is legitimately left unanswered.
NO_ACK_REQUEST = '4188019bfa26a30000'


def status(ctx, state, time_us):
    """STATUS carries two phase fields. `state` is the commission phase
    (IDLE / RECOVERY / STOPPED); `recovery` is the rejoin chain. Both are
    stamped here so the fixture cannot quietly agree with a reader of the
    wrong one -- which is the defect this shape exists to prevent."""
    return {'kind': 'STATUS', 'fields': {
        'ctx': str(ctx), 'state': 'RECOVERY', 'recovery': state,
        'time_us': str(time_us)}}


def chain(ctx, start=0, step=SEC, upto='PARENT_LINK_ACTIVE'):
    """One context walking the recovery chain, as STATUS would report it."""
    out, t = [], start
    for s in gate_b.REJOIN_CHAIN:
        out.append(status(ctx, s, t))
        t += step
        if s == upto:
            break
    return out


def poll(ctx, time_us, result='local_tx_ok', ack='1'):
    """One automatic poll as the firmware reports it: an ACCEPT carrying the
    class, then a DONE carrying the result and the ACK (and no class). Shape
    taken from attempt 10's records."""
    return [{'kind': 'AUTO_ACCEPT', 'fields': {
                'ctx': str(ctx), 'class': 'MANAGEMENT_POLL', 'id': '7',
                'time_us': str(time_us - 2000), 'session': '1', 'poll': '1',
                'retry': '0'}},
            {'kind': 'AUTO_DONE', 'fields': {
                'ctx': str(ctx), 'id': '7', 'time_us': str(time_us),
                'session': '1', 'poll': '1', 'result': result,
                'ack_present': ack, 'cleanup': 'safe',
                'reboot_required': '0'}}]


def polls(ctx, times, **kw):
    return [row for t in times for row in poll(ctx, t, **kw)]


def readiness(start=100 * SEC, seconds=60, every=SEC, ctxs=(0, 1)):
    """Both contexts polling over the same window, which is what shared
    readiness looks like."""
    out = []
    for i in range(seconds):
        for c in ctxs:
            out += poll(c, start + i * every + c * 1000)
    return out


def commissioning_traffic():
    """Frames seen while the contexts are being commissioned. A real run has
    them, and they are NOT part of the readiness population the ACK criterion
    is about -- which is why the evaluator takes the slice separately."""
    return [rx(match=c, time_us=t * SEC, ack_started=0, ack_completed=0,
               mac=NO_ACK_REQUEST)
            for t in range(1, 6) for c in ('ctx0', 'ctx1')]


def good_run():
    return (chain(0) + chain(1, start=20 * SEC) + commissioning_traffic()
            + readiness() + interleaved())


class SecuredRejoin(unittest.TestCase):
    def test_both_contexts_complete_the_chain(self):
        r = gate_b.rejoined_both(chain(0) + chain(1, start=20 * SEC))
        self.assertTrue(r['passed'], r['reasons'])
        for c in ('ctx0', 'ctx1'):
            self.assertTrue(r['per_context'][c]['passed_rejoined'])
            self.assertTrue(r['per_context'][c]['reached_active'])

    def test_ctx0_never_rejoining_fails_and_is_named(self):
        """ctx1's normal-mode rejoin was proved in V25; ctx0's on this firmware
        was not, so this is the failure Gate B exists to be able to report."""
        r = gate_b.rejoined_both(chain(0, upto='WAIT_REJOIN')
                                 + chain(1, start=20 * SEC))
        self.assertFalse(r['passed'])
        self.assertTrue(any('ctx0' in x and 'REJOINED' in x for x in r['reasons']))
        self.assertFalse([x for x in r['reasons'] if 'ctx1' in x])

    def test_the_chain_is_read_from_the_recovery_field(self):
        """Not from `state`. The firmware says state=RECOVERY throughout the
        whole chain, so a reader of that field sees one value forever and
        concludes nothing ever happened -- which is what a live run reported
        when the scan had in fact worked."""
        rows = chain(0)
        self.assertEqual({r['fields']['state'] for r in rows}, {'RECOVERY'})
        log = gate_b.phase_log(rows)
        self.assertIn('DISCOVERED', [p['state'] for p in log['ctx0']])

    def test_reaching_active_without_rejoining_fails(self):
        rows = [status(0, 'BOUND', 0), status(0, 'PARENT_LINK_ACTIVE', SEC)] + chain(1, 20 * SEC)
        r = gate_b.rejoined_both(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('never reported REJOINED' in x for x in r['reasons']))

    def test_phases_going_backwards_fail(self):
        rows = chain(0) + [status(0, 'SCANNING', 99 * SEC)] + chain(1, 20 * SEC)
        r = gate_b.rejoined_both(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('backwards' in x for x in r['reasons']))

    def test_a_repeated_state_is_not_a_regression(self):
        rows = chain(0) + [status(0, 'PARENT_LINK_ACTIVE', 99 * SEC)] + chain(1, 20 * SEC)
        self.assertTrue(gate_b.rejoined_both(rows)['passed'])


class SharedReadiness(unittest.TestCase):
    def test_overlapping_polls_pass(self):
        r = gate_b.shared_readiness(readiness())
        self.assertTrue(r['passed'], r['reasons'])
        self.assertGreaterEqual(r['overlap_seconds'], gate_b.MIN_OVERLAP_SECONDS)

    def test_sequential_readiness_fails_even_with_enough_polls(self):
        """The distinction the plan is explicit about. Each context polled
        plenty; they were simply never alive at the same moment, which is two
        single-context runs rather than a dual runtime."""
        first = polls(0, [100 * SEC + i * SEC for i in range(60)])
        second = polls(1, [200 * SEC + i * SEC for i in range(60)])
        r = gate_b.shared_readiness(first + second)
        self.assertFalse(r['passed'])
        self.assertEqual(r['overlap_seconds'], 0.0)
        self.assertTrue(any('one after the other' in x for x in r['reasons']))

    def test_a_silent_context_fails(self):
        r = gate_b.shared_readiness(readiness(ctxs=(0,)))
        self.assertFalse(r['passed'])
        self.assertTrue(any('ctx1' in x for x in r['reasons']))

    def test_two_distant_samples_do_not_buy_overlap(self):
        """A context that polled once early and once late spans the window on
        paper. The count inside the shared window is what refuses it."""
        rows = polls(0, [100 * SEC + i * SEC for i in range(60)])
        rows += polls(1, [100 * SEC, 159 * SEC])
        r = gate_b.shared_readiness(rows)
        self.assertFalse(r['passed'])
        self.assertLess(r['polls_inside_overlap']['ctx1'], gate_b.MIN_POLLS_PER_CTX)

    def test_a_brief_overlap_fails(self):
        rows = polls(0, [100 * SEC + i * SEC for i in range(60)])
        rows += polls(1, [155 * SEC + i * SEC for i in range(20)])
        r = gate_b.shared_readiness(rows)
        self.assertFalse(r['passed'])
        self.assertLess(r['overlap_seconds'], gate_b.MIN_OVERLAP_SECONDS)

    def test_polls_the_parent_never_acked_do_not_count(self):
        """A queued poll is not a live link. Every poll of ctx1 here completed
        without an ACK, so ctx1's parent was not shown to be alive."""
        rows = polls(0, [100 * SEC + i * SEC for i in range(60)])
        rows += polls(1, [100 * SEC + i * SEC + 1000 for i in range(60)], ack='0')
        r = gate_b.shared_readiness(rows)
        self.assertFalse(r['passed'])
        self.assertEqual(r['polls']['ctx1'], 0)

    def test_an_accept_without_its_done_does_not_count(self):
        rows = [p[0] for p in (poll(1, 100 * SEC + i * SEC) for i in range(60))]
        self.assertEqual(gate_b.acked_polls(rows)['ctx1'], [])

    def test_a_done_is_only_paired_with_its_own_contexts_accept(self):
        a0, _ = poll(0, 100 * SEC)
        _, d1 = poll(1, 100 * SEC)
        self.assertEqual(gate_b.acked_polls([a0, d1]),
                         {'ctx0': [], 'ctx1': []})


class Attribution(unittest.TestCase):
    def test_a_clean_run_attributes_both_and_crosses_nothing(self):
        r = gate_b.attribution(interleaved(), HARDWARE_STATS)
        self.assertTrue(r['passed'], r['reasons'])
        self.assertEqual(r['cross_pair_reject'], 0)

    def test_one_cross_pair_reject_fails_the_gate(self):
        """PAN of one context carrying the short of the other. The firmware
        refuses it, which is why it appears as a counter rather than as an
        answered frame -- and a refusal that happened at all is still the
        isolation question being asked on air."""
        r = gate_b.attribution(interleaved(),
                               dict(HARDWARE_STATS, cross_pair_reject='1'))
        self.assertFalse(r['passed'])
        self.assertTrue(any('cross-pair' in x for x in r['reasons']))

    def test_an_ambiguous_frame_fails(self):
        rows = interleaved() + [rx(match='ambiguous')]
        r = gate_b.attribution(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('not separable' in x for x in r['reasons']))

    def test_a_routing_fault_fails(self):
        r = gate_b.attribution(interleaved(),
                               dict(HARDWARE_STATS, routing_faults='2'))
        self.assertFalse(r['passed'])
        self.assertTrue(any('wrong context' in x for x in r['reasons']))

    def test_a_context_with_no_frames_at_all_fails(self):
        rows = [rx(match='ctx0', time_us=t * 1000) for t in range(1, 40)]
        r = gate_b.attribution(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('ctx1' in x for x in r['reasons']))


class TheAckMeasurementCameFromGateA(unittest.TestCase):
    def test_it_is_the_same_evaluator(self):
        """The handover, pinned: Gate B does not re-implement the measurement,
        it imports the one Gate A was written and tested with."""
        self.assertIs(gate_b.gate_a.dual_tuple_ack, gate_a.dual_tuple_ack)

    def test_a_clean_ack_set_passes_inside_gate_b(self):
        v = gate_b.evaluate(good_run(), HARDWARE_STATS, ack_records=readiness())
        self.assertTrue(v['dual_tuple_ack']['passed'], v['dual_tuple_ack']['reasons'])

    def test_an_unintended_ack_fails_gate_b(self):
        bad = good_run() + [rx(match='none', reason='foreign', ack_started=1,
                               ack_completed=1, time_us=999000)]
        v = gate_b.evaluate(bad, HARDWARE_STATS, ack_records=readiness())
        self.assertFalse(v['passed'])
        self.assertTrue(any('unintended' in x for x in v['reasons']))


class B4AsRevisedAfterAttempt11(unittest.TestCase):
    """Attempt 11: 92 keepalive polls, all ACKed with frame-pending clear, so
    readiness carried no addressed frame at all; the four that the run did
    carry -- each parent's REJOIN and TIMEOUT answers -- were all ACKed.
    B4 is now: every addressed frame that asked for an ACK got one, across
    the whole run, at least two per context."""

    def answers(self, per_ctx=2, **kw):
        return [rx(match=c, time_us=(10 + 2 * i + j) * SEC, **kw)
                for i in range(per_ctx) for j, c in enumerate(('ctx0', 'ctx1'))]

    def base(self):
        return chain(0) + chain(1, start=20 * SEC) + readiness()

    def test_attempt_11s_shape_passes(self):
        v = gate_b.evaluate(self.base() + self.answers(), HARDWARE_STATS,
                            ack_records=readiness())
        self.assertTrue(v['passed'], v['reasons'])
        self.assertEqual(v['dual_tuple_ack']['per_context']['ctx0']['samples'], 2)

    def test_an_answer_requesting_an_ack_and_not_getting_one_fails(self):
        rows = self.base() + self.answers() + [
            rx(match='ctx1', time_us=40 * SEC, ack_started=0, ack_completed=0)]
        v = gate_b.evaluate(rows, HARDWARE_STATS, ack_records=readiness())
        self.assertFalse(v['passed'])
        self.assertTrue(any('ctx1: 1 of 3 addressed frames were not ACKed' in x
                            for x in v['reasons']), v['reasons'])

    def test_one_answer_per_context_is_not_enough(self):
        v = gate_b.evaluate(self.base() + self.answers(per_ctx=1), HARDWARE_STATS,
                            ack_records=readiness())
        self.assertFalse(v['passed'])
        self.assertTrue(any('1 addressed frames in the run, 2 required' in x
                            for x in v['reasons']))

    def test_a_frame_without_an_ack_request_is_left_out(self):
        rows = self.base() + self.answers() + commissioning_traffic()
        d = gate_b.evaluate(rows, HARDWARE_STATS, ack_records=readiness())['dual_tuple_ack']
        self.assertTrue(d['passed'], d['reasons'])
        self.assertEqual(d['addressed_without_ack_request'], 10)

    def test_a_late_ack_still_fails(self):
        rows = self.base() + self.answers(deadline_miss=1)
        self.assertFalse(gate_b.evaluate(rows, HARDWARE_STATS,
                                         ack_records=readiness())['passed'])

    def test_gate_a_keeps_its_own_criterion(self):
        r = gate_a.dual_tuple_ack(self.answers())
        self.assertFalse(r['passed'])
        self.assertTrue(any('30 required' in x for x in r['reasons']))

    def test_the_readiness_slice_starts_at_the_first_keepalive(self):
        rows = [{'kind': 'HOST_COMMAND', 'raw': 'RADIOV10 STATUS id=1'},
                {'kind': 'HOST_COMMAND', 'raw': 'RADIOV10 MANAGEMENT_POLL id=2 ctx=0'},
                {'kind': 'TXDONE', 'fields': {}}]
        self.assertEqual(gate_b.readiness_slice(rows), rows[1:])
    def test_an_unanswered_sample_is_not_by_itself_a_failure(self):
        """A frame that did not request an ACK is legitimately unanswered, so
        the criterion is that each tuple WAS answered and that every answer was
        timely -- not that every frame got one. A missed obligation shows up as
        deadline_miss, which the firmware raises itself."""
        rows = interleaved() + [rx(match='ctx0', ack_started=0, ack_completed=0,
                                   time_us=30500)]
        r = gate_a.dual_tuple_ack(rows)
        self.assertTrue(r['passed'], r['reasons'])
        self.assertLess(r['per_context']['ctx0']['acked'],
                        r['per_context']['ctx0']['samples'])


class WholeGate(unittest.TestCase):
    def test_a_clean_run_passes(self):
        v = gate_b.evaluate(good_run(), HARDWARE_STATS, ack_records=readiness())
        self.assertTrue(v['passed'], v['reasons'])
        self.assertEqual(v['gate'], 'B')

    def test_each_part_can_fail_the_whole(self):
        for name, rows, ack in (
                ('rejoin', chain(0, upto='WAIT_REJOIN') + chain(1, 20 * SEC)
                 + readiness(), interleaved()),
                ('readiness', chain(0) + chain(1, 20 * SEC)
                 + polls(0, [100 * SEC + i * SEC for i in range(60)]),
                 interleaved()),
                ('ack', good_run() + [rx(match='ctx0', ack_started=0,
                                         ack_completed=0, time_us=t * 1000)
                                      for t in range(1, 40)], readiness()),
        ):
            with self.subTest(name):
                self.assertFalse(gate_b.evaluate(rows, HARDWARE_STATS,
                                                 ack_records=ack)['passed'])

    def test_incoherent_counters_fail_whatever_else_held(self):
        v = gate_b.evaluate(good_run(), dict(HARDWARE_STATS, broadcast='999'),
                            ack_records=interleaved())
        self.assertFalse(v['passed'])
        self.assertTrue(any('do not add up' in x for x in v['reasons']))

    def test_a_reconfigured_radio_during_readiness_fails(self):
        ack = interleaved()
        for row in ack[len(ack) // 2:]:
            row['fields']['config_generation'] = '3'
        v = gate_b.evaluate(good_run(), HARDWARE_STATS, ack_records=ack)
        self.assertFalse(v['passed'])
        self.assertTrue(any('allowlist changed' in x for x in v['reasons']))

    def test_a_malformed_field_is_a_fault_not_a_pass(self):
        rows = good_run()
        next(r for r in rows if r['kind'] == 'RX'
             and r['fields']['ack_started'] == '1')['fields']['rssi'] = 'not-a-number'
        with self.assertRaises(gate_b.GateBFault):
            gate_b.evaluate(rows, HARDWARE_STATS, ack_records=readiness())


if __name__ == '__main__':
    unittest.main()


class ThePhaseNamesComeFromTheFirmware(unittest.TestCase):
    """REJOIN_CHAIN is recovery_name() in src/rejoin_transport.c. Pinned here
    because a name invented on the host is a chain that can never complete,
    and the host would blame the radio for it."""

    def names(self, fn):
        import re
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               '..', 'src', 'rejoin_transport.c'),
                  encoding='utf-8') as fh:
            src = fh.read()
        # To the end of the function's line: recovery_name holds its names in
        # an array before `return`, commission_name inlines them after it, so
        # cutting at `return` would silently find nothing for the second.
        body = src[src.index('const char *%s(' % fn):]
        # INVALID is the out-of-range fallback, not a phase.
        return [n for n in re.findall(r'"([A-Z_]+)"', body[:body.index('\n')])
                if n != 'INVALID']

    def test_the_chain_is_recovery_name_verbatim(self):
        self.assertEqual(list(gate_b.REJOIN_CHAIN), self.names('recovery_name'))

    def test_the_terminal_state_is_in_the_chain(self):
        self.assertIn(gate_b.TERMINAL, gate_b.REJOIN_CHAIN)
        self.assertEqual(gate_b.TERMINAL, 'PARENT_LINK_ACTIVE')

    def test_the_commission_phase_names_are_different_and_not_used(self):
        commission = self.names('commission_name')
        self.assertIn('RECOVERY', commission)
        self.assertNotIn('RECOVERY', gate_b.REJOIN_CHAIN)
