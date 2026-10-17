"""The whole Gate A flow, driven against the real firmware through a fake port.

The inherited fake port in support.py models one context and a whole rejoin
flow. Gate A needs neither: it needs two contexts emitting addressed frames
concurrently, and nothing secured. So there is a small port here instead of a
large one bent into shape.

What this establishes: the sequence is right, the identity pin bites, the clock
check bites, both binds open the ACK gate, the collection stops at the floor
rather than running on, the counters are read, END is always attempted, and the
verdict comes from the same evaluator Gate A will use on hardware.

What it cannot establish, as ever: timing and RF margin. The fixture leaves
ack_start_us, rssi and lqi at zero, so a run here is deliberately expected to
FAIL the turnaround criterion. A test that showed Gate A passing offline would
be testing a lie.

No COM, no RF, no hardware.
"""
import subprocess, sys, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIRMWARE = HERE.parent
sys.path.insert(0, str(FIRMWARE / 'host'))
sys.path.insert(0, str(HERE))
import dual_store
import gate_a
import gate_a_runner
from gate_a_runner import GateARunner
from rejoin_wire import Fault
from test_dual_pan_ack_flow import (ctx_frame, cross_pair_frame, frame, BOOT,
                                    GENERATION)


def someone_elses_frame(ctx, **kw):
    """A frame in one of our two PANs, addressed to another of that
    coordinator's children. This is the overwhelming majority of what the
    dongle hears, and all of what it hears before it joins anything: the
    firmware classifies it foreign, and Gate A measures it by its PAN."""
    p = dual_store.PINNED[ctx]
    return frame(p['pan'], 0x1111 + ctx, p['tc_ieee'], **kw)

CLI = FIRMWARE / 'build' / 'firmware_cli.exe'


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class DualPort:
    """Two contexts talking at once, over the actual C dispatcher.

    Every read() advances the fake clock and, once both contexts are bound,
    injects one frame per context alternately -- which is what the firmware
    would see from two A7 units polling at the same cadence.
    """

    def __init__(self, clock, frames_per_read=1, misbehave=None,
                 traffic_before_bind=False, passive=False):
        self.clock = clock
        # Gate A's own mode: nothing is ever bound, and every injected frame
        # belongs to one of the two PANs but is addressed to somebody else.
        self.passive = passive
        # The air is busy before either context is bound -- which is what the
        # first hardware run saw, and what this fake did NOT model, which is how
        # the config_generation scoping defect reached hardware. Off by default
        # so the existing expectations stay exactly as measured.
        self.traffic_before_bind = traffic_before_bind
        self.buf = b''
        self.is_open = True
        self.bound = set()
        self.dsn = 0
        self.fc = 1000
        self.turn = 0
        self.frames_per_read = frames_per_read
        self.misbehave = misbehave or set()
        self.injected = {'ctx0': 0, 'ctx1': 0}
        self.p = subprocess.Popen([str(CLI)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)

    def feed(self, line):
        self.p.stdin.write(line + '\n')
        self.p.stdin.flush()
        while True:
            row = self.p.stdout.readline()
            if not row:
                raise RuntimeError('C_dispatcher_EOF')
            if row.startswith('@END'):
                break
            self.buf += row.encode()

    def inject(self, hexstr):
        self.feed('@RX ' + hexstr)

    @property
    def in_waiting(self):
        return len(self.buf)

    def write(self, data):
        cmd = data.decode().strip()
        if ' BIND ' in cmd:
            for token in cmd.split():
                if token.startswith('ctx='):
                    self.bound.add(int(token[4:]))
        self.feed(cmd)
        return len(data)

    def read(self, n):
        self.clock.now += 0.001
        self.feed('@TIME ' + str(100000 + int(self.clock.now * 1e6)))
        if self.passive:
            # What Gate A actually hears: both coordinators talking to their
            # OWN children. Same PANs, somebody else's short address, so the
            # firmware classifies every one of them as foreign and the survey
            # has to find them by PAN. Nothing is ever bound in this mode.
            self.dsn = (self.dsn + 1) % 250
            self.fc += 1
            ctx = self.turn % 2
            self.turn += 1
            if 'deaf_to_ctx1' in self.misbehave and ctx == 1:
                return self._drain(n)
            self.inject(someone_elses_frame(ctx, dsn=self.dsn, fc=self.fc))
            self.injected['ctx%d' % ctx] += 1
            return self._drain(n)
        if len(self.bound) < 2 and self.traffic_before_bind:
            self.dsn = (self.dsn + 1) % 250
            self.fc += 1
            self.inject(ctx_frame(self.turn % 2, dsn=self.dsn, fc=self.fc))
            self.turn += 1
        if len(self.bound) == 2:
            for _ in range(self.frames_per_read):
                self.dsn = (self.dsn + 1) % 250
                self.fc += 1
                ctx = self.turn % 2
                self.turn += 1
                if 'cross_pair' in self.misbehave and self.dsn % 37 == 0:
                    self.inject(cross_pair_frame(dsn=self.dsn, fc=self.fc))
                    continue
                if 'silent_ctx1' in self.misbehave and ctx == 1:
                    continue
                if 'sequential' in self.misbehave:
                    # all of ctx0 first, then all of ctx1
                    total = self.injected['ctx0'] + self.injected['ctx1']
                    ctx = 0 if total < gate_a.MIN_SAMPLES_PER_CTX else 1
                self.inject(ctx_frame(ctx, dsn=self.dsn, fc=self.fc))
                self.injected['ctx%d' % ctx] += 1
        return self._drain(n)

    def _drain(self, n):
        b = self.buf[:n]
        self.buf = self.buf[n:]
        return b

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=2)
            self.p.stdout.close()
        except Exception:
            pass


def stores():
    """The store entries the runner binds from, without touching the real
    stores -- which exist only on the operator's machine."""
    out = {}
    for ctx in (0, 1):
        p = dual_store.PINNED[ctx]
        out[ctx] = {'ctx': ctx, 'generation': GENERATION[ctx], 'short': p['short'],
                    'pan': p['pan'], 'epoch': p['epoch'], 'attempt': p['attempt'],
                    'guard': '2' * 32, 'keyseq': p['keyseq'], 'next_fc': 1280,
                    'path': '<synthetic>', 'epoch_sha256': 'x' * 64,
                    'recovery_state': 'FIRST_TYPE07_CONFIRMED',
                    'context_generation': 14, 'nwk_source_floors': {}}
    return out


class Base(unittest.TestCase):
    PASSIVE = True

    def setUp(self):
        if not CLI.exists():
            self.skipTest('run tests/run_native.sh first to build the fixture')
        # A short window: the fake clock advances 1 ms per read, so the real
        # criteria are reached in well under a second of wall time.
        self._s = gate_a_runner.SURVEY_SECONDS
        gate_a_runner.SURVEY_SECONDS = 2.0

    def tearDown(self):
        gate_a_runner.SURVEY_SECONDS = self._s

    def run_gate(self, **portkw):
        portkw.setdefault('passive', self.PASSIVE)
        clock = Clock()
        port = DualPort(clock, **portkw)
        self.addCleanup(port.close)
        return GateARunner(port, clock, stores=stores()).execute(), port


class TheSequence(Base):
    def test_it_runs_end_to_end_and_reaches_a_verdict(self):
        out, port = self.run_gate()
        self.assertIsNone(out['error'], out['error'])
        self.assertTrue(out['executed'])
        self.assertIn('verdict', out)
        # END is sent and REFUSED, because Gate A never opened a session. That
        # refusal is the evidence: a gate that claims to bind nothing should
        # have nothing to close.
        self.assertNotIn('end', out)
        self.assertIn('FIRMWARE_ERROR', out['end_error'])

    def test_nothing_is_bound_and_nothing_is_transmitted(self):
        """The property the whole gate now rests on. Gate A measures two live
        networks without joining or perturbing either, so it must leave no
        trace: no BIND, no allowlist, no frame keyed."""
        out, port = self.run_gate()
        self.assertEqual(port.bound, set())
        self.assertEqual(out['info_before']['immediate_ack'], '0')
        self.assertEqual(out['info_after_survey']['immediate_ack'], '0')
        self.assertEqual(out['stats']['config_generation'], '0')
        self.assertEqual(out['stats']['ctx0_tx_accepted'], '0')
        self.assertEqual(out['stats']['ctx1_tx_accepted'], '0')

    def test_the_survey_measures_frames_addressed_to_other_devices(self):
        """What the first hardware run could not do. Every frame here is
        foreign to both of our tuples -- ctx0_rx and ctx1_rx stay at zero in
        the firmware's own counters -- and the survey still reaches the floor
        on both networks, because it scopes by PAN."""
        out, port = self.run_gate()
        self.assertEqual(out['stats']['ctx0_rx'], '0')
        self.assertEqual(out['stats']['ctx1_rx'], '0')
        per = out['verdict']['survey']['per_context']
        for m in ('ctx0', 'ctx1'):
            self.assertGreaterEqual(per[m]['samples'],
                                    gate_a.MIN_SURVEY_SAMPLES_PER_PAN)

    def test_collection_stops_at_the_floor_rather_than_running_on(self):
        out, port = self.run_gate()
        per = out['verdict']['survey']['per_context']
        most = max(per[m]['samples'] for m in ('ctx0', 'ctx1'))
        self.assertLess(most, gate_a.MIN_SURVEY_SAMPLES_PER_PAN * 3,
                        'collection ran well past the floor: %d' % most)

    def test_nothing_was_answered(self):
        out, port = self.run_gate()
        self.assertEqual(out['verdict']['survey']['ack_observed'], 0)
        self.assertEqual(out['stats']['ack_started'] if 'ack_started'
                         in out['stats'] else '0', '0')

    def test_the_counters_are_read_and_routing_is_clean(self):
        out, port = self.run_gate()
        self.assertEqual(out['stats']['routing_faults'], '0')
        # The counter identity, checked here against the real C admission path
        # rather than against a hand-written field set: the classification
        # counters sum to rx_total, with the stage-1 aborts outside that sum.
        coh = out['stats_coherence']
        self.assertTrue(coh['coherent'], coh)
        self.assertEqual(coh['classified_sum'], coh['rx_total'])
        # The admission counters are zero here, and that is a property of the
        # fixture, not of the firmware: the @RX path of the native CLI hands
        # frames to the record layer directly and never runs dual_admit_part,
        # which is what increments them. So the identity holds trivially
        # offline. It is exercised with real numbers by StatsCoherence in
        # test_gate_a.py, whose fixture is the counter set off the dongle.
        self.assertEqual(coh['rx_total'], 0,
                         'the fixture now increments admission counters; this '
                         'test can be strengthened to assert real numbers')

    def test_the_generation_does_not_move_during_the_gate(self):
        """Gate A publishes nothing, so the generation it finds is the one it
        leaves -- whatever that value is. On a fresh fixture it is 0; on a
        dongle that already ran a gate this boot it would be 2, and that is
        equally fine."""
        out, port = self.run_gate()
        self.assertEqual(out['verdict']['config_generations'], ['0'])
        self.assertEqual(out['info_before']['config_generation'],
                         out['info_after_survey']['config_generation'])
        self.assertFalse([r for r in out['verdict']['reasons']
                          if 'config_generation' in r], out['verdict']['reasons'])

    def test_a_clean_passive_run_passes(self):
        """Unlike the old phase 2, this gate CAN pass offline: it measures
        signal and presence, not timing, and the fixture can supply both
        honestly. What it cannot supply -- real RSSI and LQI -- the fixture
        leaves at the firmware's own values rather than inventing them."""
        out, port = self.run_gate()
        self.assertIsNone(out['error'], out['error'])
        self.assertTrue(out['passed'], out['verdict']['reasons'])


class TheGuardsBite(Base):
    def test_a_wrong_firmware_identity_stops_before_any_binding(self):
        saved = dict(gate_a_runner.EXPECTED_INFO)
        try:
            gate_a_runner.EXPECTED_INFO['identity'] = 'something_else'
            out, port = self.run_gate()
        finally:
            gate_a_runner.EXPECTED_INFO.clear()
            gate_a_runner.EXPECTED_INFO.update(saved)
        self.assertIn('unexpected_firmware_identity', out['error'])
        self.assertFalse(out['executed'], 'it proceeded past the identity pin')
        self.assertEqual(port.bound, set(), 'it bound a context anyway')

    def test_a_wrong_wire_version_stops_too(self):
        saved = dict(gate_a_runner.EXPECTED_INFO)
        try:
            gate_a_runner.EXPECTED_INFO['wire'] = '11'
            out, port = self.run_gate()
        finally:
            gate_a_runner.EXPECTED_INFO.clear()
            gate_a_runner.EXPECTED_INFO.update(saved)
        self.assertIn('unexpected_firmware_identity', out['error'])
        self.assertEqual(port.bound, set())

    def test_insufficient_clock_room_stops_before_any_binding(self):
        saved = gate_a_runner.CLOCK_MARGIN_US
        try:
            # Demand more room than the 32-bit counter can ever hold.
            gate_a_runner.CLOCK_MARGIN_US = 2 ** 32
            out, port = self.run_gate()
        finally:
            gate_a_runner.CLOCK_MARGIN_US = saved
        self.assertIn('insufficient_clock_room', out['error'])
        self.assertFalse(out['executed'])
        self.assertEqual(port.bound, set(), 'it configured the radio anyway')

    def test_end_is_attempted_even_when_the_gate_fails(self):
        """Leaving the runtime bound with an open ACK gate after a failed gate
        is worse than the failure."""
        saved = dict(gate_a_runner.EXPECTED_INFO)
        try:
            gate_a_runner.EXPECTED_INFO['identity'] = 'nope'
            out, port = self.run_gate()
        finally:
            gate_a_runner.EXPECTED_INFO.clear()
            gate_a_runner.EXPECTED_INFO.update(saved)
        self.assertTrue('end' in out or 'end_error' in out,
                        'END was neither achieved nor recorded as failing')


class RealFailuresAreCaught(Base):
    def test_a_network_that_cannot_be_heard_fails_the_gate(self):
        """The section 2.2 stop criterion, which is the whole reason Gate A
        exists: if ctx1's coordinator is not audible from where the dongle
        sits, the plan stops here rather than discovering it in Gate B."""
        out, port = self.run_gate(misbehave={'deaf_to_ctx1'})
        self.assertFalse(out['passed'])
        reasons = out['verdict']['reasons']
        self.assertTrue(any('ctx1' in r and 'audible' in r for r in reasons),
                        reasons)

    def test_publishing_during_the_survey_is_refused(self):
        """The direct passivity check: the generation INFO reports at the end
        must be the one it reported at the start."""
        clock = Clock()
        port = DualPort(clock, passive=True)
        self.addCleanup(port.close)
        runner = GateARunner(port, clock, stores=stores())
        inner = runner.command
        seen = []

        def command(verb, fields='', expect=None):
            got = inner(verb, fields, expect)
            if verb == 'INFO':
                seen.append(got)
                # the probe's INFO goes through _raw_info, not here, so
                # the two that arrive here are `before` and `after`
                if len(seen) >= 2:
                    got = dict(got, config_generation='9')
            return got
        runner.command = command
        out = runner.execute()
        self.assertIn('allowlist_published_during_a_passive_gate', out['error'])
        self.assertNotIn('verdict', out)

    def test_a_gate_that_transmitted_is_refused_outright(self):
        """Not a verdict but a fault: a passive gate that keyed the radio has
        perturbed the networks it claims to have measured untouched. The STATS
        reply is doctored on the way back, so everything up to that point is
        the real firmware and the real survey."""
        clock = Clock()
        port = DualPort(clock, passive=True)
        self.addCleanup(port.close)
        runner = GateARunner(port, clock, stores=stores())
        inner = runner.command

        def command(verb, fields='', expect=None):
            got = inner(verb, fields, expect)
            if verb == 'STATS':
                got = dict(got, ctx0_tx_accepted='3')
            return got
        runner.command = command
        out = runner.execute()
        self.assertIn('gate_a_transmitted:ctx0_tx_accepted=3', out['error'])
        self.assertFalse(out['passed'])
        self.assertNotIn('verdict', out,
                         'it reached a verdict on a run it should have refused')


class ItIsStillTheRealFirmwareUnderneath(Base):
    """The fake drives the actual C dispatcher, so these assert on what the
    firmware did with the frames rather than on the fake's bookkeeping."""

    PASSIVE = True

    def test_the_firmware_classified_every_frame_as_foreign(self):
        out, port = self.run_gate()
        matches = {r['fields']['match'] for r in out['records']
                   if r['kind'] == 'RX'}
        self.assertEqual(matches, {'none'})
        # reason is `none`, not `foreign`: with no allowlist published there is
        # nothing for a frame to be foreign TO. On hardware, where Gate B will
        # have published both configs, the same frames come back as foreign.
        reasons = {r['fields']['reason'] for r in out['records']
                   if r['kind'] == 'RX'}
        self.assertEqual(reasons, {'none'})

    def test_the_survey_and_the_firmware_agree_on_how_many_frames_there_were(self):
        out, port = self.run_gate()
        survey = out['verdict']['survey']
        measured = sum(b['samples'] for b in survey['per_context'].values())
        self.assertEqual(measured + survey['frames_without_a_legible_pan']
                         + sum(survey['other_pans'].values()), survey['total'])


if __name__ == '__main__':
    unittest.main()


class TheIdFloorIsFound(Base):
    """Command ids must strictly increase within one firmware boot. A dongle
    that has not been power-cycled since an earlier run therefore refuses id=1,
    which is what ended attempt 2 before it read anything. The fixture drives
    the real C dispatcher, so the rule enforced here is the firmware's own."""

    def burn(self, port, upto):
        """Consume ids 1..upto on the dongle, as a previous run would have."""
        for i in range(1, upto + 1):
            port.feed('%s INFO id=%d' % (gate_a_runner.PREFIX, i))
        port.buf = b''          # those replies belong to the previous session

    def test_a_fresh_boot_accepts_the_first_id(self):
        out, port = self.run_gate()
        self.assertEqual(out['id_floor']['floor'], 1)
        self.assertEqual(len(out['id_floor']['probes']), 1)
        self.assertIsNone(out['error'], out['error'])

    def test_it_climbs_past_ids_a_previous_run_consumed(self):
        clock = Clock()
        port = DualPort(clock, passive=True)
        self.addCleanup(port.close)
        self.burn(port, 7)                    # roughly what attempt 1 spent
        out = GateARunner(port, clock, stores=stores()).execute()
        self.assertIsNone(out['error'], out['error'])
        floor = out['id_floor']
        self.assertEqual(floor['floor'], 8)   # 1, 2, 4 refused; 8 accepted
        self.assertEqual([p['id'] for p in floor['probes']], [1, 2, 4, 8])
        self.assertEqual([p['reason'] for p in floor['probes']],
                         ['id_reused'] * 3 + [None])
        self.assertTrue(out['passed'], out['verdict']['reasons'])

    def test_the_gate_still_runs_cleanly_after_a_long_climb(self):
        clock = Clock()
        port = DualPort(clock, passive=True)
        self.addCleanup(port.close)
        self.burn(port, 300)
        out = GateARunner(port, clock, stores=stores()).execute()
        self.assertIsNone(out['error'], out['error'])
        self.assertEqual(out['id_floor']['floor'], 512)
        self.assertTrue(out['passed'], out['verdict']['reasons'])

    def test_every_refusal_is_kept_in_the_records(self):
        """A probe that discarded what it read would be deciding on evidence
        nobody else can check."""
        clock = Clock()
        port = DualPort(clock, passive=True)
        self.addCleanup(port.close)
        self.burn(port, 7)
        out = GateARunner(port, clock, stores=stores()).execute()
        refusals = [r for r in out['records'] if r['kind'] == 'ERROR'
                    and r['fields'].get('reason') == 'id_reused']
        self.assertEqual([r['fields']['id'] for r in refusals], ['1', '2', '4'])
        probes = [r for r in out['records']
                  if r.get('note') == 'id floor probe']
        self.assertEqual(len(probes), 4)

    def test_the_probe_leaves_the_dongle_otherwise_untouched(self):
        """An id_reused refusal does not advance last_id and does not stop the
        radio, so the climb must cost nothing: the gate that follows still
        passes and still transmitted nothing."""
        clock = Clock()
        port = DualPort(clock, passive=True)
        self.addCleanup(port.close)
        self.burn(port, 7)
        out = GateARunner(port, clock, stores=stores()).execute()
        self.assertEqual(port.bound, set())
        self.assertEqual(out['stats']['ctx0_tx_accepted'], '0')
        self.assertEqual(out['stats']['ctx1_tx_accepted'], '0')
        self.assertEqual(out['stats']['config_generation'], '0')

    def test_an_unexpected_refusal_is_not_climbed_past(self):
        """Only id_reused means 'try higher'. Any other refusal is a real
        problem and must stop the gate rather than be probed around."""
        clock = Clock()
        port = DualPort(clock, passive=True)
        self.addCleanup(port.close)
        runner = GateARunner(port, clock, stores=stores())
        import id_floor
        saved = id_floor._raw_info
        id_floor._raw_info = lambda w, c, r, i: {
            'kind': 'ERROR', 'raw': 'RADIOV10 ERROR id=%d reason=boot_mismatch' % i,
            'fields': {'id': str(i), 'reason': 'boot_mismatch'}}
        self.addCleanup(lambda: setattr(id_floor, '_raw_info', saved))
        with self.assertRaises(Fault) as e:
            runner.probe_id_floor()
        self.assertIn('id_probe_unexpected_reply', str(e.exception))

    def test_a_reboot_during_the_climb_is_caught(self):
        """If the boot changes mid-probe the floor just found belongs to a
        different session, so the numbers after it would be meaningless."""
        clock = Clock()
        port = DualPort(clock, passive=True)
        self.addCleanup(port.close)
        runner = GateARunner(port, clock, stores=stores())
        import id_floor
        saved = id_floor._raw_info
        self.addCleanup(lambda: setattr(id_floor, '_raw_info', saved))
        seen = []

        def fake(w, c, r, i):
            seen.append(i)
            if len(seen) < 3:
                return {'kind': 'ERROR', 'raw': 'r', 'fields': {
                    'id': str(i), 'reason': 'id_reused', 'boot': 'a' * 32}}
            return {'kind': 'INFO', 'raw': 'r', 'fields': {
                'id': str(i), 'boot': 'b' * 32}}
        id_floor._raw_info = fake
        with self.assertRaises(Fault) as e:
            runner.probe_id_floor()
        self.assertIn('dongle_rebooted_during_id_probe', str(e.exception))
