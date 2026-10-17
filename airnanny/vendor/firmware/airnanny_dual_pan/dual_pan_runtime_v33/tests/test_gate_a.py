"""Offline tests for the Gate A evaluator. No COM, no RF, no hardware.

These exist because a hardware gate that is only exercised on hardware has no
way to be wrong safely: the first time its criteria run is the one time the
dongle is on air and both A7 units are live. Every criterion is driven here
against synthetic records first, and in particular every way of FAILING is
driven, because an evaluator that cannot fail is not a gate.
"""
import re, sys, os, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
FIRMWARE = os.path.join(HERE, '..')
sys.path.insert(0, os.path.join(FIRMWARE, 'host'))
import gate_a


def _fields_of(path, anchor, end='\n}'):
    with open(os.path.join(FIRMWARE, path), encoding='utf-8') as fh:
        src = fh.read()
    body = src[src.index(anchor):]
    body = body[:body.index(end)]
    # `(\w+)=` rather than `(\w+)=%`: some fields are emitted as literals
    # (`fcs_ok=1`), and a field is no less emitted for being constant.
    return set(re.findall(r'(\w+)=', ''.join(re.findall(r'"([^"]*)"', body))))


def firmware_rx_field_names():
    """The field names the dongle actually emits on an RX line, read out of
    src/main.c. The fixtures below are checked against this, because a fixture
    that invents its own schema tests the evaluator against a firmware that
    does not exist."""
    return _fields_of('src/main.c', 'RADIO_PREFIX " RX boot=', ');')


def dead_formatter_field_names():
    """dual_format_rx in src/dual_records.c: a SECOND RX formatter, with
    different names, that nothing in the firmware calls."""
    return _fields_of('src/dual_records.c', 'bool dual_format_rx(')


def pan_frame(pan, dest=0x1234, src=0x5678, dsn=1):
    """A minimal legible MAC header: intra-PAN DATA with short addresses, which
    is what both A7 networks actually carry."""
    fcf = 0x8861                  # DATA, PAN compressed, short dest and source
    return (fcf.to_bytes(2, 'little') + bytes([dsn]) + pan.to_bytes(2, 'little')
            + dest.to_bytes(2, 'little') + src.to_bytes(2, 'little')).hex()


def rx(match='ctx0', time_us=1000, rssi=-55, lqi=200, ack_started=1,
       ack_completed=1, ack_start_us=None, ack_address_us=None, ack_end_us=None,
       deadline_miss=0, mac=None, reason='none', config_generation='2', pan=None):
    """A record shaped like the firmware's, with the four TIMER3 captures in
    their real relationship: CRCOK < TXREADY <= ADDRESS < PHYEND."""
    if ack_start_us is None:
        ack_start_us = time_us + gate_a.ACK_TURNAROUND_US
    if ack_address_us is None:
        ack_address_us = ack_start_us + 160      # preamble and SFD
    if ack_end_us is None:
        ack_end_us = ack_start_us + 352          # an ACK is 352 us of air
    if mac is None:
        mac = pan_frame(gate_a.PAN_OF_CTX.get(pan or match, 0xdead))
    return {'kind': 'RX', 'fields': {
        'match': match, gate_a.RX_TIME: str(time_us), 'rssi': str(rssi),
        'lqi': str(lqi),
        'ack_started': str(ack_started), 'ack_completed': str(ack_completed),
        gate_a.RX_ACK_START: str(ack_start_us),
        gate_a.RX_ACK_ADDRESS: str(ack_address_us),
        gate_a.RX_ACK_END: str(ack_end_us), 'deadline_miss': str(deadline_miss),
        'mac': mac, 'reason': reason, 'fcs_ok': '1',
        'config_generation': config_generation}}


def interleaved(n_per_ctx=gate_a.MIN_SAMPLES_PER_CTX, **kw):
    """Alternating ctx0/ctx1 spread evenly over the window, which is what a
    genuinely concurrent run looks like."""
    out = []
    t = 1000
    for i in range(n_per_ctx):
        out.append(rx(match='ctx0', time_us=t, **kw)); t += 1000
        out.append(rx(match='ctx1', time_us=t, **kw)); t += 1000
    return out


def heard(n_per_pan=gate_a.MIN_SURVEY_SAMPLES_PER_PAN):
    """What Gate A actually sees: both coordinators' traffic, none of it
    addressed to us, so every frame classifies as foreign and is measured by
    its PAN instead."""
    out = []
    t = 1000
    for i in range(n_per_pan):
        for ctx in ('ctx0', 'ctx1'):
            out.append(rx(match='none', reason='foreign', pan=ctx, time_us=t,
                          ack_started=0, ack_completed=0,
                          config_generation='0'))
            t += 1000
    return out


class TheFixtureMatchesTheFirmware(unittest.TestCase):
    def test_every_fixture_field_is_one_the_firmware_emits(self):
        emitted = firmware_rx_field_names()
        self.assertIn(gate_a.RX_TIME, emitted)
        unknown = set(rx()['fields']) - emitted
        self.assertEqual(unknown, set(), 'fixture invents fields: %r' % unknown)

    def test_the_second_rx_formatter_is_still_dead(self):
        """src/dual_records.c holds dual_format_rx, a second RX formatter with
        DIFFERENT field names, called by nothing but its own unit test. Reading
        it as the live emitter and repointing this evaluator at `rx_end_us` is
        a mistake that was made here once: it would have left every timestamp
        at zero, silently. If this ever becomes the live formatter, the names
        in gate_a.RX_* are what has to change -- hence this test."""
        with open(os.path.join(FIRMWARE, 'src/main.c'), encoding='utf-8') as fh:
            main = fh.read()
        self.assertNotIn('dual_format_rx', main,
                         'main.c now calls dual_format_rx; the RX field names '
                         'in gate_a.py must be rechecked against it')
        self.assertIn('rx_end_us', dead_formatter_field_names())
        self.assertNotIn('rx_end_us', firmware_rx_field_names())
        self.assertIn('time_us', firmware_rx_field_names())

    def test_every_timestamp_the_evaluator_reads_is_emitted(self):
        emitted = firmware_rx_field_names()
        for name in (gate_a.RX_TIME, gate_a.RX_ACK_START,
                     gate_a.RX_ACK_ADDRESS, gate_a.RX_ACK_END):
            self.assertIn(name, emitted, name)

    def test_the_pans_match_the_firmware_identity_header(self):
        with open(os.path.join(FIRMWARE, 'include/dual_identity.h'),
                  encoding='utf-8') as fh:
            header = fh.read()
        for ctx, name in ((0, 'DUAL_CTX0_PAN'), (1, 'DUAL_CTX1_PAN')):
            m = re.search(r'#define\s+%s\s+0x([0-9a-fA-F]+)' % name, header)
            self.assertIsNotNone(m, name)
            self.assertEqual(int(m.group(1), 16), gate_a.PAN_OF_CTX['ctx%d' % ctx])


def passive(n_per_ctx=5):
    """Phase 1 runs before either allowlist is published, so these records carry
    config_generation 0 -- as they did on hardware. Phase 2 carries 2. Mixing
    the two windows is the defect that failed the first hardware run."""
    out = []
    t = 1000
    for i in range(n_per_ctx):
        out.append(rx(match='ctx0', time_us=t, ack_started=0, ack_completed=0,
                      config_generation='0')); t += 1000
        out.append(rx(match='ctx1', time_us=t, ack_started=0, ack_completed=0,
                      config_generation='0')); t += 1000
    return out


class FramePan(unittest.TestCase):
    """The parse Gate A now rests on. It mirrors dual_header_size, so it is
    tested the same way: every addressing shape, including the ones the
    firmware refuses."""

    def test_an_intra_pan_data_frame_yields_its_pan(self):
        self.assertEqual(gate_a.frame_pan(pan_frame(0xfa9b)), 0xfa9b)
        self.assertEqual(gate_a.frame_pan(pan_frame(0x0b7a)), 0x0b7a)

    def test_the_byte_order_is_little_endian_like_the_firmware(self):
        """0xfa9b on the wire is 9b fa. Reading it big-endian would silently
        bucket both networks as 'other' and the gate would never pass."""
        self.assertIn('9bfa', pan_frame(0xfa9b))
        self.assertEqual(gate_a.frame_pan(pan_frame(0xfa9b)), 0xfa9b)

    def test_a_source_only_frame_uses_the_source_pan(self):
        fcf = 0xc000                 # no dest, short source, not compressed
        mac = (fcf.to_bytes(2, 'little') + b'\x01' + (0x0b7a).to_bytes(2, 'little')
               + (0x1234).to_bytes(2, 'little')).hex()
        self.assertEqual(gate_a.frame_pan(mac), 0x0b7a)

    def test_the_addressing_modes_the_firmware_calls_malformed_yield_none(self):
        for fcf in (0x0400, 0x4000, 0x0841):   # dest==1, src==1, compressed+no dest
            mac = (fcf.to_bytes(2, 'little') + b'\x01' + b'\x9b\xfa\x00\x00').hex()
            self.assertIsNone(gate_a.frame_pan(mac), hex(fcf))

    def test_a_truncated_frame_yields_none_rather_than_a_guess(self):
        self.assertIsNone(gate_a.frame_pan(''))
        self.assertIsNone(gate_a.frame_pan('6188'))
        self.assertIsNone(gate_a.frame_pan(pan_frame(0xfa9b)[:8]))

    def test_non_hex_is_a_fault(self):
        with self.assertRaises(gate_a.GateAFault):
            gate_a.frame_pan('zz')


class Survey(unittest.TestCase):
    def test_both_pans_heard_and_nothing_answered(self):
        r = gate_a.survey(heard())
        self.assertTrue(r['passed'], r['reasons'])
        self.assertTrue(r['both_contexts_present'])
        self.assertEqual(r['ack_observed'], 0)
        for m in ('ctx0', 'ctx1'):
            self.assertEqual(r['per_context'][m]['samples'],
                             gate_a.MIN_SURVEY_SAMPLES_PER_PAN)

    def test_it_measures_frames_that_are_addressed_to_someone_else(self):
        """The whole point. Every record here is match=none reason=foreign --
        exactly what the first hardware run saw, and exactly what the old
        match-scoped survey scored as zero samples on both contexts."""
        rows = heard()
        self.assertTrue(all(r['fields']['match'] == 'none' for r in rows))
        self.assertTrue(all(r['fields']['reason'] == 'foreign' for r in rows))
        self.assertTrue(gate_a.survey(rows)['passed'])

    def test_rf_margin_is_measured_not_assumed(self):
        rows = [rx(pan='ctx1', match='none', time_us=1000, rssi=-90, lqi=60,
                   ack_started=0, ack_completed=0),
                rx(pan='ctx1', match='none', time_us=2000, rssi=-70, lqi=120,
                   ack_started=0, ack_completed=0),
                rx(pan='ctx0', match='none', time_us=3000, rssi=-50, lqi=240,
                   ack_started=0, ack_completed=0)]
        b = gate_a.survey(rows)['per_context']['ctx1']
        self.assertEqual((b['rssi_min'], b['rssi_max'], b['rssi_mean']), (-90, -70, -80.0))
        self.assertEqual((b['lqi_min'], b['lqi_max'], b['lqi_mean']), (60, 120, 90.0))

    def test_a_pan_never_heard_fails_and_names_it(self):
        rows = [r for r in heard()
                if gate_a.frame_pan(r['fields']['mac']) == gate_a.PAN_OF_CTX['ctx0']]
        r = gate_a.survey(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('ctx1 (PAN 0b7a)' in x and 'not adequately audible' in x
                            for x in r['reasons']), r['reasons'])

    def test_a_handful_of_frames_is_not_a_margin(self):
        """A network heard three times has not been shown to be reachable."""
        rows = [rx(pan=c, match='none', time_us=1000 * i, ack_started=0,
                   ack_completed=0)
                for i, c in enumerate(('ctx0', 'ctx1') * 3, start=1)]
        r = gate_a.survey(rows)
        self.assertFalse(r['passed'])
        self.assertEqual(len([x for x in r['reasons'] if 'audible' in x]), 2)

    def test_a_pan_that_fades_out_fails_even_with_enough_samples(self):
        """All of ctx1 at the start and none later is not 'reachable from this
        position', however good the mean RSSI looks."""
        rows, t = [], 1000
        for _ in range(gate_a.MIN_SURVEY_SAMPLES_PER_PAN):
            rows.append(rx(pan='ctx1', match='none', time_us=t,
                           ack_started=0, ack_completed=0)); t += 1000
        for _ in range(gate_a.MIN_SURVEY_SAMPLES_PER_PAN * 3):
            rows.append(rx(pan='ctx0', match='none', time_us=t,
                           ack_started=0, ack_completed=0)); t += 1000
        r = gate_a.survey(rows)
        self.assertFalse(r['passed'])
        self.assertFalse(r['concurrency']['both_in_every_part'])
        self.assertTrue(any('every part of the window' in x for x in r['reasons']))

    def test_a_third_network_is_counted_and_never_measured(self):
        rows = heard() + [rx(pan=None, mac=pan_frame(0x1234), match='none',
                             time_us=99000, ack_started=0, ack_completed=0)]
        r = gate_a.survey(rows)
        self.assertTrue(r['passed'], r['reasons'])
        self.assertEqual(r['other_pans'], {'1234': 1})
        self.assertNotIn('1234', r['per_context'])

    def test_an_illegible_frame_is_counted_rather_than_dropped_silently(self):
        rows = heard() + [rx(mac='6188', match='malformed', time_us=99000,
                             ack_started=0, ack_completed=0)]
        r = gate_a.survey(rows)
        self.assertEqual(r['frames_without_a_legible_pan'], 1)
        self.assertEqual(r['total'], len(heard()) + 1)

    def test_any_ack_at_all_fails_a_gate_that_binds_nothing(self):
        rows = heard() + [rx(pan='ctx0', match='ctx0', time_us=99000,
                             ack_started=1, ack_completed=1)]
        r = gate_a.survey(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('while nothing was bound' in x for x in r['reasons']))


class Phase2DualTupleAck(unittest.TestCase):
    def test_clean_run_passes(self):
        r = gate_a.dual_tuple_ack(interleaved())
        self.assertTrue(r['passed'], r['reasons'])
        for m in ('ctx0', 'ctx1'):
            b = r['per_context'][m]
            self.assertEqual(b['samples'], gate_a.MIN_SAMPLES_PER_CTX)
            self.assertEqual(b['acked'], gate_a.MIN_SAMPLES_PER_CTX)
            self.assertTrue(b['turnaround_within_envelope'])
            self.assertEqual(b['turnaround_mean'], float(gate_a.ACK_TURNAROUND_US))

    def test_too_few_samples_on_one_context_fails(self):
        rows = interleaved(gate_a.MIN_SAMPLES_PER_CTX)
        # drop ctx1 down to one below the floor
        ctx1 = [x for x in rows if x['fields']['match'] == 'ctx1']
        rows = [x for x in rows if x['fields']['match'] == 'ctx0'] + ctx1[:gate_a.MIN_SAMPLES_PER_CTX - 1]
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('ctx1' in x and 'required' in x for x in r['reasons']))

    def test_a_context_never_acked_fails(self):
        rows = interleaved()
        for x in rows:
            if x['fields']['match'] == 'ctx1':
                x['fields']['ack_started'] = '0'
                x['fields']['ack_completed'] = '0'
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('never answered' in x for x in r['reasons']))

    def test_one_missed_deadline_fails(self):
        rows = interleaved()
        rows[7]['fields']['deadline_miss'] = '1'
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertEqual(len(r['deadline_misses']), 1)
        self.assertTrue(any('missed ACK deadlines' in x for x in r['reasons']))

    def test_an_unintended_ack_fails_and_is_recorded_whole(self):
        """A cross-pair frame -- ctx0's PAN with ctx1's short, or the reverse --
        classifies as match=none with reason=cross_pair. `match` and `reason`
        are different fields and cross_pair is a value of the second: a frame
        is never classified AS cross_pair, it is classified as belonging to
        nobody BECAUSE of a cross pair. Getting that backwards is how a test
        can pass against a record the firmware cannot emit."""
        rows = interleaved()
        rows.append(rx(match='none', reason='cross_pair', time_us=99000,
                       mac='6188dead'))
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertEqual(len(r['unintended_acks']), 1)
        u = r['unintended_acks'][0]
        self.assertEqual((u['match'], u['mac'], u['reason']),
                         ('none', '6188dead', 'cross_pair'))
        self.assertTrue(any('unintended ACKs' in x for x in r['reasons']))

    def test_the_refusal_class_of_an_unintended_ack_is_preserved(self):
        """Why a frame should have been refused is the useful half of the
        finding: foreign means another network entirely, cross_pair means our
        own PAN with the wrong short, which is the more alarming of the two."""
        rows = interleaved()
        rows.append(rx(match='none', reason='foreign', time_us=98000, mac='aa'))
        rows.append(rx(match='none', reason='cross_pair', time_us=99000, mac='bb'))
        r = gate_a.dual_tuple_ack(rows)
        self.assertEqual([u['reason'] for u in r['unintended_acks']],
                         ['foreign', 'cross_pair'])

    def test_a_foreign_frame_merely_seen_is_not_a_failure(self):
        """Promiscuous RX delivers every CRC-valid frame, so frames belonging
        to nobody are expected throughout the record. Only answering one is a
        failure."""
        rows = interleaved()
        rows.append(rx(match='none', reason='foreign', time_us=99000,
                       ack_started=0, ack_completed=0))
        rows.append(rx(match='broadcast', time_us=99500,
                       ack_started=0, ack_completed=0))
        rows.append(rx(match='unsupported', time_us=99600,
                       ack_started=0, ack_completed=0))
        r = gate_a.dual_tuple_ack(rows)
        self.assertTrue(r['passed'], r['reasons'])
        self.assertEqual(r['unintended_acks'], [])

    def test_turnaround_outside_the_envelope_fails(self):
        rows = interleaved()
        for x in rows:
            if x['fields']['match'] == 'ctx0':
                t = int(x['fields'][gate_a.RX_TIME])
                bad = t + gate_a.ACK_TURNAROUND_US + gate_a.ACK_TURNAROUND_TOLERANCE_US + 1
                x['fields']['ack_start_us'] = str(bad)
                x['fields']['ack_address_us'] = str(bad + 160)
                x['fields']['ack_end_us'] = str(bad + 352)
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('turnaround outside' in x for x in r['reasons']))

    def test_all_three_timing_figures_are_reported(self):
        """The hardware defines the tight numbers; this file only bounds them.
        So the distribution has to come out in the record."""
        r = gate_a.dual_tuple_ack(interleaved())
        b = r['per_context']['ctx0']
        self.assertEqual(b['turnaround_mean'], float(gate_a.ACK_TURNAROUND_US))
        self.assertEqual(b['to_address_mean'], float(gate_a.ACK_TURNAROUND_US + 160))
        self.assertEqual(b['ack_duration_mean'], 352.0)
        self.assertEqual(b['turnaround_envelope_us'],
                         [gate_a.ACK_TURNAROUND_US - gate_a.ACK_TURNAROUND_TOLERANCE_US,
                          gate_a.ACK_TURNAROUND_US + gate_a.ACK_TURNAROUND_TOLERANCE_US])

    def test_an_implausible_ack_duration_fails(self):
        rows = interleaved()
        for x in rows:
            if x['fields']['match'] == 'ctx1':
                s = int(x['fields']['ack_start_us'])
                x['fields']['ack_end_us'] = str(s + gate_a.ACK_MAX_DURATION_US + 1)
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('duration implausible' in x for x in r['reasons']))


class HardwareCaptureOrdering(unittest.TestCase):
    """CRCOK < TXREADY <= ADDRESS < PHYEND holds whatever the reference points
    mean, and no correct capture path can violate it. A mis-wired PPI channel
    or a CC clash shows up here rather than silently corrupting every timing
    number in the run -- which is exactly the failure mode that cost a CC[0]
    clash earlier in this project."""

    def test_a_clean_run_has_no_ordering_violations(self):
        r = gate_a.dual_tuple_ack(interleaved())
        for m in ('ctx0', 'ctx1'):
            self.assertEqual(r['per_context'][m]['capture_order_violations'], [])

    def test_txready_before_crcok_is_caught(self):
        rows = interleaved()
        rows[0]['fields']['ack_start_us'] = str(int(rows[0]['fields'][gate_a.RX_TIME]) - 1)
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('out of order' in x for x in r['reasons']))

    def test_phyend_before_address_is_caught(self):
        rows = interleaved()
        f = rows[1]['fields']
        f['ack_end_us'] = str(int(f['ack_address_us']) - 1)
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertTrue(any('out of order' in x for x in r['reasons']))

    def test_the_violation_is_recorded_with_all_four_captures(self):
        rows = interleaved()
        rows[0]['fields']['ack_start_us'] = str(int(rows[0]['fields'][gate_a.RX_TIME]) - 1)
        r = gate_a.dual_tuple_ack(rows)
        v = r['per_context']['ctx0']['capture_order_violations'][0]
        self.assertEqual(set(v), {'match', 'crcok', 'txready', 'address', 'phyend'})

    def test_an_ordering_violation_says_no_timing_can_be_trusted(self):
        rows = interleaved()
        for x in rows:
            x['fields']['ack_start_us'] = str(int(x['fields'][gate_a.RX_TIME]) - 1)
        r = gate_a.dual_tuple_ack(rows)
        self.assertTrue(any('no timing number in this run can be trusted' in x
                            for x in r['reasons']), r['reasons'])


class RealRecordShape(unittest.TestCase):
    """The synthetic records above use field names I chose. If one of them were
    wrong, every test in this file would still pass while the evaluator read
    nothing on hardware. So the field set is checked against a record the actual
    firmware emitted, through tests/firmware_cli.c which compiles src/main.c."""

    FIELDS_THE_EVALUATOR_READS = (
        'match', 'reason', 'time_us', 'rssi', 'lqi',
        'ack_started', 'ack_completed', 'ack_start_us', 'deadline_miss', 'mac')

    def test_the_live_record_carries_every_field_the_evaluator_reads(self):
        import subprocess
        from pathlib import Path
        cli = Path(__file__).resolve().parents[1] / 'build' / 'firmware_cli.exe'
        if not cli.exists():
            self.skipTest('run tests/run_native.sh first to build the fixture')
        frame = '6188077a0b0000556c04' + '00' * 28
        p = subprocess.run([str(cli)], input='RADIOV10 INFO id=1\n@RX %s\n' % frame,
                           capture_output=True, text=True)
        rows = [l for l in p.stdout.splitlines() if ' RX ' in l]
        self.assertTrue(rows, 'the fixture emitted no RX record')
        fields = dict(tok.split('=', 1) for tok in rows[0].split()[2:] if '=' in tok)
        missing = [k for k in self.FIELDS_THE_EVALUATOR_READS if k not in fields]
        self.assertEqual(missing, [], 'the evaluator reads fields the firmware '
                                      'does not emit: %s' % missing)

    def test_the_evaluator_consumes_a_live_record_without_faulting(self):
        import subprocess
        from pathlib import Path
        cli = Path(__file__).resolve().parents[1] / 'build' / 'firmware_cli.exe'
        if not cli.exists():
            self.skipTest('run tests/run_native.sh first to build the fixture')
        frame = '6188077a0b0000556c04' + '00' * 28
        p = subprocess.run([str(cli)], input='RADIOV10 INFO id=1\n@RX %s\n' % frame,
                           capture_output=True, text=True)
        records = []
        for l in p.stdout.splitlines():
            parts = l.split()
            if len(parts) > 2 and parts[1] == 'RX':
                records.append({'kind': 'RX', 'fields': dict(
                    t.split('=', 1) for t in parts[2:] if '=' in t)})
        self.assertTrue(records)
        # It must not pass -- one unaddressed frame is nothing like a gate --
        # but it must evaluate rather than raise on the real field shape.
        r = gate_a.dual_tuple_ack(records)
        self.assertFalse(r['passed'])
        self.assertEqual(r['unintended_acks'], [])


class Interleaving(unittest.TestCase):
    """The criterion that stops two sequential single-context runs from being
    reported as one dual-context run."""

    def test_sequential_blocks_fail_even_with_perfect_counts(self):
        n = gate_a.MIN_SAMPLES_PER_CTX
        rows, t = [], 1000
        for _ in range(n):
            rows.append(rx(match='ctx0', time_us=t)); t += 1000
        for _ in range(n):
            rows.append(rx(match='ctx1', time_us=t)); t += 1000
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertEqual(r['per_context']['ctx0']['samples'], n)
        self.assertEqual(r['per_context']['ctx1']['samples'], n)
        self.assertEqual(r['per_context']['ctx0']['acked'], n)
        self.assertFalse(r['interleaving']['both_in_every_part'])
        self.assertTrue(any('same time' in x for x in r['reasons']))

    def test_one_late_sample_does_not_buy_concurrency(self):
        """A run that is sequential apart from a single token sample of the
        other context late in the window still fails: alternation has to be
        sustained, not decorative."""
        n = gate_a.MIN_SAMPLES_PER_CTX
        rows, t = [], 1000
        for _ in range(n):
            rows.append(rx(match='ctx0', time_us=t)); t += 1000
        for _ in range(n - 1):
            rows.append(rx(match='ctx1', time_us=t)); t += 1000
        rows.insert(1, rx(match='ctx1', time_us=1500))
        r = gate_a.dual_tuple_ack(rows)
        self.assertFalse(r['passed'])
        self.assertLess(r['interleaving']['alternations'], gate_a.MIN_ALTERNATIONS)

    def test_genuine_interleaving_passes(self):
        r = gate_a.dual_tuple_ack(interleaved())
        self.assertTrue(r['interleaving']['passed'])
        self.assertTrue(r['interleaving']['both_in_every_part'])
        self.assertGreaterEqual(r['interleaving']['alternations'], gate_a.MIN_ALTERNATIONS)


# The STATS field set from the first hardware run of Gate A, verbatim. It is
# the fixture for the counter identity because it is the one counter set known
# to have come off a real radio: 344 classified frames and 448 stage-1 aborts.
HARDWARE_STATS = {
    'rx_total': '344', 'ctx0_rx': '0', 'ctx1_rx': '0', 'foreign_reject': '248',
    'cross_pair_reject': '0', 'unsupported': '447', 'broadcast': '96',
    'malformed_reject': '1', 'ambiguous': '0', 'routing_faults': '0',
    'starved_polls': '0',
}


class StatsCoherence(unittest.TestCase):
    def test_the_first_hardware_counter_set_is_coherent(self):
        r = gate_a.stats_coherent(HARDWARE_STATS)
        self.assertTrue(r['coherent'], r)
        self.assertEqual(r['rx_total'], 344)
        self.assertEqual(r['classified_sum'], 344)

    def test_the_stage1_aborts_sit_outside_the_sum(self):
        """447 unsupported and 1 malformed are NOT part of rx_total. Folding
        them in is the misreading that looked like a double-count."""
        r = gate_a.stats_coherent(HARDWARE_STATS)
        self.assertEqual(r['stage1_aborts_outside_the_sum'],
                         {'unsupported': 447, 'malformed_reject': 1})
        self.assertNotEqual(r['classified_sum'], 344 + 448)

    def test_a_genuine_double_count_is_caught(self):
        """If two paths ever incremented one classification counter, the sum
        exceeds rx_total. That is the failure this check exists for."""
        s = dict(HARDWARE_STATS, broadcast=str(96 * 2))
        self.assertFalse(gate_a.stats_coherent(s)['coherent'])

    def test_a_lost_increment_is_caught_too(self):
        s = dict(HARDWARE_STATS, foreign_reject='200')
        self.assertFalse(gate_a.stats_coherent(s)['coherent'])

    def test_a_missing_counter_is_missing_and_not_a_zero(self):
        s = dict(HARDWARE_STATS)
        del s['ambiguous']
        r = gate_a.stats_coherent(s)
        self.assertFalse(r['coherent'])
        self.assertFalse(r['checked'])
        self.assertEqual(r['missing'], ['ambiguous'])

    def test_a_non_numeric_counter_is_a_fault(self):
        with self.assertRaises(gate_a.GateAFault):
            gate_a.stats_coherent(dict(HARDWARE_STATS, rx_total='lots'))


class WholeGate(unittest.TestCase):
    def test_pass(self):
        r = gate_a.evaluate(heard(), HARDWARE_STATS)
        self.assertTrue(r['passed'], r['reasons'])
        self.assertEqual(r['gate'], 'A')
        self.assertEqual(r['config_generations'], ['0'])

    def test_incoherent_counters_fail_the_gate_whatever_the_survey_said(self):
        r = gate_a.evaluate(heard(), dict(HARDWARE_STATS, broadcast='999'))
        self.assertFalse(r['passed'])
        self.assertTrue(gate_a.survey(heard())['passed'])
        self.assertTrue(any('do not add up' in x for x in r['reasons']))

    def test_an_allowlist_left_over_from_an_earlier_run_is_not_a_failure(self):
        """A dongle keeps its published allowlist for the life of a boot: END
        shuts the ACK gate but leaves the config in place. So a Gate A run that
        follows an earlier run on the same boot finds generation 2 throughout,
        with the ACK gate shut, and that is a healthy passive measurement.
        Demanding a zero here failed exactly such a run, and the only way to
        satisfy it would have been to unplug the dongle before every attempt.

        It does not affect the measurement: the survey is scoped by PAN, not by
        `match`, so what each frame classifies as never enters it."""
        rows = heard()
        for row in rows:
            row['fields']['config_generation'] = '2'
        r = gate_a.evaluate(rows, HARDWARE_STATS)
        self.assertTrue(r['passed'], r['reasons'])
        self.assertEqual(r['config_generations'], ['2'])

    def test_a_generation_that_moves_mid_window_fails(self):
        """What the check is actually for: the radio reconfigured while the
        gate was listening, which makes the samples incomparable."""
        rows = heard()
        for row in rows[-3:]:
            row['fields']['config_generation'] = '1'
        r = gate_a.evaluate(rows, HARDWARE_STATS)
        self.assertFalse(r['passed'])
        self.assertEqual(r['config_generations'], ['0', '1'])
        self.assertTrue(any('reconfigured mid-measurement' in x
                            for x in r['reasons']), r['reasons'])

    def test_the_stats_are_optional_and_their_absence_is_not_a_pass_by_default(self):
        r = gate_a.evaluate(heard())
        self.assertIsNone(r['stats_coherence'])
        self.assertTrue(r['passed'], r['reasons'])

    def test_a_survey_failure_fails_the_gate(self):
        r = gate_a.evaluate(heard()[:4], HARDWARE_STATS)
        self.assertFalse(r['passed'])

    def test_a_malformed_field_is_a_fault_not_a_pass(self):
        rows = heard()
        rows[0]['fields']['rssi'] = 'not-a-number'
        with self.assertRaises(gate_a.GateAFault):
            gate_a.evaluate(rows, HARDWARE_STATS)


class GateBInheritsTheAckMeasurement(unittest.TestCase):
    """dual_tuple_ack stays in this module because Gate B imports it. These
    pin the handover: it still works, and it is no longer reachable from
    Gate A's verdict."""

    def test_gate_a_no_longer_reports_an_ack_measurement(self):
        r = gate_a.evaluate(heard(), HARDWARE_STATS)
        self.assertNotIn('phase2_dual_tuple_ack', r)
        self.assertEqual(set(r) & {'survey', 'stats_coherence'},
                         {'survey', 'stats_coherence'})

    def test_the_evaluator_itself_is_intact_for_gate_b(self):
        b = gate_a.dual_tuple_ack(interleaved())
        self.assertTrue(b['passed'], b['reasons'])
        for m in ('ctx0', 'ctx1'):
            self.assertEqual(b['per_context'][m]['acked'],
                             gate_a.MIN_SAMPLES_PER_CTX)

    def test_it_reads_the_timestamps_the_firmware_actually_emits(self):
        """The rename defect, at the level that matters: with the real field
        names the turnaround is the 192 us the fixture built, not zero."""
        b = gate_a.dual_tuple_ack(interleaved())
        self.assertEqual(b['per_context']['ctx0']['turnaround_mean'],
                         float(gate_a.ACK_TURNAROUND_US))
        self.assertTrue(b['per_context']['ctx0']['turnaround_within_envelope'])

    def test_the_dead_formatters_name_measures_nothing_rather_than_zero(self):
        """What repointing this evaluator at dual_format_rx's `rx_end_us` would
        have done. The timestamps go missing rather than wrong, so no
        turnaround is reported at all and the gate fails loudly instead of
        passing on numbers computed against zero."""
        rows = interleaved()
        for row in rows:
            row['fields']['rx_end_us'] = row['fields'].pop(gate_a.RX_TIME)
        b = gate_a.dual_tuple_ack(rows)
        self.assertFalse(b['passed'])
        self.assertNotIn('turnaround_mean', b['per_context']['ctx0'])
        # And it says so honestly: the captures were unreadable, which is not
        # the same finding as a radio whose turnaround is out of envelope.
        self.assertTrue(any('measured nothing' in x for x in b['reasons']),
                        b['reasons'])
        self.assertFalse([x for x in b['reasons'] if 'outside the' in x])


if __name__ == '__main__':
    unittest.main()
