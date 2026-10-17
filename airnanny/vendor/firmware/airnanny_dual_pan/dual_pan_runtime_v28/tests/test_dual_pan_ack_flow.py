"""Does the real firmware answer BOTH tuples? Offline, against src/main.c.

This is the central claim of issue #5, and until now it had only been tested
against the admission layer in isolation (test_dual_admit) or against a model
of it. Here both contexts are bound through real BIND commands and real frames
are delivered, so the thing under test is the actual dispatcher, the actual
per-context ACK gate and the actual classifier in one piece -- the same
src/main.c that gets compiled into the image, through tests/firmware_cli.c.

What this canNOT establish, and Gate A still must: the fixture leaves
ack_start_us, rssi and lqi at zero, so no timing and no RF margin is measured
here. What is established is attribution and gating: who gets answered, who
does not, and that the two do not interfere.

No COM, no RF, no hardware, no cryptography, no keys.
"""
import os, subprocess, sys, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIRMWARE = HERE.parent
sys.path.insert(0, str(FIRMWARE / 'host'))
import dual_store
import gate_a

CLI = FIRMWARE / 'build' / 'firmware_cli.exe'
BOOT = '1' * 32
GUARD = '2' * 32

# generation in each store; the firmware refuses anything below its floor and
# management_resume additionally pins the epoch, the attempt and the short.
GENERATION = {0: 19, 1: 16}


def wire(hexstr):
    """An IEEE address is written big-endian in documents and travels
    little-endian on air. Reversing here rather than in a literal is the
    convention that was got wrong once in this project's 1.3 test vectors."""
    return bytes.fromhex(hexstr)[::-1]


def frame(pan, short, tc_hex, dsn=7, fc=1, keyseq=0, length=38):
    """A secured A7 DATA frame of the shape the admission predicate accepts:
    FCF 0x8861 with an ACK request, NWK FCF 0x0208, and an aux security header
    naming the trust centre and the key sequence. Built from the predicate's
    own field offsets so a layout change breaks this loudly."""
    m = bytearray(length)
    m[0:2] = (0x8861).to_bytes(2, 'little')
    m[2] = dsn
    m[3:5] = pan.to_bytes(2, 'little')          # destination PAN
    m[5:7] = short.to_bytes(2, 'little')        # destination short: us
    m[7:9] = (0).to_bytes(2, 'little')
    m[9:11] = (0x0208).to_bytes(2, 'little')    # NWK FCF, h == 8
    m[11:13] = short.to_bytes(2, 'little')
    m[13:15] = (0).to_bytes(2, 'little')
    aux = 9 + 8                                  # m + 9 + h
    m[aux] = 0x28
    m[aux + 1:aux + 5] = fc.to_bytes(4, 'little')
    m[aux + 5:aux + 13] = wire(tc_hex)
    m[aux + 13] = keyseq
    return m.hex()


def ctx_frame(ctx, **kw):
    p = dual_store.PINNED[ctx]
    return frame(p['pan'], p['short'], p['tc_ieee'], **kw)


def cross_pair_frame(**kw):
    """ctx0's PAN carrying ctx1's short address. Neither context owns this
    tuple, and answering it would be the exact isolation failure the whole
    admission layer exists to prevent."""
    return frame(dual_store.PINNED[0]['pan'], dual_store.PINNED[1]['short'],
                 dual_store.PINNED[0]['tc_ieee'], **kw)


def bind(ctx, i):
    p = dual_store.PINNED[ctx]
    return ('RADIOV10 BIND id=%d boot=%s session=1 generation=%d epoch=%s '
            'attempt=%s guard=%s short=%d ctx=%d'
            % (i, BOOT, GENERATION[ctx], p['epoch'], p['attempt'], GUARD,
               p['short'], ctx))


def drive(lines):
    if not CLI.exists():
        raise unittest.SkipTest('run tests/run_native.sh first to build the fixture')
    p = subprocess.run([str(CLI)], input=''.join(l + '\n' for l in lines),
                       capture_output=True, text=True)
    records = []
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) > 2 and parts[0] == 'RADIOV10':
            records.append({'kind': parts[1], 'raw': line, 'fields': dict(
                t.split('=', 1) for t in parts[2:] if '=' in t)})
    return records


def fields(records, kind):
    return [r['fields'] for r in records if r['kind'] == kind]


class BothContextsBind(unittest.TestCase):
    def test_binding_both_opens_ack_and_advances_the_configuration(self):
        rec = drive(['RADIOV10 INFO id=1', bind(0, 2), bind(1, 3),
                     'RADIOV10 INFO id=4'])
        self.assertEqual([f['reason'] for f in fields(rec, 'ERROR')], [])
        info = fields(rec, 'INFO')
        self.assertEqual(info[0]['immediate_ack'], '0', 'ACK open before any bind')
        self.assertEqual(info[-1]['immediate_ack'], '1', 'ACK still shut after both binds')
        # One configuration publication per bind, and the generation is
        # monotonic: a context is added without disturbing the other.
        self.assertEqual(info[-1]['config_generation'], '2')
        self.assertEqual(info[-1]['contexts'], '2')

    def test_each_status_names_the_context_it_describes(self):
        rec = drive(['RADIOV10 INFO id=1', bind(0, 2), bind(1, 3),
                     'RADIOV10 STATUS id=4 boot=%s session=1 ctx=0' % BOOT,
                     'RADIOV10 STATUS id=5 boot=%s session=1 ctx=1' % BOOT])
        st = fields(rec, 'STATUS')
        self.assertEqual(st[-2]['ctx'], '0')
        self.assertEqual(st[-1]['ctx'], '1')
        self.assertEqual(st[-2]['assigned_short'], '%04x' % dual_store.PINNED[0]['short'])
        self.assertEqual(st[-1]['assigned_short'], '%04x' % dual_store.PINNED[1]['short'])


class BothTuplesAnswered(unittest.TestCase):
    """A2 and A5, as far as they can be established without a radio."""

    def setUp(self):
        lines = ['RADIOV10 INFO id=1', bind(0, 2), bind(1, 3)]
        # Interleaved, so neither context is merely answered in isolation.
        for n in range(6):
            lines.append('@RX ' + ctx_frame(0, dsn=10 + n, fc=100 + n))
            lines.append('@RX ' + ctx_frame(1, dsn=50 + n, fc=200 + n))
        self.rec = drive(lines)
        self.rx = fields(self.rec, 'RX')

    def test_no_command_was_refused(self):
        self.assertEqual([f['reason'] for f in fields(self.rec, 'ERROR')], [])

    def test_every_frame_is_attributed_to_its_own_context(self):
        got = [f['match'] for f in self.rx]
        self.assertEqual(got, ['ctx0', 'ctx1'] * 6,
                         'frames were misattributed: %s' % got)

    def test_both_tuples_are_answered(self):
        for want in ('ctx0', 'ctx1'):
            answered = [f for f in self.rx
                        if f['match'] == want and f['ack_started'] == '1']
            self.assertEqual(len(answered), 6,
                             '%s was answered %d times out of 6' % (want, len(answered)))

    def test_the_ack_is_completed_and_no_deadline_is_missed(self):
        for f in self.rx:
            self.assertEqual(f['ack_completed'], '1', f)
            self.assertEqual(f['deadline_miss'], '0', f)

    def test_the_configuration_did_not_change_during_the_exchange(self):
        gens = {f['config_generation'] for f in self.rx}
        self.assertEqual(gens, {'2'}, 'the radio was reconfigured mid-exchange: %s' % gens)

    def test_the_evaluator_reads_this_run_without_faulting(self):
        """The real records, through the Gate A evaluator. It must not pass --
        six samples is far below the floor and nothing here is timed -- but it
        must evaluate, and it must find no unintended ACK and no deadline miss."""
        r = gate_a.dual_tuple_ack(self.rec)
        self.assertEqual(r['unintended_acks'], [])
        self.assertEqual(r['deadline_misses'], [])
        self.assertEqual(r['per_context']['ctx0']['samples'], 6)
        self.assertEqual(r['per_context']['ctx1']['samples'], 6)
        self.assertEqual(r['per_context']['ctx0']['acked'], 6)
        self.assertEqual(r['per_context']['ctx1']['acked'], 6)
        self.assertFalse(r['passed'])
        self.assertTrue(any('required' in x for x in r['reasons']))


class NothingElseIsAnswered(unittest.TestCase):
    """A4. The refusals matter more than the acceptances: an ACK is a claim of
    identity on air, and a wrong one is visible to the whole network."""

    def run_with(self, extra_frames):
        lines = ['RADIOV10 INFO id=1', bind(0, 2), bind(1, 3)]
        lines += ['@RX ' + f for f in extra_frames]
        return fields(drive(lines), 'RX')

    def test_a_cross_pair_tuple_is_not_answered(self):
        rx = self.run_with([cross_pair_frame(dsn=9, fc=300)])
        self.assertEqual(len(rx), 1)
        self.assertEqual(rx[0]['ack_started'], '0',
                         'the firmware answered a cross-pair tuple')
        self.assertEqual(rx[0]['match'], 'none')
        self.assertEqual(rx[0]['reason'], 'cross_pair')

    def test_a_foreign_pan_is_not_answered(self):
        rx = self.run_with([frame(0x1234, 0xBEEF,
                                  dual_store.PINNED[0]['tc_ieee'], dsn=11, fc=301)])
        self.assertEqual(len(rx), 1)
        self.assertEqual(rx[0]['ack_started'], '0')
        self.assertEqual(rx[0]['match'], 'none')
        self.assertEqual(rx[0]['reason'], 'foreign')

    def test_the_other_contexts_trust_centre_is_not_answered(self):
        """ctx0's PAN and short, but ctx1's trust centre in the aux header. The
        tuple is ours; the key that would decrypt it is not. The frame
        classifies as ctx0 and is still refused, by the deep predicate rather
        than by the classifier -- which is the separation issue #5 asks for:
        frame ctx == key ctx, not merely frame ctx == tuple."""
        p0 = dual_store.PINNED[0]
        rx = self.run_with([frame(p0['pan'], p0['short'],
                                  dual_store.PINNED[1]['tc_ieee'], dsn=12, fc=302)])
        self.assertEqual(len(rx), 1)
        self.assertEqual(rx[0]['match'], 'ctx0', 'the classifier should still own it')
        self.assertEqual(rx[0]['ack_started'], '0',
                         'the deep predicate let a foreign trust centre through')

    def test_a_wrong_key_sequence_is_not_answered(self):
        rx = self.run_with([ctx_frame(1, dsn=13, fc=303, keyseq=1)])
        self.assertEqual(len(rx), 1)
        self.assertEqual(rx[0]['match'], 'ctx1')
        self.assertEqual(rx[0]['ack_started'], '0')

    def test_refusing_one_does_not_disturb_the_other_context(self):
        """A5: a refusal must cost the other context nothing."""
        lines = ['RADIOV10 INFO id=1', bind(0, 2), bind(1, 3)]
        lines.append('@RX ' + ctx_frame(1, dsn=20, fc=400))
        lines.append('@RX ' + cross_pair_frame(dsn=21, fc=401))
        lines.append('@RX ' + ctx_frame(1, dsn=22, fc=402))
        lines.append('@RX ' + ctx_frame(0, dsn=23, fc=403))
        rx = fields(drive(lines), 'RX')
        self.assertEqual([f['match'] for f in rx], ['ctx1', 'none', 'ctx1', 'ctx0'])
        self.assertEqual([f['ack_started'] for f in rx], ['1', '0', '1', '1'])


class OnlyBoundContextsAnswer(unittest.TestCase):
    def test_a_context_that_was_never_bound_is_not_answered(self):
        """Only ctx1 binds. ctx0's frames must arrive -- promiscuous RX
        delivers everything -- and must not be answered."""
        lines = ['RADIOV10 INFO id=1', bind(1, 2),
                 '@RX ' + ctx_frame(0, dsn=30, fc=500),
                 '@RX ' + ctx_frame(1, dsn=31, fc=501)]
        rx = fields(drive(lines), 'RX')
        self.assertEqual(len(rx), 2)
        self.assertEqual(rx[0]['ack_started'], '0',
                         'an unbound context was answered')
        self.assertEqual(rx[1]['ack_started'], '1',
                         'the bound context was not answered')


class StatsReflectTheExchange(unittest.TestCase):
    def test_the_counters_account_for_both_contexts_and_the_refusals(self):
        lines = ['RADIOV10 INFO id=1', bind(0, 2), bind(1, 3)]
        for n in range(4):
            lines.append('@RX ' + ctx_frame(0, dsn=40 + n, fc=600 + n))
            lines.append('@RX ' + ctx_frame(1, dsn=60 + n, fc=700 + n))
        lines.append('@RX ' + cross_pair_frame(dsn=70, fc=800))
        lines.append('RADIOV10 STATS id=9 boot=%s' % BOOT)
        rec = drive(lines)
        s = fields(rec, 'STATS')
        self.assertEqual(len(s), 1, 'no STATS record')
        s = s[0]
        self.assertEqual(s['ctx0_rx'], '4')
        self.assertEqual(s['ctx1_rx'], '4')
        self.assertEqual(s['cross_pair_reject'], '1')
        self.assertEqual(s['routing_faults'], '0')
        self.assertEqual(s['config_generation'], '2')


if __name__ == '__main__':
    unittest.main()
