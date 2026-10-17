"""Offline tests for the dual-store accessor. No COM, no RF, no hardware.

The real stores exist only on the operator's machine, so these tests run
against synthetic stores in a temp directory. That is enough for every
validation rule, and the one thing it cannot check -- that the pinned paths are
right -- is checked separately on the device and recorded in evidence.

The test that matters most is test_pinned_constants_match_the_c_source. The
accessor duplicates the identity the firmware compiled in, which is exactly the
kind of duplication that rots: the C changes, Python does not, and the
disagreement surfaces as a refused BIND on hardware with both A7 units live.
That test makes the C the single source of truth and the drift a test failure.
"""
import copy, json, os, re, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'host'))
import dual_store

FIRMWARE = Path(__file__).resolve().parents[1]


def store_for(ctx):
    """A synthetic store that the accessor should accept."""
    p = dual_store.PINNED[ctx]
    return {
        'context': {'ctx': ctx, 'pan': p['pan'], 'short': p['short'],
                    'raw_ieee': p['raw_ieee'], 'tc_ieee': p['tc_ieee'],
                    'attempt': p['attempt'], 'generation': 14},
        'generation': 19 if ctx == 0 else 16,
        'next_fc': 1280 if ctx == 0 else 1088,
        'keyseq': p['keyseq'],
        'key_epoch_id': p['epoch'],
        'recovery': {'state': 'FIRST_TYPE07_CONFIRMED', 'gate': 'a' * 32},
        'nwk_source_floors': {p['tc_ieee']: 2462210},
    }


class Harness(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.paths = {}
        for ctx in (0, 1):
            f = Path(self.dir) / ('ctx%d.json' % ctx)
            f.write_text(json.dumps(store_for(ctx)), encoding='utf-8')
            self.paths[ctx] = f

    def write(self, ctx, mutate):
        r = store_for(ctx)
        mutate(r)
        self.paths[ctx].write_text(json.dumps(r), encoding='utf-8')

    def refuses(self, ctx, mutate, fragment):
        self.write(ctx, mutate)
        with self.assertRaises(dual_store.StoreFault) as e:
            dual_store.read(ctx, self.paths[ctx])
        self.assertIn(fragment, str(e.exception))


class Accepts(Harness):
    def test_both_stores_read(self):
        both = dual_store.read_both(self.paths)
        self.assertEqual(both[0]['generation'], 19)
        self.assertEqual(both[0]['next_fc'], 1280)
        self.assertEqual(both[1]['generation'], 16)
        self.assertEqual(both[1]['next_fc'], 1088)
        self.assertEqual(both[0]['short'], 0xA326)
        self.assertEqual(both[1]['short'], 0x6C55)
        self.assertEqual(both[0]['guard'], 'a' * 32)

    def test_bind_fields_project_the_store_verbatim(self):
        e = dual_store.read(1, self.paths[1])
        f = dual_store.bind_fields(e)
        self.assertIn('generation=16', f)
        self.assertIn('short=%d' % 0x6C55, f)
        self.assertIn('epoch=' + dual_store.PINNED[1]['epoch'], f)
        self.assertIn('attempt=' + dual_store.PINNED[1]['attempt'], f)
        self.assertIn('guard=' + 'a' * 32, f)
        self.assertTrue(f.startswith('session=1 '))
        # ctx is appended by the probe, not here, so that one place decides it.
        self.assertNotIn('ctx=', f)

    def test_nothing_is_written(self):
        before = {c: self.paths[c].read_bytes() for c in (0, 1)}
        dual_store.read_both(self.paths)
        for c in (0, 1):
            self.assertEqual(self.paths[c].read_bytes(), before[c])


class Refuses(Harness):
    def test_a_store_that_is_not_the_context_it_should_be(self):
        self.refuses(0, lambda r: r['context'].update(ctx=1), 'store_is_not_ctx0')

    def test_the_other_networks_pan(self):
        self.refuses(0, lambda r: r['context'].update(pan=0x0B7A), 'ctx0_pan_mismatch')

    def test_the_other_networks_short(self):
        self.refuses(1, lambda r: r['context'].update(short=0xA326), 'ctx1_short_mismatch')

    def test_a_transplanted_raw_identity(self):
        self.refuses(1, lambda r: r['context'].update(raw_ieee='e2b0275f4d582069'),
                     'ctx1_raw_ieee_mismatch')

    def test_a_transplanted_trust_centre(self):
        self.refuses(0, lambda r: r['context'].update(tc_ieee='00124b0036a1875f'),
                     'ctx0_tc_ieee_mismatch')

    def test_a_transplanted_key_epoch(self):
        self.refuses(0, lambda r: r.update(key_epoch_id='9985b15dcb574c59b87dc2fb379f317f'),
                     'ctx0_epoch_mismatch')

    def test_a_transplanted_attempt(self):
        self.refuses(1, lambda r: r['context'].update(attempt='5b09cb6bc02746298fbffcfb780844a5'),
                     'ctx1_attempt_mismatch')

    def test_a_changed_key_sequence(self):
        self.refuses(1, lambda r: r.update(keyseq=1), 'ctx1_keyseq_mismatch')

    def test_a_generation_below_the_firmwares_floor(self):
        self.refuses(1, lambda r: r.update(generation=dual_store.GENERATION_FLOOR - 1),
                     'generation_below_floor')

    def test_a_non_integer_generation(self):
        self.refuses(1, lambda r: r.update(generation='16'), 'generation_below_floor')

    def test_an_implausible_frame_counter(self):
        self.refuses(0, lambda r: r.update(next_fc=0), 'next_fc_implausible')

    def test_a_missing_guard(self):
        self.refuses(0, lambda r: r.update(recovery={'state': 'X'}),
                     'guard_missing_or_malformed')

    def test_a_malformed_guard(self):
        self.refuses(0, lambda r: r.update(recovery={'state': 'X', 'gate': 'short'}),
                     'guard_missing_or_malformed')

    def test_a_missing_store_is_a_refusal_not_an_empty_result(self):
        with self.assertRaises(dual_store.StoreFault) as e:
            dual_store.read(0, Path(self.dir) / 'absent.json')
        self.assertIn('store_missing', str(e.exception))

    def test_an_unknown_context(self):
        with self.assertRaises(dual_store.StoreFault):
            dual_store.read(2, self.paths[0])


class CrossStore(Harness):
    """The check that only exists across the two stores: one radio answering a
    single tuple for two networks is what the admission layer exists to
    prevent, and it would begin here rather than on air."""

    def test_both_stores_on_the_same_tuple(self):
        r = store_for(1)
        r['context'].update(ctx=0, pan=dual_store.PINNED[0]['pan'],
                            short=dual_store.PINNED[0]['short'],
                            raw_ieee=dual_store.PINNED[0]['raw_ieee'],
                            tc_ieee=dual_store.PINNED[0]['tc_ieee'],
                            attempt=dual_store.PINNED[0]['attempt'])
        r['key_epoch_id'] = dual_store.PINNED[0]['epoch']
        self.paths[1].write_text(json.dumps(r), encoding='utf-8')
        # ctx1's slot now holds ctx0's identity, so the per-store check fires
        # first; that is the stricter refusal and it is the right one.
        with self.assertRaises(dual_store.StoreFault) as e:
            dual_store.read_both(self.paths)
        self.assertIn('store_is_not_ctx1', str(e.exception))

    def test_same_tuple_reached_through_matching_pins_is_still_refused(self):
        """If both PINNED entries ever described the same tuple -- a mistake in
        the accessor rather than in a store -- read_both must still refuse."""
        saved = copy.deepcopy(dual_store.PINNED)
        try:
            dual_store.PINNED[1] = copy.deepcopy(dual_store.PINNED[0])
            r = store_for(1)
            r['context']['ctx'] = 1
            self.paths[1].write_text(json.dumps(r), encoding='utf-8')
            with self.assertRaises(dual_store.StoreFault) as e:
                dual_store.read_both(self.paths)
            self.assertIn('same_tuple', str(e.exception))
        finally:
            dual_store.PINNED.clear()
            dual_store.PINNED.update(saved)


class AgreesWithTheFirmware(unittest.TestCase):
    """Keeps the duplication honest. The C is the source of truth."""

    def test_pinned_constants_match_the_c_source(self):
        h = (FIRMWARE / 'include/dual_identity.h').read_text(encoding='utf-8')
        c = (FIRMWARE / 'src/dual_identity.c').read_text(encoding='utf-8')

        def define(name):
            m = re.search(r'#define\s+%s\s+0x([0-9A-Fa-f]+)u?' % name, h)
            self.assertIsNotNone(m, 'missing #define %s' % name)
            return int(m.group(1), 16)

        for ctx in (0, 1):
            self.assertEqual(dual_store.PINNED[ctx]['pan'],
                             define('DUAL_CTX%d_PAN' % ctx),
                             'ctx%d PAN disagrees with the header' % ctx)
            self.assertEqual(dual_store.PINNED[ctx]['short'],
                             define('DUAL_CTX%d_SHORT' % ctx),
                             'ctx%d short disagrees with the header' % ctx)

        floor = re.search(r'#define\s+DUAL_GENERATION_FLOOR\s+(\d+)u?', h)
        self.assertIsNotNone(floor)
        self.assertEqual(dual_store.GENERATION_FLOOR, int(floor.group(1)))

        # The epochs and attempts are string literals in the .c; each must
        # appear there exactly as Python has it.
        for ctx in (0, 1):
            for field in ('epoch', 'attempt'):
                value = dual_store.PINNED[ctx][field]
                self.assertIn('"%s"' % value, c,
                              'ctx%d %s %s is not in src/dual_identity.c'
                              % (ctx, field, value))

        # The IEEE addresses are wire-order byte arrays in the .c, so they are
        # compared by reversing the hex Python holds. This is the convention
        # that was already got wrong once in this project, in the 1.3 test
        # vectors, so it is checked rather than assumed.
        for ctx in (0, 1):
            for field in ('raw_ieee', 'tc_ieee'):
                hexstr = dual_store.PINNED[ctx][field]
                wire = list(bytes.fromhex(hexstr))[::-1]
                pattern = r',\s*'.join(r'0x%02x' % b for b in wire)
                self.assertRegex(
                    c.replace('\n', ' '), pattern,
                    'ctx%d %s wire order %s not found in src/dual_identity.c'
                    % (ctx, field, hexstr))

    def test_the_contexts_are_two(self):
        h = (FIRMWARE / 'include/dual_identity.h').read_text(encoding='utf-8')
        m = re.search(r'#define\s+DUAL_CONTEXTS\s+(\d+)u?', h)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), len(dual_store.STORE_PATHS))
        self.assertEqual(int(m.group(1)), len(dual_store.PINNED))


if __name__ == '__main__':
    unittest.main()
