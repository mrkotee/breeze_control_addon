"""Gate E: the restart evaluator, the phase runner's END discipline, and the
guards the launcher recognises. No COM, no RF, no real keys."""
import copy, sys, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'host'))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))
import gate_e
from gate_e_runner import GateERunner, phase_b_guard
from test_gate_b import polls

SEC = 1000000


def state(next_fc=(2144, 1760), floors=({'tc0': 100}, {'tc1': 200}), raw=('e2b0', '027a'),
          epoch=('ep0', 'ep1'), fcs=((), ())):
    snap, ident = {}, {}
    for i, c in enumerate(('0', '1')):
        snap[c] = {'epoch_sha256': 'h%s%d' % (c, next_fc[i]), 'generation': 27 + i,
                   'next_fc': next_fc[i], 'pan': 1 + i, 'short': 9 + i,
                   'recovery_state': 'PARENT_LINK_ACTIVE', 'context_generation': 20,
                   'nwk_source_floors': dict(floors[i])}
        ident[c] = {'raw_ieee': raw[i], 'tc_ieee': 't%d' % i, 'pan': 1 + i, 'short': 9 + i,
                    'attempt': 'a%d' % i, 'ctx': i, 'key_epoch_id': epoch[i], 'keyseq': 0,
                    'secret_ref': 's%d' % i}
    return {'snapshot': snap, 'identity': ident,
            'intent_fcs': {'0': list(fcs[0]), '1': list(fcs[1])}}


ACTIVE = {c: {'recovery': 'PARENT_LINK_ACTIVE'} for c in ('0', '1')}


class Evaluator(unittest.TestCase):
    def good(self):
        a = {'after': state(), 'reached_active': {'0': True, '1': True}, 'ended_cleanly': False}
        b0 = state()
        b1 = state(next_fc=(2240, 1856), floors=({'tc0': 150}, {'tc1': 260}),
                   fcs=((2144, 2176, 2208), (1760, 1792, 1824)))
        rows = polls(0, [t * SEC for t in range(10, 70, 10)]) + polls(1, [t * SEC for t in range(15, 75, 10)])
        return a, b0, b1, rows

    def ev(self, a, b0, b1, rows, status=ACTIVE):
        return gate_e.evaluate(a, b0, b1, rows, status)

    def test_a_clean_restart_passes(self):
        v = self.ev(*self.good())
        self.assertTrue(v['passed'], v['reasons'])
        self.assertEqual(v['phase_b_first_fc'], {'0': 2144, '1': 1760})

    def test_a_reused_frame_counter_fails(self):
        a, b0, b1, rows = self.good()
        b1['intent_fcs']['1'] = [1700, 1792]
        self.assertTrue(any('reused frame counter 1700' in r for r in self.ev(a, b0, b1, rows)['reasons']))

    def test_a_regenerated_raw_identity_fails(self):
        a, b0, b1, rows = self.good()
        b1['identity']['0']['raw_ieee'] = 'ffff'
        self.assertTrue(any('RAW identity field raw_ieee' in r for r in self.ev(a, b0, b1, rows)['reasons']))

    def test_a_silently_reinitialised_epoch_fails(self):
        a, b0, b1, rows = self.good()
        b0['identity']['1']['key_epoch_id'] = 'new'
        b1['identity']['1']['key_epoch_id'] = 'new'
        self.assertTrue(any('security epoch field key_epoch_id' in r for r in self.ev(a, b0, b1, rows)['reasons']))

    def test_a_fallen_replay_floor_fails(self):
        a, b0, b1, rows = self.good()
        b1['snapshot']['0']['nwk_source_floors'] = {'tc0': 99}
        self.assertTrue(any('replay floor for tc0 fell' in r for r in self.ev(a, b0, b1, rows)['reasons']))

    def test_a_store_that_moved_between_the_phases_fails(self):
        a, b0, b1, rows = self.good()
        b0['snapshot']['1']['next_fc'] = 1792
        self.assertTrue(any('not the one phase A left' in r for r in self.ev(a, b0, b1, rows)['reasons']))

    def test_a_phase_a_that_exited_politely_is_not_a_crash(self):
        a, b0, b1, rows = self.good()
        a['ended_cleanly'] = True
        self.assertTrue(any('needs a host that dies' in r for r in self.ev(a, b0, b1, rows)['reasons']))

    def test_a_context_that_did_not_come_back_fails(self):
        v = self.ev(*self.good(), status={'0': ACTIVE['0'], '1': {'recovery': 'STOPPED'}})
        self.assertTrue(any("ctx1: after the restart it is 'STOPPED'" in r for r in v['reasons']))

    def test_no_secured_frame_in_b_leaves_continuity_unshown(self):
        a, b0, b1, rows = self.good()
        b1['intent_fcs']['0'] = []
        self.assertTrue(any('FC continuity is unshown' in r for r in self.ev(a, b0, b1, rows)['reasons']))


class Guards(unittest.TestCase):
    def test_phase_b_guard_is_derived_and_distinct(self):
        run = 'a' * 32
        g = phase_b_guard(run)
        self.assertEqual(g, phase_b_guard(run))
        self.assertNotEqual(g, run)
        self.assertRegex(g, r'^[0-9a-f]{32}$')

    def test_the_launcher_recognises_both_guards_of_a_run(self):
        src = (ROOT / 'launch_gate_e.py').read_text(encoding='utf-8')
        self.assertIn('out.update({run, phase_b_guard(run)})', src)
        self.assertIn("guard=phase_b_guard(run_id)", src)
        self.assertIn('store_is_not_where_phase_a_left_it', src)
        self.assertIn('os._exit(', src)


class PhaseEndDiscipline(unittest.TestCase):
    def runner(self):
        r = GateERunner.__new__(GateERunner)
        r.records, r.answers, r.sent_order, r.snapshots, r.authenticated = [], [], [], [], set()
        r.polls_sent, r.misses_total, r.stopped = {0: 0, 1: 0}, {0: 0, 1: 0}, {}
        sent = []
        r.command = lambda verb, *a, **k: sent.append(verb) or {}
        r.probe_id_floor = lambda: None
        r.check_identity = lambda: {}
        r.require_a_fresh_boot = lambda: None
        r.clock = lambda: 0.0
        r.commission = lambda c: {'recovery': 'PARENT_LINK_ACTIVE'}

        def soak(seconds, started):
            r.snapshots.append({'status': ACTIVE, 'stats': {}})
        r.soak = soak
        return r, sent

    def test_phase_a_never_sends_end(self):
        r, sent = self.runner()
        out = r.execute_phase(end=False)
        self.assertNotIn('END', sent)
        self.assertFalse(out['ended_cleanly'])
        self.assertEqual(out['reached_active'], {'0': True, '1': True})

    def test_phase_b_ends_cleanly(self):
        r, sent = self.runner()
        out = r.execute_phase(end=True)
        self.assertIn('END', sent)
        self.assertTrue(out['ended_cleanly'])


if __name__ == '__main__':
    unittest.main()
