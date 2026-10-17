"""The Gate C launcher's refusals, offline."""
import subprocess, sys, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'host'))


class Refusals(unittest.TestCase):
    def test_no_operator_health_statement_no_prepare(self):
        import launch_gate_c as C
        for health in (None, '', '   '):
            with self.assertRaises(C.authority.AuthorityFault) as e:
                C.prepare(health)
            self.assertIn('operator_health_statement_required', str(e.exception))

    def test_the_statement_is_checked_before_anything_else(self):
        """Refused before preflight, so it cannot be skipped by a preflight
        that happens to fail first, nor touch the gate directory."""
        import launch_gate_c as C
        called = []
        saved = C.preflight
        C.preflight = lambda: called.append(1)
        try:
            with self.assertRaises(C.authority.AuthorityFault):
                C.prepare('')
        finally:
            C.preflight = saved
        self.assertEqual(called, [])

    def test_gate_c_starts_only_after_gate_b_evidence(self):
        src = (ROOT / 'launch_gate_c.py').read_text(encoding='utf-8')
        self.assertIn("report['gate_b'] = gate_b_passed()", src)
        self.assertIn("if not e.get('hardware_pass')", src)

    def test_an_old_interpreter_is_refused_with_the_remedy(self):
        src = (ROOT / 'launch_gate_c.py').read_text(encoding='utf-8')
        head = src[:src.index('HERE = ')]
        self.assertIn('sys.version_info < (3, 10)', head)
        self.assertIn('Python310', head)

    def test_the_runner_is_gate_c_and_carries_the_run_as_guard(self):
        src = (ROOT / 'launch_gate_c.py').read_text(encoding='utf-8')
        self.assertIn('GateCRunner(port, time.monotonic, ledgers(), guard=run_id', src)

    def test_the_lineage_is_gate_bs_stores_after_not_issue_4(self):
        src = (ROOT / 'launch_gate_c.py').read_text(encoding='utf-8')
        body = src[src.index('def preflight'):src.index('def prepare')]
        self.assertNotIn('prior_closed', body)
        self.assertNotIn('B.preflight', body)
        self.assertIn("authority.load(LINEAGE_FROM)['stores_after']", body)
        self.assertIn('lineage(', body)

class Lineage(unittest.TestCase):
    def setUp(self):
        import launch_gate_c as C
        self.C = C
        self.left = {'0': {'epoch_sha256': 'a', 'generation': 20, 'next_fc': 1408, 'pan': 1, 'short': 2,
                           'recovery_state': 'PARENT_LINK_ACTIVE', 'context_generation': 18,
                           'nwk_source_floors': {'x': 5}},
                     '1': {'epoch_sha256': 'b', 'generation': 17, 'next_fc': 1184, 'pan': 3, 'short': 4,
                           'recovery_state': 'PARENT_LINK_ACTIVE', 'context_generation': 15,
                           'nwk_source_floors': {'y': 7}}}
        self.saved = (C.prior_gate_c_runs, C.B.dual_store.read)
        C.prior_gate_c_runs = lambda: {'r' * 32}
        C.B.dual_store.read = lambda ctx, path=None: {'guard': self.guard}
        self.guard = 'r' * 32

    def tearDown(self):
        self.C.prior_gate_c_runs, self.C.B.dual_store.read = self.saved

    def moved(self, **kw):
        import copy
        now = copy.deepcopy(self.left)
        now['0'].update(dict(epoch_sha256='c', generation=21, next_fc=1504), **kw)
        return now

    def test_unchanged_is_gate_b(self):
        self.assertEqual(self.C.lineage(self.left, self.left)['from'], 'v26_last_run_stores_after')

    def test_moved_forward_by_a_gate_c_run_is_accepted_and_named(self):
        r = self.C.lineage(self.moved(), self.left)
        self.assertEqual(r['moved_by'], {'ctx0': 'r' * 32})

    def test_moved_by_a_run_gate_c_never_prepared_is_refused(self):
        self.guard = 'z' * 32
        with self.assertRaises(self.C.authority.AuthorityFault) as e:
            self.C.lineage(self.moved(), self.left)
        self.assertIn('unknown_run', str(e.exception))

    def test_moved_backwards_is_refused_whoever_did_it(self):
        with self.assertRaises(self.C.authority.AuthorityFault):
            self.C.lineage(self.moved(next_fc=1000), self.left)


if __name__ == '__main__':
    unittest.main()
