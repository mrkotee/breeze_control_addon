"""Offline tests for the Gate B launcher. No COM, no RF, no hardware.

This is the only component allowed to move a live store, so what is driven
here is its REFUSALS and the shape of its decisions -- never a real write,
which is impossible from anywhere but the operator's machine anyway: the keys
are DPAPI-bound with no plaintext fallback.
"""
import json, shutil, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / 'host'))
sys.path.insert(0, str(HERE))
import gate_a_authority as authority
import launch_gate_a
import launch_gate_b


class GateBWaitsForGateA(unittest.TestCase):
    """Gate A is the RF margin and it is a stop criterion. Commissioning both
    contexts to discover something a passive listen already knew would spend
    frame counters for nothing."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self._prior = launch_gate_b.PRIOR_GATE
        launch_gate_b.PRIOR_GATE = self.tmp / 'gate_a_v1'
        self.addCleanup(lambda: setattr(launch_gate_b, 'PRIOR_GATE', self._prior))

    def write(self, outcome):
        g = launch_gate_b.PRIOR_GATE
        (g / 'runs/abc').mkdir(parents=True, exist_ok=True)
        (g / 'milestone.json').write_text(json.dumps({'run': 'abc'}))
        (g / 'runs/abc/outcome.json').write_text(json.dumps(outcome))

    def test_a_gate_a_that_never_ran_is_refused(self):
        with self.assertRaises(authority.AuthorityFault) as e:
            launch_gate_b.gate_a_passed()
        self.assertIn('gate_a_never_ran', str(e.exception))

    def test_a_gate_a_with_no_outcome_is_refused(self):
        g = launch_gate_b.PRIOR_GATE
        g.mkdir(parents=True)
        (g / 'milestone.json').write_text(json.dumps({'run': 'abc'}))
        with self.assertRaises(authority.AuthorityFault) as e:
            launch_gate_b.gate_a_passed()
        self.assertIn('gate_a_has_no_outcome', str(e.exception))

    def test_a_failed_gate_a_is_refused_and_its_reasons_are_quoted(self):
        self.write({'hardware_pass': False,
                    'verdict': {'reasons': ['ctx1 not audible']}})
        with self.assertRaises(authority.AuthorityFault) as e:
            launch_gate_b.gate_a_passed()
        self.assertIn('gate_a_did_not_pass', str(e.exception))
        self.assertIn('ctx1 not audible', str(e.exception))

    def test_a_passed_gate_a_carries_its_rf_margin_forward(self):
        """The measurement is quoted into Gate B's own record, so the run that
        spends counters says what margin it was started on."""
        self.write({'hardware_pass': True, 'utc': 'then', 'verdict': {
            'survey': {'per_context': {
                'ctx0': {'samples': 30, 'rssi_mean': -66.7, 'lqi_mean': 104.7},
                'ctx1': {'samples': 41, 'rssi_mean': -81.9, 'lqi_mean': 43.7}}}}})
        got = launch_gate_b.gate_a_passed()
        self.assertEqual(got['run'], 'abc')
        self.assertEqual(got['rf_margin']['ctx1']['rssi_mean'], -81.9)
        self.assertEqual(got['rf_margin']['ctx0']['samples'], 30)


class TheStoreExpectationDiffersFromGateA(unittest.TestCase):
    """Gate A expected nothing to move. Gate B spends counters on purpose, so
    it uses the general rule with secured_frames_sent=True -- and that is the
    ONLY allowance: the identity fields, the monotonic fields and the replay
    floors are held exactly as before."""

    def before(self):
        return {'0': {'pan': 64155, 'short': 41766, 'generation': 19,
                      'next_fc': 1280, 'epoch_sha256': 'a' * 64,
                      'nwk_source_floors': {'x': 10}}}

    def test_a_risen_counter_is_allowed_for_gate_b(self):
        after = {'0': dict(self.before()['0'], next_fc=1312)}
        self.assertEqual(
            authority.transitions(self.before(), after, secured_frames_sent=True), [])

    def test_the_same_rise_is_a_finding_for_gate_a(self):
        after = {'0': dict(self.before()['0'], next_fc=1312)}
        self.assertTrue(
            authority.transitions(self.before(), after, secured_frames_sent=False))

    def test_a_decreasing_counter_is_refused_even_for_gate_b(self):
        after = {'0': dict(self.before()['0'], next_fc=1000)}
        self.assertTrue(
            authority.transitions(self.before(), after, secured_frames_sent=True))

    def test_the_epoch_digest_is_expected_to_change_here(self):
        """epoch_sha256 is the digest of the whole epoch.json, and Gate B
        writes that file every time it leases a counter. So it is correctly
        NOT a frozen field: freezing it would refuse the gate's own work.
        What must not change is the IDENTITY inside the file, which is the
        next test. Gate A caught a moved digest only because its rule was
        'nothing moved at all'."""
        after = {'0': dict(self.before()['0'], epoch_sha256='b' * 64)}
        self.assertEqual(
            authority.transitions(self.before(), after,
                                  secured_frames_sent=True), [])
        self.assertNotIn('epoch_sha256', authority.FROZEN_STORE_FIELDS)

    def test_identity_may_not_change_whatever_was_sent(self):
        for field, value in (('pan', 1), ('short', 2), ('raw_ieee', 'ff'),
                             ('tc_ieee', 'ee')):
            after = {'0': dict(self.before()['0'], **{field: value})}
            self.assertTrue(
                authority.transitions(self.before(), after,
                                      secured_frames_sent=True), field)

    def test_a_replay_floor_may_not_go_backwards(self):
        after = {'0': dict(self.before()['0'], nwk_source_floors={'x': 9})}
        self.assertTrue(
            authority.transitions(self.before(), after, secured_frames_sent=True))


class TheGuardIsOneShotAndSeparateFromGateA(unittest.TestCase):
    def test_gate_b_has_its_own_directory(self):
        self.assertNotEqual(launch_gate_b.GATE, launch_gate_a.GATE)
        self.assertEqual(launch_gate_b.GATE.name, 'gate_b_v1')

    def test_supersede_is_shared_but_scoped_to_the_gate_it_is_given(self):
        """One implementation, two gates. Passing the gate explicitly is what
        stops Gate B archiving Gate A's attempts."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        b = tmp / 'gate_b_v1'
        b.mkdir(parents=True)
        (b / 'milestone.json').write_text('{"run": "x"}')
        launch_gate_a.supersede('because', gate=b)
        self.assertTrue((b / 'attempts/1/milestone.json').exists())
        self.assertFalse((b / 'milestone.json').exists())

    def test_superseding_an_empty_gate_is_refused(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        (tmp / 'g').mkdir()
        with self.assertRaises(authority.AuthorityFault):
            launch_gate_a.supersede('x', gate=tmp / 'g')


class OnlyThisLauncherMayWriteALiveStore(unittest.TestCase):
    def test_it_is_the_only_caller_that_asks_for_hardware(self):
        """Option 1 in one assertion. Parsed rather than grepped: the
        construction spans two lines, and gate_b_runner's docstring mentions
        the flag in prose, so a textual search answers the wrong question."""
        import ast
        root = HERE.parent
        callers = []
        for p in list(root.glob('*.py')) + list((root / 'host').glob('*.py')):
            if p.name == 'dual_ledger.py':
                continue
            for node in ast.walk(ast.parse(p.read_text(encoding='utf-8'))):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, 'attr', getattr(node.func, 'id', ''))
                if name != 'ContextLedger':
                    continue
                for kw in node.keywords:
                    if kw.arg == 'hardware' and getattr(kw.value, 'value', None) is True:
                        callers.append(p.name)
        self.assertEqual(sorted(set(callers)), ['launch_gate_b.py'], callers)

    def test_the_inherited_ledger_still_refuses_unconditionally(self):
        src = (HERE.parent / 'host/ledger.py').read_text(encoding='utf-8')
        self.assertIn('OFFLINE_ONLY_no_hardware_authority', src)
        self.assertIn('simulation_NO_REAL_AUTHORITY', src)


if __name__ == '__main__':
    unittest.main()
