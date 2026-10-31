"""Offline tests for the Gate A authority. No COM, no RF, no hardware.

Everything is driven through injected dictionaries, so the rules are exercised
without the real stores, the real inventory or a dongle. The point is that each
refusal is reachable: an authority that cannot refuse is decoration.
"""
import copy, json, os, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIRMWARE = HERE.parent
sys.path.insert(0, str(FIRMWARE))
sys.path.insert(0, str(FIRMWARE / 'host'))
import gate_a_authority as A


PRIOR_OK = {
    'issue4_PASS': True, 'guard_FINISHED': True, 'clean_END': True,
    'final_V17_verified': True, 'final_both_pairs_health_verified': True,
    'error': None,
    'final_CURRENT_sha256': 'deadbeef' * 8,
}


def snap(ctx0=None, ctx1=None):
    base = {
        '0': {'epoch_sha256': 'a' * 64, 'generation': 19, 'next_fc': 1280,
              'pan': 0xFA9B, 'short': 0xA326, 'recovery_state': 'X',
              'context_generation': 17, 'nwk_source_floors': {'tc0': 100}},
        '1': {'epoch_sha256': 'b' * 64, 'generation': 16, 'next_fc': 1088,
              'pan': 0x0B7A, 'short': 0x6C55, 'recovery_state': 'X',
              'context_generation': 14, 'nwk_source_floors': {'tc1': 200}},
    }
    if ctx0:
        base['0'].update(ctx0)
    if ctx1:
        base['1'].update(ctx1)
    return base


class PriorGate(unittest.TestCase):
    def test_a_closed_prior_gate_with_a_matching_store_is_accepted(self):
        r = A.prior_closed(PRIOR_OK, ctx1_epoch_sha='deadbeef' * 8)
        self.assertIs(r, PRIOR_OK)

    def test_each_closure_flag_is_required(self):
        for key in ('issue4_PASS', 'guard_FINISHED', 'clean_END',
                    'final_V17_verified', 'final_both_pairs_health_verified'):
            bad = dict(PRIOR_OK, **{key: False})
            with self.assertRaises(A.AuthorityFault) as e:
                A.prior_closed(bad, ctx1_epoch_sha='deadbeef' * 8)
            self.assertIn('prior_gate_not_closed', str(e.exception))
            self.assertIn(key, str(e.exception))

    def test_a_prior_error_is_a_refusal(self):
        bad = dict(PRIOR_OK, error='something went wrong')
        with self.assertRaises(A.AuthorityFault):
            A.prior_closed(bad, ctx1_epoch_sha='deadbeef' * 8)

    def test_a_ctx1_store_that_moved_since_the_prior_gate(self):
        """The lineage link. A store that moved since the prior gate closed has
        an unexplained history, and Gate A is not the place to find out."""
        with self.assertRaises(A.AuthorityFault) as e:
            A.prior_closed(PRIOR_OK, ctx1_epoch_sha='c' * 64)
        self.assertIn('ctx1_store_moved_since_the_prior_gate', str(e.exception))

    def test_the_real_lineage_link_holds_today(self):
        """Against the committed hardware_result.json and the hash dual_store
        read from the live ctx1 store on 2026-10-11."""
        r = json.loads((A.PRIOR_RESULT).read_text(encoding='utf-8'))
        self.assertEqual(
            r['final_CURRENT_sha256'],
            '9eef08a7722e9f60377d61389158428e606ae84e60ce430dc033ab1f58fb727b')


class Transitions(unittest.TestCase):
    """The replacement for holding ctx0 as byte-unchanged."""

    def test_nothing_moving_is_clean(self):
        b = snap()
        self.assertEqual(A.transitions(b, copy.deepcopy(b)), [])

    def test_generation_may_rise(self):
        b = snap()
        a = snap(ctx0={'generation': 20})
        self.assertEqual(A.transitions(b, a), [])

    def test_generation_may_not_fall(self):
        v = A.transitions(snap(), snap(ctx0={'generation': 18}))
        self.assertEqual(len(v), 1)
        self.assertIn('generation decreased', v[0])

    def test_identity_may_never_change(self):
        for field, value in (('pan', 0x1234), ('short', 0x9999),
                             ('raw_ieee', 'x'), ('tc_ieee', 'y')):
            v = A.transitions(snap(), snap(ctx1={field: value}))
            self.assertTrue(any('%s changed' % field in x for x in v),
                            '%s was allowed to change: %r' % (field, v))

    def test_a_replay_floor_may_not_fall(self):
        v = A.transitions(snap(), snap(ctx1={'nwk_source_floors': {'tc1': 199}}))
        self.assertEqual(len(v), 1)
        self.assertIn('replay floor', v[0])

    def test_a_replay_floor_may_rise(self):
        self.assertEqual(
            A.transitions(snap(), snap(ctx1={'nwk_source_floors': {'tc1': 500}})), [])

    def test_a_frame_counter_that_moved_with_no_secured_frame_is_reported(self):
        """Gate A sends nothing secured, so a counter that moved is a finding
        to explain rather than an allowance."""
        v = A.transitions(snap(), snap(ctx0={'next_fc': 1312}),
                          secured_frames_sent=False)
        self.assertEqual(len(v), 1)
        self.assertIn('next_fc moved', v[0])
        self.assertIn('needs an explanation', v[0])

    def test_the_same_movement_is_allowed_when_secured_frames_were_sent(self):
        self.assertEqual(
            A.transitions(snap(), snap(ctx0={'next_fc': 1312}),
                          secured_frames_sent=True), [])

    def test_a_vanished_store_is_a_violation(self):
        a = snap()
        del a['1']
        v = A.transitions(snap(), a)
        self.assertEqual(len(v), 1)
        self.assertIn('appeared or vanished', v[0])


class GateAExpectsNothingToMove(unittest.TestCase):
    """The correction to my own first draft. Gate A sends nothing secured and
    writes no store, so both stores must come out byte-unchanged and ctx0 stays
    sealed in the protected inventory. The relaxation belongs to Gate B."""

    def test_an_unmoved_pair_of_stores_is_clean(self):
        b = snap()
        self.assertEqual(A.gate_a_store_expectation(b, copy.deepcopy(b)), [])

    def test_a_store_that_moved_at_all_is_a_violation_in_gate_a(self):
        v = A.gate_a_store_expectation(snap(), snap(ctx0={'epoch_sha256': 'z' * 64}))
        self.assertTrue(any('sends nothing secured' in x for x in v), v)

    def test_even_a_legitimate_generation_rise_is_a_violation_in_gate_a(self):
        """transitions() allows generation to rise, because Gate B needs that.
        Gate A does not, and the two rules are kept apart so loosening the
        general one cannot silently loosen this one."""
        b, a = snap(), snap(ctx0={'generation': 20, 'epoch_sha256': 'z' * 64})
        self.assertEqual(A.transitions(b, a), [])
        self.assertNotEqual(A.gate_a_store_expectation(b, a), [])

    def test_ctx0_stays_in_the_protected_inventory_by_default(self):
        live = A.live_store_prefixes()
        inv = {live[0]: 'h',
               'firmware/airnanny_dual_pan/something_else/.local/x.json': 'h'}
        self.assertIn(live[0], A.protected(inv),
                      'ctx0 was dropped from the protected set in Gate A')

    def test_a_ctx0_store_change_IS_reported_in_gate_a(self):
        live = A.live_store_prefixes()
        now = {live[0]: 'moved'}
        before = {live[0]: 'original'}
        out = A.protected_unchanged(now, before)
        self.assertEqual(out, ['MODIFIED:' + live[0]],
                         'Gate A must notice a store change, and say how')

    def test_a_later_gate_can_opt_out_explicitly(self):
        live = A.live_store_prefixes()
        inv = {p: 'h' for p in live}
        inv['firmware/airnanny_dual_pan/something_else/.local/x.json'] = 'h'
        kept = A.protected(inv, exclude_live_stores=True)
        self.assertEqual(list(kept),
                         ['firmware/airnanny_dual_pan/something_else/.local/x.json'])


class SealedIntegrityIsTheStrongHalf(unittest.TestCase):
    """Measured on the operator's machine: all 354 sealed files intact, and 274
    files added since the seal by later gates' runs. So the question is split --
    a sealed file that moved is a refusal, a benign addition is accounted for.
    Comparing the whole set instead would fail on those 274, and the tempting
    cure (excluding prefixes until green) is the anti-pattern this guard exists
    to avoid."""

    def tree(self):
        import tempfile
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(d, ignore_errors=True))
        repo = d / 'breeze_control'
        base = repo / 'firmware' / 'airnanny_dual_pan' / 'm_a' / '.local'
        base.mkdir(parents=True)
        (base / 'one.json').write_text('1')
        (base / 'two.json').write_text('2')
        sealed = {
            'firmware/airnanny_dual_pan/m_a/.local/one.json': A.sha(base / 'one.json'),
            'firmware/airnanny_dual_pan/m_a/.local/two.json': A.sha(base / 'two.json'),
        }
        return repo, base, sealed

    def test_an_intact_seal(self):
        repo, base, sealed = self.tree()
        r = A.sealed_integrity(sealed, repo=repo)
        self.assertTrue(r['intact'])
        self.assertEqual((r['missing'], r['modified']), ([], []))
        self.assertEqual(r['sealed_count'], 2)

    def test_a_modified_sealed_file_is_caught(self):
        repo, base, sealed = self.tree()
        (base / 'one.json').write_text('tampered')
        r = A.sealed_integrity(sealed, repo=repo)
        self.assertFalse(r['intact'])
        self.assertEqual(r['modified'],
                         ['firmware/airnanny_dual_pan/m_a/.local/one.json'])

    def test_a_deleted_sealed_file_is_caught(self):
        repo, base, sealed = self.tree()
        (base / 'two.json').unlink()
        r = A.sealed_integrity(sealed, repo=repo)
        self.assertFalse(r['intact'])
        self.assertEqual(r['missing'],
                         ['firmware/airnanny_dual_pan/m_a/.local/two.json'])

    def test_an_addition_under_a_milestone_local_is_reported_not_failed(self):
        live = dict.fromkeys(
            ['firmware/airnanny_dual_pan/m_a/.local/one.json',
             'firmware/airnanny_dual_pan/m_b/.local/runs/x/outcome.json'], 'h')
        sealed = {'firmware/airnanny_dual_pan/m_a/.local/one.json': 'h'}
        r = A.additions_since_seal(live, sealed)
        self.assertEqual(r['count'], 1)
        self.assertEqual(r['stray'], [], 'a normal run artifact was called stray')

    def test_an_addition_outside_a_milestone_local_is_stray(self):
        live = dict.fromkeys(
            ['firmware/airnanny_dual_pan/m_a/.local/one.json',
             'firmware/somewhere_else/secrets.json'], 'h')
        sealed = {'firmware/airnanny_dual_pan/m_a/.local/one.json': 'h'}
        r = A.additions_since_seal(live, sealed)
        self.assertEqual(r['stray'], ['firmware/somewhere_else/secrets.json'])

    def test_protected_unchanged_refuses_only_on_what_must_never_change(self):
        live = dict.fromkeys(
            ['firmware/airnanny_dual_pan/m_a/.local/one.json',
             'firmware/airnanny_dual_pan/m_b/.local/runs/x/outcome.json'], 'h')
        sealed = {'firmware/airnanny_dual_pan/m_a/.local/one.json': 'h'}
        # 274-style benign additions must not make this non-empty.
        self.assertEqual(A.protected_unchanged(live, sealed), [])

    def test_protected_unchanged_reports_a_modified_sealed_file(self):
        live = {'firmware/airnanny_dual_pan/m_a/.local/one.json': 'different'}
        sealed = {'firmware/airnanny_dual_pan/m_a/.local/one.json': 'h'}
        out = A.protected_unchanged(live, sealed)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].startswith('MISSING:') or out[0].startswith('MODIFIED:'))

    def test_the_real_seal_is_intact_today(self):
        """Against the operator's actual sealed inventory, when present."""
        if not A.INVENTORY_BEFORE.exists():
            self.skipTest('sealed inventory not on this host')
        r = A.sealed_integrity()
        self.assertEqual(r['sealed_count'], 354)
        self.assertEqual(r['missing'], [])
        # ctx0's store is sealed here since issue #4 and Gate B moves it on
        # purpose (secured rejoin, new cycle); transitions() is what holds it
        # to its rules. Every OTHER sealed file must still be untouched.
        live = A.live_store_prefixes()
        self.assertEqual([m for m in r['modified']
                          if not any(m.endswith(x) for x in live)], [])

    def test_gate_b_exclusion_hides_only_the_live_stores(self):
        store = A.live_store_prefixes()[0]
        other = 'firmware/airnanny_dual_pan/m_a/.local/one.json'
        sealed = {store: 'h', other: 'h'}
        moved = {store: 'moved', other: 'h'}
        self.assertEqual(A.protected_unchanged(moved, sealed), ['MODIFIED:' + store])
        self.assertEqual(A.protected_unchanged(moved, sealed,
                                               exclude_live_stores=True), [])
        tampered = {store: 'moved', other: 'different'}
        self.assertEqual(A.protected_unchanged(tampered, sealed,
                                               exclude_live_stores=True),
                         ['MODIFIED:' + other])

    def test_the_exclusion_is_applied_to_both_sides(self):
        """Excluding from the live side alone reports the store MISSING."""
        store = A.live_store_prefixes()[0]
        out = A.protected_unchanged({}, {store: 'h'}, exclude_live_stores=True)
        self.assertEqual(out, [])

    def test_gate_b_launcher_uses_the_exclusion_everywhere(self):
        src = (HERE.parent / 'launch_gate_b.py').read_text(encoding='utf-8')
        self.assertNotIn('protected_unchanged()', src)
        self.assertNotIn('protected()', src)
        self.assertEqual(src.count('exclude_live_stores=True'), 3)


class Software(unittest.TestCase):
    def setUp(self):
        self.review = {'passed': True, 'hardware_performed': False,
                       'source_sha256': {}, 'image_sha256': 'AA' * 32}
        # sdk_root must resolve on this host or the authority refuses before
        # reaching the condition under test -- which is correct behaviour and
        # was found by running the preflight on a host that was not the build
        # host. The SDK itself is irrelevant here: these manifests carry no
        # 'nrf sdk/' inputs.
        self.manifest = {'input_sha256': {}, 'flashed': False,
                         'bit_comparable_with_v17_to_v25_lineage': True,
                         'hex_sha256': 'AA' * 32, 'sdk_root': str(FIRMWARE)}

    def refuses(self, fragment, review=None, manifest=None, needs_image=False):
        # Two of these compare against the release image itself. The image is a
        # build artifact rather than a source, so it is absent in a fresh
        # checkout and on any machine that has not built it; the rules it
        # guards are still worth exercising everywhere else.
        if needs_image and not A.IMAGE.exists():
            self.skipTest('release image not present: %s' % A.IMAGE.name)
        with self.assertRaises(A.AuthorityFault) as e:
            A.software(review or self.review, manifest or self.manifest)
        self.assertIn(fragment, str(e.exception))

    def test_a_failed_review(self):
        self.refuses('offline_review_required', review=dict(self.review, passed=False))

    def test_a_review_that_already_touched_hardware(self):
        self.refuses('offline_review_required',
                     review=dict(self.review, hardware_performed=True))

    def test_an_image_the_manifest_does_not_describe(self):
        self.refuses('image_does_not_match_its_manifest',
                     manifest=dict(self.manifest, hex_sha256='BB' * 32),
                     needs_image=True)

    def test_an_image_the_review_did_not_review(self):
        if not A.IMAGE.exists():
            self.skipTest('release image not present: %s' % A.IMAGE.name)
        m = dict(self.manifest, hex_sha256=A.sha(A.IMAGE).upper())
        self.refuses('reviewed_image_is_not_this_image', manifest=m)

    def test_a_manifest_claiming_the_image_was_flashed(self):
        self.refuses('manifest_claims_flashed', manifest=dict(self.manifest, flashed=True))

    def test_an_image_not_bit_comparable_with_the_lineage(self):
        self.refuses('image_not_bit_comparable',
                     manifest=dict(self.manifest,
                                   bit_comparable_with_v17_to_v25_lineage=False))

    def test_a_source_that_moved_since_review(self):
        self.refuses('reviewed_source_changed',
                     review=dict(self.review, source_sha256={'src/main.c': 'FF' * 32}))

    def test_a_firmware_input_that_moved_since_the_build(self):
        """The check that already refused a stale image once in this work."""
        self.refuses('firmware_input_changed',
                     manifest=dict(self.manifest,
                                   input_sha256={'src/main.c': 'FF' * 32}))

    def test_a_firmware_input_that_vanished(self):
        self.refuses('firmware_input_missing',
                     manifest=dict(self.manifest,
                                   input_sha256={'src/does_not_exist.c': 'FF' * 32}))

    def test_the_real_v17_reference_is_still_itself(self):
        self.assertEqual(A.sha(A.V17).upper(), A.V17_HASH)


class TheFastInventoryIsTheSameInventory(unittest.TestCase):
    """prepare.py is another milestone's frozen file and is not edited, so the
    fast walk is a reimplementation. That only helps if the two agree exactly,
    so they are compared on a synthetic tree built to include every case that
    could make them differ."""

    def build(self):
        import tempfile
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(d, ignore_errors=True))
        repo = d / 'breeze_control'
        milestones = repo / 'firmware' / 'airnanny_dual_pan'
        # A normal milestone with nested files.
        a = milestones / 'm_a' / '.local'
        (a / 'runs' / 'deep' / 'deeper').mkdir(parents=True)
        (a / 'keep.json').write_text('1')
        (a / 'runs' / 'deep' / 'keep2.json').write_text('2')
        (a / 'runs' / 'deep' / 'deeper' / 'keep3.json').write_text('3')
        # Every excluded directory name, with content inside.
        for bad in ('__pycache__', 'zig-global', 'zig-local'):
            (a / bad).mkdir()
            (a / bad / 'junk.json').write_text('x')
            (a / bad / 'nested').mkdir()
            (a / bad / 'nested' / 'junk2.json').write_text('y')
        # The edge case: a FILE whose own name is an excluded name. prepare.py
        # tests every path component, so it excludes this; pruning directories
        # alone would keep it.
        (a / 'zig-local').exists() or None
        (a / 'runs' / 'zig-global').write_text('a file, not a directory')
        # A milestone with no .local at all, and a non-directory entry.
        (milestones / 'm_b').mkdir(parents=True)
        (milestones / 'not_a_dir.txt').write_text('ignored')
        # A deep excluded directory, to prove pruning is recursive.
        c = milestones / 'm_c' / '.local' / 'x' / '__pycache__'
        c.mkdir(parents=True)
        (c / 'junk.json').write_text('z')
        (milestones / 'm_c' / '.local' / 'x' / 'keep.json').write_text('4')
        return repo, milestones

    def reference(self, milestones, repo):
        """prepare.py's own logic, transcribed verbatim from the frozen file so
        the comparison is against what it actually does."""
        out = {}
        for directory in milestones.iterdir():
            if not directory.is_dir():
                continue
            for path in (directory / '.local').rglob('*'):
                if path.is_file() and not any(
                        x in path.parts for x in A.INVENTORY_EXCLUDED):
                    out[path.relative_to(repo).as_posix()] = A.sha(path)
        return out

    def test_the_two_walks_agree_exactly(self):
        repo, milestones = self.build()
        fast = A.protected_inventory_fast(milestones=milestones, repo=repo)
        ref = self.reference(milestones, repo)
        self.assertEqual(set(fast), set(ref),
                         'the fast walk and prepare.py disagree on which files '
                         'are in the inventory')
        self.assertEqual(fast, ref, 'they agree on paths but not on hashes')

    def test_it_found_the_files_that_should_be_there(self):
        repo, milestones = self.build()
        fast = A.protected_inventory_fast(milestones=milestones, repo=repo)
        names = sorted(Path(k).name for k in fast)
        self.assertEqual(names, ['keep.json', 'keep.json', 'keep2.json', 'keep3.json'])

    def test_a_file_named_like_an_excluded_directory_is_excluded(self):
        """The edge case that pruning alone would get wrong."""
        repo, milestones = self.build()
        fast = A.protected_inventory_fast(milestones=milestones, repo=repo)
        self.assertFalse(any(Path(k).name == 'zig-global' for k in fast),
                         'a file named zig-global survived the fast walk')

    def test_nothing_from_an_excluded_directory_survives(self):
        repo, milestones = self.build()
        fast = A.protected_inventory_fast(milestones=milestones, repo=repo)
        for k in fast:
            for bad in A.INVENTORY_EXCLUDED:
                self.assertNotIn(bad, Path(k).parts, k)


class SdkRootIsLocatedNotTrusted(unittest.TestCase):
    """The manifest records sdk_root as the build host's absolute path, which
    is a Windows path. The input hash KEYS were made repository-relative so the
    evidence travels; sdk_root was not, and that asymmetry made the whole
    firmware-input check fail on any host but the build host. Found by running
    the preflight on the Linux VM rather than by reading the code."""

    def test_the_tree_is_preferred_over_the_recorded_path(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            # A recorded path that exists, to prove the tree still wins when
            # the tree has one.
            tree = A.HERE.parents[3] / 'nrf sdk'
            got = A.sdk_root({'sdk_root': d})
            self.assertEqual(got, tree if tree.exists() else Path(d))

    def test_the_recorded_path_is_the_fallback(self):
        import tempfile
        if (A.HERE.parents[3] / 'nrf sdk').exists():
            self.skipTest('this host has the SDK in the tree, so the fallback '
                          'is not reachable here')
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(A.sdk_root({'sdk_root': d}), Path(d))

    def test_neither_resolving_is_a_refusal_naming_both(self):
        if (A.HERE.parents[3] / 'nrf sdk').exists():
            self.skipTest('this host has the SDK in the tree')
        with self.assertRaises(A.AuthorityFault) as e:
            A.sdk_root({'sdk_root': '/definitely/not/here'})
        msg = str(e.exception)
        self.assertIn('sdk_root_not_found', msg)
        self.assertIn('/definitely/not/here', msg)
        self.assertIn('nrf sdk', msg)

    def test_a_manifest_with_no_recorded_root_still_tries_the_tree(self):
        if (A.HERE.parents[3] / 'nrf sdk').exists():
            self.assertTrue(A.sdk_root({}).exists())
        else:
            with self.assertRaises(A.AuthorityFault):
                A.sdk_root({})


class DeviceSelection(unittest.TestCase):
    class P:
        def __init__(self, vid, pid, serial, device='COM9'):
            self.vid, self.pid, self.serial_number, self.device = vid, pid, serial, device

    def test_exactly_one_match_is_selected(self):
        ports = [self.P(1, 2, 'other'),
                 self.P(A.DONGLE['vid'], A.DONGLE['pid'], A.DONGLE['serial'], 'COM7')]
        self.assertEqual(A.select_device(ports)['port'], 'COM7')

    def test_no_match_is_a_refusal(self):
        with self.assertRaises(A.AuthorityFault):
            A.select_device([self.P(1, 2, 'other')])

    def test_two_matches_is_a_refusal_rather_than_a_choice(self):
        p = self.P(A.DONGLE['vid'], A.DONGLE['pid'], A.DONGLE['serial'])
        with self.assertRaises(A.AuthorityFault) as e:
            A.select_device([p, p])
        self.assertIn('one_positively_identified_dongle_required', str(e.exception))

    def test_a_right_serial_on_the_wrong_vid_is_not_a_match(self):
        with self.assertRaises(A.AuthorityFault):
            A.select_device([self.P(0x0000, A.DONGLE['pid'], A.DONGLE['serial'])])


if __name__ == '__main__':
    unittest.main()


class SupersedingAFinishedAttempt(unittest.TestCase):
    """The one-shot guard must stay one-shot, and a second attempt must still
    be possible. Gate A's first hardware run failed on two defects in the host
    evaluator and on a criterion that could not be met passively at all, so a
    second attempt is exactly the case this has to serve -- deliberately,
    with a reason, and without destroying what the first attempt produced."""

    def setUp(self):
        import shutil, tempfile
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import launch_gate_a
        self.L = launch_gate_a
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))
        self._gate = launch_gate_a.GATE
        launch_gate_a.GATE = self.d / 'gate_a_v1'
        self.addCleanup(lambda: setattr(launch_gate_a, 'GATE', self._gate))

    def first_attempt(self):
        self.L.GATE.mkdir(parents=True, exist_ok=True)
        self.L.durable(self.L.GATE / 'milestone.json', {'run': 'aaa'})
        (self.L.GATE / 'runs/aaa').mkdir(parents=True)
        self.L.durable(self.L.GATE / 'runs/aaa/outcome.json', {'passed': False})

    def test_a_second_prepare_without_a_reason_is_still_refused(self):
        self.first_attempt()
        with self.assertRaises(A.AuthorityFault) as e:
            self.L.immutable(self.L.GATE / 'milestone.json', {'run': 'bbb'})
        self.assertIn('immutable_NO_RERUN', str(e.exception))

    def test_superseding_archives_everything_and_deletes_nothing(self):
        self.first_attempt()
        n = self.L.supersede('phase 2 was unreachable passively')
        self.assertEqual(n, 1)
        kept = self.L.GATE / 'attempts/1'
        self.assertEqual(json.loads((kept / 'milestone.json').read_text()),
                         {'run': 'aaa'})
        self.assertEqual(
            json.loads((kept / 'runs/aaa/outcome.json').read_text()),
            {'passed': False})
        said = json.loads((kept / 'superseded.json').read_text())
        self.assertEqual(said['reason'], 'phase 2 was unreachable passively')
        self.assertEqual(said['attempt'], 1)
        self.assertEqual(sorted(said['archived']), ['milestone.json', 'runs'])
        self.assertFalse((self.L.GATE / 'milestone.json').exists())

    def test_a_fresh_milestone_can_then_be_written_once(self):
        self.first_attempt()
        self.L.supersede('because')
        self.L.immutable(self.L.GATE / 'milestone.json', {'run': 'bbb'})
        with self.assertRaises(A.AuthorityFault):
            self.L.immutable(self.L.GATE / 'milestone.json', {'run': 'ccc'})

    def test_attempts_accumulate_rather_than_overwrite(self):
        self.first_attempt()
        self.L.supersede('first')
        self.L.durable(self.L.GATE / 'milestone.json', {'run': 'bbb'})
        self.assertEqual(self.L.supersede('second'), 2)
        self.assertEqual(json.loads(
            (self.L.GATE / 'attempts/1/milestone.json').read_text()), {'run': 'aaa'})
        self.assertEqual(json.loads(
            (self.L.GATE / 'attempts/2/milestone.json').read_text()), {'run': 'bbb'})

    def test_superseding_nothing_is_refused(self):
        self.L.GATE.mkdir(parents=True, exist_ok=True)
        with self.assertRaises(A.AuthorityFault) as e:
            self.L.supersede('nothing here')
        self.assertIn('nothing_to_supersede', str(e.exception))
