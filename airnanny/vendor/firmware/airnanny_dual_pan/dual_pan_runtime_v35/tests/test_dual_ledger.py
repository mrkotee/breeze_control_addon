"""Offline tests for the per-context store writers. No COM, no RF, no hardware.

Every test here constructs hardware=False ledgers over disposable roots. What
is proved is mostly what the writers REFUSE, because this is the component
that is allowed to move a live store and the refusals are the whole safety
argument for letting it exist.
"""
import json, os, shutil, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'host'))
sys.path.insert(0, str(HERE))
import dual_ledger
import dual_store
import secured_frame
from dual_ledger import ContextLedger, BURNED, BUILT, SENT
from recovery_model import Fault, Secret

KEYS = {0: Secret(bytes(range(16))), 1: Secret(bytes(range(16, 32)))}


def record(ctx, next_fc=2000, generation=19):
    p = dual_store.PINNED[ctx]
    return {'next_fc': next_fc, 'generation': generation,
            'sequences': {'nwk': 1, 'dsn': 2, 'aps': 3, 'zdo': 4},
            'context': {'short': p['short'], 'pan': p['pan']},
            'recovery': {'state': 'DISCOVERING', 'intents': {}}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=str(dual_ledger.SIMULATION_ROOT)))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def root(self, ctx):
        d = self.tmp / ('ctx%d' % ctx)
        d.mkdir(parents=True, exist_ok=True)
        (d / 'epoch.json').write_text(json.dumps(record(ctx)) + '\n',
                                      encoding='utf-8')
        return d

    def ledger(self, ctx=1, **kw):
        return ContextLedger(ctx, KEYS[ctx], root=self.root(ctx), **kw)

    @classmethod
    def setUpClass(cls):
        dual_ledger.SIMULATION_ROOT.mkdir(parents=True, exist_ok=True)


class ItRefusesTheWrongTerritory(Base):
    def test_simulation_cannot_write_outside_the_disposable_root(self):
        for bad in ('/tmp', str(HERE), str(HERE.parent)):
            with self.assertRaises(Fault) as e:
                ContextLedger(1, KEYS[1], root=bad)
            self.assertIn('simulation_NO_REAL_AUTHORITY', str(e.exception))

    def test_simulation_cannot_reach_a_pinned_store(self):
        """The one that matters: a test with a typo must not become a live
        write."""
        with self.assertRaises(Fault):
            ContextLedger(0, KEYS[0], root=dual_store.STORE_PATHS[0])

    def test_simulation_demands_a_root_rather_than_defaulting(self):
        with self.assertRaises(Fault) as e:
            ContextLedger(1, KEYS[1])
        self.assertIn('disposable_root', str(e.exception))

    def test_hardware_writes_only_the_pinned_store_of_its_own_context(self):
        """A hardware ledger does not take a path, it takes a context. Handing
        it a path -- even the other context's real one -- is refused."""
        with self.assertRaises(Fault) as e:
            ContextLedger(0, KEYS[0], hardware=True,
                          root=dual_store.STORE_PATHS[1])
        self.assertIn('pinned_not_chosen', str(e.exception))

    def test_an_unknown_context_is_refused(self):
        for ctx in (2, -1, None, '0'):
            with self.assertRaises(Fault):
                ContextLedger(ctx, KEYS[1], root=str(self.tmp))


class TheAllocatorIsPerContext(Base):
    def test_two_ledgers_do_not_share_a_counter(self):
        """The structural form of frame ctx == FC allocator ctx: neither can
        see the other's root, so neither can spend the other's counters."""
        a, b = self.ledger(0), self.ledger(1)
        self.assertNotEqual(a.root, b.root)
        a.reserve('REJOIN')
        self.assertEqual(a.read()['next_fc'], 2000 + dual_ledger.FC_BLOCK)
        self.assertEqual(b.read()['next_fc'], 2000)

    def test_pair_refuses_a_shared_root(self):
        one = self.root(0)
        with self.assertRaises(Fault) as e:
            dual_ledger.pair(KEYS, roots={0: one, 1: one})
        self.assertIn('share a store root', str(e.exception))

    def test_pair_builds_two_distinct_contexts(self):
        p = dual_ledger.pair(KEYS, roots={0: self.root(0), 1: self.root(1)})
        self.assertNotEqual(p[0].identity['pan'], p[1].identity['pan'])
        self.assertNotEqual(p[0].identity['short'], p[1].identity['short'])


class TheCounterIsSpentBeforeTheFrameExists(Base):
    def test_reserve_advances_the_counter_and_the_sequences(self):
        L = self.ledger(1)
        before = L.read()
        i = L.reserve('REJOIN')
        after = L.read()
        self.assertEqual(i['fc'], before['next_fc'])
        self.assertEqual(after['next_fc'], before['next_fc'] + dual_ledger.FC_BLOCK)
        self.assertEqual(after['sequences'],
                         secured_frame.advance(before['sequences'], 'REJOIN'))
        self.assertEqual(after['recovery']['intents']['REJOIN']['phase'], BURNED)

    def test_the_intent_carries_the_context_it_belongs_to(self):
        L = self.ledger(0)
        i = L.reserve('REJOIN')
        self.assertEqual(i['ctx'], 0)
        self.assertEqual(i['pan'], dual_store.PINNED[0]['pan'])
        self.assertEqual(i['short'], dual_store.PINNED[0]['short'])

    def test_a_kind_cannot_be_attempted_twice(self):
        L = self.ledger(1)
        L.reserve('REJOIN')
        with self.assertRaises(Fault) as e:
            L.reserve('REJOIN')
        self.assertIn('one_shot_state', str(e.exception))

    def test_an_exhausted_counter_is_refused_before_anything_is_written(self):
        L = self.ledger(1)
        r = L.read(); r['next_fc'] = 0xffffffe8; L._write(r)
        with self.assertRaises(Fault):
            L.reserve('REJOIN')
        self.assertEqual(L.read()['next_fc'], 0xffffffe8)

    def test_a_generic_kind_is_refused(self):
        with self.assertRaises(Fault):
            self.ledger(1).reserve('TYPE07')


class TheFrameBelongsToItsContext(Base):
    def test_build_uses_this_contexts_identity_not_an_argument(self):
        L = self.ledger(0)
        L.reserve('REJOIN')
        raw, fc = L.build('REJOIN')
        self.assertEqual(int.from_bytes(raw[3:5], 'little'),
                         dual_store.PINNED[0]['pan'])
        self.assertEqual(int.from_bytes(raw[7:9], 'little'),
                         dual_store.PINNED[0]['short'])

    def test_the_two_contexts_produce_different_frames(self):
        out = {}
        for ctx in (0, 1):
            L = self.ledger(ctx)
            L.reserve('REJOIN')
            out[ctx] = L.build('REJOIN')[0]
        self.assertNotEqual(out[0], out[1])
        self.assertNotEqual(out[0][3:5], out[1][3:5])

    def test_building_without_reserving_fails(self):
        with self.assertRaises(KeyError):
            self.ledger(1).build('REJOIN')

    def test_building_twice_is_refused(self):
        L = self.ledger(1)
        L.reserve('REJOIN'); L.build('REJOIN')
        with self.assertRaises(Fault) as e:
            L.build('REJOIN')
        self.assertIn('intent_not_fresh', str(e.exception))

    def test_the_digest_is_recorded_with_the_intent(self):
        import hashlib
        L = self.ledger(1)
        L.reserve('REJOIN')
        raw, _ = L.build('REJOIN')
        self.assertEqual(L.read()['recovery']['intents']['REJOIN']['sha256'],
                         hashlib.sha256(raw).hexdigest())


class AnUnknownOutcomeBurnsTheIntent(Base):
    def test_a_good_send_is_recorded(self):
        L = self.ledger(1)
        L.reserve('REJOIN'); L.build('REJOIN')
        L.sent('REJOIN', 'local_tx_ok', 123456)
        self.assertEqual(L.read()['recovery']['intents']['REJOIN']['phase'], SENT)

    def test_a_failed_send_raises_but_still_records(self):
        """Retrying a frame whose fate is unknown is how a counter gets used
        twice, so the intent is burned on disk BEFORE the fault is raised."""
        L = self.ledger(1)
        L.reserve('REJOIN'); L.build('REJOIN')
        with self.assertRaises(Fault):
            L.sent('REJOIN', 'unknown', 123456)
        j = L.read()['recovery']['intents']['REJOIN']
        self.assertEqual(j['phase'], SENT)
        self.assertEqual(j['result'], 'unknown')

    def test_sending_something_never_built_is_refused(self):
        L = self.ledger(1)
        L.reserve('REJOIN')
        with self.assertRaises(Fault) as e:
            L.sent('REJOIN', 'local_tx_ok', 1)
        self.assertIn('intent_not_built', str(e.exception))


class EveryWriteIsLockedAndReadBack(Base):
    def test_a_record_that_cannot_be_read_back_is_a_fault(self):
        L = self.ledger(1)
        L.save = lambda path, value: None        # a save that silently does not
        with self.assertRaises(Fault) as e:
            L.reserve('REJOIN')
        self.assertIn('durable_readback_failed', str(e.exception))

    def test_the_lock_is_released_so_a_second_write_succeeds(self):
        L = self.ledger(1)
        L.reserve('REJOIN')
        L.build('REJOIN')
        self.assertFalse((L.root / 'owner.lock').exists())

    def test_a_held_lock_refuses_a_concurrent_writer(self):
        L = self.ledger(1)
        (L.root / 'owner.lock').write_text('999')
        with self.assertRaises(FileExistsError):
            L.reserve('REJOIN')


if __name__ == '__main__':
    unittest.main()

class EachRunOpensItsOwnCycle(Base):
    """The one-shot rule is per recovery cycle. A live store arrives holding
    the previous cycle's REJOIN/ANNOUNCE/TIMEOUT, and attempt 9 was refused
    REJOIN for exactly that, before any frame existed."""

    GUARD = 'c' * 32

    def spent(self, ctx=0):
        L = self.ledger(ctx)
        r = L.read()
        r['recovery'] = {'state': 'FIRST_TYPE07_CONFIRMED', 'gate': 'b' * 32,
                         'intents': {k: {'phase': 'LOCAL_MAC_ACK'}
                                     for k in ('REJOIN', 'ANNOUNCE', 'TIMEOUT')}}
        L._write(r)
        return L

    def test_a_live_shaped_store_refuses_rejoin_without_a_cycle(self):
        with self.assertRaises(Fault) as e:
            self.spent().reserve('REJOIN')
        self.assertIn('one_shot_state', str(e.exception))

    def test_a_new_cycle_permits_rejoin_and_archives_the_old(self):
        L = self.spent()
        before = L.read()
        L.begin_cycle(self.GUARD)
        L.reserve('REJOIN')
        after = L.read()
        self.assertEqual(after['recovery_history'][-1], before['recovery'])
        self.assertEqual(after['recovery']['gate'], self.GUARD)
        self.assertEqual(after['recovery']['predecessor'], 'b' * 32)
        self.assertEqual(list(after['recovery']['intents']), ['REJOIN'])

    def test_a_new_cycle_never_rewinds_the_counter(self):
        L = self.spent()
        fc = L.read()['next_fc']
        L.begin_cycle(self.GUARD)
        self.assertEqual(L.read()['next_fc'], fc)
        self.assertEqual(L.reserve('REJOIN')['fc'], fc)

    def test_the_same_guard_cannot_open_two_cycles(self):
        L = self.spent()
        L.begin_cycle(self.GUARD)
        L.reserve('REJOIN')
        with self.assertRaises(Fault) as e:
            L.begin_cycle(self.GUARD)
        self.assertIn('NO_RERUN', str(e.exception))
        self.assertIn('REJOIN', L.read()['recovery']['intents'])

    def test_a_malformed_guard_is_refused_before_anything_moves(self):
        L = self.spent()
        before = L.read()
        for bad in ('', 'C' * 32, 'c' * 31, None):
            with self.assertRaises(Fault):
                L.begin_cycle(bad)
        self.assertEqual(L.read(), before)

ACK = {'ack_started': '1', 'ack_completed': '1', 'deadline_miss': '0'}


def answer(ctx, payload, fc=3000000, key=None, short=None, fcf=0x1a09):
    """A parent's NWK command to this context's device, encrypted as a parent
    sends it -- V25's test_recovery.vector, with the identity of `ctx`."""
    from management import encrypt, ieee, le
    p = dual_store.PINNED[ctx]
    dst = p['short'] if short is None else short
    h = le(fcf) + le(dst) + le(0) + b'\x01\x07'
    h += ieee(p['raw_ieee']) + ieee(p['tc_ieee'])
    return (b'\x61\x88\x07' + le(p['pan']) + le(dst) + le(0)
            + encrypt(h, b'\x28' + le(fc, 4) + ieee(p['tc_ieee']) + bytes([0]),
                      payload, key or KEYS[ctx]))


class TheParentsAnswerIsAuthenticatedPerContext(Base):
    """The firmware is host_only: it latches a frame of the right shape and
    waits for the host to say it was a real answer. This is the host saying
    so, for each context with its own key and identity."""

    GUARD = 'e' * 32

    def requested(self, ctx=0, kind='REJOIN'):
        L = self.ledger(ctx)
        L.begin_cycle(self.GUARD)
        L.reserve('REJOIN'); L.build('REJOIN'); L.sent('REJOIN', 'local_tx_ok', 1)
        return L

    def rejoin_ok(self, ctx=0):
        return answer(ctx, b'\x07' + dual_store.PINNED[ctx]['short'].to_bytes(2, 'little') + b'\x00')

    def test_a_good_rejoin_response_commits_rejoined_and_the_generation(self):
        for ctx in (0, 1):
            with self.subTest(ctx=ctx):
                L = self.requested(ctx)
                gen = L.read()['generation']
                result, detail = L.authenticate_response('REJOIN', self.rejoin_ok(ctx), 9, ACK)
                after = L.read()
                self.assertEqual(result, 'REJOINED')
                self.assertEqual(after['generation'], gen + 1)
                self.assertEqual(after['recovery']['state'], 'REJOINED')
                self.assertEqual(after['nwk_source_floors'][dual_store.PINNED[ctx]['tc_ieee']],
                                 3000001)
                self.assertEqual(after['recovery']['rejoin_response']['revision'], 9)

    def test_the_other_contexts_answer_is_not_ours(self):
        L = self.requested(0)
        before = L.read()
        result, _ = L.authenticate_response('REJOIN', self.rejoin_ok(1), 9, ACK)
        self.assertEqual(result, 'NOT_THIS_CONTEXT')
        self.assertEqual(L.read(), before)

    def test_an_answer_under_another_key_is_not_ours(self):
        L = self.requested(0)
        raw = answer(0, b'\x07' + dual_store.PINNED[0]['short'].to_bytes(2, 'little') + b'\x00',
                     key=KEYS[1])
        self.assertEqual(L.authenticate_response('REJOIN', raw, 9, ACK)[0], 'NOT_THIS_CONTEXT')

    def test_a_replayed_counter_is_refused_and_writes_nothing(self):
        L = self.requested(0)
        r = L.read()
        r['nwk_source_floors'] = {dual_store.PINNED[0]['tc_ieee']: 3000001}
        L._write(r)
        result, _ = L.authenticate_response('REJOIN', self.rejoin_ok(0), 9, ACK)
        self.assertEqual(result, 'REPLAY_REJECTED')
        self.assertEqual(L.read(), r)

    def test_a_refusal_from_the_parent_is_terminal(self):
        L = self.requested(0)
        raw = answer(0, b'\x07\xff\xff\x02')
        self.assertEqual(L.authenticate_response('REJOIN', raw, 9, ACK)[0], 'REJECTED')
        self.assertEqual(L.read()['recovery']['state'], 'REJECTED')

    def test_a_different_short_is_a_stop_not_an_install(self):
        L = self.requested(0)
        raw = answer(0, b'\x07\x21\x43\x00')
        self.assertEqual(L.authenticate_response('REJOIN', raw, 9, ACK)[0], 'SHORT_CHANGED')
        self.assertEqual(L.read()['context']['short'], dual_store.PINNED[0]['short'])

    def test_an_unclean_ack_is_not_a_response(self):
        L = self.requested(0)
        bad = dict(ACK, ack_completed='0')
        self.assertEqual(L.authenticate_response('REJOIN', self.rejoin_ok(0), 9, bad)[0],
                         'MAC_ACK_NOT_CLEAN')
        self.assertEqual(L.read()['recovery']['state'], 'DISCOVERING')

    def test_no_answer_is_accepted_before_its_request_went_out(self):
        L = self.ledger(0)
        L.begin_cycle(self.GUARD)
        with self.assertRaises(Fault):
            L.authenticate_response('REJOIN', self.rejoin_ok(0), 9, ACK)

    def test_announce_waits_for_an_authenticated_rejoin(self):
        L = self.requested(0)
        with self.assertRaises(Fault) as e:
            L.reserve('ANNOUNCE')
        self.assertIn('needs REJOINED', str(e.exception))
        L.authenticate_response('REJOIN', self.rejoin_ok(0), 9, ACK)
        L.reserve('ANNOUNCE')

    def negotiated(self, ctx=0):
        L = self.requested(ctx)
        L.authenticate_response('REJOIN', self.rejoin_ok(ctx), 9, ACK)
        for kind in ('ANNOUNCE', 'TIMEOUT'):
            L.reserve(kind); L.build(kind); L.sent(kind, 'local_tx_ok', 2)
        return L

    def test_timeout_before_announce_is_refused(self):
        L = self.requested(0)
        L.authenticate_response('REJOIN', self.rejoin_ok(0), 9, ACK)
        with self.assertRaises(Fault):
            L.reserve('TIMEOUT')

    def test_a_good_timeout_response_makes_the_parent_link_active(self):
        L = self.negotiated(0)
        result, _ = L.authenticate_response('TIMEOUT', answer(0, b'\x0c\x00\x01', fc=3000005), 12, ACK)
        q = L.read()['recovery']
        self.assertEqual(result, 'PARENT_LINK_ACTIVE')
        self.assertEqual(q['state'], 'PARENT_LINK_ACTIVE')
        self.assertEqual([p['revision'] for p in q['proofs']], [9, 12])

    def test_a_parent_that_wants_keepalives_we_do_not_send_is_a_stop(self):
        L = self.negotiated(0)
        raw = answer(0, b'\x0c\x00\x02', fc=3000005)
        self.assertEqual(L.authenticate_response('TIMEOUT', raw, 12, ACK)[0],
                         'KEEPALIVE_METHOD_UNIMPLEMENTED')


class TheHardwarePathsAreDerivedCorrectly(unittest.TestCase):
    """The hardware branch cannot be exercised anywhere but the operator's
    machine -- the keys are DPAPI-bound with no plaintext fallback -- so the
    paths it would use are asserted here instead. The defect this catches was
    real: STORE_PATHS points at epoch.json itself, and taking it as the root
    built .../epoch.json/epoch.json."""

    def test_the_pinned_store_path_is_a_file_not_a_directory(self):
        for ctx in (0, 1):
            self.assertEqual(Path(dual_store.STORE_PATHS[ctx]).name, 'epoch.json')

    def test_a_hardware_ledger_would_write_the_pinned_epoch_file(self):
        for ctx in (0, 1):
            L = ContextLedger.__new__(ContextLedger)
            pinned = Path(dual_store.STORE_PATHS[ctx]).resolve()
            L.root = pinned.parent
            L.path = L.root / 'epoch.json'
            self.assertEqual(L.path, pinned)

    def test_the_secrets_sit_beside_the_run_that_owns_the_store(self):
        for ctx in (0, 1):
            secrets = dual_ledger.secrets_root(ctx)
            self.assertEqual(secrets.name, 'secrets')
            store = Path(dual_store.STORE_PATHS[ctx]).resolve()
            self.assertTrue(str(store).startswith(str(secrets.parent)),
                            'ctx%d: secrets and store belong to different runs'
                            % ctx)

    def test_the_two_contexts_resolve_to_different_runs(self):
        self.assertNotEqual(dual_ledger.secrets_root(0),
                            dual_ledger.secrets_root(1))


class ItRunsOnTheOperatorsPython(unittest.TestCase):
    """The operator's machine runs Python 3.7. The first live Gate B attempt
    died on Path.is_relative_to, which arrived in 3.9 -- and it died INSIDE the
    check that decides whether a write is allowed, after the keys had already
    been unwrapped. A check that crashes is not a check, so the version floor
    is asserted here rather than discovered there again."""

    FLOOR = (3, 7)
    MODULES = ('host/dual_ledger.py', 'host/secured_frame.py',
               'host/gate_b.py', 'host/gate_b_runner.py', 'launch_gate_b.py')
    # Names that do not exist on the floor version.
    TOO_NEW = ('is_relative_to', 'removeprefix', 'removesuffix',
               'cache_parameters', 'pairwise', 'importlib.resources.files')

    def test_no_module_uses_an_api_newer_than_the_floor(self):
        root = Path(__file__).resolve().parent.parent
        for rel in self.MODULES:
            src = (root / rel).read_text(encoding='utf-8')
            for name in self.TOO_NEW:
                self.assertNotIn(name + '(', src, '%s uses %s' % (rel, name))

    def test_within_behaves_like_the_builtin_it_replaces(self):
        base = Path('/a/b')
        self.assertTrue(dual_ledger.within('/a/b/c', base))
        self.assertTrue(dual_ledger.within('/a/b', base))
        self.assertFalse(dual_ledger.within('/a', base))
        self.assertFalse(dual_ledger.within('/a/bb/c', base))
        self.assertFalse(dual_ledger.within('/x/y', base))

    def test_the_simulation_boundary_still_holds_with_it(self):
        with self.assertRaises(Fault):
            ContextLedger(1, KEYS[1], root='/tmp/not-the-simulation-root')
