"""The Gate B sequence, offline. No COM, no RF, no hardware.

Gate B transmits, spends frame counters and advances ctx0's store, so it
cannot be run twice to look more closely. What is driven here is the part the
runner owns: the ORDER, the ctx scoping, and that each context's frames go
through that context's ledger and no other.

The chain is declared in gate_b_runner.CHAIN, which is what makes that
checkable without a radio or a dispatcher.
"""
import os, shutil, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'host'))
sys.path.insert(0, str(HERE))
import gate_b_runner
from gate_b_runner import CHAIN, CTX_REFUSED, BOOTLESS
from rejoin_wire import Fault


class TheChainIsDeclared(unittest.TestCase):
    def test_it_is_the_v25_order(self):
        """The order V17..V25 proved on hardware, carried over unchanged. A
        reordering here would be a new protocol, not a dual runtime."""
        self.assertEqual([verb for verb, _ in CHAIN], [
            'ACTIVE_DISCOVERY_BEACON_REQUEST', 'DISCOVERY_COMMIT',
            'REJOIN_REQUEST', 'CURRENT_SHORT_COMMIT', 'DEVICE_ANNOUNCE',
            'END_DEVICE_TIMEOUT', 'PARENT_LINK_ACTIVE'])

    def test_exactly_three_steps_send_a_secured_frame(self):
        secured = [kind for _, kind in CHAIN if kind]
        self.assertEqual(secured, ['REJOIN', 'ANNOUNCE', 'TIMEOUT'])

    def test_every_secured_kind_is_one_the_frame_builder_knows(self):
        import secured_frame
        for _, kind in CHAIN:
            if kind:
                self.assertIn(kind, secured_frame.KINDS)

    def test_no_chain_step_is_a_global_verb(self):
        """Every step of the chain acts on ONE context, so none of them may be
        a verb the firmware refuses ctx on."""
        for verb, _ in CHAIN:
            self.assertNotIn(verb, CTX_REFUSED)

    def test_the_global_verbs_are_the_ones_the_firmware_refuses_ctx_on(self):
        import json
        surface = json.loads(
            (HERE.parent / 'evidence/wire_surface.json').read_text(encoding='utf-8'))
        refused = {v for v, s in surface['commands'].items()
                   if s['ctx'] == 'refused'}
        self.assertEqual(set(CTX_REFUSED), refused)

    def test_every_chain_verb_requires_ctx_in_the_firmware(self):
        import json
        surface = json.loads(
            (HERE.parent / 'evidence/wire_surface.json').read_text(encoding='utf-8'))
        for verb, _ in CHAIN:
            self.assertEqual(surface['commands'][verb]['ctx'], 'required', verb)


class Recorder:
    """A runner with the wire removed: it records what would be sent.

    Enough to drive the ctx scoping and the ledger routing, which is what the
    runner owns. Everything below the command line -- framing, receipts,
    timing -- belongs to the Wire and to the firmware and is driven elsewhere.
    """

    def __init__(self, ledgers):
        self.runner = gate_b_runner.GateBRunner.__new__(gate_b_runner.GateBRunner)
        self.runner.ledgers = ledgers
        self.runner.sent_order = []
        self.runner.records = []
        self.runner.answers, self.runner.authenticated = [], set()
        self.runner.auto_open = {}
        self.sent = []

        class FakeWire:
            boot = 'a' * 32
            rx_revision = None
            id = 0

            def next_id(self):
                self.id += 1
                return self.id

            def send(inner, line, raw=None, kind=None):
                self.sent.append(line)
        self.runner.w = FakeWire()
        self.runner.until = lambda p, s: {'fields': {'result': 'local_tx_ok',
                                                     'time_us': '1000'}}


class CtxScopingIsEnforced(unittest.TestCase):
    def setUp(self):
        self.rec = Recorder({0: None, 1: None})
        self.r = self.rec.runner

    def test_a_per_context_verb_without_ctx_is_refused(self):
        with self.assertRaises(Fault) as e:
            self.r.command('REJOIN_REQUEST')
        self.assertIn('ctx_missing', str(e.exception))

    def test_ctx_on_a_global_verb_is_refused(self):
        for verb in CTX_REFUSED:
            with self.assertRaises(Fault) as e:
                self.r.command(verb, 0)
            self.assertIn('ctx_on_a_global_verb', str(e.exception))

    def test_ctx_reaches_the_command_line(self):
        self.r.command('PARENT_LINK_ACTIVE', 1, 'session=1')
        self.assertIn(' ctx=1', self.rec.sent[-1])
        self.assertIn(' boot=', self.rec.sent[-1])

    def test_info_carries_neither_ctx_nor_boot(self):
        self.r.command('INFO')
        self.assertNotIn(' ctx=', self.rec.sent[-1])
        self.assertNotIn(' boot=', self.rec.sent[-1])

    def test_end_and_stats_carry_boot_but_not_ctx(self):
        """The sets are different, which the first live attempt proved: an END
        without boot is refused with reason=field_set."""
        for verb in ('END', 'STATS'):
            self.r.command(verb, fields='session=1' if verb == 'END' else '')
            self.assertIn(' boot=', self.rec.sent[-1], verb)
            self.assertNotIn(' ctx=', self.rec.sent[-1], verb)

    def test_the_boot_and_ctx_rules_match_the_firmware_surface(self):
        import json
        surface = json.loads(
            (HERE.parent / 'evidence/wire_surface.json').read_text(encoding='utf-8'))
        for verb, spec in surface['commands'].items():
            self.assertEqual(verb in CTX_REFUSED, spec['ctx'] == 'refused', verb)
            self.assertEqual(verb in BOOTLESS, 'boot' not in spec['fields'], verb)

    def test_status_may_omit_ctx(self):
        self.r.command('STATUS', fields='session=1')     # must not raise


class SecuredFramesGoThroughTheirOwnLedger(unittest.TestCase):
    """frame ctx == key ctx == FC allocator ctx, at the level the runner owns:
    the ctx it puts on the wire must be the ctx whose ledger built the bytes."""

    def test_a_ledger_for_another_context_is_refused(self):
        class Stub:
            ctx = 1
        r = Recorder({0: Stub(), 1: Stub()}).runner
        with self.assertRaises(Fault) as e:
            r.secured(0, 'REJOIN_REQUEST', 'REJOIN')
        self.assertIn('ledger_belongs_to_another_context', str(e.exception))


class TheOrderIsRejoinRejoinThenSharedReadiness(unittest.TestCase):
    def test_commission_returns_before_readiness(self):
        """commission() must not hold readiness itself: if it did, the two
        contexts would be commissioned one after the other with a full
        readiness window between them, which is the sequential shape the plan
        rules out and gate_b.shared_readiness refuses."""
        import inspect
        src = inspect.getsource(gate_b_runner.GateBRunner.commission)
        self.assertNotIn('READINESS_SECONDS', src)
        self.assertNotIn('observe(gate_b_runner.READINESS', src)

    def test_execute_commissions_both_before_observing(self):
        src = __import__('inspect').getsource(gate_b_runner.GateBRunner.execute)
        self.assertLess(src.index('commissioned'), src.index('readiness_start_us'))
        self.assertIn('for ctx in (0, 1)', src)

    def test_readiness_is_observed_once_for_both(self):
        src = __import__('inspect').getsource(gate_b_runner.GateBRunner.execute)
        self.assertEqual(src.count('READINESS_SECONDS'), 1)

    def test_ctx0_is_commissioned_first(self):
        """ctx0's secured rejoin on this firmware has never been proved, so it
        is attempted while the session budget is freshest."""
        src = __import__('inspect').getsource(gate_b_runner.GateBRunner.execute)
        self.assertIn('(0, 1)', src)


class TheIdentityPinBites(unittest.TestCase):
    def test_the_expected_info_matches_what_the_firmware_reports(self):
        import json
        surface = json.loads(
            (HERE.parent / 'evidence/wire_surface.json').read_text(encoding='utf-8'))
        self.assertEqual(gate_b_runner.EXPECTED_INFO['version'],
                         surface['firmware_version'])
        self.assertEqual(gate_b_runner.EXPECTED_INFO['wire'], surface['wire'])

    def test_immediate_ack_is_not_pinned_to_zero(self):
        """Unlike Gate A, Gate B opens the ACK gate on purpose. Pinning it shut
        here would refuse the gate's own working state."""
        self.assertNotIn('immediate_ack', gate_b_runner.EXPECTED_INFO)


if __name__ == '__main__':
    unittest.main()


class ABoundDongleIsRefusedWithTheRemedy(unittest.TestCase):
    """A context can be bound exactly once per dongle boot: management_resume
    demands G_IDLE, and commission_phase_t runs IDLE -> RECOVERY -> STOPPED
    with nothing moving it back. END stops a session; it does not reopen one,
    and the association session number survives it. So the gate must say
    'power-cycle the dongle', not send a BIND and relay
    reason=current_context_only."""

    def runner_with(self, info):
        r = Recorder({0: None, 1: None}).runner
        r.info = info
        return r

    def test_a_fresh_boot_passes(self):
        self.runner_with({'session': '0', 'config_generation': '0'}
                         ).require_a_fresh_boot()

    def test_an_open_session_is_refused_with_the_remedy(self):
        with self.assertRaises(Fault) as e:
            self.runner_with({'session': '1', 'config_generation': '2'}
                             ).require_a_fresh_boot()
        self.assertIn('Unplug the dongle', str(e.exception))
        self.assertIn('Nothing needs reflashing', str(e.exception))

    def test_a_published_allowlist_alone_is_also_refused(self):
        """config_generation outlives the session, so a dongle that was bound
        and then ENDed still cannot be bound again."""
        with self.assertRaises(Fault) as e:
            self.runner_with({'session': '0', 'config_generation': '2'}
                             ).require_a_fresh_boot()
        self.assertIn('once per boot', str(e.exception))

    def test_the_firmware_really_has_no_path_back_to_idle(self):
        """If a future firmware adds one, this test is where to notice."""
        src = (HERE.parent / 'src/rejoin_transport.c').read_text(encoding='utf-8')
        self.assertIn('s->phase!=G_IDLE', src.replace(' ', ''))
        for f in ('src/main.c', 'src/rejoin_transport.c'):
            body = (HERE.parent / f).read_text(encoding='utf-8')
            self.assertNotIn('phase=G_IDLE', body.replace(' ', ''))


class DiscoveryIsScopedToItsContext(unittest.TestCase):
    """The inherited beacon check hardcoded ctx1's PAN and trust centre, as
    several other places in the V25 host stack still do. On the discovery path
    that is not a cosmetic issue: a good ctx0 beacon is refused as
    beacon_MAC_context and the gate reports a coordinator that did not answer
    when in fact it did."""

    def test_validate_takes_a_pan_and_a_trust_centre(self):
        import inspect, discovery
        sig = inspect.signature(discovery.validate).parameters
        self.assertIn('pan', sig)
        self.assertIn('tc', sig)

    def test_the_defaults_are_ctx1s_so_v25_callers_are_unchanged(self):
        import inspect, discovery, dual_store
        sig = inspect.signature(discovery.validate).parameters
        self.assertEqual(sig['pan'].default, dual_store.PINNED[1]['pan'])
        self.assertIsNone(sig['tc'].default)

    def test_the_runner_passes_the_context_it_is_discovering_for(self):
        import inspect
        src = inspect.getsource(gate_b_runner.GateBRunner.discover)
        self.assertIn("pan=identity['pan']", src)
        self.assertIn("tc=identity['tc_ieee']", src)


class TheRevisionFloorHandlesAnEmptyWire(unittest.TestCase):
    """The first scan of the first context runs before the Wire has seen a
    single RX record, so its revision counter is None. None is not zero -- it
    is the absence of a floor -- and comparing an int against it raised
    TypeError inside the beacon validation, after the beacon had already been
    found. V25 never met this because its probe had been observing first."""

    def test_the_floor_is_minus_one_when_nothing_has_been_seen(self):
        import inspect
        src = inspect.getsource(gate_b_runner.GateBRunner.discover)
        self.assertIn('-1 if self.w.rx_revision is None', src)

    def test_any_revision_clears_an_absent_floor(self):
        floor = -1
        for revision in (0, 1, 2, 10 ** 6):
            self.assertGreater(revision, floor)


class TheCycleOpensBeforeBind(unittest.TestCase):
    """BIND sends the store's guard and the firmware holds every later secured
    frame to it (intent_binding), so the run's cycle must exist in the store
    before BIND reads it -- and under this run's guard, not a previous one's."""

    def test_begin_cycle_runs_before_anything_is_sent(self):
        rec = Recorder({0: None, 1: None})
        r = rec.runner
        r.guard = 'd' * 32
        seen = []

        class Stop(Exception):
            pass

        class Ledger:
            ctx = 0

            def begin_cycle(self, guard):
                seen.append((guard, list(rec.sent)))
                raise Stop()
        r.ledgers = {0: Ledger()}
        with self.assertRaises(Stop):
            r.commission(0)
        self.assertEqual(seen, [('d' * 32, [])])

    def test_the_launcher_passes_the_run_id_as_the_guard(self):
        src = (HERE.parent / 'launch_gate_b.py').read_text(encoding='utf-8')
        self.assertIn('guard=run_id', src)

    def test_without_one_the_runner_mints_a_well_formed_guard(self):
        r = gate_b_runner.GateBRunner(None, lambda: 0, {})
        self.assertRegex(r.guard, r'^[0-9a-f]{32}$')


class ACrashStillLeavesAnOutcome(unittest.TestCase):
    """Attempt 9 died on recovery_model.Fault, which is not the wire's Fault;
    it escaped execute() and the launcher wrote no outcome.json at all."""

    def test_a_foreign_exception_is_recorded_and_end_is_still_sent(self):
        from recovery_model import Fault as LedgerFault
        rec = Recorder({0: None, 1: None})
        r = rec.runner

        def boom():
            raise LedgerFault('one_shot_state:REJOIN already attempted')
        r.probe_id_floor = boom
        outcome = r.execute()
        self.assertFalse(outcome['passed'])
        self.assertIn('one_shot_state', outcome['error'])
        self.assertIn(' END ', rec.sent[-1])


ATTEMPT_10_AUTO = (
    'RADIOV10 AUTO_ACCEPT boot=f6f4360d2eb3c15128f1a68dbaf9c503 id=7 ctx=0 '
    'session=1 class=MANAGEMENT_POLL mac=6388f49bfa000026a304 retry=0 '
    'time_us=19003250 poll=1',
    'RADIOV10 AUTO_DONE boot=f6f4360d2eb3c15128f1a68dbaf9c503 id=7 ctx=0 '
    'session=1 result=local_tx_ok time_us=19005063 ack_present=1 ack_fcf=18 '
    'ack_dsn=244 poll=1 cleanup=safe reboot_required=0',
)


def auto_row(raw):
    parts = raw.split()
    return {'kind': parts[1],
            'fields': dict(x.split('=', 1) for x in parts[2:])}


class AutomaticPollsAreClaimed(unittest.TestCase):
    """Once a secured rejoin is out the firmware polls its parent by itself,
    and the Wire faults on an AUTO record with no handler. Attempt 10 sent
    ctx0's REJOIN, the first automatic poll followed, and the run stopped on
    UNEXPECTED_AUTO_POLL."""

    def runner(self):
        r = Recorder({0: None, 1: None}).runner
        r.auto_open = {}
        return r

    def test_the_runner_installs_a_handler(self):
        r = gate_b_runner.GateBRunner(None, lambda: 0, {})
        self.assertEqual(r.w.on_auto, r.on_auto)

    def test_attempt_10s_poll_is_accepted(self):
        r = self.runner()
        for raw in ATTEMPT_10_AUTO:
            r.on_auto(auto_row(raw))
        self.assertEqual(r.auto_open, {})

    def test_a_ctx0_poll_carrying_ctx1s_pan_is_refused(self):
        row = auto_row(ATTEMPT_10_AUTO[0].replace('9bfa', '7a0b'))
        with self.assertRaises(Fault) as e:
            self.runner().on_auto(row)
        self.assertIn('auto_poll_frame', str(e.exception))

    def test_the_same_poll_is_refused_as_the_other_contexts(self):
        row = auto_row(ATTEMPT_10_AUTO[0].replace('ctx=0', 'ctx=1'))
        with self.assertRaises(Fault):
            self.runner().on_auto(row)

    def test_a_done_without_its_accept_is_refused(self):
        with self.assertRaises(Fault) as e:
            self.runner().on_auto(auto_row(ATTEMPT_10_AUTO[1]))
        self.assertIn('done_without_accept', str(e.exception))

    def test_an_unclean_radio_stops_the_run(self):
        r = self.runner()
        r.on_auto(auto_row(ATTEMPT_10_AUTO[0]))
        with self.assertRaises(Fault) as e:
            r.on_auto(auto_row(ATTEMPT_10_AUTO[1].replace('reboot_required=0',
                                                          'reboot_required=1')))
        self.assertIn('AUTO_CLEANUP_UNPROVEN', str(e.exception))

    def test_a_failed_poll_is_not_a_fault_here(self):
        """Whether the parent answered is the verdict's question, not a reason
        to abandon the run halfway through the chain."""
        r = self.runner()
        r.on_auto(auto_row(ATTEMPT_10_AUTO[0]))
        r.on_auto(auto_row(ATTEMPT_10_AUTO[1].replace('ack_present=1',
                                                      'ack_present=0')))


class TheChainIsDrivenByAuthenticatedAnswers(unittest.TestCase):
    """commission() end to end against a scripted firmware: real ledgers over
    disposable stores, real encrypted answers, the firmware's own rules for
    what it accepts. Attempt 10 showed the old chain waited for the firmware
    to report REJOINED, which it only does after the host's commit."""

    def setUp(self):
        import json, dual_ledger, dual_store, test_dual_ledger as T
        self.T, self.store = T, dual_store
        self.tmp = Path(tempfile.mkdtemp(dir=str(dual_ledger.SIMULATION_ROOT)))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        roots = {}
        for ctx in (0, 1):
            d = self.tmp / ('ctx%d' % ctx)
            d.mkdir()
            rec = T.record(ctx)
            pin = dual_store.PINNED[ctx]
            # The whole identity dual_store.read checks, so the runner can read
            # these stores exactly as it reads the live ones.
            rec['context'].update(ctx=ctx, raw_ieee=pin['raw_ieee'],
                                  tc_ieee=pin['tc_ieee'], attempt=pin['attempt'])
            rec.update(keyseq=pin['keyseq'], key_epoch_id=pin['epoch'])
            rec['generation'] = 16 + 3 * ctx
            rec['recovery']['gate'] = 'b' * 32
            (d / 'epoch.json').write_text(json.dumps(rec), encoding='utf-8')
            roots[ctx] = d
        self.ledgers = dual_ledger.pair(T.KEYS, roots=roots)

    def drive(self, ctx, answer_rejoin=True, other_first=True):
        T, store, ledgers = self.T, self.store, self.ledgers
        rec = Recorder(ledgers)
        r = rec.runner
        r.guard = 'f' * 32
        r.clock = iter(range(10 ** 6)).__next__
        fw = {'gen': None, 'rev': 100, 'phase': 'BOUND', 'commands': []}

        def rx(raw, **ack):
            fw['rev'] += 1
            r.records.append({'kind': 'RX', 'fields': dict(
                T.ACK, mac=raw.hex(), revision=str(fw['rev']), **ack)})
            return fw['rev']

        def command(verb, c=None, fields='', raw=None, kind=None):
            f = dict(x.split('=', 1) for x in fields.split() if '=' in x)
            fw['commands'].append((verb, f))
            short = store.PINNED[ctx]['short']
            if verb == 'BIND':
                fw['gen'] = int(f['generation'])
            elif verb == 'REJOIN_REQUEST':
                fw['phase'] = 'WAIT_REJOIN'
                if other_first:     # the other network talks first
                    rx(T.answer(1 - ctx, b'\x07' + store.PINNED[1 - ctx]['short']
                                .to_bytes(2, 'little') + b'\x00'))
                if answer_rejoin:
                    fw['latched'] = rx(T.answer(ctx, b'\x07' + short.to_bytes(2, 'little') + b'\x00'))
            elif verb == 'CURRENT_SHORT_COMMIT':
                assert fw['phase'] == 'WAIT_REJOIN'
                assert int(f['generation']) == fw['gen'] + 1, f
                assert int(f['revision']) == fw['latched'], f
                fw['gen'] += 1
                fw['phase'] = 'REJOINED'
                return {'assigned_short': '%04x' % short, 'recovery': 'REJOINED'}
            elif verb == 'END_DEVICE_TIMEOUT':
                fw['phase'] = 'WAIT_TIMEOUT'
                fw['latched'] = rx(T.answer(ctx, b'\x0c\x00\x01', fc=3000009))
            elif verb == 'PARENT_LINK_ACTIVE':
                assert fw['phase'] == 'WAIT_TIMEOUT'
                assert int(f['generation']) == fw['gen'], f
                assert int(f['revision']) == fw['latched'], f
                fw['phase'] = 'PARENT_LINK_ACTIVE'
            if raw is not None:
                return {'result': 'local_tx_ok', 'time_us': '1000'}
            return {'recovery': fw['phase']}
        r.command = command
        r.discover = lambda c, gen: type('E', (), {'revision': 1, 'raw_hash': 'a' * 64})()
        return r, fw

    def test_ctx0_reaches_the_parent_link_through_both_answers(self):
        r, fw = self.drive(0)
        self.assertEqual(r.commission(0), {'recovery': 'PARENT_LINK_ACTIVE'})
        q = self.ledgers[0].read()['recovery']
        self.assertEqual(q['state'], 'PARENT_LINK_ACTIVE')
        self.assertEqual([a['result'] for a in r.answers],
                         ['NOT_THIS_CONTEXT', 'REJOINED', 'PARENT_LINK_ACTIVE'])
        self.assertEqual([v for v, _ in fw['commands']], [
            'BIND', 'DISCOVERY_COMMIT', 'REJOIN_REQUEST', 'CURRENT_SHORT_COMMIT',
            'DEVICE_ANNOUNCE', 'END_DEVICE_TIMEOUT', 'PARENT_LINK_ACTIVE', 'STATUS'])

    def test_ctx1_too(self):
        r, _ = self.drive(1)
        r.commission(1)
        self.assertEqual(self.ledgers[1].read()['recovery']['state'], 'PARENT_LINK_ACTIVE')
        self.assertEqual(self.ledgers[0].read()['recovery'].get('state'), 'DISCOVERING')

    def test_no_answer_stops_before_any_commit_or_announce(self):
        r, fw = self.drive(0, answer_rejoin=False)
        with self.assertRaises(Fault) as e:
            r.commission(0)
        self.assertIn('no_authenticated_REJOIN_response', str(e.exception))
        self.assertNotIn('CURRENT_SHORT_COMMIT', [v for v, _ in fw['commands']])
        self.assertNotIn('ANNOUNCE', self.ledgers[0].read()['recovery']['intents'])

    def test_wait_state_is_gone(self):
        """The model it encoded -- the firmware reports REJOINED by itself --
        is the one attempt 10 disproved."""
        self.assertFalse(hasattr(gate_b_runner.GateBRunner, 'wait_state'))


class ReadinessIsKeptAliveByTheHost(unittest.TestCase):
    """In PARENT_LINK_ACTIVE the firmware's automatic polls are over (the
    response window is closed); every keepalive is a host MANAGEMENT_POLL,
    at least 1 s apart per context (rejoin_transport.c, idle_poll_bound)."""

    def run_keep_alive(self, seconds=60, ack='1'):
        import dual_store

        class Ledger:
            def __init__(self, ctx):
                self.ctx, self.identity = ctx, dual_store.PINNED[ctx]

            def read(self):
                return {'generation': 20 + self.ctx, 'sequences': {'dsn': 250}}
        rec = Recorder({0: Ledger(0), 1: Ledger(1)})
        r = rec.runner
        now = [0.0]

        def clock():
            now[0] += 0.01
            return now[0]
        r.clock = clock
        r.w.read = lambda: None
        sent = []

        def command(verb, ctx=None, fields='', raw=None, kind=None):
            f = dict(x.split('=', 1) for x in fields.split())
            i = len(sent) + 1
            sent.append({'verb': verb, 'ctx': ctx, 'at': now[0], 'raw': raw,
                         'fields': f, 'kind': kind})
            us = str(int(now[0] * 1e6))
            r.records.append({'kind': 'TXACCEPT', 'fields': {
                'ctx': str(ctx), 'id': str(i), 'class': kind, 'mac': raw.hex()}})
            done = {'ctx': str(ctx), 'id': str(i), 'result': 'local_tx_ok',
                    'ack_present': ack, 'time_us': us, 'poll': '0'}
            r.records.append({'kind': 'TXDONE', 'fields': done})
            return done
        r.command = command
        return r.keep_alive(seconds), sent

    def test_both_contexts_are_polled_throughout(self):
        rows, sent = self.run_keep_alive()
        for ctx in (0, 1):
            mine = [s for s in sent if s['ctx'] == ctx]
            self.assertGreaterEqual(len(mine), 40, ctx)
            gaps = [b['at'] - a['at'] for a, b in zip(mine, mine[1:])]
            self.assertGreaterEqual(min(gaps), 1.0)
            self.assertGreaterEqual(mine[0]['at'], 1.0)

    def test_each_poll_is_its_own_contexts_frame_and_generation(self):
        import dual_store
        _, sent = self.run_keep_alive(10)
        for s in sent:
            p = dual_store.PINNED[s['ctx']]
            self.assertEqual(s['verb'], 'MANAGEMENT_POLL')
            self.assertEqual(s['kind'], 'MANAGEMENT_POLL')
            self.assertEqual(s['raw'][3:5], p['pan'].to_bytes(2, 'little'))
            self.assertEqual(s['raw'][7:9], p['short'].to_bytes(2, 'little'))
            self.assertEqual(s['raw'][2], int(s['fields']['dsn']))
            self.assertEqual(s['fields']['generation'], str(20 + s['ctx']))

    def test_the_evaluator_accepts_what_keep_alive_produces(self):
        rows, _ = self.run_keep_alive()
        import gate_b
        r = gate_b.shared_readiness(rows)
        self.assertTrue(r['passed'], r['reasons'])

    def test_and_refuses_it_when_no_parent_acked(self):
        rows, _ = self.run_keep_alive(ack='0')
        import gate_b
        self.assertFalse(gate_b.shared_readiness(rows)['passed'])

    def test_execute_keeps_alive_rather_than_only_listening(self):
        src = __import__('inspect').getsource(gate_b_runner.GateBRunner.execute)
        self.assertIn('keep_alive(READINESS_SECONDS)', src)


class AMacRetransmissionIsNotAReplay(unittest.TestCase):
    """Gate E attempt 2: a neighbour router's unicast to the coordinator came
    three times in 8 ms, byte-identical. The first authenticated (not an
    answer), the floor rejected the copies, and the run ended. A copy of a
    frame already accepted is skipped; any other replay still ends the run."""
    A, B, ANSWER = b'\x61\x88\x75', b'\x61\x88\x76', b'\x61\x88\x77'

    def runner(self, verdicts):
        r = gate_b_runner.GateBRunner.__new__(gate_b_runner.GateBRunner)
        r.answers, r.authenticated = [], set()
        r.records = [{'kind': 'RX', 'fields': {'mac': raw.hex(), 'revision': str(i)}}
                     for i, (raw, _) in enumerate(verdicts)]
        it = iter(v for _, v in verdicts)

        class Ledger:
            def authenticate_response(self, kind, raw, revision, fields):
                return next(it), {}
        r.ledgers = {0: Ledger()}
        r.clock = lambda: 0.0
        return r

    def test_byte_identical_copies_are_skipped(self):
        r = self.runner([(self.A, 'AUTHENTICATED_NOT_A_RESPONSE'),
                         (self.A, 'REPLAY_REJECTED'), (self.A, 'REPLAY_REJECTED'),
                         (self.ANSWER, 'PARENT_LINK_ACTIVE')])
        self.assertEqual(r.await_response(0, 'TIMEOUT', 0), 3)
        self.assertEqual([a['result'] for a in r.answers][1:3], ['MAC_RETRANSMISSION'] * 2)

    def test_a_replay_of_a_frame_never_accepted_still_ends_the_run(self):
        r = self.runner([(self.A, 'AUTHENTICATED_NOT_A_RESPONSE'),
                         (self.B, 'REPLAY_REJECTED')])
        with self.assertRaisesRegex(Fault, 'parent_answer:REPLAY_REJECTED'):
            r.await_response(0, 'TIMEOUT', 0)

    def test_a_copy_seen_by_the_other_context_is_not_this_ones(self):
        r = self.runner([(self.A, 'REPLAY_REJECTED')])
        r.authenticated.add((1, self.A))
        with self.assertRaisesRegex(Fault, 'parent_answer:REPLAY_REJECTED'):
            r.await_response(0, 'TIMEOUT', 0)
