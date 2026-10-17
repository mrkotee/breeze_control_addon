"""Gate B driver: commission both contexts, then hold them live together.

The port and the ledgers are injected, so the whole sequence is drivable
offline before a dongle is on air -- the same split that let Gate A's runner
be wrong three times on a fake port instead of once on a radio.

The order is the thing. The plan asks for rejoin -> rejoin -> SHARED
readiness, not two complete sequential phases, because the first context's
parent link goes cold while the second is commissioned and a run shaped that
way is two single-context runs wearing one session. So COMMISSION runs per
context, bounded, and readiness runs ONCE for both.

Nothing here decides whether the gate passed: that is gate_b.evaluate, which
is pure and tested separately. Nothing here writes a store either -- the
ledgers do, and only the launcher constructs them with hardware=True.
"""
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dual_store
import gate_b
# Before discovery, deliberately. discovery puts the V8 milestone's host
# directory first on sys.path and imports `management` from there, so whichever
# module imports `management` first decides it for the whole process. The
# ledger's per-context decode_nwk(pan=...) exists only in this tree's copy.
# The launcher already imported in this order, which is what attempts 9-10 ran.
import management                                   # noqa: F401  (this tree's)
from discovery import validate, beacon_request
import id_floor
from rejoin_wire import Wire, Fault, PREFIX

EXPECTED_INFO = {
    'identity': 'airnanny_dual_pan_runtime_v28', 'version': '28', 'wire': '10',
    'contexts': '2', 'channel': '21', 'crypto': 'host_only',
    'application_tx': 'typed_fan_once', 'pending_tx': '0',
}

READINESS_SECONDS = 60
SCAN_SETTLE_S = 0.28
MAX_SCANS = 3
# The firmware listens RESPONSE_US (491.52 ms) after the request's TXDONE;
# the host waits a little longer so a latched answer is always read.
RESPONSE_WAIT_S = 1.0
# The firmware refuses a MANAGEMENT_POLL within 1 s of that context's previous
# one (idle_poll_bound) -- counted from PARENT_LINK_ACTIVE for the first. The
# margin absorbs the two clocks disagreeing.
POLL_PERIOD_S = 1.25
CLOCK_WRAP_US = 2 ** 32
CLOCK_MARGIN_US = 120 * 1000000

# The chain, declared rather than written out twice. Each entry is
# (verb, kind) where kind is the secured frame this step sends, or None for a
# plain command. Declaring it makes the ORDER testable without a radio, and
# makes it impossible for the two contexts to be driven through different
# sequences by accident.
CHAIN = (
    ('ACTIVE_DISCOVERY_BEACON_REQUEST', None),
    ('DISCOVERY_COMMIT', None),
    ('REJOIN_REQUEST', 'REJOIN'),
    ('CURRENT_SHORT_COMMIT', None),
    ('DEVICE_ANNOUNCE', 'ANNOUNCE'),
    ('END_DEVICE_TIMEOUT', 'TIMEOUT'),
    ('PARENT_LINK_ACTIVE', None),
)

# Two different sets, which the first live attempt proved are not the same
# one. CTX_REFUSED is the verbs the firmware refuses `ctx` on; BOOTLESS is the
# single verb that must NOT carry `boot`, because INFO is the handshake that
# reveals it. Conflating them sent an END without boot and earned
# reason=field_set -- evidence/wire_surface.json says plainly that END and
# STATS take boot and INFO does not.
CTX_REFUSED = ('INFO', 'END', 'STATS')
BOOTLESS = ('INFO',)


class GateBRunner:
    def __init__(self, port, clock, ledgers, guard=None):
        self.clock = clock
        # The run's guard: each context's recovery cycle is opened under it and
        # every BIND and secured frame of this run carries it. The launcher
        # passes the run id so the store names the run that moved it.
        self.guard = guard or uuid.uuid4().hex
        self.records = []
        self.w = Wire(port, clock, self.records)
        # The firmware polls its parent on its own once a secured rejoin is out,
        # and the Wire refuses an AUTO record nobody claims. V25's probe claimed
        # them; this runner did not, and attempt 10 stopped there.
        self.w.on_auto = self.on_auto
        self.auto_open = {}             # ctx -> (id, poll) of the queued poll
        self.answers = []               # every RX offered as a parent's answer
        self.authenticated = set()      # (ctx, raw) of every frame a ledger accepted
        self.ledgers = ledgers          # {0: ContextLedger, 1: ContextLedger}
        self.info = None
        self.sent_order = []            # what was sent, in order, for evidence

    # -- plumbing ---------------------------------------------------------
    def command(self, verb, ctx=None, fields='', raw=None, kind=None):
        i = self.w.next_id()
        line = '%s %s id=%d' % (PREFIX, verb, i)
        if self.w.boot and verb not in BOOTLESS:
            line += ' boot=' + self.w.boot
        if ctx is not None:
            if verb in CTX_REFUSED:
                raise Fault('ctx_on_a_global_verb:%s' % verb)
            line += ' ctx=%d' % ctx
        elif verb not in CTX_REFUSED and verb != 'STATUS':
            raise Fault('ctx_missing_on_a_per_context_verb:%s' % verb)
        if fields:
            line += ' ' + fields
        self.w.send(line, raw, kind)
        self.sent_order.append({'verb': verb, 'ctx': ctx, 'id': i,
                                'secured': bool(raw)})
        want = ('TXDONE' if raw else
                {'INFO': 'INFO', 'STATS': 'STATS'}.get(verb, 'STATUS'))
        return self.until(lambda r: r['kind'] == want
                          and r['fields'].get('id') == str(i), 3)['fields']

    def on_auto(self, row):
        """Check one automatic poll as it arrives: the things that must stop
        the run at once, not the verdict. Whether the parent link was alive is
        gate_b.acked_polls' question, answered from the records afterwards.

        Stops on: a poll not bound to a context, not this context's poll frame
        (V25 checked the bytes too; a ctx0 poll carrying ctx1's PAN is the
        single-context trap again), a DONE without its ACCEPT, and a radio
        that reports it was not left clean.
        """
        f = row['fields']
        ctx = f.get('ctx')
        if ctx not in ('0', '1'):
            raise Fault('auto_poll_context:%r' % ctx)
        key = (f.get('id'), f.get('poll'))
        if row['kind'] == 'AUTO_ACCEPT':
            ident = dual_store.PINNED[int(ctx)]
            want = ('6388', '%02x%02x' % (ident['pan'] & 255, ident['pan'] >> 8),
                    '0000', '%02x%02x' % (ident['short'] & 255, ident['short'] >> 8),
                    '04')
            mac = f.get('mac', '')
            got = (mac[0:4], mac[6:10], mac[10:14], mac[14:18], mac[18:])
            if (f.get('class') != 'MANAGEMENT_POLL' or f.get('retry') != '0'
                    or len(mac) != 20 or got != want):
                raise Fault('auto_poll_frame:ctx=%s class=%s mac=%s'
                            % (ctx, f.get('class'), mac))
            if self.auto_open.get(ctx):
                raise Fault('auto_poll_accept_twice:ctx=%s' % ctx)
            self.auto_open[ctx] = key
            return
        if self.auto_open.pop(ctx, None) != key:
            raise Fault('auto_poll_done_without_accept:ctx=%s' % ctx)
        if f.get('cleanup') != 'safe' or f.get('reboot_required') != '0':
            raise Fault('AUTO_CLEANUP_UNPROVEN:ctx=%s cleanup=%s reboot=%s'
                        % (ctx, f.get('cleanup'), f.get('reboot_required')))

    def until(self, predicate, seconds):
        end = self.clock() + seconds
        while self.clock() < end:
            row = self.w.read()
            if row and predicate(row):
                return row
        raise Fault('bounded_receipt_timeout')

    def keep_alive(self, seconds):
        """Both parent links, polled together for `seconds`, and the records
        of that window returned.

        In PARENT_LINK_ACTIVE the firmware does not poll by itself: its
        automatic polls run only inside a response window, which
        PARENT_LINK_ACTIVE closes. Every keepalive is a host MANAGEMENT_POLL.
        The first version only listened here, which would have let both links
        go quiet and then reported, correctly, that neither had polled. V25
        sent these itself (probe.reserve_idle_poll); this is that, for both
        contexts, interleaved.
        """
        start = len(self.records)
        t0 = self.clock()
        due = {}
        for ctx in (0, 1):
            r = self.ledgers[ctx].read()
            due[ctx] = {'at': t0 + POLL_PERIOD_S + 0.5 * ctx,
                        'generation': r['generation'],
                        'dsn': r['sequences']['dsn']}
        end = t0 + seconds
        while self.clock() < end:
            for ctx in (0, 1):
                d = due[ctx]
                if self.clock() >= d['at']:
                    d['dsn'] = (d['dsn'] + 1) & 255
                    self.idle_poll(ctx, d['generation'], d['dsn'])
                    d['at'] = self.clock() + POLL_PERIOD_S
            self.w.read()
        return self.records[start:]

    def idle_poll(self, ctx, generation, dsn):
        """One keepalive poll for one context. The bytes are this context's,
        given to the Wire so it can hold TXACCEPT to them: a ctx0 poll the
        firmware built with ctx1's PAN would be refused there, not counted."""
        ident = self.ledgers[ctx].identity
        raw = (bytes([0x63, 0x88, dsn]) + ident['pan'].to_bytes(2, 'little')
               + b'\x00\x00' + ident['short'].to_bytes(2, 'little') + b'\x04')
        return self.command('MANAGEMENT_POLL', ctx,
                            'session=1 generation=%d dsn=%d' % (generation, dsn),
                            raw, 'MANAGEMENT_POLL')

    def observe(self, seconds):
        start = len(self.records)
        end = self.clock() + seconds
        while self.clock() < end:
            self.w.read()
        return self.records[start:]

    # -- the gate ---------------------------------------------------------
    def probe_id_floor(self):
        """Raise the command-id counter above whatever this boot has already
        used. Gate A ran on this same dongle, so ids 1..N are spent and a
        counter starting at 1 is refused on the first command."""
        return id_floor.probe(self.w, self.clock, self.records)

    def check_identity(self):
        self.info = self.command('INFO')
        wrong = {k: self.info.get(k) for k, v in EXPECTED_INFO.items()
                 if self.info.get(k) != v}
        if wrong:
            raise Fault('unexpected_firmware_identity:%r' % wrong)
        return self.info

    def require_a_fresh_boot(self):
        """Refuse, with the remedy, if this dongle has already been commissioned.

        A context can be bound exactly ONCE per dongle boot. management_resume
        demands phase == G_IDLE, and G_IDLE is only the initial value:
        commission_phase_t runs IDLE -> RECOVERY -> STOPPED and nothing in the
        firmware ever moves it back. END stops a session, it does not reopen
        one, and the association session number survives it -- which is why
        INFO still reports session=1 afterwards.

        So an END-then-retry loop cannot work, and discovering that by sending
        BIND and reading reason=current_context_only tells the operator
        nothing useful. This says what is actually required: power-cycle the
        dongle. That is a manual action and the gate stops for it rather than
        spending a run id to fail the same way again.
        """
        session = self.info.get('session', '0')
        if session != '0' or self.info.get('config_generation', '0') != '0':
            raise Fault(
                'dongle_already_commissioned_this_boot: session=%s '
                'config_generation=%s. A context can be bound once per boot -- '
                'the firmware never returns a context to IDLE and END does not '
                'reopen one. Unplug the dongle and plug it back in, then run '
                'this gate again. Nothing needs reflashing.'
                % (session, self.info.get('config_generation')))
        return None

    def store(self, ctx):
        """This context's store, read through the file its ledger writes.

        On hardware that is the pinned path either way. Reading it through the
        ledger makes it impossible for BIND to quote one file while the ledger
        commits to another -- which an end-to-end test of the chain did, the
        first time it ran against disposable stores.
        """
        return dual_store.read(ctx, self.ledgers[ctx].path)

    def secured(self, ctx, verb, kind):
        """Reserve, build, send, record -- in that order, through THIS
        context's ledger.

        The counter is spent before the frame exists and the outcome is
        recorded whatever it was, both decided by the ledger; the runner's job
        is only to make sure the ctx it passes is the ctx whose ledger it
        used. Those two being the same is the whole of
        frame ctx == key ctx == FC allocator ctx at this level.
        """
        ledger = self.ledgers[ctx]
        if ledger.ctx != ctx:
            raise Fault('ledger_belongs_to_another_context:%d' % ledger.ctx)
        ledger.reserve(kind)
        raw, fc = ledger.build(kind)
        entry = self.store(ctx)
        fields = ('session=1 generation=%s epoch=%s attempt=%s guard=%s '
                  'fc=%d hash=%s mac=%s'
                  % (entry['generation'], entry['epoch'], entry['attempt'],
                     entry['guard'], fc,
                     ledger.read()['recovery']['intents'][kind]['sha256'],
                     raw.hex()))
        row = self.command(verb, ctx, fields, raw, verb)
        ledger.sent(kind, row.get('result', 'unknown'), int(row['time_us']))
        return row

    def commission(self, ctx):
        """One context through the whole chain, bounded.

        Runs per context and returns as soon as that context is ACTIVE, so the
        other one can be started while this parent link is still warm. Holding
        readiness here instead would make the two phases sequential, which is
        the shape the plan rules out.
        """
        ledger = self.ledgers[ctx]
        # Before BIND, because BIND reads the guard from the store and the
        # firmware holds every later secured frame to it.
        ledger.begin_cycle(self.guard)
        entry = self.store(ctx)
        gen = entry['generation']
        # Built by dual_store, not here. It is a direct projection of the
        # store, and the firmware refuses a BIND whose epoch or attempt does
        # not match the identity compiled into the image -- so this is not a
        # place where values may be chosen. Gate A used the same projection.
        self.command('BIND', ctx, dual_store.bind_fields(entry))
        evidence = self.discover(ctx, gen)
        self.command('DISCOVERY_COMMIT', ctx,
                     'session=1 generation=%s revision=%d hash=%s'
                     % (gen, evidence.revision, evidence.raw_hash))
        # The firmware cannot tell a real answer from a well-shaped one -- it
        # is host_only -- so it latches the frame and waits in WAIT_REJOIN for
        # the host to authenticate it and commit. REJOINED is what it reports
        # AFTER that commit, not before; waiting for it first is waiting for
        # something only this side can cause.
        since = len(self.records)
        self.secured(ctx, 'REJOIN_REQUEST', 'REJOIN')
        revision = self.await_response(ctx, 'REJOIN', since)
        # The ledger has just committed generation+1, and the firmware
        # requires exactly that: c->generation == s->generation + 1.
        gen = ledger.read()['generation']
        short = ledger.identity['short']
        receipt = self.command('CURRENT_SHORT_COMMIT', ctx,
                               'session=1 generation=%d revision=%d short=%d'
                               % (gen, revision, short))
        if (receipt.get('assigned_short') != '%04x' % short
                or receipt.get(gate_b.RECOVERY_FIELD) != 'REJOINED'):
            raise Fault('short_install_receipt:ctx=%d got=%r/%r'
                        % (ctx, receipt.get('assigned_short'),
                           receipt.get(gate_b.RECOVERY_FIELD)))
        self.secured(ctx, 'DEVICE_ANNOUNCE', 'ANNOUNCE')
        since = len(self.records)
        self.secured(ctx, 'END_DEVICE_TIMEOUT', 'TIMEOUT')
        revision = self.await_response(ctx, 'TIMEOUT', since)
        linked = self.command('PARENT_LINK_ACTIVE', ctx,
                              'session=1 generation=%d revision=%d'
                              % (gen, revision))
        if linked.get(gate_b.RECOVERY_FIELD) != 'PARENT_LINK_ACTIVE':
            raise Fault('parent_link_receipt:ctx=%d got=%r'
                        % (ctx, linked.get(gate_b.RECOVERY_FIELD)))
        return self.command('STATUS', ctx, 'session=1')

    def await_response(self, ctx, kind, since):
        """The parent's answer to this context's REJOIN or TIMEOUT, found and
        authenticated on the host, bounded by the firmware's own window.

        Every RX since the request went out is offered to THIS context's
        ledger, which decides whether it is ours (key, PAN, short, RAW, TC),
        advances the replay floor and, on success, commits durably -- all
        before the firmware is told anything. Frames of the other network are
        skipped, and so are MAC retransmissions of a frame already accepted;
        anything else authenticated but wrong ends the run. Scanning the
        records rather than only new reads matters: an answer that arrived
        while secured() was still waiting for its TXDONE is already there.
        """
        ledger = self.ledgers[ctx]
        end = self.clock() + RESPONSE_WAIT_S
        seen = since
        while True:
            while seen < len(self.records):
                row = self.records[seen]
                seen += 1
                if row.get('kind') != 'RX':
                    continue
                f = row['fields']
                raw = bytes.fromhex(f['mac'])
                result, detail = ledger.authenticate_response(
                    kind, raw, int(f['revision']), f)
                if result == 'REPLAY_REJECTED' and (ctx, raw) in self.authenticated:
                    # A byte-identical copy of a frame this ledger already
                    # accepted: the sender's MAC retrying after a lost ACK
                    # (Gate E attempt 2 saw three in 8 ms from a neighbour
                    # router to the coordinator). The floor already rejected
                    # it, which is right; ending the run over it is not.
                    # A replay that is not such a copy still ends the run.
                    result = 'MAC_RETRANSMISSION'
                elif result not in ('NOT_THIS_CONTEXT', 'REPLAY_REJECTED'):
                    self.authenticated.add((ctx, raw))
                self.answers.append({'ctx': ctx, 'kind': kind,
                                     'result': result, 'detail': detail})
                if result in ('REJOINED', 'PARENT_LINK_ACTIVE'):
                    return int(f['revision'])
                if result in ('NOT_THIS_CONTEXT', 'AUTHENTICATED_NOT_A_RESPONSE',
                              'MAC_RETRANSMISSION'):
                    continue
                raise Fault('parent_answer:%s ctx=%d %r' % (result, ctx, detail))
            if self.clock() >= end:
                raise Fault('no_authenticated_%s_response:ctx=%d' % (kind, ctx))
            self.w.read()

    def discover(self, ctx, generation):
        """Bounded beacon scan for this context's coordinator."""
        ledger = self.ledgers[ctx]
        for attempt in range(1, MAX_SCANS + 1):
            dsn = ledger.read()['sequences']['dsn']
            # The revision floor is "newer than anything seen before this
            # scan". The Wire has seen nothing yet on the first scan of the
            # first context, so its counter is None -- which is not zero, it
            # is the absence of a floor, and -1 is how that compares. V25
            # never met this because its probe had already been observing.
            floor = -1 if self.w.rx_revision is None else self.w.rx_revision
            scan = self.command('ACTIVE_DISCOVERY_BEACON_REQUEST', ctx,
                                'session=1 generation=%s dsn=%d' % (generation, dsn),
                                beacon_request(dsn), 'ACTIVE_DISCOVERY_BEACON_REQUEST')
            start = int(scan['time_us'])
            self.observe(SCAN_SETTLE_S)
            status = self.command('STATUS', ctx, 'session=1')
            if status.get(gate_b.RECOVERY_FIELD) == 'BOUND' and attempt < MAX_SCANS:
                continue
            if status.get(gate_b.RECOVERY_FIELD) != 'DISCOVERED':
                raise Fault('no_target_beacon_after_bounded_scans:ctx=%d' % ctx)
            row = next((r for r in reversed(self.records)
                        if r['kind'] == 'RX'
                        and r['fields'].get('revision') == status['beacon_revision']),
                       None)
            if not row:
                raise Fault('discovery_RX_missing:ctx=%d' % ctx)
            # The PAN and trust centre of THIS context. The inherited check
            # defaults to ctx1's, which would refuse a good ctx0 beacon and
            # report a coordinator that did not answer when it did.
            identity = self.ledgers[ctx].identity
            return validate(bytes.fromhex(row['fields']['mac']), row['fields'],
                            self.w.boot, self.store(ctx)['guard'],
                            floor, start, int(status['time_us']),
                            pan=identity['pan'], tc=identity['tc_ieee'])
        raise Fault('discovery_scan_bound:ctx=%d' % ctx)

    def execute(self):
        outcome = {'executed': False, 'error': None, 'passed': False}
        try:
            # The id floor first: the dongle has not been power-cycled since
            # Gate A, so its counter is well past 1 and everything after would
            # fail for a reason that has nothing to do with the radio.
            outcome['id_floor'] = self.probe_id_floor()
            outcome['info_before'] = self.check_identity()
            self.require_a_fresh_boot()
            outcome['executed'] = True
            # ctx0 first: its secured rejoin on this firmware is the one that
            # has never been proved, so it is attempted while the session is
            # freshest rather than after ctx1 has used part of the budget.
            outcome['commissioned'] = {
                str(ctx): self.commission(ctx) for ctx in (0, 1)}
            outcome['readiness_start_us'] = self.clock()
            readiness = self.keep_alive(READINESS_SECONDS)
            outcome['stats'] = self.command('STATS')
            verdict = gate_b.evaluate(self.records, outcome['stats'],
                                      ack_records=readiness)
            outcome['verdict'] = verdict
            outcome['passed'] = verdict['passed']
        except Exception as e:
            # Every class, not only the wire's. Attempt 9 died on
            # recovery_model.Fault from the ledger, escaped this clause, and the
            # launcher wrote no outcome at all -- the one run with the most to
            # say left no evidence. A crash is a failed gate, recorded.
            outcome['error'] = '%s:%s' % (type(e).__name__, e)
        finally:
            try:
                outcome['end'] = self.command('END', fields='session=1')
            except Exception as e:
                outcome['end_error'] = '%s:%s' % (type(e).__name__, e)
            outcome['records'] = self.records
            outcome['sent_order'] = self.sent_order
            outcome['answers'] = self.answers
        return outcome
