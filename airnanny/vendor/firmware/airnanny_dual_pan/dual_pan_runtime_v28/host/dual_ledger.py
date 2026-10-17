"""One store writer per context, for Gate B and nothing else.

This is the component option 1 decided on (GATE_B_PROCEDURE.md section 3): the
inherited Ledger keeps refusing real stores unconditionally, because twelve
offline suites call it and that refusal is what stops any of them moving a
live store through a mistake. The right to write therefore lives here, in the
one module only the Gate B launcher imports.

Two instances, one per context, each owning its own root. That is not a
convenience -- it is the issue #5 requirement made structural:

    frame ctx == key ctx == RAW IEEE ctx == FC allocator ctx

A single writer shared across both contexts would hold one frame-counter
allocator for two networks, which is the exact property the gates exist to
prove is NOT the case. Two instances cannot share a counter because neither
can see the other's root.

What this module does NOT do is build frames. That is secured_frame, which has
no authority to write anything, so the bytes and the durability are decided in
different places on purpose: this one leases the counter and records the
intent, that one turns numbers into bytes.
"""
import copy
import hashlib
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dual_store
import secured_frame
from key_announce import durable, store          # locked(), atomic durable()
import management
from management import decode_nwk, ieee, le
from recovery_model import Fault

# Several milestones ship a `management` module and the first import in a
# process wins. Only this tree's decodes per context (pan=...); any other would
# check every answer against ctx1's PAN. Refused at import, not discovered on air.
if Path(management.__file__).resolve() != HERE / 'management.py':
    raise ImportError("dual_ledger needs this tree's management.py, got %s"
                      % management.__file__)

# Where a non-hardware instance is allowed to write. Anything else is refused
# whether or not it happens to exist.
SIMULATION_ROOT = (HERE.parent / '.local/tests').resolve()

# Secrets sit beside the run that owns the store: a store at
# <run>/runtime/current/key/security/epoch.json has its keys under
# <run>/secrets, which is how management.Model resolves them. Derived rather
# than written out, so the two cannot drift to different runs.
SECRETS_DEPTH = 3


def secrets_root(ctx):
    """Where this context's DPAPI-protected keys live.

    Windows only in practice: the secrets have no plaintext fallback, so they
    can be unwrapped on the operator's machine and nowhere else. That is why
    the Gate B launcher is the only thing that resolves them.
    """
    store_dir = Path(dual_store.STORE_PATHS[ctx]).resolve().parent
    return store_dir.parents[SECRETS_DEPTH] / 'secrets'

# The intent phases a frame passes through. The counter is spent at the first
# one, before any crypto, so a crash between them loses the counter rather than
# risking its reuse -- a spent counter is cheap, a reused one is a replay.
BURNED, BUILT, SENT = 'BURNED_BEFORE_CRYPTO', 'BUILT_NEVER_RETRY', 'SENT'

FC_BLOCK = 32          # counters are leased in blocks of 32, as V17..V25 did


def within(path, root):
    """Is `path` inside `root`?

    Written out rather than using Path.is_relative_to, which arrived in Python
    3.9: the operator's machine runs 3.7, and this is the only place in the
    tree where that mattered. It showed up as an AttributeError on the first
    live Gate B attempt, after the keys had already been unwrapped -- which is
    to say the safety check that decides whether a write is allowed was the
    thing that could not run. A check that crashes is not a check.
    """
    path, root = Path(path).resolve(), Path(root).resolve()
    return path == root or root in path.parents


class ContextLedger:
    """The durable authority for ONE context's store.

    `hardware=False` is the only thing offline tests may construct, and it can
    write nowhere but a disposable root under .local/tests. `hardware=True`
    may write nowhere but the pinned store of the context it claims -- not a
    path the caller chose, the one dual_store pins for that ctx. So neither
    mode can reach the other's territory, and a typo in a path cannot turn a
    test into a live write.
    """

    def __init__(self, ctx, key, *, hardware=False, root=None, save=durable):
        if ctx not in (0, 1):
            raise Fault('no_such_context:%r' % ctx)
        self.ctx = ctx
        self.key = key
        self.save = save
        self.identity = dual_store.PINNED[ctx]

        if hardware:
            # STORE_PATHS points at epoch.json itself, not at its directory.
            # Taking it as the root would have built .../epoch.json/epoch.json,
            # and no offline test could have caught it: the hardware branch is
            # unreachable from anywhere but the operator's machine, where the
            # keys are DPAPI-bound. So the relationship is asserted here and
            # pinned by test.
            pinned_file = Path(dual_store.STORE_PATHS[ctx]).resolve()
            if pinned_file.name != 'epoch.json':
                raise Fault('pinned_store_is_not_an_epoch_file:%s' % pinned_file)
            pinned = pinned_file.parent
            if root is not None and Path(root).resolve() != pinned:
                raise Fault('hardware_root_is_pinned_not_chosen:%s' % root)
            self.root = pinned
            if within(self.root, SIMULATION_ROOT):
                raise Fault('pinned_store_inside_the_simulation_root')
        else:
            if root is None:
                raise Fault('simulation_requires_a_disposable_root')
            self.root = Path(root).resolve()
            if not within(self.root, SIMULATION_ROOT):
                raise Fault('simulation_NO_REAL_AUTHORITY:%s' % self.root)
        self.hardware = bool(hardware)
        self.path = self.root / 'epoch.json'

    # -- reading ----------------------------------------------------------
    def read(self):
        if not self.path.exists():
            raise Fault('no_store_at:%s' % self.path)
        import json
        return json.loads(self.path.read_text(encoding='utf-8'))

    def _write(self, record):
        """Atomic, locked, and read back. A record that cannot be read back is
        not a record, and a store written without the lock is a store two
        processes may be writing."""
        with store.locked(self.root):
            self.save(self.path, record)
        if self.read() != record:
            raise Fault('durable_readback_failed:%s' % self.path)

    # -- the recovery cycle -----------------------------------------------
    def begin_cycle(self, guard):
        """Open this run's recovery cycle: archive the previous one, start a
        fresh record with no intents, and make `guard` the one BIND will carry.

        The one-shot rule is per cycle, not per store. A live store arrives
        holding the intents of the cycle that commissioned it -- REJOIN,
        ANNOUNCE, TIMEOUT, all LOCAL_MAC_ACK -- so without this step reserve()
        refuses REJOIN on the first live run, which is what attempt 9 met. V25's
        Ledger.begin_discovery did the same archive-and-open; this module was
        written without it because every offline store started empty.

        Nothing here can reuse a counter: next_fc is untouched and only ever
        rises, so a new cycle spends new blocks. What is refused is opening the
        same guard twice -- a guard names one run, and a second cycle under it
        would let one run send REJOIN twice.

        The guard must be in the store before BIND: the firmware keeps the
        BIND's guard and refuses a secured frame carrying any other
        (rejoin_transport.c, intent_binding), and both are read from here.
        """
        if (not isinstance(guard, str) or len(guard) != 32
                or any(c not in '0123456789abcdef' for c in guard)):
            raise Fault('guard_malformed:%r' % (guard,))
        r = self.read()
        previous = r.get('recovery') or {}
        if previous.get('gate') == guard:
            raise Fault('NO_RERUN:cycle_already_opened_by:%s' % guard)
        r.setdefault('recovery_history', []).append(copy.deepcopy(previous))
        r['recovery'] = {
            'state': 'DISCOVERING', 'gate': guard,
            'predecessor': previous.get('gate'), 'intents': {},
            'initial_generation': r['generation'], 'ctx': self.ctx,
        }
        self._write(r)
        return r['recovery']

    # -- the parent's answers ----------------------------------------------
    def authenticate_response(self, kind, raw, revision, rx_fields):
        """Decide, on the host, whether `raw` is this context's parent
        answering this context's REJOIN or TIMEOUT request -- and if it is a
        success, commit that durably BEFORE the firmware is told.

        The firmware cannot do this: crypto is host_only, so in its response
        window it only latches a frame of the right shape (rejoin_transport.c
        line 126) and waits in WAIT_REJOIN / WAIT_TIMEOUT for the host's
        CURRENT_SHORT_COMMIT / PARENT_LINK_ACTIVE. V25 did it in
        recovery_model.receive, with ctx1's PAN, RAW and TC inline; this is
        that check with every identity taken from the pinned record of THIS
        context, so a ctx1 answer can never satisfy ctx0 or the reverse.

        Returns (result, detail). Only 'REJOINED' and 'PARENT_LINK_ACTIVE'
        are successes; 'NOT_THIS_CONTEXT' means keep listening; anything else
        is terminal for the run. Every authenticated frame advances the
        replay floor of its source, in the same atomic write as any state.
        """
        if kind not in ('REJOIN', 'TIMEOUT'):
            raise Fault('no_response_expected_for:%s' % kind)
        ident = self.identity
        r = self.read()
        q = r.get('recovery') or {}
        want_state = 'DISCOVERING' if kind == 'REJOIN' else 'REJOINED'
        intent = (q.get('intents') or {}).get(kind) or {}
        if q.get('state') != want_state or intent.get('phase') != SENT \
                or intent.get('result') != 'local_tx_ok':
            raise Fault('response_without_its_request:%s state=%s phase=%s'
                        % (kind, q.get('state'), intent.get('phase')))
        try:
            m, p, meta = decode_nwk(raw, self.key, ident['keyseq'], pan=ident['pan'])
        except Exception as exc:
            # A frame for the other network, or one that does not
            # authenticate under this context's key, is not an answer to us.
            return 'NOT_THIS_CONTEXT', '%s:%s' % (type(exc).__name__, exc)
        source, fc = meta['source_ieee'], meta['counter']
        floors = r.setdefault('nwk_source_floors', {})
        if fc < floors.get(source, 0) or fc >= 0xffffffff:
            return 'REPLAY_REJECTED', 'source=%s fc=%d floor=%d' % (
                source, fc, floors.get(source, 0))
        floors[source] = fc + 1
        short = ident['short']
        addressed = (m.fcf == 0x8861 and m.src == le(0) and m.dst == le(short)
                     and meta['nwk_src'] == 0 and meta['nwk_dst'] == short
                     and source == ident['tc_ieee'])
        command = (addressed and meta['nwk_fcf'] == 0x1a09
                   and m.payload[8:16] == ieee(ident['raw_ieee'])
                   and m.payload[16:24] == ieee(ident['tc_ieee']))
        detail = {'revision': revision, 'fc': fc, 'source': source}
        result = None
        if not command:
            result = 'AUTHENTICATED_NOT_A_RESPONSE'
        elif not (rx_fields.get('ack_started') == '1'
                  and rx_fields.get('ack_completed') == '1'
                  and rx_fields.get('deadline_miss') == '0'):
            result = 'MAC_ACK_NOT_CLEAN'
        elif kind == 'REJOIN':
            if len(p) != 4 or p[0] != 7:
                result = 'AUTHENTICATED_NOT_A_RESPONSE'
            elif p[3] != 0:
                result = 'REJECTED'
                q.update(state='REJECTED', rejoin_status=p[3])
            elif int.from_bytes(p[1:3], 'little') != short:
                # dual_store and the image both pin this short. A parent that
                # hands out another one has moved the identity, and that is a
                # stop and a decision, not something to install silently.
                result = 'SHORT_CHANGED'
                q.update(state='REJECTED', offered_short=int.from_bytes(p[1:3], 'little'))
            else:
                result = 'REJOINED'
                r['generation'] += 1
                r['context']['generation'] = r['context'].get('generation', 0) + 1
                q.update(state='REJOINED', current_short=short,
                         rejoin_response=dict(detail, status=0, clean_ack=True))
        else:
            if len(p) != 3 or p[0] != 12:
                result = 'AUTHENTICATED_NOT_A_RESPONSE'
            elif p[1] != 0 or p[2] & 0xf8 or not p[2] & 3:
                result = 'TIMEOUT_REJECTED'
                q.update(state='REJECTED', timeout_status=p[1], parent_information=p[2])
            elif not p[2] & 1:
                # The parent wants keepalives this host does not send. Claiming
                # that data polls refresh it would be false; V25 stopped here too.
                result = 'KEEPALIVE_METHOD_UNIMPLEMENTED'
                q.update(state='REJECTED', parent_information=p[2])
            else:
                result = 'PARENT_LINK_ACTIVE'
                q.update(state='PARENT_LINK_ACTIVE',
                         lifetime={'enum': 8, 'configuration': 0, 'seconds': 15360,
                                   'parent_information': p[2],
                                   'keepalive_method': 'MAC_DATA_POLL'},
                         proofs=[q.get('rejoin_response'),
                                 dict(detail, status=0, clean_ack=True)])
        self._write(r)
        return result, detail

    # -- an established link (Gate D) ------------------------------------
    def observe_addressed(self, raw, revision):
        """A frame the parent addressed to this context's device while the
        link is up. Returns 'LEAVE', 'AUTHENTICATED', 'NOT_THIS_CONTEXT' or
        'REPLAY_REJECTED'.

        A Leave is the one thing a soak must not shrug off. The plan (§2)
        makes it an explicit degraded terminal that keeps the floors, never a
        reason to rejoin: both stores already carry an observed Leave from
        before issue #5 with no_automatic_rejoin. So it is recorded in the
        store, the floor is spent, and nothing else moves.
        """
        ident = self.identity
        try:
            m, p, meta = decode_nwk(raw, self.key, ident['keyseq'], pan=ident['pan'])
        except Exception:
            return 'NOT_THIS_CONTEXT'
        r = self.read()
        floors = r.setdefault('nwk_source_floors', {})
        source, fc = meta['source_ieee'], meta['counter']
        if fc < floors.get(source, 0) or fc >= 0xffffffff:
            return 'REPLAY_REJECTED'
        floors[source] = fc + 1
        short = ident['short']
        leave = (m.dst == le(short) and meta['nwk_dst'] == short
                 and source == ident['tc_ieee'] and meta['nwk_fcf'] & 3 == 1
                 and len(p) == 2 and p[0] == 4)
        if leave:
            q = r.setdefault('recovery', {})
            q.update(state='DEGRADED_LEAVE',
                     leave={'revision': revision, 'fc': fc, 'options': p[1]})
        self._write(r)
        return 'LEAVE' if leave else 'AUTHENTICATED'

    # -- the application command (Gate C) --------------------------------
    def consume(self, source, fc):
        """Advance one source's replay floor, durably. False for a replay.
        The application observer authenticates frames that are not answers to
        us (status, the remote's own TYPE07), and those still spend a floor."""
        r = self.read()
        floors = r.setdefault('nwk_source_floors', {})
        if fc < floors.get(source, 0) or fc >= 0xffffffff:
            return False
        floors[source] = fc + 1
        self._write(r)
        return True

    def reserve_application(self, context, epoch, key_sequence, count):
        """The counter block for this cycle's one TYPE07, in the shape
        airnanny.counters.CounterAllocator asks for it. Spent before the frame
        exists, as every other block here.

        One per cycle and only on a live parent link: the firmware enforces
        the same (application_once, R_ACTIVE), and the store says so first so
        that a host which crashed after reserving can never send it again.
        """
        want = ('dual-ctx%d' % self.ctx, self.identity['epoch'], self.identity['keyseq'], 32)
        if (context, epoch, key_sequence, count) != want:
            raise Fault('application_counter_context:%r' % ((context, epoch, key_sequence, count),))
        r = self.read()
        q = r.get('recovery') or {}
        intents = q.setdefault('intents', {})
        if q.get('state') != 'PARENT_LINK_ACTIVE':
            raise Fault('application_needs_PARENT_LINK_ACTIVE:%s' % q.get('state'))
        if 'TYPE07' in intents:
            raise Fault('one_command_NO_RETRY')
        fc = r['next_fc']
        if fc + FC_BLOCK - 1 > 0xfffffffe:
            raise Fault('FC_exhaustion')
        r['next_fc'] = fc + FC_BLOCK
        seq = r.setdefault('sequences', {})
        for name in ('nwk', 'aps', 'dsn', 'zcl'):
            seq[name] = (seq.get(name, 0) + 1) & 255
        intents['TYPE07'] = {'fc': fc, 'block_end': fc + FC_BLOCK - 1,
                             'ctx': self.ctx, 'phase': BURNED,
                             'generation': r['generation'],
                             'token': uuid.uuid4().hex}
        self._write(r)
        return range(fc, fc + FC_BLOCK)

    def application(self, expect_phase, **fields):
        """Move the TYPE07 intent on, from exactly `expect_phase`. Each phase is
        entered once; there is no path back, which is what NO_RETRY means in
        the store rather than only in the caller."""
        r = self.read()
        i = ((r.get('recovery') or {}).get('intents') or {}).get('TYPE07')
        if not i or i.get('phase') != expect_phase:
            raise Fault('application_phase:%s expected %s'
                        % (i and i.get('phase'), expect_phase))
        i.update(fields)
        self._write(r)
        return dict(i)

    # -- the frame counter ------------------------------------------------
    def reserve(self, kind):
        """Lease a block of frame counters and record the intent, BEFORE the
        frame exists. Returns what secured_frame needs to build it.

        The order matters and is deliberate: spend first, build second. A crash
        between them loses a block of counters, which costs nothing anyone can
        observe; the opposite order risks a counter being used twice, which is
        a replay and cannot be undone.
        """
        if kind not in secured_frame.KINDS:
            raise Fault('NO_GENERIC_OR_TYPE07:%r' % kind)
        r = self.read()
        q = r.setdefault('recovery', {})
        intents = q.setdefault('intents', {})
        if kind in intents:
            raise Fault('one_shot_state:%s already attempted' % kind)
        # V25's order, kept: nothing announces or negotiates a timeout on a
        # network whose parent has not authenticated the rejoin.
        want = {'REJOIN': 'DISCOVERING', 'ANNOUNCE': 'REJOINED',
                'TIMEOUT': 'REJOINED'}[kind]
        if q.get('state') != want:
            raise Fault('one_shot_state:%s needs %s, store is %s'
                        % (kind, want, q.get('state')))
        if kind == 'TIMEOUT' and (intents.get('ANNOUNCE') or {}).get('phase') != SENT:
            raise Fault('one_shot_state:TIMEOUT before ANNOUNCE was sent')
        fc = r['next_fc']
        if fc + FC_BLOCK - 1 > 0xfffffffe:
            raise Fault('FC_exhaustion')
        seq = dict(r['sequences'])

        r['next_fc'] = fc + FC_BLOCK
        r['sequences'] = secured_frame.advance(seq, kind)
        intents[kind] = {
            'fc': fc, 'block_end': fc + FC_BLOCK - 1, 'sequences': seq,
            'short': self.identity['short'], 'pan': self.identity['pan'],
            'ctx': self.ctx, 'phase': BURNED, 'token': uuid.uuid4().hex,
            'keyseq': self.identity['keyseq'], 'generation': r['generation'],
        }
        self._write(r)
        return dict(intents[kind])

    def build(self, kind):
        """Build this context's frame from the counters just leased.

        Every identity that goes in is THIS context's, taken from the pinned
        record rather than from an argument, so a caller cannot hand ctx0's
        ledger ctx1's PAN. That mistake would otherwise be invisible until a
        coordinator somewhere answered a frame it should never have seen.
        """
        intent = self.read()['recovery']['intents'][kind]
        if intent['phase'] != BURNED:
            raise Fault('intent_not_fresh:%s' % intent['phase'])
        raw, digest = secured_frame.build_secured(
            kind, pan=self.identity['pan'], short=self.identity['short'],
            fc=intent['fc'], sequences=intent['sequences'], key=self.key,
            raw_ieee=self.identity['raw_ieee'], tc_ieee=self.identity['tc_ieee'],
            keyseq=self.identity['keyseq'])
        r = self.read()
        j = r['recovery']['intents'][kind]
        if j['token'] != intent['token'] or j['phase'] != BURNED:
            raise Fault('intent_lineage')
        j.update(phase=BUILT, sha256=digest)
        self._write(r)
        return raw, intent['fc']

    def sent(self, kind, result, radio_end_us):
        """Record what the radio reported. A TX whose outcome is unknown burns
        the intent rather than leaving it retryable: retrying a frame whose
        fate is unknown is how a counter gets used twice."""
        r = self.read()
        j = r['recovery']['intents'][kind]
        if j['phase'] != BUILT:
            raise Fault('intent_not_built:%s' % j['phase'])
        j.update(phase=SENT, result=result, radio_end_us=radio_end_us)
        self._write(r)
        if result != 'local_tx_ok':
            raise Fault('unknown_or_failed_TX_burned:%s' % result)
        return j


def pair(keys, *, hardware=False, roots=None):
    """Both contexts' ledgers, built together so neither can be forgotten.

    Returned as a dict keyed by ctx, and the two are checked to be distinct
    roots: two ledgers sharing a root would share a frame-counter allocator,
    which is the one thing this whole structure exists to prevent.
    """
    out = {}
    for ctx in (0, 1):
        out[ctx] = ContextLedger(
            ctx, keys[ctx], hardware=hardware,
            root=None if hardware else (roots or {})[ctx])
    if out[0].root == out[1].root:
        raise Fault('the two contexts share a store root')
    if out[0].identity['pan'] == out[1].identity['pan']:
        raise Fault('the two contexts claim the same PAN')
    return out
