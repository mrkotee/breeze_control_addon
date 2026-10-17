"""One FAN command per context, for Gate C. Offline-tested; no COM, no keys.

This is application_control.FirstFanControl with every identity taken from
the context it serves. The inherited adapter had ctx1 inline in seven places:
PAN 0x0b7a, TC, RAW, EPOCH, the remote's short 0xf59f and IEEE (PEER), and
the counter context 'raw-first-control'. Used for ctx0, it would have refused
every good ctx0 frame as foreign, and nothing would have looked wrong except
that the command never ran.

What is NOT re-implemented is the frozen control core in airnanny2mqtt:
Type06/Type07, Baseline, build, Confirmation, secured_frame. That core is
what issue #3 proved on hardware. The rules it carries stay:

- The command is a fresh TYPE07 from this network's own remote with bytes 6
  and 11 changed. Nothing unknown is synthesized, so without a remote press
  in the session there is no baseline and no command.
- One adjacent FAN step: +1 below the top level, otherwise -1 (operator's
  decision, 2026-10-13, the same rule the inherited adapter had).
- Confirmation needs a fresh authenticated TYPE06 that matches the command's
  sequence and FAN, after the radio start, within 20 s. No match means
  FAILED_OR_UNKNOWN, and there is never a retry.

Needs Python >= 3.10 because the core does (`Type07 | None`). The operator's
3.7 cannot import it. Which interpreter the Gate C launcher runs under is an
open decision; see SESSION_HANDOFF_ISSUE5.md.
"""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[3] / 'host/airnanny2mqtt/src'))

import management                                   # noqa: F401  this tree's
from management import decode_nwk, le
from recovery_model import Fault
from airnanny.application import Type06, Type07
from airnanny.aps import APS
from airnanny.baseline import Baseline
from airnanny.commands import CommandRequest, build
from airnanny.config import DeviceConfig
from airnanny.confirmation import Confirmation
from airnanny.context import ZigbeeContext
from airnanny.counters import CounterAllocator
from airnanny.outgoing import secured_frame
from airnanny.zcl import ZCL

# Each network's original AirControl. The IEEE is the identity and is pinned:
# the captures carry it (capture_layers.json: c9b7 -> 00124b00369c711f in FA9B)
# and the stores' replay floors name it. The short is only the LAST KNOWN one.
# A re-pairing assigns a new one (0B7A was re-paired on 2026-10-13), so the
# adapter takes the current short from the remote's own authenticated TYPE07.
REMOTES = {
    0: {'short': 0xC9B7, 'ieee': '00124b00369c711f'},
    1: {'short': 0xF59F, 'ieee': '00124b0036a18944'},
}
CHANNEL = 21
CONFIRM_WINDOW_MS = 20000
TYPE07_LENGTH = 68                  # rejoin_transport.c, c->mac_length != 68
TOP_FAN = 7


class _ApplicationCounters:
    def __init__(self, ledger):
        self.ledger = ledger

    def reserve(self, context, epoch, key_sequence, count):
        return self.ledger.reserve_application(context, epoch, key_sequence, count)


def target_fan(current):
    """+1 unless at the top, then -1. Always exactly one step."""
    return current + 1 if current < TOP_FAN else current - 1


class ContextFanControl:
    """One context's one command. Bound at construction to the store's
    generation, guard and key, and refuses to act if any of them moved."""

    def __init__(self, ledger, boot, now):
        r = ledger.read()
        q = r.get('recovery') or {}
        if q.get('state') != 'PARENT_LINK_ACTIVE' or not boot:
            raise Fault('live_parent_link_required:ctx=%d state=%s' % (ledger.ctx, q.get('state')))
        self.ledger, self.ctx, self.boot = ledger, ledger.ctx, boot
        self.ident = ledger.identity
        self.remote = dict(REMOTES[ledger.ctx])     # short updated when learned
        self.binding = (r['generation'], q.get('gate'), ledger.key.value)
        self.ready_at = now
        self.radio_floor = None         # set by the runner from a live STATUS
        self.command_radio_floor = None
        self.match_radio_us = None
        self.baseline = Baseline()
        self.status = self.status_at = None
        self.revision = 0
        self.confirmation = None
        self.request = None
        self.command_at = None
        self.used = self.sent = self.concluded = False
        self.result = None

    # -- binding ---------------------------------------------------------
    def live(self):
        r = self.ledger.read()
        q = r.get('recovery') or {}
        if (q.get('state') != 'PARENT_LINK_ACTIVE'
                or (r['generation'], q.get('gate'), self.ledger.key.value) != self.binding):
            raise Fault('stale_or_wrong_live_context:ctx=%d' % self.ctx)
        return r

    # -- what arrives ----------------------------------------------------
    def classify(self, raw):
        """('status'|'remote', frame, meta, mac) for this context's TYPE06
        from its A7 or TYPE07 from its own remote; None for anything else.
        Pure: no floor is spent here."""
        try:
            mac, plain, meta = decode_nwk(raw, self.ledger.key, self.ident['keyseq'],
                                          pan=self.ident['pan'])
            aps = APS.parse(plain)
            zcl = ZCL.parse(aps.payload)
        except Exception:
            return None
        if (aps.cluster, aps.profile, aps.source_endpoint, zcl.control, zcl.command) \
                != (6, 0x104, 8, 0x11, 1):
            return None
        if mac.fcf not in (0x8861, 0x8841) or mac.dst_pan != le(self.ident['pan']):
            return None
        dst = int.from_bytes(mac.dst, 'little')
        src = int.from_bytes(mac.src, 'little')
        own, rshort = self.ident['short'], self.remote['short']
        status = (meta['source_ieee'] == self.ident['tc_ieee'] and meta['nwk_src'] == 0
                  and src == 0 and dst == meta['nwk_dst']
                  and (meta['nwk_fcf'] == 0x0248
                       or (meta['nwk_fcf'] == 0x0208 and dst == rshort))
                  and dst in (own, 0xffff, rshort)
                  and aps.destination_endpoint == 8 and aps.group is None)
        # The remote by IEEE, whatever short it has now.
        remote = (meta['source_ieee'] == self.remote['ieee'] and src == meta['nwk_src']
                  and src not in (0, 0xffff, 0xfffd, own)
                  and dst == 0 and meta['nwk_dst'] == 0xfffd and meta['nwk_fcf'] == 0x2208
                  and aps.control == 12 and aps.group == 10)
        try:
            if status:
                return 'status', Type06(zcl.payload), meta, mac
            if remote:
                return 'remote', Type07(zcl.payload), meta, mac
        except ValueError:
            return None
        return None

    def receive(self, raw, revision, now, radio_us):
        c = self.classify(raw)
        if c is None:
            return None
        kind, frame, meta, _ = c
        self.live()
        if (revision <= self.revision or now < self.ready_at
                or self.radio_floor is None or radio_us <= self.radio_floor):
            return 'APPLICATION_STALE'
        if not self.ledger.consume(meta['source_ieee'], meta['counter']):
            return 'APPLICATION_STALE'
        self.revision = revision
        if kind == 'status':
            self.status, self.status_at = frame, now
            if self.confirmation and now >= self.command_at \
                    and radio_us > (self.command_radio_floor or self.radio_floor):
                self.confirmation.observe(frame, revision, int(now * 1000),
                                          self.baseline.generation, int(now * 1000))
                if self.confirmation.match_revision == revision:
                    self.match_radio_us = radio_us
            self.baseline.observe(frame, revision)
        else:
            src = meta['nwk_src']
            if src != self.remote['short']:
                self.remote['short'] = src           # learned from the remote itself
            self.baseline.remote(frame, src, self.ident['short'])
        self.tick(now)
        return 'APPLICATION_AUTHENTICATED'

    # -- the command -----------------------------------------------------
    def ready(self):
        return (self.status is not None and self.baseline.valid and self.baseline.live
                and not self.baseline.remote_pending)

    def prepare(self, now):
        """Build the one command. Spends the counter block first; after this
        returns, every failure is FAILED_OR_UNKNOWN and needs review."""
        r = self.live()
        if self.used or 'TYPE07' in (r['recovery'].get('intents') or {}):
            raise Fault('one_command_NO_RETRY')
        if not self.ready() or self.status_at < self.ready_at:
            raise Fault('fresh_authenticated_status_and_lossless_baseline_required')
        s, b = self.status, self.baseline.frame
        if (not s.power or s.night or s.mode_raw != 0 or s.humidifier_raw > 2
                or s.humidifier_raw != b.humidifier_raw or s.target_tenths != b.target_tenths):
            raise Fault('conservative_FAN_state_required')
        self.request = CommandRequest('fan', target_fan(s.fan))
        tx = build(self.request, self.baseline, s, int((now - self.status_at) * 1000),
                   self.remote['short'])
        if any(tx.raw[i] != b.raw[i] for i in range(21) if i not in (6, 11, 20)):
            raise Fault('FAN_only_preserve_all_opaque_bytes')
        self.used = True
        self.command_at = now
        self.confirmation = Confirmation(self.request, tx, b, self.baseline.generation,
                                         self.revision, int(now * 1000), CONFIRM_WINDOW_MS)
        seq = r.get('sequences') or {}
        identity = 'dual-ctx%d' % self.ctx
        zctx = ZigbeeContext(identity, self.ident['pan'], int(self.ident['tc_ieee'], 16), CHANNEL,
                             int(self.ident['raw_ieee'], 16), self.ident['short'],
                             int(self.ident['tc_ieee'], 16),
                             key_epochs={self.ident['keyseq']: self.ident['epoch']},
                             nwk_sequence=seq.get('nwk', 0), aps_counter=seq.get('aps', 0),
                             zcl_tsn=seq.get('zcl', 0), mac_dsn=seq.get('dsn', 0))
        zctx.keys.put(self.ident['keyseq'], self.ledger.key.value)
        # The core's allocator calls store.reserve(context, epoch, keyseq, n);
        # this ledger's answer is reserve_application. The same object goes to
        # secured_frame, which refuses a second store within one epoch.
        store = _ApplicationCounters(self.ledger)
        zctx.outgoing[(self.ident['epoch'], self.ident['keyseq'])] = CounterAllocator(
            store, identity, self.ident['epoch'], self.ident['keyseq'], 32)
        raw = secured_frame(DeviceConfig('ctx%d' % self.ctx, zctx, self.remote['short'],
                                         'env:DPAPI_CTX%d' % self.ctx), tx, store)
        if len(raw) != TYPE07_LENGTH:
            raise Fault('typed_application_length:%d' % len(raw))
        digest = hashlib.sha256(raw).hexdigest()
        intent = self.ledger.application('BURNED_BEFORE_CRYPTO', phase='BUILT_NEVER_RETRY',
                                         sha256=digest, requested=self.request.value,
                                         from_fan=s.fan)
        return raw, intent

    def handoff(self, now):
        self.live()
        if (self.confirmation is None or self.result is not None
                or self.baseline.generation != self.confirmation.generation
                or not 0 <= now - self.status_at <= 15):
            raise Fault('baseline_changed_before_handoff')
        self.ledger.application('BUILT_NEVER_RETRY', phase='HANDED_UNKNOWN_NO_RETRY', handed_at=now)

    def complete(self, local_ok, now, rf_start_us):
        self.live()
        if rf_start_us <= 0 and local_ok:
            raise Fault('missing_radio_start_receipt')
        self.command_radio_floor = max(self.command_radio_floor or self.radio_floor, rf_start_us)
        if self.match_radio_us is not None and self.match_radio_us <= self.command_radio_floor:
            self.confirmation.match = None
        self.sent = True
        self.ledger.application('HANDED_UNKNOWN_NO_RETRY', phase='SENT',
                                result='local_tx_ok' if local_ok else 'failed_or_unknown',
                                rf_start_us=rf_start_us)
        self.confirmation.complete(0 if local_ok else -1, self.baseline.generation, int(now * 1000))
        self.tick(now)

    def tick(self, now):
        if self.confirmation is None or self.result is not None:
            return
        self.confirmation.check(self.baseline.generation, int(now * 1000))
        if self.confirmation.failure:
            self.result = 'FAILED_OR_UNKNOWN'
        elif self.confirmation.confirmed:
            self.result = ('CONFIRMED' if self.baseline.commit(self.confirmation.generation,
                                                              self.confirmation.tx)
                           else 'FAILED_OR_UNKNOWN')
        # Written only once the send is on record: a verdict reached while the
        # TX receipt is still outstanding waits for complete() to land first.
        if self.result and self.sent and not self.concluded:
            self.concluded = True
            self.ledger.application('SENT', phase='CONCLUDED', application_result=self.result,
                                    match_revision=self.confirmation.match_revision or None)
