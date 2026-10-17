"""Injected single-session FAN adapter. No COM, key loader or hardware launcher.

Only disposable synthetic ledgers are supported by this offline milestone.
Application codecs/build/confirmation remain the frozen host control core.
"""
import sys
import hashlib
from pathlib import Path
from ledger import R, Ledger, Fault, RAW, TC, EPOCH, ATTEMPT, decode_nwk, le
from probe import Probe

sys.path.insert(0, str(R.parents[2] / 'host/airnanny2mqtt/src'))
from airnanny.application import Type06, Type07
from airnanny.baseline import Baseline
from airnanny.commands import CommandRequest, build
from airnanny.confirmation import Confirmation
from airnanny.context import ZigbeeContext
from airnanny.config import DeviceConfig
from airnanny.counters import CounterAllocator
from airnanny.outgoing import secured_frame
from airnanny.aps import APS
from airnanny.zcl import ZCL
from context_scope import PEER


class ApplicationLedger(Ledger):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.app = None
        self.boot = None
        self.radio_session = None

    def restart_radio(self):
        self.boot = self.radio_session = None
        if self.app:
            self.app.stopped = True
            self.app.baseline.invalidate()

    def receive_management(self, raw, revision, now, ack=None, poll_dsn=None):
        # Radio-time fallback bypasses the already-run application observer.
        return super().receive(raw, revision, now, ack, poll_dsn)

    def receive(self, raw, revision, now, ack=None, poll_dsn=None):
        # Narrow application observer is separate from membership/proof credit.
        # RX remains authenticated once, with the existing durable source floor.
        if self.app:
            result = self.app.receive(raw, revision, now)
            if result is not None:
                return result
        return super().receive(raw, revision, now, ack, poll_dsn)


class DurableApplicationCounters:
    def __init__(self, app):
        self.app = app

    def reserve(self, context, epoch, key_sequence, count):
        a = self.app
        a.live(a.now)
        if (context, epoch, key_sequence, count) != ('raw-first-control', EPOCH, 0, 32):
            raise Fault('counter_context')
        def reserve(r):
            if 'application_intent' in r:
                raise Fault('one_command_NO_RETRY')
            fc = r['next_fc']
            if fc + 31 > 0xfffffffe:
                raise Fault('FC_exhaustion')
            r['next_fc'] = fc + 32
            r['application_intent'] = dict(phase='BURNED_BEFORE_CRYPTO', fc=fc,
                block_end=fc+31, generation=r['generation'], epoch=EPOCH, keyseq=0,
                short=r['context']['short'], boot=a.boot, guard=a.ledger.guard,
                baseline_generation=a.baseline.generation, revision_floor=a.revision,
                kind='fan', requested=a.request.value)
            for name in ('nwk', 'aps', 'dsn', 'zcl'):
                r['sequences'][name] = (r['sequences'].get(name, 0) + 1) & 255
        r = a.ledger.change(reserve)
        return range(r['application_intent']['fc'], r['next_fc'])


class FirstFanControl:
    def __init__(self, ledger, boot, session, now):
        self.ledger, self.boot, self.session = ledger, boot, session
        r = ledger.usable()
        if not ledger.ready(True) or not boot or session != 1 or ledger.boot is not None:
            raise Fault('fresh_live_readiness_required')
        ledger.boot, ledger.radio_session = boot, session
        self.binding = (r['key_epoch_id'], r['keyseq'], r['generation'], r['context'].copy())
        self.key_binding = ledger.key.value
        self.ready_at = now
        self.radio_floor = int(r['recovery']['last_idle_intent']['receipt']['time_us'])
        self.command_radio_floor = None
        self.match_radio_us = None
        self.now = now
        self.baseline = Baseline()
        self.status = self.status_at = None
        self.revision = 0
        self.confirmation = None
        self.request = None
        self.used = self.stopped = False
        self.result = None

    def live(self, now):
        r = self.ledger.usable()
        if (self.stopped or self.ledger.key.value != self.key_binding or
            self.ledger.boot != self.boot or self.ledger.radio_session != self.session or
            self.binding != (r['key_epoch_id'], r['keyseq'], r['generation'], r['context']) or
            r['recovery'].get('gate') != self.ledger.guard or
            r['recovery']['state'] != 'PARENT_LINK_ACTIVE' or
            not r['recovery'].get('readiness_candidate') or
            now < self.ready_at or now-r['recovery'].get('last_idle_intent', {}).get('at', -100) > 2):
            raise Fault('stale_or_wrong_live_context')
        return r

    def receive(self, raw, revision, now, radio_us=None):
        try:
            mac, plain, meta = decode_nwk(raw, self.ledger.key)
            aps = APS.parse(plain)
            zcl = ZCL.parse(aps.payload)
        except ValueError:
            return None
        if (aps.cluster, aps.profile, aps.source_endpoint, zcl.control, zcl.command) != (6, 0x104, 8, 0x11, 1):
            return None
        r = self.live(now)
        dst = int.from_bytes(mac.dst, 'little')
        src = int.from_bytes(mac.src, 'little')
        source_pan = mac.dst_pan if mac.fcf & 0x40 else mac.src_pan
        if mac.fcf not in (0x8861,0x8841) or source_pan != le(0x0b7a) or mac.dst_pan != le(0x0b7a):
            return None
        # Reviewed TC status may address RAW, broadcast, or original controller.
        status_scope = (meta['source_ieee'] == TC and meta['nwk_src'] == 0 and src == 0 and
            (meta['nwk_fcf'] == 0x0248 or (meta['nwk_fcf'] == 0x0208 and dst == 0xf59f)) and dst == meta['nwk_dst'] and
            dst in (r['context']['short'], 0xffff, 0xf59f) and
            aps.destination_endpoint == 8 and aps.group is None)
        remote_scope = (meta['source_ieee'] == PEER and src == meta['nwk_src'] == 0xf59f and
            dst == 0 and meta['nwk_dst'] == 0xfffd and meta['nwk_fcf'] == 0x2208 and
            aps.control == 12 and aps.group == 10)
        if status_scope:
            try: frame = Type06(zcl.payload)
            except ValueError: return None
        elif remote_scope:
            try: frame = Type07(zcl.payload)
            except ValueError: return None
        else:
            return None
        radio_us = int(now*1e6) if radio_us is None else radio_us
        if revision <= self.revision or now < self.ready_at or radio_us <= self.radio_floor:
            return 'APPLICATION_STALE'
        try: self.ledger.consume(meta['source_ieee'], meta['counter'])
        except Fault as exc:
            if str(exc) == 'NWK_replay': return 'APPLICATION_STALE'
            raise
        self.revision = revision
        if status_scope:
            self.status, self.status_at = frame, now
            if self.confirmation:
                # Additional command-time floor; host callback order alone is insufficient.
                if now >= self.command_at and radio_us > (self.command_radio_floor or self.radio_floor):
                    self.confirmation.observe(frame, revision, int(now*1000),
                        self.baseline.generation, int(now*1000))
                    if self.confirmation.match_revision == revision:
                        self.match_radio_us = radio_us
                self.tick(now)
            self.baseline.observe(frame, revision)
        else:
            self.baseline.remote(frame, src, r['context']['short'])
            self.tick(now)
        return 'APPLICATION_AUTHENTICATED'

    def prepare(self, now, value=None):
        self.now = now
        r = self.live(now)
        if self.used or 'application_intent' in r:
            raise Fault('one_command_NO_RETRY')
        if self.status is None or self.status_at < self.ready_at or not self.baseline.live:
            raise Fault('fresh_authenticated_status_and_lossless_baseline_required')
        s = self.status
        b = self.baseline.frame
        if not s.power or s.night or s.mode_raw != 0 or s.humidifier_raw > 2 or b is None or s.humidifier_raw != b.humidifier_raw or s.target_tenths != b.target_tenths:
            raise Fault('conservative_FAN_state_required')
        target = (s.fan + 1 if s.fan < 7 else 6) if value is None else value
        self.request = CommandRequest('fan', target)
        if target == s.fan or abs(target-s.fan) != 1:
            raise Fault('one_adjacent_reversible_FAN_change')
        tx = build(self.request, self.baseline, s, int((now-self.status_at)*1000), 0xf59f)
        if any(tx.raw[i] != b.raw[i] for i in range(21) if i not in (6, 11, 20)):
            raise Fault('FAN_only_preserve_all_opaque_bytes')
        self.used = True # every failure after this point requires separate review, never retry
        self.command_at = now
        self.confirmation = Confirmation(self.request, tx, b, self.baseline.generation,
            self.revision, int(now*1000), 20000)
        c = r['context']; seq = r['sequences']
        ctx = ZigbeeContext('raw-first-control', c['pan'], int(TC,16), c['channel'],
            int(RAW,16), c['short'], int(TC,16), key_epochs={0:EPOCH},
            nwk_sequence=seq['nwk'], aps_counter=seq['aps'], zcl_tsn=seq.get('zcl',0), mac_dsn=seq['dsn'])
        ctx.keys.put(0, self.ledger.key.value)
        counters = DurableApplicationCounters(self)
        ctx.outgoing[(EPOCH,0)] = CounterAllocator(counters, ctx.identity, EPOCH, 0, 32)
        raw = secured_frame(DeviceConfig('bedroom', ctx, 0xf59f, 'env:RAW_KEY'), tx, counters)
        if len(raw) != 68:
            raise Fault('typed_application_length')
        self.ledger.change(lambda r: r['application_intent'].update(
            phase='BUILT_NEVER_RETRY', sha256=hashlib.sha256(raw).hexdigest()))
        return raw

    def handoff(self, now):
        self.live(now)
        if (self.confirmation is None or self.result is not None or
            self.baseline.generation != self.confirmation.generation or
            not 0 <= now-self.status_at <= 15):
            raise Fault('baseline_changed_before_handoff')
        def change(r):
            if r['application_intent']['phase'] != 'BUILT_NEVER_RETRY':
                raise Fault('one_handoff_NO_RETRY')
            r['application_intent'].update(phase='HANDED_UNKNOWN_NO_RETRY', handed_at=now)
        self.ledger.change(change)

    def complete(self, status, now, rf_start_us=None):
        self.live(now)
        if self.ledger.read().get('application_intent',{}).get('phase') != 'HANDED_UNKNOWN_NO_RETRY':
            raise Fault('completion_without_handoff')
        if rf_start_us is not None:
            if status == 0 and rf_start_us <= 0:
                raise Fault('missing_radio_start_receipt')
            self.command_radio_floor = max(self.command_radio_floor or self.radio_floor, rf_start_us)
            if self.match_radio_us is not None and self.match_radio_us <= self.command_radio_floor:
                self.confirmation.match = None
        self.confirmation.complete(status, self.baseline.generation, int(now*1000))
        self.tick(now)

    def tick(self, now):
        if self.confirmation is None or self.result is not None:
            return
        self.confirmation.check(self.baseline.generation, int(now*1000))
        if self.confirmation.failure:
            self.result = 'FAILED_OR_UNKNOWN'
        elif self.confirmation.confirmed:
            if self.baseline.commit(self.confirmation.generation, self.confirmation.tx):
                self.result = 'CONFIRMED'
            else:
                self.result = 'FAILED_OR_UNKNOWN'
        if self.result:
            self.ledger.change(lambda r: r['application_intent'].update(result=self.result))


class ApplicationProbe(Probe):
    """V18 sequencer with a hook BEFORE its unchanged final END cleanup."""
    def execute(self, observe_seconds=60):
        result = super().execute(observe_seconds)
        result['TYPE07'] = self.w.tx_counts.get('TYPE07_FAN', 0)
        result['application_result'] = self.ledger.app.result if self.ledger.app else None
        self.ledger.restart_radio() # END consumes this live readiness regardless of outcome
        return result

    def application_ready(self):
        self.ledger.app = FirstFanControl(self.ledger, self.w.boot, self.session, self.clock())
        app = self.ledger.app
        end = self.clock()+10
        while self.clock() < end and (app.status is None or not app.baseline.valid or app.baseline.remote_pending):
            self.keepalive()
            self.w.read()
        floor = self.command('STATUS', 'session=1')
        if (floor.get('recovery') != 'PARENT_LINK_ACTIVE' or floor.get('pending') != '0' or
            floor.get('generation') != str(self.ledger.read()['generation'])):
            raise Fault('current_live_STATUS_required')
        app.command_radio_floor = int(floor['time_us'])
        raw = app.prepare(self.clock())
        r = self.ledger.read(); i = r['application_intent']
        app.handoff(self.clock())
        fields = (f'session=1 generation={r["generation"]} epoch={EPOCH} attempt={ATTEMPT} '
            f'guard={self.ledger.guard} fc={i["fc"]} hash={i["sha256"]} mac={raw.hex()}')
        receipt = self.command('TYPE07_FAN', fields, raw)
        app.complete(0 if receipt['result']=='local_tx_ok' else -1, self.clock(), int(receipt['rf_start_us']))
        while app.result is None:
            self.keepalive()
            self.w.read()
            app.tick(self.clock())
        if app.result != 'CONFIRMED':
            raise Fault('application_confirmation_failed_or_unknown')

    def keepalive(self):
        r = self.ledger.read()
        if self.clock()-r['recovery'].get('last_idle_intent',{}).get('at',0) >= 1.02:
            raw = self.ledger.reserve_idle_poll(self.clock())
            receipt = self.command('MANAGEMENT_POLL',
                f'session=1 generation={r["generation"]} dsn={raw[2]}', raw)
            self.ledger.idle_result(raw[2], receipt['result'], receipt)

    def on_rx(self, row):
        if self.ledger.app:
            f = row['fields']
            if f.get('session') != '1': raise Fault('RX_wrong_session')
            result = self.ledger.app.receive(bytes.fromhex(f['mac']), int(f['revision']), self.clock(), int(f['time_us']))
            if result in ('APPLICATION_AUTHENTICATED','APPLICATION_STALE'): return
            return super().on_rx(row,receiver=self.ledger.receive_management)
        super().on_rx(row)
