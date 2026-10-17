"""Persistent service policy. Transport gaps permit a new retained-key cycle.

Security/protocol faults latch durably and cannot trigger an automatic rejoin.
No queued command, baseline or TX bytes survive a service cycle.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
from .daemon import AirNannyDaemon
from .radio_daemon import RadioDaemonLoop

RECOVERABLE = frozenset(('serial_io_error', 'serial_disconnected', 'serial_open_failed', 'radio_parent_link_lost'))

# Faults an operator may clear by naming them, because they moved no secured
# state and spent no counter. A failed plaintext discovery beacon is an
# ordinary radio condition -- a busy channel -- and latching it protects
# nothing once someone has looked at it. Everything else stays latched: a
# rolled-back store, an authenticated Leave and any interrupted secured
# exchange all need a person to decide what actually happened, and that
# decision cannot be expressed as a string.
OPERATOR_CLEARABLE = frozenset(('late_join_discovery_tx_failed',))
HISTORY_LIMIT = 64
RESULT_LIMIT = 256


def prune_consumed_events(daemon):
    """Prune only events already consumed by the existing MQTT adapters."""
    for adapter in daemon.adapters.values():
        discard = min(adapter.cursor, max(0, len(adapter.device.events) - HISTORY_LIMIT))
        if discard:
            del adapter.device.events[:discard]
            adapter.cursor -= discard


def bounded_transient(daemon, topic, payload):
    if daemon.publish(topic, payload):
        return
    if len(daemon.outbox) >= RESULT_LIMIT:
        daemon.result_delivery_drops = min(0xffffffff, daemon.result_delivery_drops + 1)
        daemon.log.emit('mqtt_result_dropped', reason='result_buffer_full_delivery_unknown')
        return
    daemon.outbox.append((topic, payload))


class ServiceDaemon(AirNannyDaemon):
    def __init__(self, *args, command_retries=False, rollover_successor=0, **kwargs):
        super().__init__(*args, **kwargs)
        if command_retries:
            from .radio_retry import RetryingCommandDevice
            devices = self.collection.devices
            for name, old in list(devices.items()):
                device = RetryingCommandDevice(old.config, old.clock, old.transport, old.counters,
                                                rollover_successor=rollover_successor)
                devices[name] = device
                self.collection.by_context[device.config.context.identity] = device
                self.adapters[name].device = device
        self.result_delivery_drops = 0

    def transient(self, topic, payload):
        bounded_transient(self, topic, payload)


class RadioServiceSession(RadioDaemonLoop):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mqtt_due = 0

    def pump(self):
        super().pump()
        late_join=getattr(self,'late_join',None)
        if late_join is not None:
            late_join.pump()
        prune_consumed_events(self.daemon)
        now = self.radio.clock.now_ms()
        if not self.daemon.mqtt.connected and now >= self.mqtt_due:
            self.mqtt_due = now + 5000
            self.daemon.reconnect()


class ServiceBlocked(RuntimeError):
    pass


class StartupUnavailable(ConnectionError):
    """Port absent before any recovery mutation or RF command."""


class RecoveryParentLost(ConnectionError):
    """Both secured chains settled; only clean readiness polls lost the link."""


class RecoveryDiscoveryUnavailable(ConnectionError):
    """No target beacon; this guard has no uncertain secured transmission."""


class RecoveryCleanTxLoss(ConnectionError):
    """Safe terminal RF miss; a new recovery cycle may spend new FC blocks."""


def settle_recovery_poll(runner, slot):
    """Schedule a host commit after the response-window automatic poll settles.

    Authentication may fsync a ledger while the next automatic poll starts.
    Read its validated completion before sending the commit, rather than
    racing it and treating tx_busy as permission to resend a command.
    """
    start=len(runner.records);deadline=runner.clock()+.25
    while runner.clock()<deadline:
        runner.w.read()
        if (slot not in runner.auto_open and any(row.get('kind')=='AUTO_DONE'
                and row.get('fields',{}).get('ctx')==str(slot) for row in runner.records[start:])):
            return
    if slot in runner.auto_open:
        raise ServiceBlocked('recovery_auto_poll_completion_unknown')
    # A closed response window produces no further automatic polls. No
    # observed in-flight TX remains; the firmware still validates the commit.


def response_timeout_retry_safe(error, ledgers, guard, records):
    """An absent reply is ordinary loss ONLY with a fully known TX lifecycle."""
    choices = {f'no_authenticated_{kind}_response:ctx={slot}': (kind, slot)
               for kind in ('REJOIN', 'TIMEOUT') for slot in (0, 1)}
    if str(error) not in choices or not records:
        return False
    kind, missing = choices[str(error)]
    if any(r.get('kind') == 'ERROR' or
           any(r.get('fields', {}).get(k, '0') != '0' for k in ('rx_drop','out_drop','reboot_required'))
           or r.get('fields', {}).get('cleanup') == 'unproven' for r in records):
        return False
    offsets = {'REJOIN': ('REJOIN_REQUEST',34), 'ANNOUNCE': ('DEVICE_ANNOUNCE',18),
               'TIMEOUT': ('END_DEVICE_TIMEOUT',34)}
    for slot, ledger in ledgers.items():
        record = ledger.read(); q = record.get('recovery') or {}
        # Match ServiceState's guard-scoped Leave check. The immutable stores
        # also retain the historical pre-issue-5 Leave diagnosis; the operator
        # already authorized and completed retained recovery after that event.
        if q.get('leave') or q.get('state') == 'DEGRADED_LEAVE':
            return False
        if q.get('gate') != guard:
            if slot == missing:return False
            continue
        intents = q.get('intents') or {}
        expected = {'REJOIN'} if kind == 'REJOIN' else {'REJOIN','ANNOUNCE','TIMEOUT'}
        if slot != missing:expected = {'REJOIN','ANNOUNCE','TIMEOUT'}
        state = ('DISCOVERING' if kind == 'REJOIN' else 'REJOINED') if slot == missing else 'PARENT_LINK_ACTIVE'
        if q.get('state') != state or set(intents) != expected:
            return False
        for name, intent in intents.items():
            if (intent.get('phase') != 'SENT' or intent.get('result') != 'local_tx_ok'
                    or intent.get('block_end', record['next_fc']) >= record['next_fc']):
                return False
            verb, offset = offsets[name]
            accepts = [r['fields'] for r in records if r.get('kind') == 'TXACCEPT'
                       and r['fields'].get('ctx') == str(slot) and r['fields'].get('class') == verb]
            if len(accepts) != 1:return False
            accepted = accepts[0]
            done = [r['fields'] for r in records if r.get('kind') == 'TXDONE'
                    and r['fields'].get('ctx') == str(slot) and r['fields'].get('id') == accepted.get('id')]
            if len(done) != 1:return False
            terminal = done[0]
            try:
                raw = bytes.fromhex(accepted['mac'])
                if (terminal.get('result') != 'local_tx_ok' or terminal.get('cleanup') != 'safe'
                        or terminal.get('reboot_required') != '0'
                        or intent.get('radio_end_us') != int(terminal['time_us'])
                        or intent.get('sha256') != hashlib.sha256(raw).hexdigest()
                        or intent.get('fc') != int.from_bytes(raw[offset:offset+4], 'little')):
                    return False
            except (KeyError,ValueError):return False
    return True


def clean_recovery_loss_safe(error, ledgers, guard, records):
    result = str(error).removeprefix('unknown_or_failed_TX_burned:')
    if str(error) == result or result not in ('no_ack', 'invalid_ack', 'cca_fail'):
        return False
    if not records or records[-1].get('kind') != 'TXDONE':
        return False
    if any(r.get('kind') == 'ERROR' or
           any(r.get('fields', {}).get(k, '0') != '0' for k in ('rx_drop', 'out_drop', 'reboot_required'))
           or r.get('fields', {}).get('cleanup') == 'unproven' for r in records):
        return False
    terminal = records[-1]['fields']
    if (terminal.get('result') != result or terminal.get('cleanup') != 'safe'
            or terminal.get('reboot_required') != '0' or terminal.get('session') != '1'
            or terminal.get('ctx') not in ('0', '1')):
        return False
    slot = int(terminal['ctx'])
    accepted = [r['fields'] for r in records if r.get('kind') == 'TXACCEPT'
                and r['fields'].get('id') == terminal.get('id')]
    if len(accepted) != 1 or accepted[0].get('ctx') != terminal['ctx']:
        return False
    kinds = {'REJOIN_REQUEST': ('REJOIN', 34), 'DEVICE_ANNOUNCE': ('ANNOUNCE', 18),
             'END_DEVICE_TIMEOUT': ('TIMEOUT', 34)}
    if accepted[0].get('class') not in kinds:
        return False  # TYPE07/application commands never use this exception
    kind, fc_offset = kinds[accepted[0]['class']]
    for ctx, ledger in ledgers.items():
        r = ledger.read();q = r.get('recovery') or {}
        if q.get('leave') or q.get('state') == 'DEGRADED_LEAVE':
            return False
        if q.get('gate') != guard:
            if ctx == slot:return False
            continue
        intents = q.get('intents') or {}
        if any(k not in ('REJOIN', 'ANNOUNCE', 'TIMEOUT')
               or i.get('phase') != 'SENT' or i.get('block_end', r['next_fc']) >= r['next_fc']
               or i.get('result') != (result if ctx == slot and k == kind else 'local_tx_ok')
               for k, i in intents.items()):
            return False
        if ctx == slot:
            i = intents.get(kind) or {}
            try:
                mac = bytes.fromhex(accepted[0]['mac'])
                if (i.get('radio_end_us') != int(terminal['time_us'])
                        or hashlib.sha256(mac).hexdigest() != i.get('sha256')
                        or int.from_bytes(mac[fc_offset:fc_offset+4], 'little') != i.get('fc')):
                    return False
            except (KeyError, ValueError):
                return False
    return True


def discovery_retry_safe(error, ledgers, guard):
    if str(error) not in ('no_target_beacon_after_bounded_scans:ctx=0',
                          'no_target_beacon_after_bounded_scans:ctx=1'):
        return False
    missing = int(str(error)[-1])
    for slot, ledger in ledgers.items():
        r = ledger.read();q = r.get('recovery') or {}
        if q.get('leave') or q.get('state') == 'DEGRADED_LEAVE':
            return False
        if q.get('gate') != guard:
            if slot == missing:
                return False
            continue  # untouched slot; no frame of this cycle was submitted
        intents = q.get('intents') or {}
        if slot == missing:
            if q.get('state') != 'DISCOVERING' or intents:
                return False
        elif (q.get('state') != 'PARENT_LINK_ACTIVE'
              or set(intents) != {'REJOIN', 'ANNOUNCE', 'TIMEOUT'}
              or any(i.get('phase') != 'SENT' or i.get('result') != 'local_tx_ok'
                     or i.get('block_end', r['next_fc']) >= r['next_fc'] for i in intents.values())):
            return False
    return True


def discovery_slot_absent_safe(error, slot, ledger, guard, records):
    """Only absence before any secured request may leave a startup slot offline."""
    if str(error) != f'no_target_beacon_after_bounded_scans:ctx={slot}':
        return False
    r = ledger.read(); q = r.get('recovery') or {}
    if (q.get('gate') != guard or q.get('state') != 'DISCOVERING'
            or q.get('intents') or q.get('leave')):
        return False
    if any(row.get('kind') == 'ERROR' or any(row.get('fields', {}).get(k, '0') != '0'
           for k in ('rx_drop', 'out_drop', 'reboot_required')) for row in records):
        return False
    statuses = [row['fields'] for row in records if row.get('kind') == 'STATUS'
                and row['fields'].get('ctx') == str(slot)]
    if not statuses:
        return False
    last = statuses[-1]
    if (last.get('generation') != str(r['generation'])
            or last.get('quarantine') != '0' or last.get('reboot_required') != '0'):
        return False
    if (last.get('recovery'),last.get('state')) == ('BOUND','RECOVERY'):
        return True
    if (last.get('recovery'),last.get('state')) != ('STOPPED','STOPPED'):
        return False
    # V32 deliberately stops this slot at its third empty scan deadline.
    # A generic STOPPED state is never sufficient: all three exact scan
    # transmissions must have known safe completions, with no secured intent.
    scans=[row['fields'] for row in records if row.get('kind')=='TXACCEPT'
           and row['fields'].get('ctx')==str(slot)
           and row['fields'].get('class')=='ACTIVE_DISCOVERY_BEACON_REQUEST']
    if len(scans)!=3 or len({s.get('id') for s in scans})!=3:
        return False
    for scan in scans:
        done=[row['fields'] for row in records if row.get('kind')=='TXDONE'
              and row['fields'].get('ctx')==str(slot) and row['fields'].get('id')==scan.get('id')]
        if (len(done)!=1 or done[0].get('result')!='local_tx_ok'
                or done[0].get('cleanup')!='safe' or done[0].get('reboot_required')!='0'):
            return False
    return True


class ReadinessPolls:
    def __init__(self, ledgers, guard, *, tolerate_active_loss=False):
        self.ledgers, self.guard = ledgers, guard
        self.tolerate_active_loss = tolerate_active_loss
        self.misses = {0: 0, 1: 0}

    def completed(self, slot, fields):
        if fields.get('cleanup') != 'safe' or fields.get('reboot_required') != '0':
            raise ServiceBlocked('readiness_poll_cleanup_unproven')
        result = fields.get('result')
        if result == 'local_tx_ok':
            self.misses[slot] = 0
            return
        if result not in ('no_ack', 'invalid_ack', 'cca_fail'):
            raise ServiceBlocked('readiness_poll_failed_or_unknown')
        self.misses[slot] = min(0xffffffff, self.misses[slot] + 1)
        if self.tolerate_active_loss:
            return
        if self.misses[slot] < 3:
            return
        for ledger in self.ledgers.values():
            r = ledger.read();q = r.get('recovery') or {}
            intents = q.get('intents') or {}
            if (q.get('state') != 'PARENT_LINK_ACTIVE' or q.get('gate') != self.guard
                    or q.get('leave') or set(intents) != {'REJOIN', 'ANNOUNCE', 'TIMEOUT'}
                    or any(i.get('phase') != 'SENT' or i.get('result') != 'local_tx_ok'
                           or i.get('block_end', r['next_fc']) >= r['next_fc'] for i in intents.values())):
                raise ServiceBlocked('readiness_secured_chain_not_settled')
        raise RecoveryParentLost('radio_parent_link_lost_during_readiness')


class PersistentRadioService:
    def __init__(self, state, clock, establish, *, retry_ms=5000):
        if type(retry_ms) is not int or retry_ms < 2000:
            raise ValueError('bounded reconnect backoff required')
        self.state, self.clock, self.establish = state, clock, establish
        self.retry_ms, self.next_open = retry_ms, 0
        self.session = None
        self.stopped = False
        self.active_recorded = False
        self.retry_attempt = 0

    def _retry(self, reason):
        delay = min(300000, self.retry_ms * (2 ** min(self.retry_attempt, 6)))
        self.retry_attempt += 1
        self.state.write('WAITING', reason=reason, retry_delay_ms=delay)
        self.next_open = self.clock.now_ms() + delay

    def pump(self):
        if self.stopped:
            return
        if self.session is None:
            if self.clock.now_ms() < self.next_open:
                return
            try:
                if self.state.read()['state'] == 'BLOCKED':
                    raise ServiceBlocked('service_fault_latched')
                self.session = self.establish(self.state)
                self.active_recorded = False
            except StartupUnavailable:
                self._retry('serial_open_failed')
                return
            except RecoveryParentLost:
                self._retry('radio_parent_link_lost_during_readiness')
                return
            except RecoveryDiscoveryUnavailable:
                self._retry('target_beacon_unavailable')
                return
            except RecoveryCleanTxLoss:
                self._retry('clean_recovery_RF_loss_new_cycle_required')
                return
            except ServiceBlocked as exc:
                if self.state.read()['state'] != 'BLOCKED':
                    self.state.write('BLOCKED', reason=str(exc))
                raise
            except Exception:
                self.state.write('BLOCKED', reason='retained_recovery_failed_or_unknown')
                raise ServiceBlocked('retained_recovery_failed_or_unknown') from None
        try:
            self.session.pump()
            radio = self.session.radio
            if radio.state in ('disconnected', 'blocked'):
                self.state.disconnected(radio.reason)
                session, self.session = self.session, None
                session.close()  # callbacks conclude unknown; old bytes discarded
                self.next_open = self.clock.now_ms() + self.retry_ms
            elif radio.connected and not self.active_recorded:
                self.state.write('ACTIVE', reason=None)
                self.active_recorded = True
                self.retry_attempt = 0
        except ServiceBlocked:
            if self.session:
                session, self.session = self.session, None
                session.close()
            raise
        except Exception:
            self.state.write('BLOCKED', reason='service_runtime_fault')
            if self.session:
                session, self.session = self.session, None
                session.close()
            raise ServiceBlocked('service_runtime_fault') from None

    def close(self):
        self.stopped = True
        if self.session:
            session, self.session = self.session, None
            session.close()
        if self.state.read()['state'] not in ('BLOCKED', 'RECOVERING'):
            self.state.write('STOPPED', reason='operator_shutdown')


class ServiceState:
    def __init__(self, path):
        self.path = Path(path)

    def read(self):
        if not self.path.exists():
            return {'version': 1, 'state': 'NEW', 'cycles': 0}
        try:
            record = json.loads(self.path.read_text(encoding='utf-8'))
            if (record['version'] != 1 or record['state'] not in
                    ('NEW', 'RECOVERING', 'ACTIVE', 'WAITING', 'STOPPED', 'BLOCKED')
                    or type(record['cycles']) is not int or record['cycles'] < 0):
                raise ValueError()
            return record
        except Exception:
            raise ServiceBlocked('service_state_invalid') from None

    def write(self, state, **fields):
        record = self.read()
        record.update(state=state, **fields)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix('.tmp')
        with temp.open('w', encoding='utf-8') as stream:
            json.dump(record, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, self.path)
        if self.read() != record:
            raise ServiceBlocked('service_state_readback_failed')
        return record

    def require_recovery(self, ledgers):
        record = self.read()
        if record['state'] == 'BLOCKED':
            raise ServiceBlocked('service_fault_latched:' + record.get('reason', 'unknown'))
        # A process killed while recovery was moving secured state cannot
        # automatically run another recovery chain. Inspect it explicitly.
        if record['state'] == 'RECOVERING':
            raise ServiceBlocked('interrupted_recovery_requires_review')
        late=record.get('late_join') or {}
        if late and (late.get('secured') or any(
                (ledger.read().get('recovery') or {}).get('gate')==late.get('guard')
                and (ledger.read().get('recovery') or {}).get('intents')
                for ledger in ledgers.values())):
            raise ServiceBlocked('interrupted_late_join_requires_review')
        for ledger in ledgers.values():
            q = ledger.read().get('recovery') or {}
            if q.get('state') == 'DEGRADED_LEAVE' or q.get('leave'):
                self.write('BLOCKED', reason='radio_authenticated_leave')
                raise ServiceBlocked('radio_authenticated_leave')

    def require_monotonic_stores(self, ledgers):
        """Durable counters may only ever move forward.

        A store that comes back lower than this service last saw it has been
        rolled back -- restored from an older copy, or half written -- and
        transmitting from it would reuse counters that were already spent.
        Two histories now exist and only a person can say which is real, so
        the run is refused and latched rather than quietly repaired.

        The first run of a freshly migrated store records a baseline instead
        of rejecting it: there is nothing yet to compare against, and the
        deliberate act of putting the store there is the operator's answer.
        """
        record = self.read()
        seen = record.get('stores') or {}
        current = {}
        for slot, ledger in ledgers.items():
            store = ledger.read()
            current[str(slot)] = {'generation': int(store['generation']),
                                  'next_fc': int(store['next_fc'])}
        for slot, previous in seen.items():
            now = current.get(slot)
            if now is None:
                continue
            if (now['generation'] < previous['generation']
                    or now['next_fc'] < previous['next_fc']):
                self.write('BLOCKED', reason='store_rollback_detected',
                           review={'reason': 'ctx%s durable store moved backwards' % slot,
                                   'context': slot, 'seen': previous, 'found': now})
                raise ServiceBlocked('store_rollback:ctx%s' % slot)
        self.write(record['state'], stores=current)
        return current

    def begin(self, boot, guard):
        r = self.read()
        self.write('RECOVERING', cycles=r['cycles'] + 1, boot=boot, guard=guard, reason=None,late_join=None)

    def disconnected(self, reason):
        if reason not in RECOVERABLE:
            self.write('BLOCKED', reason=reason)
            raise ServiceBlocked(reason)
        self.write('WAITING', reason=reason)

    def acknowledge(self, reason):
        """Clear a latch whose reason the operator has named exactly.

        Naming it is the whole mechanism. A restart must not clear a fault,
        and neither must a blanket reset switch: someone has to have read the
        reason and written it back, which is deliberate and leaves a record of
        who decided what.

        Only faults that moved no secured state can be cleared this way. A
        rolled-back store or an interrupted secured recovery needs a person to
        work out which history is the real one, and typing a string is not
        that work. Those stay latched however exactly they are named.
        """
        record = self.read()
        if record['state'] != 'BLOCKED':
            return 'not_blocked'
        latched = record.get('reason')
        if reason != latched:
            return 'mismatch'
        if latched not in OPERATOR_CLEARABLE:
            return 'not_clearable'
        cleared = dict(record.get('cleared') or {})
        cleared[latched] = cleared.get(latched, 0) + 1
        self.write('WAITING', reason=None, cleared=cleared,
                   last_cleared={'reason': latched, 'review': record.get('review')})
        return 'cleared'


class BoundedLedger:
    """Delegate to the existing authority; bound only diagnostic history.

    Atomic writer, FC high water, keys and source replay floors are unchanged.
    Each delegate method uses its own _write, so wrap that writer once.
    """
    @staticmethod
    def install(ledger):
        original = ledger._write
        def write(record):
            record = copy.deepcopy(record)
            if 'recovery_history' in record:
                record['recovery_history'] = record['recovery_history'][-HISTORY_LIMIT:]
            q = record.get('recovery') or {}
            if 'application_history' in q:
                q['application_history'] = q['application_history'][-HISTORY_LIMIT:]
            for prior in record.get('recovery_history', []):
                if 'application_history' in prior:
                    prior['application_history'] = prior['application_history'][-HISTORY_LIMIT:]
            return original(record)
        ledger._write = write
        return ledger


class ServiceLock:
    """OS-owned lock released even after process death; no stale-file bypass."""
    def __init__(self, path):
        self.path = Path(path)
        self.stream = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = self.path.open('a+b')
        if self.stream.tell() == 0:
            self.stream.write(b'\0')
            self.stream.flush()
        self.stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise ServiceBlocked('another_radio_service_owns_the_stores') from None
        return self

    def __exit__(self, *args):
        self.stream.close()
