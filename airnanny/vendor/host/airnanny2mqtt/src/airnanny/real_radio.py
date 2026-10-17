"""Owner-thread V28 serial RadioTransport. No Zigbee/application semantics.

V28 binding/recovery is explicit and external: the adapter verifies an already
active pair. A fresh/stopped boot needs the reviewed recovery state machine;
reconnect never implicitly BINDs, rejoins or resets durable contexts.
"""
from collections import OrderedDict, deque
from dataclasses import dataclass
import threading
import hashlib
from .serial_support import SerialChannel, SerialFault, SerialLimits
from .radio_wire import SURFACE, command, parse_record, number, mac_bytes, HEX32
from .mac import MAC
from .nwk import NWK
from .security import SecurityHeader

FIRMWARE_PROFILES = {
    28: ('airnanny_dual_pan_runtime_v28', 'typed_fan_once', False),
    29: ('airnanny_dual_pan_runtime_v29', 'typed_type07_repeat', True),
    30: ('airnanny_dual_pan_runtime_v30', 'typed_type07_repeat', True),
    31: ('airnanny_dual_pan_runtime_v31', 'typed_type07_repeat', True),
    32: ('airnanny_dual_pan_runtime_v32', 'typed_type07_repeat', True),
    33: ('airnanny_dual_pan_runtime_v33', 'typed_type07_repeat_late_join', True),
}


@dataclass(frozen=True)
class RadioBinding:
    slot: int
    context_id: str
    pan: int
    short: int
    raw_ieee: int
    generation: int
    epoch: str
    attempt: str
    guard: str
    key_sequence: int = 0

    def __post_init__(self):
        if (type(self.slot) is not int or self.slot not in (0, 1) or not self.context_id
                or not 0 <= self.pan < 0xffff or not 0 < self.short < 0xfff8
                or not 0 < self.raw_ieee < 1 << 64 or self.generation < 6
                or any(not HEX32.fullmatch(t) for t in (self.epoch, self.attempt, self.guard))
                or not 0 <= self.key_sequence <= 255):
            raise ValueError('invalid durable radio binding')


@dataclass
class _Request:
    verb: str
    slot: int | None
    deadline: int
    raw: bytes | None = None
    tx_id: str | None = None
    callback: object = None
    accepted: bool = False


class RealRadioTransport:
    def __init__(self, clock, bindings, *, port_factory, port_name,
                 limits=SerialLimits(), command_limit=8, result_history=128,
                 response_ms=3000, reconnect_ms=2000, intent_hook=None, completion_hook=None,
                 initial_bytes=b'', firmware_version=28, initial_command_id=0,
                 initial_poll_misses=None, active_slots=None):
        if type(firmware_version) is not int or firmware_version not in FIRMWARE_PROFILES:
            raise ValueError('explicit reviewed firmware profile required')
        self.firmware_version = firmware_version
        self.firmware_identity, self.application_tx, self.repeat_commands = FIRMWARE_PROFILES[firmware_version]
        if type(initial_command_id) is not int or not 0 <= initial_command_id < 0xffffffff:
            raise ValueError('valid owned command-id handoff required')
        self.clock, self.bindings = clock, tuple(bindings)
        if (len(self.bindings) != 2 or {b.slot for b in self.bindings} != {0, 1}
                or len({b.context_id for b in self.bindings}) != 2
                or len({b.pan for b in self.bindings}) != 2):
            raise ValueError('two independent durable bindings required')
        if any(type(v) is not int or v <= 0 for v in
               (command_limit, result_history, response_ms, reconnect_ms)):
            raise ValueError('positive radio limits required')
        self.by_slot = {b.slot: b for b in self.bindings}
        self.by_context = {b.context_id: b for b in self.bindings}
        self.by_pan = {b.pan: b for b in self.bindings}
        self.active_slots = frozenset((0, 1) if active_slots is None else active_slots)
        if (not self.active_slots or not self.active_slots <= {0, 1}
                or any(type(s) is not int for s in self.active_slots)
                or firmware_version < 32 and self.active_slots != {0, 1}):
            raise ValueError('explicit V32 active context set required')
        self.port_factory, self.port_name, self.limits = port_factory, port_name, limits
        self.command_limit, self.result_history = command_limit, result_history
        self.response_ms, self.reconnect_ms = response_ms, reconnect_ms
        self.intent_hook = intent_hook or (lambda *args: None)
        self.completion_hook = completion_hook or (lambda *args: None)
        self._initial_bytes = initial_bytes
        self._owner = threading.get_ident()
        self.channel = None
        self.boot = None
        self._id = initial_command_id
        self._probe = 1
        self._pending = {}
        self._commands = deque()
        self._wire_waiting = None
        self._history = OrderedDict()
        self._checked = set()
        self._status_due = {0: 0, 1: 0}
        self._poll_due = {0: 0, 1: 0}
        self._dsn = {0: 0, 1: 128}
        if initial_poll_misses is None:
            initial_poll_misses = {0: 0, 1: 0}
        if (set(initial_poll_misses) != {0, 1} or
                any(type(v) is not int or not 0 <= v <= (0xffffffff if firmware_version >= 32 else 2)
                    for v in initial_poll_misses.values())):
            raise ValueError('owned per-context poll-miss handoff required')
        self._poll_misses = dict(initial_poll_misses)
        self._used = set()
        self._held_rx = {0: deque(), 1: deque()}
        self._confirmation_after = {}
        self._last_fc = {}
        self._revision = None
        self._snapshot_fence = None
        self._config_generation = None
        self._radio_time = None
        self._next_open = 0
        self.state, self.reason = 'closed', None
        self.connected = False
        self.stopped = False
        self.receiver = lambda ctx, raw, fields: None
        self.health_handler = lambda healthy, reason: None
        self.record_observer = lambda kind, fields: None

    def _owner_only(self):
        if threading.get_ident() != self._owner:
            raise RuntimeError('radio owner thread required')

    def set_receiver(self, receiver):
        self._owner_only()
        self.receiver = receiver

    def context_available(self, context_id):
        b = self.by_context.get(context_id)
        return self.connected and b is not None and b.slot in self.active_slots

    def application_ready(self, context_id):
        self._owner_only()
        b = self.by_context.get(context_id)
        return (self.context_available(context_id) and b is not None
                and (self.repeat_commands or b.slot not in self._used)
                and len(self._pending) < self.command_limit
                and not any(p.slot == b.slot and p.raw is not None for p in self._pending.values()))

    def set_health_handler(self, handler):
        self._owner_only()
        self.health_handler = handler

    def open(self):
        self._owner_only()
        if self.stopped:
            raise RuntimeError('stopped radio cannot reopen')
        if self.channel is not None:
            return
        try:
            port = self.port_factory(self.port_name)
            self.channel = SerialChannel(port, self.limits)
            if self._initial_bytes:
                self.channel._ingest(self._initial_bytes)
                self._initial_bytes = b''
            self.state, self.reason = 'handshake', None
            self._checked.clear()
            self._probe = max(1, self._id + 1)
            self._send('INFO', identifier=self._probe)
        except Exception:
            self._disconnect('serial_open_failed', retry=True)

    def _send(self, verb, slot=None, *, identifier=None, raw=None, tx_id=None, callback=None, **fields):
        if len(self._pending) >= self.command_limit:
            raise SerialFault('radio_command_queue_full')
        identifier = identifier or self._id + 1
        if identifier > 0xffffffff:
            raise SerialFault('radio_id_exhausted')
        line = command(verb, identifier, boot=None if verb == 'INFO' else self.boot, ctx=slot, **fields)
        self._id = identifier
        self._pending[identifier] = _Request(verb, slot, 0,
                                              raw, tx_id, callback)
        self._commands.append((identifier, line))
        return identifier

    def send_frame(self, ctx_id, mac_bytes_, tx_id, completion):
        self._owner_only()
        b = self.by_context.get(ctx_id)
        if not self.application_ready(ctx_id):
            return False
        raw = bytes(mac_bytes_)
        try:
            mac = MAC.parse(raw)
            nwk = NWK.parse(mac.payload)
            aux = SecurityHeader.parse(nwk.payload)[0]
            if (len(raw) != 68 or mac.fcf != 0x8861 or mac.destination_pan != b.pan
                    or mac.source_pan != b.pan or mac.source != b.short or mac.destination != 0
                    or nwk.fcf != 0x2208 or nwk.destination != 0xfffd or nwk.source != b.short
                    or nwk.radius != 60 or aux.control != 0x28 or aux.source_ieee != b.raw_ieee
                    or aux.key_sequence != b.key_sequence or aux.counter < 32
                    or aux.counter == 0xffffffff or aux.counter < self._last_fc.get(b.slot, 0) + 32):
                return False
            digest = hashlib.sha256(raw).hexdigest()
            self.intent_hook(b, tx_id, raw, aux.counter, digest)
            self._used.add(b.slot)  # Never release after ambiguous write/disconnect.
            self._last_fc[b.slot] = aux.counter
            self._confirmation_after.pop(b.slot, None)
            self._send('TYPE07_FAN', b.slot, raw=raw, tx_id=tx_id, callback=completion,
                       session=1, generation=b.generation, epoch=b.epoch, attempt=b.attempt,
                       guard=b.guard, fc=aux.counter, hash=digest, mac=raw.hex())
            return True
        except Exception:
            self._disconnect('radio_submission_fault', retry=False)
            return False

    def _disconnect(self, reason, *, retry):
        self.connected = False
        self.state, self.reason = ('disconnected' if retry else 'blocked'), reason
        self._next_open = self.clock.now_ms() + self.reconnect_ms
        if self.channel:
            self.channel.close(reason)
        self.channel = None
        pending, self._pending = self._pending, {}
        self._commands.clear()
        self._wire_waiting = None
        self._history.clear()
        for records in self._held_rx.values():
            records.clear()
        try:
            self.health_handler(False, reason)
        except Exception:
            pass  # Failure callbacks still must be attempted for every TX.
        for p in pending.values():
            if p.callback:
                try:
                    self.completion_hook(self.by_slot[p.slot], p.tx_id, -1, {})
                except Exception:
                    pass
                try:
                    p.callback(p.tx_id, -1)
                except Exception:
                    pass

    def _finish(self, identifier, kind, fields):
        p = self._pending.pop(identifier)
        if self._wire_waiting == identifier:
            self._wire_waiting = None
        self._history[identifier] = (kind, fields.copy())
        if len(self._history) > self.result_history:
            self._history.popitem(last=False)
        return p

    def _record(self, kind, f):
        if self.firmware_version<33 and kind=='STATUS' and (
                'late_join_restartable' in f or 'config_generation' in f):
            raise SerialFault('radio_unexpected_status_extension')
        if self.boot is not None and f['boot'] != self.boot:
            raise SerialFault('radio_boot_changed')
        if f.get('rx_drop', '0') != '0' or f.get('out_drop', '0') != '0':
            raise SerialFault('radio_capture_loss')
        if kind == 'RX':
            revision = number(f, 'revision')
            if self.state == 'handshake':
                return  # Pre-handshake bytes cannot reach the core.
            # INFO is a capture-counter snapshot, not the last emitted RX.
            # Records already captured may still be in the USB/output queue.
            # Drop that pre-handshake tail without decrypting or crediting it.
            if self._snapshot_fence is not None and revision <= self._snapshot_fence:
                return
            if self._revision is not None and revision != self._revision + 1:
                raise SerialFault('radio_rx_revision_gap')
            self._snapshot_fence = None
            self._revision = revision
            if f['channel'] != '21' or f['fcs_ok'] != '1' or f['deadline_miss'] != '0':
                raise SerialFault('radio_rx_integrity')
            if number(f, 'config_generation') != self._config_generation or f['session'] != '1':
                raise SerialFault('radio_rx_binding_changed')
            if not self.connected:
                return
            raw = mac_bytes(f['mac'])
            try:
                mac = MAC.parse(raw)
            except ValueError:
                return  # Beacon/ACK/non-application frames are not core input.
            b = self.by_pan.get(mac.destination_pan)
            if b is None:
                if f['ctx'] != 'none':
                    raise SerialFault('radio_wrong_rx_context')
                return
            if mac.source_pan != b.pan or f['ctx'] not in ('none', str(b.slot)):
                raise SerialFault('radio_wrong_rx_context')
            if f['ctx'] != 'none' and mac.destination != b.short:
                raise SerialFault('radio_wrong_rx_tuple')
            if b.slot not in self.active_slots:
                return  # Discovery-only context is not an application session.
            if any(p.slot == b.slot and p.verb == 'TYPE07_FAN' for p in self._pending.values()):
                if len(self._held_rx[b.slot]) >= self.limits.ingress_records:
                    raise SerialFault('radio_result_rx_overflow')
                self._held_rx[b.slot].append((raw, f.copy()))
            else:
                if b.slot in self._confirmation_after:
                    f['confirmation_after_us'] = self._confirmation_after[b.slot]
                self.receiver(b.context_id, raw, f)
            return
        if kind in ('AUTO_ACCEPT', 'AUTO_DONE'):
            raise SerialFault('radio_unexpected_recovery_poll')
        identifier = number(f, 'id')
        p = self._pending.get(identifier)
        if kind == 'ERROR':
            # V28/V29's actual fail path stops both contexts on id_reused.
            # Never probe an active session with guesses; carry the owned id.
            raise SerialFault('radio_firmware_error:' + f['reason'])
        if p is None:
            if self._history.get(identifier) == (kind, f):
                return
            raise SerialFault('radio_unknown_or_conflicting_result')
        if kind == 'INFO' and p.verb == 'INFO':
            expected = dict(identity=self.firmware_identity, version=str(self.firmware_version), wire='10', contexts='2',
                            channel='21', crypto='host_only', application_tx=self.application_tx, pending_tx='0')
            if any(f.get(k) != v for k, v in expected.items()):
                raise SerialFault('radio_firmware_mismatch')
            if self.boot is not None and self.boot != f['boot']:
                raise SerialFault('radio_recovery_required_new_boot')
            self.boot = f['boot']
            self._finish(identifier, kind, f)
            if f['session'] != '1' or number(f, 'config_generation') == 0:
                raise SerialFault('radio_explicit_recovery_required')
            self._config_generation = number(f, 'config_generation')
            self._revision = number(f, 'rx_revision')
            self._snapshot_fence = self._revision
            self.state = 'verifying'
            for slot in sorted(self.active_slots):
                self._send('STATUS', slot, session=1)
            return
        if f.get('ctx') != str(p.slot) or f.get('session') != '1':
            raise SerialFault('radio_wrong_result_context')
        if kind == 'STATUS' and p.verb == 'STATUS':
            b = self.by_slot[p.slot]
            if (f['recovery'] != 'PARENT_LINK_ACTIVE' or number(f, 'generation') != b.generation
                    or f['assigned_short'] != f'{b.short:04x}' or f['state'] != 'RECOVERY'
                    or f['quarantine'] != '0' or f['reboot_required'] != '0'
                    or f['rx_cutoff_stalled'] != '0'):
                raise SerialFault('radio_context_not_active')
            now_us = number(f, 'time_us')
            backwards = (self._radio_time is not None and
                         (now_us - self._radio_time) & 0xffffffff >= 0x80000000)
            if ((self.firmware_version < 30 and now_us >= 3800 * 1000000)
                    or backwards):
                raise SerialFault('radio_session_budget_exhausted')
            self._radio_time = now_us
            self._finish(identifier, kind, f)
            self._checked.add(p.slot)
            if self._checked == self.active_slots and not self.connected:
                self.connected, self.state = True, 'active'
                now = self.clock.now_ms()
                self._poll_due = {0: now + 1250, 1: now + 1875}
                self._status_due = {0: now + 10000, 1: now + 10500}
                self.health_handler(True, None)
            return
        if p.raw is None or kind not in ('TXACCEPT', 'TXDONE'):
            raise SerialFault('radio_unexpected_receipt')
        if kind == 'TXACCEPT':
            if (f['class'] != p.verb or mac_bytes(f['mac']) != p.raw or f['retry'] != '0'):
                raise SerialFault('radio_tx_accept_mismatch')
            p.accepted = True
            return
        if not p.accepted or f['cleanup'] != 'safe' or f['reboot_required'] != '0':
            raise SerialFault('radio_tx_cleanup_or_acceptance')
        if f['result'] not in ('local_tx_ok', 'no_ack', 'cca_fail', 'invalid_ack', 'aborted', 'error',
                               'watchdog', 'end', 'usb', 'loss'):
            raise SerialFault('radio_unknown_tx_result')
        if p.verb == 'TYPE07_FAN' and f['result'] == 'local_tx_ok':
            if self.firmware_version < 30 and number(f, 'rf_start_us') == 0:
                raise SerialFault('radio_missing_rf_start')
        if p.verb == 'MANAGEMENT_POLL' and f['result'] == 'local_tx_ok':
            if (f['ack_present'] != '1' or number(f, 'ack_dsn', 255) != p.raw[2]
                    or number(f, 'ack_fcf', 65535) & 7 != 2):
                raise SerialFault('radio_poll_ack_mismatch')
        clean_miss = (self.firmware_version >= 32 and f['result'] in ('no_ack', 'invalid_ack', 'cca_fail'))
        local_status = 0 if f['result'] == 'local_tx_ok' else -2 if clean_miss else -1
        if p.callback:
            self._confirmation_after[p.slot] = f['rf_start_us']
            self.completion_hook(self.by_slot[p.slot], p.tx_id,
                                 local_status, f)
        self._finish(identifier, kind, f)
        if p.verb == 'MANAGEMENT_POLL':
            # USB/scheduler delay can spend most of an enqueue-based period.
            # Anchor the next poll to observed completion, so a delayed poll
            # cannot be followed by a catch-up poll inside the firmware's 1 s
            # minimum. Missed periods are never made up in a burst.
            self._poll_due[p.slot] = self.clock.now_ms() + 1250
        if (self.firmware_version >= 31 and p.verb == 'TYPE07_FAN'
                and f['result'] == 'local_tx_ok'):
            self._poll_misses[p.slot] = 0  # matches V31's parent ACK success
        if self.firmware_version >= 30 and p.verb == 'MANAGEMENT_POLL':
            if f['result'] == 'local_tx_ok':
                self._poll_misses[p.slot] = 0
            elif f['result'] in ('no_ack', 'invalid_ack', 'cca_fail'):
                self._poll_misses[p.slot] = min(0xffffffff, self._poll_misses[p.slot] + 1)
                if self.firmware_version < 32 and self._poll_misses[p.slot] >= 3:
                    raise SerialFault('radio_parent_link_lost')
            else:
                raise SerialFault('radio_poll_failed_or_unknown')
        if p.callback:
            p.callback(p.tx_id, local_status)
            held = self._held_rx[p.slot]
            while held:
                raw, fields = held.popleft()
                fields['confirmation_after_us'] = f['rf_start_us']
                self.receiver(self.by_slot[p.slot].context_id, raw, fields)

    def pump(self):
        self._owner_only()
        if self.stopped:
            return
        if self.channel is None:
            if self.state == 'disconnected' and self.clock.now_ms() >= self._next_open:
                self.open()
            return
        try:
            if self._wire_waiting is None and self._commands:
                identifier, line = self._commands.popleft()
                self._wire_waiting = identifier
                self._pending[identifier].deadline = self.clock.now_ms() + self.response_ms
                self.channel.submit_line(line)
            self.channel.pump()
            while (line := self.channel.pop_line()) is not None:
                kind, fields = parse_record(line)
                self.record_observer(kind, fields.copy())
                self._record(kind, fields)
            if any(p.deadline and self.clock.now_ms() >= p.deadline for p in self._pending.values()):
                raise SerialFault('radio_result_timeout')
            if self.connected:
                now = self.clock.now_ms()
                for slot in sorted(self.active_slots):
                    if any(p.slot == slot for p in self._pending.values()):
                        continue
                    b = self.by_slot[slot]
                    if now >= self._status_due[slot]:
                        self._send('STATUS', slot, session=1)
                        self._status_due[slot] = now + 10000
                    elif now >= self._poll_due[slot]:
                        self._dsn[slot] = (self._dsn[slot] + 1) & 255
                        raw = bytes([0x63, 0x88, self._dsn[slot]]) + b.pan.to_bytes(2, 'little') + b'\0\0' + b.short.to_bytes(2, 'little') + b'\x04'
                        self._send('MANAGEMENT_POLL', slot, raw=raw, session=1,
                                   generation=b.generation, dsn=self._dsn[slot])
                        self._poll_due[slot] = now + 1250
        except Exception as exc:
            reason = str(exc) if isinstance(exc, SerialFault) else 'radio_handler_fault'
            self._disconnect(reason, retry=reason in ('serial_io_error', 'serial_disconnected', 'radio_parent_link_lost'))

    def close(self):
        self._owner_only()
        if self.stopped:
            return
        # CDC close makes the reviewed firmware stop both contexts and ACK.
        self.stopped = True
        if self.channel is None and self.state in ('blocked','disconnected'):
            return  # Preserve the original diagnostic after prior cleanup.
        self._disconnect('radio_shutdown', retry=False)


def serial_port_factory(name):
    import serial
    return serial.Serial(name, 115200, timeout=0, write_timeout=0.25)


def bootstrap_port_factory(port, opener=serial_port_factory):
    """Handoff the open recovery port once; a reconnect opens a NEW handle."""
    first = port
    def open_port(name):
        nonlocal first
        if first is not None:
            current, first = first, None
            return current
        return opener(name)
    return open_port
