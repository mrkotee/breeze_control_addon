"""Persistent service policy. Transport gaps permit a new retained-key cycle.

Security/protocol faults latch durably and cannot trigger an automatic rejoin.
No queued command, baseline or TX bytes survive a service cycle.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
from .commands import FRESH_MS
from .daemon import AirNannyDaemon
from .lifecycle import EventLog
from .radio_daemon import RadioDaemonLoop

RECOVERABLE = frozenset(('serial_io_error', 'serial_disconnected', 'serial_open_failed',
                         'radio_parent_link_lost', 'radio_result_timeout'))

# `radio_result_timeout` is in that set, and the reason it is belongs here.
# It means the dongle did not answer a host command within three seconds.
# Arriving at this policy at all means the service was already running: a
# timeout inside a recovery chain is caught and reclassified where the chain
# is built, and never reaches here. So what was outstanding was one of the
# two commands a running service sends on its own -- STATUS every ten
# seconds, MANAGEMENT_POLL every one and a quarter -- or a single secured
# setter whose counter was spent in the durable store before it was
# submitted, recorded as handed over and never retried, and concluded by the
# daemon as unknown. Neither is a question a person can answer by reading
# it, and refusing to reopen the port makes neither safer: the counter
# cannot be reused, appliance state is still published only from the
# appliance's own reports, and the next cycle re-runs the whole recovery
# chain including the store monotonicity check. Latching it instead stopped
# the add-on dead, under a reason no acknowledgement could clear, after an
# hour of ordinary service.

# Faults an operator may clear by naming them, because they moved no secured
# state and spent no counter. A failed plaintext discovery beacon is an
# ordinary radio condition -- a busy channel -- and latching it protects
# nothing once someone has looked at it. Everything else stays latched: a
# rolled-back store, an authenticated Leave and any interrupted secured
# exchange all need a person to decide what actually happened, and that
# decision cannot be expressed as a string.
# `radio_result_timeout` is named here only so a latch an earlier version
# wrote can be cleared. This version never writes it -- it is recoverable
# above -- so the entry reaches nothing a running service can produce.
OPERATOR_CLEARABLE = frozenset(('late_join_discovery_tx_failed',
                                'radio_result_timeout'))

# Faults whose name cannot decide, but whose retained trace can. A recovery
# chain is latched under one reason whether or not anything secured went out,
# so the evidence is allowed to answer what the name cannot -- for these and
# nothing else. Named positively: a rolled-back store is not about what a
# transmission spent but about which history is real, and no trace answers
# that, so no amount of evidence may reach it.
# A recovery interrupted after a secured frame was built latches under the
# second name. Both ask the same question -- did anything secured move? --
# and both are answered by the trace rather than by the name, so both are
# here and neither is clearable without one.
EVIDENCE_CLEARABLE = frozenset(('retained_recovery_failed_or_unknown',
                                'interrupted_recovery_requires_review'))
HISTORY_LIMIT = 64
RESULT_LIMIT = 256

# How often the service loop runs. Every pass drains the serial port, pumps
# MQTT and ticks the daemon, and the tick is not cheap: the reviewed adapter
# decides what to publish by serialising each device's state and diagnostics
# and comparing the bytes, so a pass costs two JSON encodings per device
# whether or not anything changed. At the original 5 ms that is sixteen
# hundred encodings a second, which measured as a fifth of a Raspberry Pi
# core doing nothing.
#
# The two deadlines this must stay well inside are both far away: a pending
# transmission is given 3000 ms to be answered, and a dropped transport
# reopens after 2000 ms. The firmware's own output queue is not a constraint
# here -- it drains into USB independently of when this process reads, and
# the bytes wait in the kernel buffer, not in its 32-line ring.
# What a retry reason means and what to do about it. An appliance has no
# shell, so a reason nobody can act on is only slightly better than silence.
# Reasons absent from here are still reported; they just carry no remedy.
# Reasons whose own evidence showed the cycle spent no counter and moved no
# secured state. Waiting longer is no answer to them: the channel was busy
# for forty milliseconds, or one frame went unanswered. A prompt retry costs
# a counter block out of four billion and a few seconds; the exponential
# schedule costs minutes of a device sitting unavailable in Home Assistant
# over a collision. Bounded, so a parent that is genuinely gone still
# reaches the slow schedule rather than being polled forever.
TRANSIENT_REASONS = frozenset(('clean_recovery_RF_loss_new_cycle_required',
                               'recovery_response_timeout_new_cycle_required',
                               'recovery_answer_unacknowledged_new_cycle_required',
                               'recovery_handshake_interrupted_new_cycle_required',
                               'target_beacon_unavailable'))
PROMPT_RETRIES = 6

REMEDIES = {
    'dongle_in_bootloader':
        'the dongle is in its DFU bootloader: the runtime firmware is not'
        ' running. Flash it and replug.',
    'dongle_absent':
        'no dongle with the pinned USB identity is present.',
    'serial_open_failed':
        'the dongle is present but its serial port could not be opened.',
    'recovery_answer_unacknowledged_new_cycle_required':
        'the unit answered and the acknowledgement did not get back to it.'
        ' Ordinary radio loss; the next cycle asks again.',
    'recovery_handshake_interrupted_new_cycle_required':
        'a frame arrived on the air before the dongle answered the opening'
        ' query. Nothing was commanded but that query; the next cycle starts'
        ' the handshake again.',
    'radio_result_timeout':
        'the dongle stopped answering the host within three seconds. The'
        ' port is reopened and the recovery chain run again. If a command'
        ' was outstanding -- the preceding HEALTH line says cmd=pending --'
        ' its outcome is unknown and it is not retried; the appliance keeps'
        ' reporting its own state.',
}

POLL_INTERVAL_MS = 20
POLL_INTERVAL_BOUNDS = (1, 200)


def poll_interval_ms(value, default=POLL_INTERVAL_MS):
    """The loop interval, from an operator-supplied value or the default.

    Refused rather than clamped: a value outside the bounds means someone
    expected something this service will not do, and silently substituting
    a different number would hide that.
    """
    if value in (None, ''):
        return default
    try:
        interval = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError('poll interval must be whole milliseconds') from None
    low, high = POLL_INTERVAL_BOUNDS
    if not low <= interval <= high:
        raise ValueError('poll interval must be %d-%d ms' % (low, high))
    return interval


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


# What an operator needs to see happen, out of everything the daemon records.
# state_changed and availability_changed are left out on purpose: the first
# fires on every reception and the second on every ordinary gap between two
# of them, and the HEALTH line already carries the transitions that matter.
ANNOUNCED_EVENTS = ('command_received', 'command_held', 'command_accepted',
                    'command_failed', 'mqtt_connect', 'mqtt_disconnect',
                    'daemon_start', 'daemon_stop')


class AnnouncingEventLog(EventLog):
    """The daemon's own event log, with the operator-visible events printed.

    Keeping every event in a bounded deque is right for a process somebody
    can attach to. Nobody can attach to this one: there is no shell on the
    appliance, so a command that failed and a broker that went away were
    being recorded exactly where no one could read them.
    """

    def __init__(self, announce, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.announce = announce

    def emit(self, category, **fields):
        super().emit(category, **fields)  # validates the fields first
        if category not in ANNOUNCED_EVENTS or self.announce is None:
            return
        try:
            self.announce(event_line(category, fields))
        except Exception:
            pass  # An instrument must not be the thing that stops the service.


def event_line(category, fields):
    device, command = fields.get('device'), fields.get('command')
    reason = fields.get('reason')
    if category.startswith('command_'):
        line = 'COMMAND %s %s %s' % (device, command, category[len('command_'):])
    else:
        line = category.replace('_', ' ').upper()
    return line if not reason else line + ': ' + reason


# How long a command may wait for the appliance's next report before it is
# handed to the core anyway. One full reporting cycle and a little margin:
# an A7 reports about every twenty seconds, and the point is to ask the
# question at a moment when it can be answered, not to sit on it.
COMMAND_HOLD_MS = 25000


def status_too_old(device):
    """Would the reviewed preflight refuse this device for staleness alone?

    The same expression build() opens with, and deliberately only that one:
    every other thing it refuses for -- an invalid baseline, a pending remote
    change, a state mismatch -- is a condition waiting will not mend, and
    delaying those would only delay an answer the operator should have now.
    """
    age = device.age_ms
    return device.status is None or age is None or not 0 <= age <= FRESH_MS


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
        # Commands waiting only for the appliance's next report.
        self._held_commands = []
        # Attached after construction, because the document needs the durable
        # stores and the service state that only the launcher holds.
        self.diagnostics = None

    def transient(self, topic, payload):
        bounded_transient(self, topic, payload)

    def _message(self, message):
        """Hold a command whose only problem is that we are between reports.

        The reviewed core refuses to build a setter from a snapshot older
        than the confirmation bound, and it is right to: a setter carries the
        whole state with one field changed, so an old one would write back
        something that may already have moved. But the appliance reports on
        its own schedule, about every twenty seconds, and that bound is
        fifteen -- so a quarter of all commands met a picture a few seconds
        too old and were refused outright, with the device sitting there
        available in Home Assistant.

        Nothing here decides anything about the command. It is handed to the
        same reviewed path, unchanged, either when a current report makes the
        answer meaningful or when the wait runs out -- and then it is refused
        exactly as it is today. This is what the retrying device already does
        one layer down when a sequence is not yet usable: wait for a real
        status rather than guess.
        """
        pair = self.command_topics.get(message.topic)
        if (self.running and self.accepting and pair is not None
                and not message.retained and not message.duplicate
                and status_too_old(pair[0].device)):
            self.log.emit('command_held', device=pair[0].device.config.name,
                          command=pair[1])
            self._held_commands.append((self.clock.now_ms(), message))
            return
        super()._message(message)

    def release_held_commands(self, *, now=None):
        """Hand over every held command a report, or the clock, has settled."""
        if not self._held_commands:
            return
        now = self.clock.now_ms() if now is None else now
        waiting, ready = [], []
        for held_ms, message in self._held_commands:
            pair = self.command_topics.get(message.topic)
            if (pair is not None and self.running and self.accepting
                    and status_too_old(pair[0].device)
                    and now - held_ms < COMMAND_HOLD_MS):
                waiting.append((held_ms, message))
            else:
                ready.append(message)
        self._held_commands = waiting
        for message in ready:
            super()._message(message)

    def shutdown(self):
        if not self.stopped:
            # Answer what is still waiting rather than swallow it. Handed to
            # the reviewed path while the daemon is still running, it is
            # refused as shutting_down, which is an answer; dropping it
            # silently is not.
            self.accepting = False
            self.release_held_commands()
        super().shutdown()

    def _connection(self, connected):
        # The reviewed handler re-establishes the retained device documents
        # and the discovery messages it owns; everything added here follows
        # it, never instead of it.
        super()._connection(connected)
        if not (connected and self.running):
            return
        from .appliance_discovery import entities
        from .mqtt_schema import encode
        for topic, payload in entities(self.config).items():
            self.publish(topic, encode(payload), True)
        if self.diagnostics is not None:
            self.diagnostics.announce()


class RadioServiceSession(RadioDaemonLoop):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mqtt_due = 0
        self.diagnostics = None

    def pump(self):
        super().pump()
        self.daemon.release_held_commands()
        late_join=getattr(self,'late_join',None)
        if late_join is not None:
            late_join.pump()
        prune_consumed_events(self.daemon)
        now = self.radio.clock.now_ms()
        if not self.daemon.mqtt.connected and now >= self.mqtt_due:
            self.mqtt_due = now + 5000
            self.daemon.reconnect()
        if self.diagnostics is not None:
            self.diagnostics.pump()

    def close(self):
        # Published while the broker is still reachable: a retained document
        # left saying ACTIVE after a deliberate stop reads as a crash.
        if self.diagnostics is not None:
            self.diagnostics.stopping()
        super().close()


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


RECOVERY_FRAMES = {'REJOIN': ('REJOIN_REQUEST', 34), 'ANNOUNCE': ('DEVICE_ANNOUNCE', 18),
                   'TIMEOUT': ('END_DEVICE_TIMEOUT', 34)}


def sent_frame_proven(records, record, slot, name, intent):
    """One recovery intent whose frame the firmware accepted and finished.

    The durable intent and the serial record have to agree about the same
    single frame: one acceptance, one terminal result, the same radio clock,
    the same bytes and the same frame counter, over a block already spent.
    Anything less is not a known lifecycle, and an unknown one is never the
    evidence for retrying.
    """
    if (intent.get('phase') != 'SENT' or intent.get('result') != 'local_tx_ok'
            or intent.get('block_end', record['next_fc']) >= record['next_fc']):
        return False
    verb, offset = RECOVERY_FRAMES[name]
    accepts = [r['fields'] for r in records if r.get('kind') == 'TXACCEPT'
               and r['fields'].get('ctx') == str(slot) and r['fields'].get('class') == verb]
    if len(accepts) != 1:
        return False
    accepted = accepts[0]
    done = [r['fields'] for r in records if r.get('kind') == 'TXDONE'
            and r['fields'].get('ctx') == str(slot) and r['fields'].get('id') == accepted.get('id')]
    if len(done) != 1:
        return False
    terminal = done[0]
    try:
        raw = bytes.fromhex(accepted['mac'])
        return not (terminal.get('result') != 'local_tx_ok' or terminal.get('cleanup') != 'safe'
                    or terminal.get('reboot_required') != '0'
                    or intent.get('radio_end_us') != int(terminal['time_us'])
                    or intent.get('sha256') != hashlib.sha256(raw).hexdigest()
                    or intent.get('fc') != int.from_bytes(raw[offset:offset+4], 'little'))
    except (KeyError, ValueError):
        return False


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
        if slot != missing and q.get('state') == 'DISCOVERING':
            # Partial startup: a slot inside this cycle that has declared
            # nothing and submitted nothing has nothing to prove. Demanding a
            # settled peer chain here latched an unanswered request over a
            # cycle in which the other context never got as far as asking.
            if intents:
                return False
            continue
        expected = {'REJOIN'} if kind == 'REJOIN' else {'REJOIN','ANNOUNCE','TIMEOUT'}
        if slot != missing:expected = {'REJOIN','ANNOUNCE','TIMEOUT'}
        state = ('DISCOVERING' if kind == 'REJOIN' else 'REJOINED') if slot == missing else 'PARENT_LINK_ACTIVE'
        if q.get('state') != state or set(intents) != expected:
            return False
        for name, intent in intents.items():
            if not sent_frame_proven(records, record, slot, name, intent):
                return False
    return True


def unacknowledged_answer_safe(error, ledgers, guard, records):
    """The parent answered, and this host did not acknowledge it on the MAC.

    Every other parent_answer result is the parent saying something about
    us -- rejected, a short we do not own, a keepalive method we do not
    implement -- and each of those is a decision a person has to see. This
    one says nothing about us. It says the answer arrived intact and our own
    radio did not get an acknowledgement back out, which is ordinary loss in
    the inbound direction.

    Nothing of ours moved. The ledger spends that response's replay floor,
    which is monotonic and is exactly what a floor is for, and leaves the
    recovery state and the generation alone, because only an accepted answer
    advances them. The parent's own MAC retransmission cannot rescue this
    cycle either -- the floor has passed that frame's counter -- so a new
    cycle is the only thing that can finish the join, and stopping the
    service instead stops whichever context is already serving.
    """
    prefix = 'parent_answer:MAC_ACK_NOT_CLEAN ctx='
    text = str(error)
    if not text.startswith(prefix) or not records:
        return False
    named, _, detail_text = text[len(prefix):].partition(' ')
    try:
        named = int(named)
        detail = ast.literal_eval(detail_text)
    except (SyntaxError, ValueError):
        return False
    if named not in (0, 1) or type(detail) is not dict:
        return False
    if any(r.get('kind') == 'ERROR' or
           any(r.get('fields', {}).get(k, '0') != '0' for k in ('rx_drop', 'out_drop', 'reboot_required'))
           or r.get('fields', {}).get('cleanup') == 'unproven' for r in records):
        return False
    # The fault's own premise, read from the record rather than believed:
    # one reception, on this context, intact, whose acknowledgement was not
    # the clean triple. A record that does not show that is a different
    # failure wearing this name.
    answers = [r['fields'] for r in records if r.get('kind') == 'RX'
               and r['fields'].get('ctx') == str(named)
               and r['fields'].get('revision') == str(detail.get('revision'))]
    if len(answers) != 1 or answers[0].get('fcs_ok') != '1':
        return False
    acknowledgement = tuple(answers[0].get(k) for k in ('ack_started', 'ack_completed', 'deadline_miss'))
    if None in acknowledgement or acknowledgement == ('1', '1', '0'):
        return False
    for context, ledger in ledgers.items():
        record = ledger.read();q = record.get('recovery') or {}
        if q.get('leave') or q.get('state') == 'DEGRADED_LEAVE':
            return False
        if q.get('gate') != guard:
            if context == named:return False
            continue
        intents = q.get('intents') or {}
        if context == named:
            # An unaccepted answer does not move the stage, so the slot must
            # still be standing where it asked the question.
            expected = {'DISCOVERING': {'REJOIN'},
                        'REJOINED': {'REJOIN', 'ANNOUNCE', 'TIMEOUT'}}.get(q.get('state'))
            if expected is None or set(intents) != expected:
                return False
        elif q.get('state') == 'DISCOVERING':
            # Partial startup: a slot that has declared nothing and submitted
            # nothing under this guard has nothing to prove.
            if intents:
                return False
            continue
        elif q.get('state') != 'PARENT_LINK_ACTIVE' or set(intents) != {'REJOIN', 'ANNOUNCE', 'TIMEOUT'}:
            return False
        for name, intent in intents.items():
            if not sent_frame_proven(records, record, context, name, intent):
                return False
    return True


# Faults the opening handshake raises before anything is commissioned.
HANDSHAKE_FAULTS = frozenset(('INFO_FIRST',))
# A record whose presence means the radio was engaged on our behalf.
SPENDING_RECORDS = frozenset(('TXACCEPT', 'TXDONE', 'AUTO_ACCEPT', 'AUTO_DONE', 'ERROR'))
# Host commands that ask the dongle something and change nothing. Named
# positively, so a verb this host has not heard of means `cannot say` rather
# than `harmless`. explain_fault keeps the same list for the same reason; a
# change to one belongs in both.
QUERY_COMMANDS = frozenset(('INFO', 'STATUS', 'STATS'))


def handshake_retry_safe(error, ledgers, guard, records):
    """A failure in the opening handshake, before the radio was ever used.

    The dongle listens from the moment it boots, so an ambient frame can
    reach the host in the window between opening the port and the reply to
    the opening query -- and the wire refuses it, because the first line it
    reads is what establishes the boot identity every later line is checked
    against. Refusing is right. Latching is not: the only thing commanded
    was a query, nothing was accepted for transmission, and no recovery
    cycle was opened at all -- this guard appears in neither store, which is
    the proof that none was.
    """
    if str(error) not in HANDSHAKE_FAULTS or not records:
        return False
    if any(r.get('kind') in SPENDING_RECORDS for r in records):
        return False
    for record in records:
        if record.get('kind') != 'HOST_COMMAND':
            continue
        parts = (record.get('raw') or '').split()
        if len(parts) < 2 or parts[1] not in QUERY_COMMANDS:
            return False
    for ledger in ledgers.values():
        q = ledger.read().get('recovery') or {}
        if q.get('leave') or q.get('state') == 'DEGRADED_LEAVE' or q.get('gate') == guard:
            return False
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
        if slot == missing or q.get('state') == 'DISCOVERING':
            # The slot the error names, or -- under partial startup -- one
            # already declared offline in this same cycle. Both carry the
            # same proof: discovery submits no secured frame, so an empty
            # intent set under this guard is nothing spent. Demanding a
            # settled peer chain here latched a review-only fault over a
            # cycle that provably moved nothing, because both parents were
            # silent and neither had a chain to settle.
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
    def __init__(self, state, clock, establish, *, retry_ms=5000, announce=None):
        if type(retry_ms) is not int or retry_ms < 2000:
            raise ValueError('bounded reconnect backoff required')
        self.state, self.clock, self.establish = state, clock, establish
        # The operator's only window onto an appliance is its log, so a
        # changed reason is announced once. Injected rather than printed
        # here, so this stays testable and silent by default.
        self.announce = announce
        self.announced = None
        self.retry_ms, self.next_open = retry_ms, 0
        self.session = None
        self.stopped = False
        self.active_recorded = False
        self.retry_attempt = 0
        self.prompt_retries = 0

    def _retry(self, reason):
        if reason in TRANSIENT_REASONS and self.prompt_retries < PROMPT_RETRIES:
            # Spends the prompt budget without advancing the slow schedule,
            # so a run of collisions does not leave a later real absence
            # already backed off to five minutes.
            self.prompt_retries += 1
            delay = self.retry_ms
        else:
            delay = min(300000, self.retry_ms * (2 ** min(self.retry_attempt, 6)))
            self.retry_attempt += 1
        self.state.write('WAITING', reason=reason, retry_delay_ms=delay)
        self.next_open = self.clock.now_ms() + delay
        self._announce_once(reason)

    def _announce_once(self, reason):
        """Say a reason once, to the only window an appliance has.

        Once per distinct reason: the backoff reaches five minutes, and a
        line every cycle would bury the one that changed. Cleared when the
        service reaches ACTIVE, so the same reason occurring again is said
        again.
        """
        if self.announce is None or reason == self.announced:
            return
        self.announced = reason
        remedy = REMEDIES.get(reason)
        self.announce('WAITING: ' + reason + ('' if remedy is None else ' -- ' + remedy))

    def pump(self):
        if self.stopped:
            return
        if self.session is None:
            if self.clock.now_ms() < self.next_open:
                return
            try:
                latched = self.state.read()
                if latched['state'] == 'BLOCKED':
                    # Name it. The operator clears a latch by writing its
                    # reason back, and on an appliance there is nowhere else
                    # to read it from.
                    raise ServiceBlocked('service_fault_latched:'
                                         + (latched.get('reason') or 'unknown'))
                self.session = self.establish(self.state)
                self.active_recorded = False
            except StartupUnavailable as exc:
                # The exception names which of several conditions it was;
                # flattening them all to one reason threw that away exactly
                # where an operator needed it.
                self._retry(str(exc) or 'serial_open_failed')
                return
            except RecoveryParentLost:
                self._retry('radio_parent_link_lost_during_readiness')
                return
            except RecoveryDiscoveryUnavailable:
                self._retry('target_beacon_unavailable')
                return
            except RecoveryCleanTxLoss as exc:
                # Carried for the same reason StartupUnavailable carries its
                # own. These are different losses -- a frame that never went
                # on air, a reply that never came, an answer this host did
                # not acknowledge, a handshake a passing frame interrupted --
                # and flattening them to one name threw away the only thing
                # that tells an operator which of them is happening.
                self._retry(str(exc) or 'clean_recovery_RF_loss_new_cycle_required')
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
                # A transport dropping under a running service wrote WAITING
                # and printed nothing. The health line said the radio was
                # unavailable and never said why, which is the one thing an
                # operator needed from it.
                self._announce_once(radio.reason)
            elif radio.connected and not self.active_recorded:
                self.state.write('ACTIVE', reason=None)
                self.active_recorded = True
                self.retry_attempt = 0
                self.prompt_retries = 0
                self.announced = None
        except ServiceBlocked:
            if self.session:
                session, self.session = self.session, None
                session.close()
            raise
        except Exception:
            self.state.write('BLOCKED', reason='service_runtime_fault', trace=None)
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

    def interrupted_recovery_spent_nothing(self, ledgers, record):
        """Did an interrupted recovery cycle get as far as a secured frame?

        ContextLedger.reserve leases the counter block and records the intent
        BEFORE the frame exists -- deliberately, because a crash between the
        two loses a block, which costs nothing anyone can observe, while the
        opposite order risks a counter used twice. This reads the
        contrapositive: no intent recorded under this cycle's guard means no
        secured frame was ever built, so none was transmitted and none could
        have been acted on.

        Matched on the guard, not merely on the presence of intents. A store
        that has been commissioned carries the intents of the cycle that
        commissioned it, and begin_cycle archives those and opens a fresh
        record; intents under an older guard belong to a cycle that was
        already concluded. A guard this cycle never opened on a ledger is a
        cycle that never touched it.

        Everything that runs before the first reserve is discovery, which is
        a plaintext beacon request: it spends no counter and moves no secured
        state. Being interrupted there is the ordinary case -- an add-on
        restart lands in it -- and refusing to continue afterwards stopped
        the service until someone edited durable state by hand.
        """
        guard = record.get('guard')
        if not isinstance(guard, str) or not guard:
            return False  # no guard recorded: nothing to match, so no proof
        for ledger in ledgers.values():
            recovery = ledger.read().get('recovery') or {}
            if recovery.get('gate') == guard and recovery.get('intents'):
                return False
        return True

    def require_recovery(self, ledgers):
        record = self.read()
        if record['state'] == 'BLOCKED':
            raise ServiceBlocked('service_fault_latched:' + record.get('reason', 'unknown'))
        # A process killed while recovery was moving secured state cannot
        # automatically run another recovery chain. Inspect it explicitly --
        # unless the stores show it never got that far, which is the common
        # case and used to stop the service dead anyway.
        if record['state'] == 'RECOVERING':
            if not self.interrupted_recovery_spent_nothing(ledgers, record):
                raise ServiceBlocked('interrupted_recovery_requires_review')
            # Recorded rather than passed over in silence: the run was
            # interrupted, and that it was safe to continue is a finding.
            self.write('WAITING', reason='interrupted_recovery_resumed_nothing_spent')
            record = self.read()
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
        # Merged, not replaced: a call with one slot would otherwise erase
        # the other's baseline, and a later rollback there would find nothing
        # to compare against and be accepted.
        self.write(record['state'], stores={**seen, **current})
        return current

    def begin(self, boot, guard):
        r = self.read()
        # A new run spends the previous acknowledgement, so the same reason
        # can be acknowledged again later as a deliberate act rather than
        # being re-applied by every restart in between.
        # `trace` is cleared with the rest: it names the failure this cycle
        # recorded, and a name left over from an earlier one would let a
        # cycle that was killed outright -- writing no trace at all -- be
        # cleared on evidence belonging to something else.
        self.write('RECOVERING', cycles=r['cycles'] + 1, boot=boot, guard=guard, reason=None,
                   late_join=None, consumed_acknowledgement=None, trace=None)

    def disconnected(self, reason):
        if reason not in RECOVERABLE:
            # A fault raised while the service was already running wrote no
            # trace of its own. Leaving the previous failure's name in place
            # made the next start print that failure's summary under this
            # fault's heading, and offered its evidence to the gate that
            # decides whether this one may be cleared.
            self.write('BLOCKED', reason=reason, trace=None)
            raise ServiceBlocked(reason)
        self.write('WAITING', reason=reason)

    def acknowledge(self, reason, evidence_permits=False):
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
        # Two ways a latch can be clearable, and a reason string only answers
        # the first. Some faults are harmless by their nature. Others, like a
        # recovery chain that ended without a classifiable result, are latched
        # under one name whether or not anything secured went out -- so the
        # name cannot decide, and the retained trace has to. The caller
        # establishes that from the evidence; this records which it was.
        by_name = latched in OPERATOR_CLEARABLE
        by_evidence = evidence_permits and latched in EVIDENCE_CLEARABLE
        if not (by_name or by_evidence):
            return 'not_clearable'
        cleared = dict(record.get('cleared') or {})
        cleared[latched] = cleared.get(latched, 0) + 1
        self.write('WAITING', reason=None, cleared=cleared,
                   consumed_acknowledgement={'reason': latched, 'cycles': record.get('cycles', 0)},
                   last_cleared={'reason': latched, 'review': record.get('review'),
                                 'basis': 'reason' if by_name else 'trace_spent_nothing'})
        return 'cleared'

    def acknowledgement_spent(self, reason):
        """Has this acknowledgement already been used?

        The operator writes the reason into a field that stays where they put
        it, and the service restarts on its own. Without this, a fault that
        keeps returning is cleared again on every restart for as long as the
        field is populated -- a restart clearing a fault, which is the one
        thing the latch exists to prevent.

        Tied to the run it was used on, so the same reason can be
        acknowledged again deliberately after the service has moved on.
        """
        spent = self.read().get('consumed_acknowledgement') or {}
        return spent.get('reason') == reason


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
