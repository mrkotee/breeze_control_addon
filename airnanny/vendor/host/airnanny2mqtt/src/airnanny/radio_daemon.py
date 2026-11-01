"""Production radio loop and explicit durable ingress, around the frozen core."""
from dataclasses import replace
from collections import OrderedDict
from .application import Type06, Type07
from .aps import APS
from .binary import CodecError
from .events import CommandCompleted
from .frames import ApplicationFrame
from .mac import MAC
from .nwk import NWK
from .pipeline import DecodedFrame
from .security import decrypt, AuthenticationError
from .serial_support import SerialFault
from .zcl import ZCL


class DurableApplicationIngress:
    """One explicit context, one key and one durable replay floor before mutation.

    Supports the shipped A7 status-to-remote and remote-to-coordinator forms
    proven by issue #5 ContextFanControl, in addition to addressed RAW status.
    Unsupported authenticated traffic spends its replay floor but no app state.
    """
    def __init__(self, daemon, ledgers, remote_ieees):
        self.daemon, self.ledgers, self.remote_ieees = daemon, ledgers, remote_ieees
        self._stock_shorts = {}
        self._remote_messages = OrderedDict()

    def __call__(self, context_id, raw, fields):
        device = self.daemon.collection.by_context[context_id]
        ctx = device.config.context
        ledger = self.ledgers[context_id]
        mac = MAC.parse(raw)
        if mac.destination_pan != ctx.pan or mac.source_pan != ctx.pan:
            raise CodecError('explicit PAN context mismatch')
        try:
            nwk = NWK.parse(mac.payload)
        except CodecError:
            # Management commands include extended NWK headers unsupported by
            # the application codec. The reviewed durable observer handles
            # authenticated Leave without permitting an automatic rejoin.
            observe = getattr(ledger, 'observe_addressed', None)
            if observe and observe(raw, int(fields['revision'])) == 'LEAVE':
                raise SerialFault('radio_authenticated_leave')
            return False
        try:
            header, plain = decrypt(nwk, ctx.keys)
        except (CodecError, AuthenticationError):
            return False  # unsupported NWK or unauthenticated RF input
        if header.key_sequence != ctx.active_key_sequence:
            return False
        # Durable consumption precedes every app mutation. Identical MAC
        # retransmissions cannot mutate a second time; no trial of other keys.
        if not ledger.consume(f'{header.source_ieee:016x}', header.counter):
            return False
        identity = (header.source_ieee, ctx.key_epochs[header.key_sequence], header.key_sequence)
        ctx.incoming_high_water[identity] = header.counter
        try:
            aps = APS.parse(plain)
            zcl = ZCL.parse(aps.payload)
            if (aps.cluster, aps.profile, aps.source_endpoint, zcl.control) != (6, 0x104, 8, 0x11):
                return False
            remote = (header.source_ieee == self.remote_ieees[context_id]
                      and mac.source == nwk.source and mac.source not in (0, 0xfffd, 0xffff, ctx.local_short)
                      and mac.destination == 0 and nwk.destination == 0xfffd and nwk.fcf == 0x2208
                      and aps.control == 12 and aps.group == 10)
            if remote and zcl.command == 2 and not zcl.payload:
                # The pinned stock remote requests status without a TYPE07.
                # Learn its reassigned short after durable replay admission,
                # so status-to-remote works after restart without a button press.
                # This is address discovery only: never create a baseline or
                # cancel an in-flight command as a new remote generation.
                if device.config.controller_short != nwk.source:
                    device.config = replace(device.config, controller_short=nwk.source)
                self._stock_shorts[context_id] = nwk.source
                return False
            if zcl.command != 1:
                return False
            relay = (header.source_ieee == ctx.coordinator_ieee and mac.source == 0
                     and nwk.source == self._stock_shorts.get(context_id)
                     and mac.destination == 0xffff and nwk.destination == 0xfffd
                     and nwk.fcf == 0x208 and aps.control == 12 and aps.group == 10)
            status = (header.source_ieee == ctx.coordinator_ieee and mac.source == nwk.source == 0
                      and mac.destination == nwk.destination
                      and mac.destination in (ctx.local_short, 0xffff, device.config.controller_short)
                      and (nwk.fcf == 0x248 or nwk.fcf == 0x208 and mac.destination == device.config.controller_short)
                      and aps.destination_endpoint == 8 and aps.group is None)
            frame = Type07(zcl.payload) if remote or relay else Type06(zcl.payload) if status else None
            if frame is None:
                return False
        except ValueError:
            return False
        decoded = DecodedFrame(context_id, mac, nwk, header, aps, zcl, ApplicationFrame.parse(frame.raw))
        if remote and device.config.controller_short != nwk.source:
            # The pinned remote IEEE authenticates its newly assigned short.
            device.config = replace(device.config, controller_short=nwk.source)
        message = None
        if remote or relay:
            if remote:
                self._stock_shorts[context_id] = nwk.source
            # A7 forwards the original NWK/APS/ZCL request under its own NWK
            # security counter. Credit one stock generation for the two paths,
            # after consuming both durable replay floors. Old cached unicast
            # TYPE07 and our own echoed RAW commands cannot enter this branch.
            message = (context_id, header.key_sequence, nwk.source, nwk.sequence,
                       aps.counter, zcl.tsn, frame.raw)
            if message in self._remote_messages:
                return False
        # A queued status captured before actual RF start may update observation
        # but must never satisfy the command. Remote generations still win.
        c = device.confirmation
        after = fields.get('confirmation_after_us')
        elapsed = ((int(fields['time_us']) - int(after)) & 0xffffffff) if after is not None else None
        exclude = (status and c is not None and elapsed is not None
                   and (elapsed == 0 or elapsed >= 0x80000000))
        if exclude:
            device.confirmation = None
        try:
            result = device._receive_validated(decoded)
        finally:
            if exclude:
                device.confirmation = c
        if result and message is not None:
            self._remote_messages[message] = None
            if len(self._remote_messages) > 128:
                self._remote_messages.popitem(last=False)
        self.daemon.tick()
        return result


# How long an idle service may go without a tick. A tick that no command is
# waiting on can only republish time-derived display state -- availability and
# status age -- and those move on the appliance's own reporting cadence, tens
# of seconds apart. Running the full adapter drain for both devices fifty
# times a second spent a Raspberry Pi's CPU recomputing an answer that could
# not have changed. Every event-driven path still ticks immediately: reception
# ticks from the ingress, transport health ticks from the handler, and an
# outstanding command ticks every pump exactly as before.
IDLE_TICK_MS = 250


class RadioDaemonLoop:
    """All MQTT/radio/control mutations execute on the constructing owner thread."""
    def __init__(self, daemon, radio, ingress, *, verdict_hook=None, announce=None):
        self.daemon, self.radio = daemon, radio
        self.verdict_hook = verdict_hook or (lambda device: None)
        # Confirmation is the one outcome the daemon's own log has no category
        # for, and under a non-optimistic model it is the one that means the
        # appliance actually did it. A failure is already announced from there.
        self.announce = announce
        self._idle_due = 0
        self._recorded = {}
        radio.set_receiver(ingress)
        radio.set_health_handler(self.health)
        for adapter in daemon.adapters.values():
            adapter.context_available = False

    def health(self, available, reason):
        for adapter in self.daemon.adapters.values():
            context_available = getattr(self.radio, 'context_available', lambda ctx: True)
            adapter.context_available = available and context_available(adapter.device.config.context.identity)
            if not available:
                device = adapter.device
                device.intent = None
                if device.confirmation is not None and device.result is None:
                    device.confirmation.failure = 'tx_error'
                    device.tick()
                device.invalidate_baseline('transport_gap')
        self.daemon.tick()

    def start(self):
        self.daemon.start()
        self.radio.open()

    def pump(self):
        self.radio.pump()  # transport faults disable command handling first
        # One heartbeat decision per pump, so an idle service still ticks on
        # both sides of the MQTT drain and keeps the shape of the ordering.
        beat = self._heartbeat()
        if beat or self._outstanding():
            self.daemon.tick()
        # Recording stays on every pump: the ordering it guarantees is what
        # makes a verdict durable before the next command, and after the memo
        # below a pump with nothing new to record costs a dictionary lookup.
        self._record_verdicts()  # durable verdict before another MQTT command
        self.daemon.mqtt.pump()
        if beat or self._outstanding():
            self.daemon.tick()
        self._record_verdicts()

    def _outstanding(self):
        """Is any device still waiting on something a tick could resolve?

        Nothing outstanding means no tick can produce a verdict: the frozen
        device tick returns at once without an intent or a live confirmation.
        """
        return any(d.busy for d in self.daemon.collection.devices.values())

    def _heartbeat(self):
        now = self.daemon.clock.now_ms()
        if now < self._idle_due:
            return False
        self._idle_due = now + IDLE_TICK_MS
        return True

    def _record_verdicts(self):
        # The hook reads a durable store, and `result` stays set until the next
        # command is queued -- so calling it every pump re-read and re-parsed
        # both ledgers for the rest of the session over a verdict that was
        # concluded once. A verdict already recorded cannot change by being
        # read again; a new attempt carries a new token and is recorded again.
        for name, device in self.daemon.collection.devices.items():
            verdict = device.result
            if verdict is None:
                continue
            token = (verdict, getattr(device, 'attempt_tx_id', device.tx_id))
            if self._recorded.get(name) == token:
                continue
            self.verdict_hook(device)
            self._recorded[name] = token
            if self.announce is not None and isinstance(verdict, CommandCompleted):
                confirmation = device.confirmation
                self.announce('COMMAND %s %s confirmed' % (
                    name, confirmation.request.kind if confirmation else 'unknown'))

    def close(self):
        self.radio.close()
        self.daemon.shutdown()
