from .application import Type06, Type07
from .baseline import Baseline
from .commands import CommandRequest, CommandError, build, FRESH_MS, DEFAULT_WINDOW_MS, TEMP_POWER_WINDOW_MS
from .confirmation import Confirmation
from .config import DeviceConfig, Configuration
from .counters import FrameCounterStore
from .events import CommandAccepted, CommandCompleted, CommandFailed, StateEvent
from .outgoing import secured_frame
from .pipeline import receive
from .state import DeviceStateSnapshot, display_target
from .transport import Clock, RadioTransport


class AirNannyDevice:
    def __init__(self, config: DeviceConfig, clock: Clock, transport: RadioTransport, counters: FrameCounterStore):
        self.config, self.clock, self.transport, self.counters = config, clock, transport, counters
        self.baseline = Baseline()
        self.status = None
        self.status_ms = None
        self.rx_revision = 0
        self.events = []
        self.intent = None
        self.intent_generation = None
        self.intent_ms = None
        self.confirmation = None
        self.tx_id = None
        self.result = None
        self._request_number = 0
        self._event_key = None
        self._remote_sequence = None

    @property
    def age_ms(self):
        return None if self.status_ms is None else self.clock.now_ms() - self.status_ms

    @property
    def busy(self):
        c = self.confirmation
        return self.intent is not None or c is not None and (self.result is None or c.local_status is None)

    def _failure(self, reason):
        event = CommandFailed(self.config.name, self.tx_id, reason)
        self.events.append(event)
        return event

    def queue(self, request: CommandRequest):
        self.tick()
        if self.busy: return self._failure("busy")
        try:
            if request.kind != "power" and self.status is not None:
                self.baseline.observe(self.status, self.rx_revision)
            build(request, self.baseline, self.status, self.age_ms, self.config.controller_short)
        except CommandError as exc:
            return self._failure(exc.reason)
        self.intent, self.intent_generation = request, self.baseline.generation
        self.intent_ms = self.clock.now_ms()
        self._request_number += 1
        self.tx_id = f"{self.config.context.identity}:{self._request_number}"
        self.result = None
        self.confirmation = None
        event = CommandAccepted(self.config.name, self.tx_id, request.kind)
        self.events.append(event)
        return event

    def dispatch(self):
        if self.intent is None: return self.result
        request, self.intent = self.intent, None
        try:
            if self.baseline.generation != self.intent_generation:
                raise CommandError("newer_remote_generation")
            if self.clock.now_ms() - self.intent_ms >= 45000:
                raise CommandError("tx_error")
            if request.kind != "power" and self.status is not None:
                self.baseline.observe(self.status, self.rx_revision)
            tx = build(request, self.baseline, self.status, self.age_ms, self.config.controller_short)
        except CommandError as exc:
            self.result = self._failure(exc.reason)
            return self.result
        window = self.config.timeout_ms.get(request.kind,
            TEMP_POWER_WINDOW_MS if request.kind in ("temp", "power") else DEFAULT_WINDOW_MS)
        self.confirmation = Confirmation(request, tx, self.baseline.frame, self.baseline.generation,
                                         self.rx_revision, self.clock.now_ms(), window)
        try:
            raw = secured_frame(self.config, tx, self.counters)
        except (ValueError, OverflowError):
            self.confirmation.local_status = -1
            self.confirmation.failure = "internal"
            self.tick()
            return self.result
        try:
            submitted = self.transport.send_frame(self.config.context.identity, raw, self.tx_id, self.local_complete)
        except Exception:
            # A transport exception is ambiguous: never retry or release counters.
            submitted = False
        if not submitted:
            self.confirmation.local_status = -1
            self.confirmation.failure = "tx_error"
            self.tick()
        return self.result

    def command(self, kind, value):
        try: request = CommandRequest.parse(kind, value)
        except CommandError as exc: return self._failure(exc.reason)
        accepted = self.queue(request)
        if isinstance(accepted, CommandAccepted):
            self.dispatch()
            return self.result or accepted
        return accepted

    def set_fan(self, value): return self.command("fan", value)
    def set_mode(self, value): return self.command("mode", value)
    def set_temp(self, value): return self.command("temp", value)
    def set_humidifier(self, value): return self.command("humidifier", value)
    def set_night(self, value): return self.command("night", value)
    def set_power(self, value): return self.command("power", value)

    def local_complete(self, tx_id: str, status: int):
        if self.confirmation is None or tx_id != self.tx_id: return
        self.confirmation.complete(status, self.baseline.generation, self.clock.now_ms())
        self.tick()

    def tick(self):
        if self.intent is not None and self.clock.now_ms() - self.intent_ms >= 45000:
            self.intent = None
            self.result = self._failure("tx_error")
        c = self.confirmation
        if c is None or self.result is not None: return
        c.check(self.baseline.generation, self.clock.now_ms())
        if c.failure:
            self.result = self._failure(c.failure)
        elif c.confirmed:
            if not self.baseline.commit(c.generation, c.tx):
                self.result = self._failure("newer_remote_generation")
            else:
                if c.request.kind == "night" and self.status is not None:
                    self.baseline.observe(self.status, self.rx_revision)
                self.result = CommandCompleted(self.config.name, self.tx_id, c.match_revision, c.match.sequence)
                self.events.append(self.result)

    def invalidate_baseline(self, reason="unsafe_raw"):
        self.baseline.invalidate()
        self.tick()

    def receive_mac(self, raw: bytes):
        return self._receive_validated(receive(raw, [self.config.context]))

    def _receive_validated(self, decoded):
        # Private entry: only the authenticated/replay-checked codec calls this.
        ctx = self.config.context
        if decoded.context != ctx.identity: return False
        raw = decoded.application.serialize()
        if decoded.application.type == 7:
            frame = Type07(raw)  # length validation precedes any application mutation
            if not self.baseline.remote(frame, decoded.nwk.source, ctx.local_short): return False
            self._remote_sequence = frame.sequence
            if self.status is not None: self.baseline.observe(self.status, self.rx_revision)
            self.tick()
            return True
        if decoded.application.type != 6 or decoded.nwk.source != ctx.coordinator_short: return False
        status = Type06(raw)
        self.status, self.status_ms = status, self.clock.now_ms()
        self.rx_revision += 1
        c = self.confirmation
        if c is not None and self.result is None:
            c.observe(status, self.rx_revision, self.status_ms, self.baseline.generation, self.status_ms)
            self.tick()
        # Match V17 maintenance suppression for in-flight NIGHT and unsuccessful POWER.
        hold = c is not None and (
            c.request.kind == "night" and self.result is None or
            c.request.kind == "power" and not c.confirmed and self.baseline.generation == c.generation)
        if not hold: self.baseline.observe(status, self.rx_revision)
        key = status.known_key()
        if key != self._event_key:
            self._event_key = key
            origin = "unknown"
            if status.sequence == self._remote_sequence: origin = "remote-correlated"
            elif c is not None and status.sequence == c.tx.sequence: origin = "own-correlated"
            self.events.append(StateEvent(self.config.name, self.rx_revision, status.sequence, status.power,
                status.fan, status.mode, display_target(status.target_tenths), status.night, status.humidifier,
                self.baseline.generation, origin))
        return True

    def snapshot(self):
        s, b, age = self.status, self.baseline, self.age_ms
        return DeviceStateSnapshot(self.config.name, s is not None, age is not None and 0 <= age <= FRESH_MS,
            age, s.power if s else None, s.fan if s else None, s.mode if s else None,
            display_target(s.target_tenths) if s else None, s.night if s else None, s.humidifier if s else None,
            s.sequence if s else None, self.rx_revision, b.valid, b.remote_pending, b.generation,
            "none" if not b.valid else "live" if b.live else "captured", b.source,
            s.raw.hex() if s else None, b.frame.raw.hex() if b.frame else None, self.tx_id if self.busy else None)


class DeviceCollection:
    """N independent devices; clear MAC routing happens exactly once in the codec."""
    def __init__(self, configuration: Configuration, clock: Clock, transport: RadioTransport, counters: FrameCounterStore):
        self.devices = {c.name: AirNannyDevice(c, clock, transport, counters) for c in configuration.devices}
        self.by_context = {d.config.context.identity: d for d in self.devices.values()}

    def receive_mac(self, raw: bytes):
        decoded = receive(raw, [d.config.context for d in self.devices.values()])
        return self.by_context[decoded.context]._receive_validated(decoded)

    def tick(self):
        for device in self.devices.values(): device.tick()
