"""Bounded absolute setters over V32. Never replay ciphertext or relative actions."""
from collections import deque
from .device import AirNannyDevice
from .events import CommandAccepted, CommandCompleted
from .outgoing import secured_frame
from .lifecycle import RadioSession
from .commands import build, CommandError, DEFAULT_WINDOW_MS, TEMP_POWER_WINDOW_MS, FRESH_MS
from .application import Type06, Type07, checksum
from .confirmation import Confirmation


class RetryingCommandDevice(AirNannyDevice):
    ATTEMPTS = 3
    PAUSES_MS = (2000, 5000)

    def __init__(self, config, clock, transport, counters, *, rollover_successor=0):
        if type(rollover_successor) is not int or rollover_successor not in (0, 2):
            raise ValueError('explicit reviewed rollover profile required')
        self.rollover_successor = rollover_successor
        self._radio = transport
        self._attempt = 0
        self.attempt_tx_id = None
        self._due = None
        self._pause = False
        self._inside_send = False
        self._wait_ms = None
        self._confirmed_sequences = deque(maxlen=128)
        self._remembered_completion = None
        self._sequence_wait = False
        self._radio_wait = False
        self._last_status_was_raw = False
        self.cached_stock_status_ignored = 0
        # The frozen core's first dispatch still builds and validates the setter.
        # Only this service device intercepts its physical submissions.
        class Sender:
            def send_frame(_, context, raw, tx_id, completion):
                return self._send_attempt(context, raw)
        super().__init__(config, clock, Sender(), counters)

    def queue(self, request):
        outcome = super().queue(request)
        if isinstance(outcome, CommandAccepted):
            self._attempt = 0
            self._due = None
            self._pause = False
            self.attempt_tx_id = None
            self._sequence_wait = False
            self._radio_wait = False
        return outcome

    def _reuses_confirmed_sequence(self):
        # A fresh secured TC packet can carry an older application snapshot
        # for the stock remote. Do not derive another logical setter using a
        # number we already confirmed in this remote generation. No guessed
        # skip/max arithmetic: wait for a usable real status instead.
        return (self.status is not None
                and self._next_sequence(self.status.sequence) in self._confirmed_sequences)

    def _next_sequence(self, sequence):
        return self.rollover_successor if sequence == 255 else (sequence + 1) & 255

    def dispatch(self):
        if self.intent is not None and self._reuses_confirmed_sequence():
            self._sequence_wait = True
            self._radio_wait = False
            return None  # No FC reservation, encryption or physical submission.
        if self.intent is not None and not self._radio_ready():
            self._radio_wait = True
            self._sequence_wait = False
            return None  # A local management poll must settle before crypto.
        self._sequence_wait = False
        self._radio_wait = False
        if self.rollover_successor == 2 and self.status is not None and self.status.sequence == 255:
            return self._dispatch_observed_rollover()
        return super().dispatch()

    def _dispatch_observed_rollover(self):
        # Selected service profile. Reuse the frozen preflight and preserve every
        # payload field except the observed successor and its app checksum.
        # This happens BEFORE counter allocation/encryption, never by altering
        # already-secured bytes or fabricating a received status.
        if self.intent is None:
            return self.result
        request, self.intent = self.intent, None
        try:
            if self.baseline.generation != self.intent_generation:
                raise CommandError('newer_remote_generation')
            if self.clock.now_ms() - self.intent_ms >= 45000:
                raise CommandError('tx_error')
            if request.kind != 'power' and self.status is not None:
                self.baseline.observe(self.status, self.rx_revision)
            tx = build(request, self.baseline, self.status, self.age_ms, self.config.controller_short)
            raw = bytearray(tx.raw); raw[6] = 2
            tx = Type07(checksum(raw))
        except CommandError as exc:
            self.result = self._failure(exc.reason)
            return self.result
        window = self.config.timeout_ms.get(request.kind,
            TEMP_POWER_WINDOW_MS if request.kind in ('temp', 'power') else DEFAULT_WINDOW_MS)
        self.confirmation = Confirmation(request, tx, self.baseline.frame, self.baseline.generation,
                                         self.rx_revision, self.clock.now_ms(), window)
        try:
            raw = secured_frame(self.config, tx, self.counters)
        except (ValueError, OverflowError):
            self.confirmation.local_status = -1
            self.confirmation.failure = 'internal'
            self.tick()
            return self.result
        try:
            submitted = self.transport.send_frame(self.config.context.identity, raw, self.tx_id, self.local_complete)
        except Exception:
            submitted = False
        if not submitted:
            self.confirmation.local_status = -1
            self.confirmation.failure = 'tx_error'
            self.tick()
        return self.result

    def _radio_ready(self):
        radio = self._radio
        if isinstance(radio, RadioSession):
            if not radio.running:
                return False
            radio = radio.backend  # Readiness only; sends retain lifecycle gating.
        ready = getattr(radio, 'application_ready', lambda ctx: True)
        return ready(self.config.context.identity)

    def _receive_validated(self, decoded):
        if self._is_cached_stock_status(decoded):
            # Durable ingress has already consumed this authenticated packet's
            # replay floor. Retain the actual fresh RAW response and its ORIGINAL
            # timestamp/revision, never synthesize or refresh a status.
            self.cached_stock_status_ignored += 1
            return False
        accepted = super()._receive_validated(decoded)
        if accepted and decoded.application.type == 6:
            self._last_status_was_raw = decoded.mac.destination == self.config.context.local_short
        if accepted and decoded.application.type == 7:
            # A new authenticated stock generation has priority and may reuse
            # an old number. Histories never survive a new service cycle.
            self._confirmed_sequences.clear()
        return accepted

    def _is_cached_stock_status(self, decoded):
        ctx = self.config.context
        if (decoded.application.type != 6 or decoded.context != ctx.identity
                or decoded.security.source_ieee != ctx.coordinator_ieee
                or decoded.mac.source != 0 or decoded.nwk.source != ctx.coordinator_short
                or decoded.mac.destination != self.config.controller_short
                or decoded.nwk.destination != self.config.controller_short
                or not self._last_status_was_raw or self.status is None
                or self.age_ms is None or not 0 <= self.age_ms <= FRESH_MS
                or not self._confirmed_sequences
                or self._confirmed_sequences[-1] != self.status.sequence):
            return False
        incoming = Type06(decoded.application.serialize())
        return (incoming.sequence != self.status.sequence
                and self._next_sequence(incoming.sequence) in self._confirmed_sequences
                and incoming.known_key() == self.status.known_key()
                and incoming.target_tenths == self.status.target_tenths
                and incoming.humidifier_raw == self.status.humidifier_raw
                and incoming.flags == self.status.flags)

    def _remember_confirmation(self):
        if (isinstance(self.result, CommandCompleted)
                and self.result.tx_id != self._remembered_completion):
            self._confirmed_sequences.append(self.result.application_sequence)
            self._remembered_completion = self.result.tx_id

    def _send_attempt(self, context, raw):
        self._attempt += 1
        token = f'{self.tx_id}/attempt-{self._attempt}'
        self.attempt_tx_id = token
        self._pause = False
        c = self.confirmation
        if self._attempt == 1:
            self._wait_ms = c.window_ms
            c.window_ms = self.ATTEMPTS*self._wait_ms + sum(self.PAUSES_MS)
        self._due = self.clock.now_ms() + self._wait_ms
        # One logical confirmation stays open during pauses, so a late valid
        # status cancels the remaining sends. Remote generation checks persist.
        self._inside_send = True
        try:
            return self._radio.send_frame(context, raw, token,
                lambda identifier, status: self._complete_attempt(token, identifier, status))
        finally:
            self._inside_send = False

    def _complete_attempt(self, token, identifier, status):
        if token != self.attempt_tx_id or token != identifier:
            return
        # A remote may cancel the logical request before the terminal radio
        # callback arrives. Settle that exact attempt even after cancellation;
        # Confirmation preserves the existing failure and tick cannot retry it.
        # -2 is issued ONLY for a terminal clean RF miss. A subsequent
        # authenticated matching TYPE06 proves execution even if MAC ACK lost.
        self.confirmation.complete(0 if status == -2 else status,
                                   self.baseline.generation, self.clock.now_ms())
        self.tick()

    def tick(self):
        if (self._sequence_wait and self.intent is not None
                and self.clock.now_ms() - self.intent_ms >= 45000):
            self.intent = None
            self.result = self._failure('stale_status_sequence')
            self._sequence_wait = False
        super().tick()
        self._remember_confirmation()
        if self._radio_wait and self.intent is not None and self._radio_ready():
            self.dispatch()
        if (self._sequence_wait and self.intent is not None
                and not self._reuses_confirmed_sequence()):
            self.dispatch()
        c = self.confirmation
        if (self._inside_send or c is None
                or self.result is not None or self._due is None):
            return
        now = self.clock.now_ms()
        if now < self._due:
            return
        if c.local_status is None:
            # An unknown write/completion never authorizes another attempt.
            c.failure = 'tx_error'
        elif self._attempt >= self.ATTEMPTS:
            c.failure = 'confirmation_timeout'
        elif not self._pause:
            self._pause = True
            self._due = now + self.PAUSES_MS[self._attempt-1]
            return
        else:
            if not self._radio_ready():
                return  # Keep the late-confirmation window open; burn no FC.
            try:
                conclude = getattr(self.counters, 'conclude_attempt', None)
                if conclude:
                    conclude(self)
                # Reuse the absolute application target/sequence, with fresh
                # MAC/NWK/APS/ZCL sequences and a new durably reserved FC.
                raw = secured_frame(self.config, c.tx, self.counters)
                c.local_status = None
                c.match = None
                c.rx_baseline = self.rx_revision
                if self._send_attempt(self.config.context.identity, raw):
                    return
                c.failure = 'tx_error'
            except Exception:
                c.failure = 'tx_error'
        super().tick()
        self._remember_confirmation()
