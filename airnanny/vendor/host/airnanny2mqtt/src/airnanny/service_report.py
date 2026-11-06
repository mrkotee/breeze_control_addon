"""Publish why the bridge is degraded, beside the per-device topics.

The reviewed daemon publishes one diagnostics document per A7, and each of
them answers whether that unit is online. None of them can answer why the
bridge as a whole is not working: a broker outage, an unplugged dongle, a
durable store that will not load and a unit that stopped talking all leave
the same silence on a device topic.

Everything here sits outside the reviewed daemon. The document is derived
from what the daemon already exposes and goes out through its own publish,
so the per-device topic contract, the retained documents and the discovery
messages the daemon owns are untouched. The service topic is the one the
daemon already established for its process liveness -- Topics with the
daemon id reproduces the existing availability path exactly -- so the new
document lands beside it rather than in a namespace of its own invention.

Two things this deliberately does not do. It never reads a durable store on
the hot path: the counter positions are refreshed on a bounded interval and
cached in between, because the loop pumps every few milliseconds and the
stores live on an SD card. And it never lets a reading failure stop the
service: a store that will not answer is reported as the degraded reason,
which is the whole point of having one.
"""
from .availability import availability
from .mqtt_schema import Topics, encode, state_payload
from .service_diagnostics import (ContextHealth, DEVICE_STALE, degraded_reason,
                                  service_diagnostics)

# The id the reviewed daemon already uses for its own process topic.
SERVICE_ID = 'daemon'

# A configured A7 under either of these names would collide with the service
# topics or with its Home Assistant device. The reviewed daemon has no such
# check because it published nothing under its own id except availability;
# now that a document lives there too, the clash would be silent and would
# corrupt both.
RESERVED_DEVICE_IDS = frozenset((SERVICE_ID, 'bridge'))

# Latched reasons that are a persistence failure rather than a radio one.
# Reported as the store error so the reason reads as context_store_error,
# which is what an operator has to act on, instead of being flattened into
# "the devices are unavailable".
STORE_LATCH_PREFIXES = ('store_rollback', 'service_state_invalid',
                        'service_state_readback_failed')

# Bounded on purpose: the full confirmed state has its own topic, and
# repeating it here would grow the document without telling anyone more.
CONFIRMED_FIELDS = ('power', 'fan', 'mode')

STORE_INTERVAL_MS = 5000

# How often the picture is examined at all. The loop pumps a few hundred
# times a second to drain the serial port; rebuilding the document at that
# rate would cost more than the document is worth, and nothing an operator
# reads changes meaningfully inside a quarter second.
CHECK_INTERVAL_MS = 250

# How the runtime names a context: radio_runtime builds every ZigbeeContext
# identity this way, and the durable stores are keyed by slot, so this is
# what joins a store to the adapter that speaks for it.
CONTEXT_IDENTITY = 'dual-ctx%d'

# Sentinel for "no reason has been derived yet", which None cannot express
# because None is the reason reported by a healthy service.
UNDERIVED = object()


# What a transmission reports in the ordinary course of things: the result
# that worked, and the three ordinary radio losses. Anything else is the
# firmware saying something about itself.
ORDINARY_TX_RESULTS = frozenset(('local_tx_ok', 'no_ack', 'invalid_ack', 'cca_fail'))


class NotableRecords:
    """Print the firmware's own complaints, once per distinct complaint.

    The retained trace holds all of this, but a trace is written only when a
    recovery attempt fails. A fault that latches an already-running service
    writes none — which is how an operator came to read
    `radio_poll_failed_or_unknown` with no way to learn which result caused
    it, and `internal` with no way to learn what was internal.

    Bounded by distinctness rather than by a rate: the firmware repeats
    itself, and a line per repetition would bury the next new thing. Nothing
    here is secret — a result name, a context number and a firmware reason
    are the same material the diagnostics topic already carries.
    """

    def __init__(self, observer, limit=64):
        self.observer, self.limit = observer, limit
        self.seen = set()

    def __call__(self, kind, fields, verb=None):
        token = self.token(kind, fields, verb)
        if token is None or token in self.seen or len(self.seen) >= self.limit:
            return
        self.seen.add(token)
        try:
            self.observer('FIRMWARE ' + token)
        except Exception:
            pass  # An instrument must not be the thing that stops the service.

    def token(self, kind, fields, verb=None):
        if kind == 'ERROR':
            # Which command was refused is the whole fact. Without it a
            # production refusal read `error state_or_deadline (command id
            # 1735)`, and an id says nothing about what the dongle would
            # not do.
            identifier = fields.get('id')
            named = ' '.join(part for part in (verb, None if identifier is None
                                               else 'id=%s' % identifier) if part)
            return 'error %s%s' % (fields.get('reason') or 'unstated',
                                   '' if not named else ' (%s)' % named)
        if kind in ('TXDONE', 'AUTO_DONE') and fields.get('result') not in ORDINARY_TX_RESULTS:
            return 'ctx%s %s ended %s cleanup=%s' % (
                fields.get('ctx'), kind.lower(), fields.get('result'),
                fields.get('cleanup'))
        return None


def command_block_reason(ledger):
    """Why this context can build no further setter, in words, or None.

    The durable authority refuses a reservation and the frozen device turns
    that refusal into the command failure `internal`, which names nothing.
    On an appliance that is the whole diagnosis, so the same question is
    asked again here and answered in a sentence.

    This decides nothing and is not the gate: it reads the ledger the gate
    reads and reports what it finds. If it finds nothing it says so, rather
    than inventing a reason for a refusal it cannot explain.
    """
    try:
        record = ledger.read()
        recovery = record.get('recovery') or {}
    except Exception as error:
        return 'the durable store for this context could not be read (%r)' % (error,)
    if recovery.get('state') != 'PARENT_LINK_ACTIVE':
        return ('the durable parent link is not active (recovery state %s)'
                % recovery.get('state'))
    intent = (recovery.get('intents') or {}).get('TYPE07')
    if intent is None:
        return None
    phase, result = intent.get('phase'), intent.get('result')
    if phase != 'CONCLUDED':
        return ('the previous command on this context never reached a durable'
                ' conclusion (phase %s). No further setter can be built on'
                ' this recovery cycle; restart the bridge, which reviews the'
                ' durable record before it starts another one.' % phase)
    clean = (intent.get('retry_safe') is True
             and result in ('no_ack', 'invalid_ack', 'cca_fail'))
    if not (result == 'local_tx_ok' or clean):
        return ('the previous command on this context ended with an outcome'
                ' nobody can determine (%s). No further setter can be built'
                ' on this recovery cycle; restart the bridge, which reviews'
                ' the durable record before it starts another one.' % result)
    return None


def service_topics(prefix, device_ids=()):
    """The service topics, refusing a device name that would collide."""
    clash = sorted(set(device_ids) & RESERVED_DEVICE_IDS)
    if clash:
        raise ValueError('device id reserved for the service: ' + ', '.join(clash))
    return Topics(prefix, SERVICE_ID)


def confirmed_summary(snapshot):
    payload = state_payload(snapshot)
    return {name: payload[name] for name in CONFIRMED_FIELDS}


def context_health(slot, adapter, running, *, generation=None,
                   outgoing_fc_high_water=None):
    """One context reading, derived exactly as the device topics derive it.

    The availability verdict comes from the reviewed function the daemon
    itself publishes from, so the service document cannot contradict the
    device topic it sits beside.
    """
    snapshot = adapter.device.snapshot()
    current = availability(snapshot, running, adapter.context_available)
    return ContextHealth(context=slot,
                         available=current != 'unavailable',
                         stale=current == 'stale',
                         rx_age_ms=snapshot.status_age_ms,
                         command_pending=adapter.pending is not None,
                         outgoing_fc_high_water=outgoing_fc_high_water,
                         generation=generation,
                         last_confirmed_state=confirmed_summary(adapter.released))


def context_state(fields):
    """The three-way verdict, from one context's reading in the document."""
    if not fields.get('available'):
        return 'unavailable'
    return 'stale' if fields.get('stale') else 'online'


def visible_health(document):
    """What a person would notice, as a value that can be compared.

    Which contexts are out of Home Assistant, and the service reason unless
    it is `device_stale`. A gap between two of an appliance's own reports is
    normal and goes on all day; announcing it would bury the transition that
    matters under a line every twenty seconds.
    """
    contexts = document.get('contexts') or {}
    reason = document.get('degraded_reason')
    return (tuple(sorted(slot for slot, fields in contexts.items()
                         if not fields.get('available'))),
            None if reason == DEVICE_STALE else reason)


def health_line(document):
    """One line an operator can read in the add-on log.

    Ages and counter positions only: the same material the diagnostics topic
    already carries, which is why none of it is secret.
    """
    parts = []
    for slot, fields in sorted((document.get('contexts') or {}).items()):
        age = fields.get('rx_age_ms')
        parts.append('ctx%s %s rx=%s%s' % (
            slot, context_state(fields),
            'never' if not isinstance(age, int) else '%.1fs' % (age / 1000.0),
            ' cmd=pending' if fields.get('command_pending') else ''))
    return 'HEALTH %s; %s' % (document.get('degraded_reason') or 'ok', '; '.join(parts))


def discovery(prefix, discovery_prefix, device_ids=()):
    """HA discovery for the service diagnostic entities.

    Additive: these carry their own device and their own unique ids, so the
    entities the reviewed discovery owns are neither replaced nor renamed.
    Availability follows the daemon process topic alone -- when the bridge is
    gone it cannot report why, and saying so is more honest than leaving a
    stale reason on display.
    """
    topics = service_topics(prefix, device_ids)
    device = dict(identifiers=['airnanny_bridge'], name='AirNanny Bridge',
                  manufacturer='AirNanny', model='Zigbee bridge')
    entities = (('degraded_reason',
                 "{{ value_json.degraded_reason | default('none', true) }}"),
                ('service_state', '{{ value_json.service_state }}'))
    result = {}
    for name, template in entities:
        unique_id = 'airnanny_bridge_' + name
        result['%s/sensor/%s/config' % (discovery_prefix, unique_id)] = dict(
            name=name.replace('_', ' ').title(), unique_id=unique_id,
            device=device.copy(), state_topic=topics.diagnostics,
            value_template=template, entity_category='diagnostic',
            availability=[{'topic': topics.availability}],
            payload_available='online', payload_not_available='offline')
    return result


class ServiceDiagnostics:
    """Derives and publishes the service document on a bounded cadence."""

    def __init__(self, daemon, radio, ledgers, state, *, firmware_identity=None,
                 firmware_version=None, store_interval_ms=STORE_INTERVAL_MS,
                 check_interval_ms=CHECK_INTERVAL_MS,
                 context_identity=CONTEXT_IDENTITY, health_observer=None):
        if type(store_interval_ms) is not int or store_interval_ms < 1000:
            raise ValueError('bounded store read interval required')
        # Demanded here rather than read defensively on the hot path: a
        # transport without it would otherwise report radio_unavailable for
        # the life of the process and look like a radio fault.
        if type(check_interval_ms) is not int or not 0 < check_interval_ms <= store_interval_ms:
            raise ValueError('check interval must be positive and no longer than the store interval')
        if not hasattr(radio, 'connected'):
            raise ValueError('transport does not report its connection')
        self.daemon, self.radio = daemon, radio
        self.ledgers, self.state = ledgers, state
        self.firmware_identity = firmware_identity
        self.firmware_version = firmware_version
        self.store_interval_ms = store_interval_ms
        self.check_interval_ms = check_interval_ms
        self.names = [registered.core.name for registered in daemon.config.devices]
        self.topics = service_topics(daemon.config.mqtt.topic_prefix, self.names)
        self.adapters = {}
        for slot in sorted(ledgers):
            device = daemon.collection.by_context.get(context_identity % slot)
            if device is not None:
                self.adapters[slot] = daemon.adapters[device.config.name]
        self._stores = {}
        self._stores_due = 0
        self._check_due = 0
        self._store_error = None
        # Cached with the stores: ServiceState.read opens and parses a file,
        # and the loop that calls this runs on the hot path.
        self._record = {'state': 'NEW', 'reason': None, 'cycles': 0}
        self._record_error = None
        self._fingerprint = None
        self._last_reason = UNDERIVED
        # Deliberately not cleared by reset(): a broker reconnect is not a
        # change in a device's health, and re-announcing it as one would
        # teach an operator to stop reading these lines.
        self._last_visible = UNDERIVED
        self.health_observer = health_observer

    # -- readings ---------------------------------------------------------

    def _read_service_record(self):
        try:
            return self.state.read(), None
        except Exception:
            # ServiceState.read refuses an unreadable or tampered record by
            # raising. Here that is the finding, not a failure to report.
            return {'state': 'UNKNOWN', 'reason': None, 'cycles': 0}, 'service_state_invalid'

    def _refresh_stores(self, now):
        self._stores_due = now + self.store_interval_ms
        self._record, self._record_error = self._read_service_record()
        readings, error = {}, None
        for slot, ledger in sorted(self.ledgers.items()):
            try:
                record = ledger.read()
                readings[slot] = (int(record['generation']), int(record['next_fc']))
            except Exception:
                readings[slot] = (None, None)
                if error is None:
                    error = 'ctx%d_store_unreadable' % slot
        self._stores, self._store_error = readings, error

    def _store_error_for(self, record, read_error):
        if read_error:
            return read_error
        if self._store_error:
            return self._store_error
        reason = record.get('reason')
        if record.get('state') == 'BLOCKED' and reason:
            for prefix in STORE_LATCH_PREFIXES:
                if reason.startswith(prefix):
                    return reason
        return None

    def contexts(self):
        running = self.daemon.running
        out = []
        for slot, adapter in sorted(self.adapters.items()):
            generation, high_water = self._stores.get(slot, (None, None))
            out.append(context_health(slot, adapter, running, generation=generation,
                                      outgoing_fc_high_water=high_water))
        return out

    def _radio_connected(self):
        return bool(self.radio.connected)

    def document(self, *, service_state=None):
        record, read_error = self._record, self._record_error
        return service_diagnostics(
            self.contexts(),
            service_state=service_state or record.get('state'),
            firmware_identity=self.firmware_identity,
            firmware_version=self.firmware_version,
            store_error=self._store_error_for(record, read_error),
            radio_connected=self._radio_connected(),
            mqtt_connected=bool(self.daemon.mqtt.connected),
            last_reconnect_reason=record.get('reason'),
            reconnects=record.get('cycles', 0),
            result_backlog=len(self.daemon.outbox),
            result_delivery_drops=getattr(self.daemon, 'result_delivery_drops', 0))

    # -- publication ------------------------------------------------------

    def cheap_reason(self):
        """The reason derivable without touching a store.

        Used only to decide whether to publish early: a reason that has just
        changed is what an operator is waiting for, and making them wait out
        the interval for it would defeat the document.
        """
        record, read_error = self._record, self._record_error
        return degraded_reason(self.contexts(),
                               store_error=self._store_error_for(record, read_error),
                               radio_connected=self._radio_connected(),
                               mqtt_connected=bool(self.daemon.mqtt.connected))

    def reset(self):
        """Forget what was published, so a reconnect re-establishes it.

        The store interval is cleared with it: a reset means the retained
        document is gone as far as this process knows, and waiting out the
        interval before replacing it would leave the broker holding nothing.
        """
        self._fingerprint = None
        self._last_reason = UNDERIVED
        self._stores_due = 0
        self._check_due = 0

    def _fingerprint_of(self, document):
        # The reception age ticks every pump and would publish forever; the
        # rest of the document is what an operator reads for a change.
        trimmed = dict(document)
        trimmed['contexts'] = {slot: {name: value for name, value in fields.items()
                                      if name != 'rx_age_ms'}
                               for slot, fields in document['contexts'].items()}
        return encode(trimmed)

    def publish(self, *, force=False, service_state=None):
        document = self.document(service_state=service_state)
        fingerprint = self._fingerprint_of(document)
        if not force and fingerprint == self._fingerprint:
            return False
        # Announced before the publish is attempted, not after it succeeds: a
        # broker that has gone is exactly when the log is the only instrument
        # left, and that is not the moment to go quiet.
        self._report_health(document)
        if not self.daemon.publish(self.topics.diagnostics, encode(document), True):
            return False
        self._fingerprint = fingerprint
        self._last_reason = document['degraded_reason']
        return True

    def announce(self):
        """Publish the service discovery messages, then the document itself."""
        messages = discovery(self.daemon.config.mqtt.topic_prefix,
                             self.daemon.config.mqtt.discovery_prefix, self.names)
        for topic, payload in messages.items():
            self.daemon.publish(topic, encode(payload), True)
        self.reset()
        # Read the stores before the first document, or it would report no
        # counter position at all -- which is how an unreadable store is
        # reported, and would be read as one.
        self._refresh_stores(self.daemon.clock.now_ms())
        self.publish()

    def pump(self):
        now = self.daemon.clock.now_ms()
        if now < self._check_due:
            return
        self._check_due = now + self.check_interval_ms
        if self._last_reason is not UNDERIVED and self.cheap_reason() != self._last_reason:
            self._refresh_stores(now)
            self.publish()
            return
        if now < self._stores_due:
            return
        self._refresh_stores(now)
        self.publish()

    def _report_health(self, document):
        if self.health_observer is None:
            return
        visible = visible_health(document)
        if visible == self._last_visible:
            return
        self._last_visible = visible
        try:
            self.health_observer(health_line(document))
        except Exception:
            pass  # An instrument must not be the thing that stops the service.

    def stopping(self):
        """A final document, so a clean stop does not read as a crash."""
        self.publish(force=True, service_state='STOPPING')
