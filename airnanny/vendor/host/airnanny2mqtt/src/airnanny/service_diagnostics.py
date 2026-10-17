"""Why the service is degraded, as distinct from whether a device is online.

The per-device diagnostics the daemon already publishes say whether one A7 is
online, stale or unavailable. They cannot say why, and why is what an operator
needs: a broker outage, a dongle someone unplugged, a durable store that will
not load, and an A7 that simply stopped talking all look identical from a
device topic.

This derives one reason for the service and carries a bounded set of counters
beside it. It reads nothing and re-derives nothing -- callers pass what the
service already knows -- so it stays a pure function that can be reasoned
about and tested without a radio.

A command that failed is deliberately not an input. One refused or unanswered
command says nothing about whether the device is reachable, and marking it
unavailable while its state messages keep arriving would be a lie that
Home Assistant would then act on.
"""
from dataclasses import dataclass, field

# Ordered worst first. The first that applies is the reason reported: a store
# that will not load makes every later question moot, and a dongle that is not
# present explains silence that would otherwise read as a stale device.
CONTEXT_STORE_ERROR = 'context_store_error'
RADIO_UNAVAILABLE = 'radio_unavailable'
MQTT_UNAVAILABLE = 'mqtt_unavailable'
DEVICE_UNAVAILABLE = 'device_unavailable'
DEVICE_STALE = 'device_stale'

REASONS = (CONTEXT_STORE_ERROR, RADIO_UNAVAILABLE, MQTT_UNAVAILABLE,
           DEVICE_UNAVAILABLE, DEVICE_STALE)

HISTORY_LIMIT = 64


@dataclass(frozen=True)
class ContextHealth:
    """One context's share of the picture.

    `rx_age_ms` is None when nothing has been received yet in this session,
    which is not the same as a large age and must not be reported as one.
    """
    context: int
    available: bool = False
    stale: bool = False
    rx_age_ms: int = None
    rx_drop: int = 0
    out_drop: int = 0
    ack_deadline_misses: int = 0
    replay_rejects: int = 0
    outgoing_fc_high_water: int = None
    queue_depth: int = 0
    last_confirmed_state: dict = field(default_factory=dict)

    def as_document(self):
        return {'available': self.available, 'stale': self.stale,
                'rx_age_ms': self.rx_age_ms, 'rx_drop': self.rx_drop,
                'out_drop': self.out_drop,
                'ack_deadline_misses': self.ack_deadline_misses,
                'replay_rejects': self.replay_rejects,
                # A counter position, not key material: it says how far the
                # outgoing sequence has advanced, which is what makes an
                # unexpected jump or stall visible.
                'outgoing_fc_high_water': self.outgoing_fc_high_water,
                'queue_depth': self.queue_depth,
                'last_confirmed_state': dict(self.last_confirmed_state)}


def degraded_reason(contexts, *, store_error=None, radio_connected=True,
                    mqtt_connected=True):
    """The single most significant reason, or None when nothing is wrong."""
    if store_error:
        return CONTEXT_STORE_ERROR
    if not radio_connected:
        return RADIO_UNAVAILABLE
    if not mqtt_connected:
        return MQTT_UNAVAILABLE
    contexts = list(contexts)
    if not contexts or any(not c.available for c in contexts):
        return DEVICE_UNAVAILABLE
    if any(c.stale for c in contexts):
        return DEVICE_STALE
    return None


def service_diagnostics(contexts, *, service_state, firmware_identity=None,
                        firmware_version=None, store_error=None,
                        radio_connected=True, mqtt_connected=True,
                        last_reconnect_reason=None, reconnects=0):
    """The bounded document published on the service's diagnostics topic.

    Bounded on purpose: this is published retained and read by a person, so it
    carries current counters and one reason rather than an unbroken history
    that would grow without limit and tell them less.
    """
    contexts = sorted(contexts, key=lambda c: c.context)
    if len({c.context for c in contexts}) != len(contexts):
        raise ValueError('a context is reported twice')
    reason = degraded_reason(contexts, store_error=store_error,
                             radio_connected=radio_connected,
                             mqtt_connected=mqtt_connected)
    return {'service_state': service_state,
            'degraded': reason is not None,
            'degraded_reason': reason,
            'firmware_identity': firmware_identity,
            'firmware_version': firmware_version,
            'radio_connected': radio_connected,
            'mqtt_connected': mqtt_connected,
            'store_error': store_error,
            'reconnects': reconnects,
            'last_reconnect_reason': last_reconnect_reason,
            'contexts': {str(c.context): c.as_document() for c in contexts}}
