"""In-memory MQTT contract. This module never opens a network connection."""
from dataclasses import dataclass
from typing import Callable, Protocol


@dataclass(frozen=True)
class Message:
    topic: str
    payload: bytes
    retained: bool = False
    duplicate: bool = False


@dataclass(frozen=True)
class Publication:
    client: str
    topic: str
    payload: bytes
    retain: bool


class MqttTransport(Protocol):
    connected: bool
    def set_message_handler(self, handler: Callable[[Message], None]): ...
    def set_connection_handler(self, handler: Callable[[bool], None]): ...
    def set_will(self, topic: str, payload: bytes, retain: bool = True): ...
    def publish(self, topic: str, payload: bytes, retain: bool = False): ...
    def subscribe(self, topic_filter: str): ...
    def connect(self): ...
    def disconnect(self): ...


def matches(topic_filter: str, topic: str) -> bool:
    parts, levels = topic_filter.split('/'), topic.split('/')
    if topic.startswith('$') and not topic_filter.startswith('$'): return False
    for index, part in enumerate(parts):
        if part == '#': return index == len(parts) - 1
        if index >= len(levels) or part not in ('+', levels[index]): return False
    return len(parts) == len(levels)


def valid_filter(value: str):
    if not value or '\x00' in value: raise ValueError('invalid topic filter')
    parts = value.split('/')
    for index, part in enumerate(parts):
        if ('+' in part and part != '+') or ('#' in part and (part != '#' or index != len(parts)-1)):
            raise ValueError('invalid topic filter')


class MemoryMqttBroker:
    def __init__(self):
        self.available = True
        self.retained = {}
        self.history = []
        self.clients = []

    def publish(self, client: str, topic: str, payload: bytes, retain=False):
        if not self.available: raise ConnectionError('memory broker unavailable')
        if not topic or any(c in topic for c in ('+', '#', '\x00')): raise ValueError('invalid topic')
        payload = bytes(payload)
        self.history.append(Publication(client, topic, payload, retain))
        if retain:
            if payload: self.retained[topic] = payload
            else: self.retained.pop(topic, None)
        # Snapshot iteration permits synchronous handlers to change subscriptions.
        for subscriber in list(self.clients):
            if subscriber.connected and any(matches(f, topic) for f in subscriber.subscriptions):
                subscriber.handler(Message(topic, payload, retained=retain))

    def inject(self, topic: str, payload: str | bytes, retain=False, duplicate=False):
        raw = payload.encode() if isinstance(payload, str) else payload
        if duplicate:
            for client in list(self.clients):
                if client.connected and any(matches(f, topic) for f in client.subscriptions):
                    client.handler(Message(topic, raw, retain, True))
        else: self.publish('test-publisher', topic, raw, retain)

    def set_available(self, value: bool):
        if not value:
            for client in list(self.clients):
                if client.connected: client.disconnect(unexpected=True)
        self.available = value


class FakeMqttTransport:
    def __init__(self, broker: MemoryMqttBroker, client_id='airnanny-daemon'):
        self.broker, self.client_id = broker, client_id
        self.connected = False
        self.subscriptions = set()
        self.handler = lambda message: None
        self.connection_handler = lambda connected: None
        self.will = None
        broker.clients.append(self)

    def set_message_handler(self, handler): self.handler = handler
    def set_connection_handler(self, handler): self.connection_handler = handler
    def set_will(self, topic, payload, retain=True): self.will = (topic, bytes(payload), retain)

    def connect(self):
        if self.connected: return
        if not self.broker.available: raise ConnectionError('memory broker unavailable')
        self.connected = True
        self.connection_handler(True)

    def disconnect(self, unexpected=False):
        if not self.connected: return
        self.connected = False
        self.subscriptions.clear()  # clean session; daemon must resubscribe
        if unexpected and self.will is not None and self.broker.available:
            self.broker.publish(self.client_id, *self.will)
        self.connection_handler(False)

    def subscribe(self, topic_filter):
        if not self.connected: raise ConnectionError('memory client disconnected')
        valid_filter(topic_filter)
        if topic_filter in self.subscriptions: return
        self.subscriptions.add(topic_filter)
        for topic, payload in list(self.broker.retained.items()):
            if matches(topic_filter, topic): self.handler(Message(topic, payload, retained=True))

    def publish(self, topic, payload, retain=False):
        if not self.connected: raise ConnectionError('memory client disconnected')
        self.broker.publish(self.client_id, topic, payload, retain)
