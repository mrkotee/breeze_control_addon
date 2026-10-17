"""Deterministic adapter loop; core alone owns Zigbee and SAFE semantics."""
from dataclasses import dataclass
from uuid import uuid4
from .availability import availability, binary_availability
from .commands import CommandError
from .config import Configuration
from .device import DeviceCollection
from .events import CommandAccepted, CommandCompleted, CommandFailed, StateEvent
from .ha_discovery import discovery
from .lifecycle import EventLog, RadioSession
from .mqtt_schema import COMMANDS, Topics, encode, parse_command, state_payload, state_fingerprint


@dataclass
class PendingRequest:
    request_id: str
    command: str
    tx_id: str


class DeviceMqttAdapter:
    def __init__(self, daemon, device):
        self.daemon, self.device = daemon, device
        self.topics = Topics(daemon.config.mqtt.topic_prefix,device.config.name)
        self.cursor = len(device.events)
        self.pending = None
        self.released = device.snapshot()
        self.release_block_revision = -1
        self.last_state = None
        self.last_availability = None
        self.last_detail_availability = None
        self.last_diagnostics = None
        self.context_available = True

    def result(self, request_id, command, status, reason=None):
        payload = dict(request_id=request_id,command=command,status=status)
        if reason is not None: payload['reason']=reason
        self.daemon.transient(self.topics.result,encode(payload))

    def state(self, force=False):
        fingerprint=state_fingerprint(self.released)
        if force or fingerprint != self.last_state:
            if self.daemon.publish(self.topics.state,encode(state_payload(self.released)),True):
                self.last_state=fingerprint
                self.daemon.log.emit('state_changed',device=self.device.config.name)

    def drain(self):
        snapshot=self.device.snapshot()
        events=self.device.events[self.cursor:]
        self.cursor=len(self.device.events)
        # A status before command completion is not a released command state.
        for event in events:
            pending=self.pending
            if pending and isinstance(event,(CommandCompleted,CommandFailed)) and event.tx_id==pending.tx_id:
                self.pending=None
                if isinstance(event,CommandCompleted):
                    self.release_block_revision=-1
                    self.released=snapshot
                    self.state(force=True)  # confirmed state must precede success result
                    self.result(pending.request_id,pending.command,'ok')
                else:
                    self.release_block_revision=snapshot.rx_revision
                    self.result(pending.request_id,pending.command,'error',event.reason)
                    self.daemon.log.emit('command_failed',device=self.device.config.name,
                                         request_id=pending.request_id,command=pending.command,reason=event.reason)
        if self.pending is None and snapshot.rx_revision>self.release_block_revision:
            self.released=snapshot
        self.state()
        current=availability(snapshot,self.daemon.running,self.context_available)
        binary=binary_availability(current)
        if current != self.last_detail_availability:
            self.daemon.log.emit('availability_changed',device=self.device.config.name,availability=current)
            self.last_detail_availability=current
        if binary != self.last_availability:
            if self.daemon.publish(self.topics.availability,binary.encode(),True):
                self.last_availability=binary
        diagnostic=dict(availability=current,status_valid=snapshot.status_valid,status_fresh=snapshot.status_fresh,
            status_age_ms=snapshot.status_age_ms,rx_revision=snapshot.rx_revision,
            baseline_generation=snapshot.baseline_generation,baseline_source=snapshot.baseline_source,
            baseline_valid=snapshot.baseline_valid,baseline_pending=snapshot.baseline_pending,
            pending_transaction=snapshot.pending_transaction,mqtt_connected=self.daemon.mqtt.connected)
        fingerprint=diagnostic.copy()
        for key in ('status_age_ms','rx_revision'):fingerprint.pop(key)
        fingerprint=encode(fingerprint)
        if fingerprint!=self.last_diagnostics:
            if self.daemon.publish(self.topics.diagnostics,encode(diagnostic),True): self.last_diagnostics=fingerprint

    def handle(self, command, message):
        self.drain()
        request_id=self.daemon.next_request_id()
        self.daemon.log.emit('command_received',device=self.device.config.name,request_id=request_id,command=command)
        reason=None
        if message.retained: reason='retained_command'
        elif message.duplicate: reason='duplicate_delivery'
        elif not self.daemon.accepting: reason='shutting_down'
        elif not self.context_available: reason='context_unavailable'
        if reason:
            self.result(request_id,command,'error',reason)
            self.daemon.log.emit('command_failed',device=self.device.config.name,request_id=request_id,command=command,reason=reason)
            return
        try: request=parse_command(command,message.payload)
        except CommandError:
            self.result(request_id,command,'error','bad_argument')
            self.daemon.log.emit('command_failed',device=self.device.config.name,request_id=request_id,command=command,reason='bad_argument')
            return
        # queue may emit a busy error using the old tx_id. Handle its synchronous
        # return directly, so it cannot terminate the earlier adapter request.
        outcome=self.device.queue(request)
        self.cursor=len(self.device.events)
        if isinstance(outcome,CommandFailed):
            self.result(request_id,command,'error',outcome.reason)
            self.daemon.log.emit('command_failed',device=self.device.config.name,request_id=request_id,command=command,reason=outcome.reason)
            return
        self.pending=PendingRequest(request_id,command,outcome.tx_id)
        self.result(request_id,command,'accepted')
        self.daemon.log.emit('command_accepted',device=self.device.config.name,request_id=request_id,command=command)
        self.device.dispatch()
        self.drain()

    def republish(self):
        self.last_state=self.last_availability=self.last_diagnostics=None
        self.drain()


class AirNannyDaemon:
    def __init__(self, config, clock, radio, mqtt, counters, *, session_id=None, log=None):
        self.config,self.clock,self.mqtt=config,clock,mqtt
        self.radio=RadioSession(radio)
        self.collection=DeviceCollection(Configuration(tuple(d.core for d in config.devices)),clock,self.radio,counters)
        self.adapters={name:DeviceMqttAdapter(self,device) for name,device in self.collection.devices.items()}
        self.log=log or EventLog()
        self.running=self.accepting=self.stopped=False
        self.session_id=session_id or uuid4().hex
        self.request_sequence=0
        self.outbox=[]
        self.process_topic=config.mqtt.topic_prefix+'/daemon/availability'
        self.command_topics={adapter.topics.command(c):(adapter,c) for adapter in self.adapters.values() for c in COMMANDS}

    def next_request_id(self):
        self.request_sequence+=1
        return f'{self.session_id}:{self.request_sequence}'

    def publish(self, topic, payload, retain=False):
        if not self.mqtt.connected: return False
        try:self.mqtt.publish(topic,payload,retain)
        except ConnectionError:return False
        return True

    def transient(self, topic, payload):
        if not self.publish(topic,payload):self.outbox.append((topic,payload))

    def _connection(self, connected):
        self.log.emit('mqtt_connect' if connected else 'mqtt_disconnect')
        if not connected or not self.running:return
        self.publish(self.process_topic,b'online',True)
        # Discovery/state precede subscriptions; retained commands can only be rejected.
        for topic,payload in discovery(self.config).items():self.publish(topic,encode(payload),True)
        for adapter in self.adapters.values():adapter.republish()
        for topic in self.command_topics:self.mqtt.subscribe(topic)
        queued,self.outbox=self.outbox,[]
        for topic,payload in queued:self.transient(topic,payload)

    def _message(self,message):
        if not self.running:return
        pair=self.command_topics.get(message.topic)
        if pair is not None:
            self.collection.tick()
            pair[0].handle(pair[1],message)

    def start(self):
        if self.stopped:raise RuntimeError('stopped daemon cannot restart; construct a new instance')
        if self.running:return
        self.running=self.accepting=self.radio.running=True
        self.log.emit('daemon_start')
        self.mqtt.set_message_handler(self._message)
        self.mqtt.set_connection_handler(self._connection)
        self.mqtt.set_will(self.process_topic,b'offline',True)
        if self.mqtt.connected:self._connection(True)
        else:self.reconnect()

    def reconnect(self):
        if not self.running:return
        try:self.mqtt.connect()
        except ConnectionError:self.log.emit('mqtt_disconnect',reason='broker_unavailable')

    def receive_mac(self,raw):
        if not self.running:return False
        result=self.collection.receive_mac(raw)
        self.tick()
        return result

    def tick(self):
        if not self.running:return
        self.collection.tick()
        for adapter in self.adapters.values():adapter.drain()

    def set_context_available(self,device_id,available):
        self.adapters[device_id].context_available=bool(available)
        self.tick()

    def shutdown(self):
        if self.stopped:return
        self.accepting=False
        # Pending outcomes terminate at the adapter boundary, never become OK.
        for adapter in self.adapters.values():
            if adapter.pending:
                p,adapter.pending=adapter.pending,None
                adapter.result(p.request_id,p.command,'error','daemon_shutdown')
                self.log.emit('command_failed',device=adapter.device.config.name,
                              request_id=p.request_id,command=p.command,reason='daemon_shutdown')
            self.publish(adapter.topics.availability,b'offline',True)
            snapshot=adapter.device.snapshot()
            self.publish(adapter.topics.diagnostics,encode(dict(availability='unavailable',
                status_valid=snapshot.status_valid,status_fresh=snapshot.status_fresh,
                rx_revision=snapshot.rx_revision,baseline_generation=snapshot.baseline_generation,
                baseline_source=snapshot.baseline_source)),True)
        self.publish(self.process_topic,b'offline',True)
        self.radio.stop()
        self.running=False
        self.stopped=True
        self.mqtt.disconnect()
        self.log.emit('daemon_stop')
