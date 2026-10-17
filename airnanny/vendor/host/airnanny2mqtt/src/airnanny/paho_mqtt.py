"""Paho MQTT3.1.1 backend: callback thread never invokes daemon/core handlers."""
from collections import Counter,deque
from dataclasses import dataclass,field
from queue import Queue,Full,Empty
import socket
import threading
import time
from .mqtt import Message
from .mqtt_runtime import MqttRuntimeConfig


@dataclass(frozen=True)
class WireMessage(Message):
    qos: int = 0
    mid: int = 0  # connection-local packet id, NOT an application request id


@dataclass
class PublishReceipt:
    mid: int
    done: threading.Event = field(default_factory=threading.Event,repr=False)
    error: str | None = None

    @property
    def acknowledged(self): return self.done.is_set() and self.error is None


class PahoMqttTransport:
    def __init__(self, config: MqttRuntimeConfig, *, credential_resolver=None, client_factory=None):
        self.config=config
        self.client_id=config.effective_client_id()
        self._resolver=credential_resolver
        self._factory=client_factory
        self._owner=threading.get_ident()
        self._lock=threading.RLock()
        self._events=Queue(maxsize=config.inbound_limit)
        self._overflow=threading.Event()
        self._wake=threading.Event()
        self._client=None
        self._epoch=0
        self._pending={}
        self._publishing=False
        self._early_acks={}
        self._subscriptions=set()
        self._sub_pending=set()
        self._sub_failed=False
        self._will=None
        self.connected=False
        self.handler=lambda message:None
        self.connection_handler=lambda connected:None
        names=('mqtt_connects','mqtt_disconnects','mqtt_reconnects','inbound_messages',
               'retained_commands_rejected','duplicate_commands_rejected','outbound_publish_failures',
               'outbound_queue_drops','inbound_queue_drops','subscription_failures','connect_failures')
        self._metrics=Counter({name:0 for name in names})
        self.log=deque(maxlen=256)
        self.completed=deque(maxlen=config.outbound_limit)

    def _assert_owner(self):
        if threading.get_ident()!=self._owner: raise RuntimeError('MQTT owner thread required')

    def _count(self,name,amount=1):
        with self._lock:self._metrics[name]+=amount

    def _log(self,event,reason=None):
        with self._lock:self.log.append(dict(event=event,reason=reason))

    @property
    def metrics(self):
        with self._lock:
            return dict(self._metrics,outbound_queue_depth=len(self._pending),inbound_queue_depth=self._events.qsize())

    def set_message_handler(self,handler): self._assert_owner();self.handler=handler
    def set_connection_handler(self,handler): self._assert_owner();self.connection_handler=handler
    def set_will(self,topic,payload,retain=True):
        self._assert_owner()
        if self._client is not None: raise RuntimeError('Will must be configured before connect')
        self._will=(topic,bytes(payload),retain)

    def _enqueue(self,epoch,kind,data):
        if epoch!=self._epoch:return
        try:self._events.put_nowait((epoch,kind,data))
        except Full:
            self._count('inbound_queue_drops');self._overflow.set();self._log('queue_overflow','inbound')
        self._wake.set()

    def _fail_pending(self,reason):
        with self._lock:
            for receipt in self._pending.values():
                receipt.error=reason;receipt.done.set();self.completed.append(receipt)
            count=len(self._pending)
            self._metrics['outbound_publish_failures']+=count
            self._metrics['outbound_queue_drops']+=count
            self._pending.clear()
        if count:self._log('publish_failure',reason)

    def connect(self):
        self._assert_owner()
        if self.connected:return
        if self._client is not None:self._close(graceful=False,notify=False)
        import paho.mqtt.client as mqtt
        self._epoch+=1
        epoch=self._epoch
        factory=self._factory or mqtt.Client
        client=factory(callback_api_version=mqtt.CallbackAPIVersion.VERSION2,client_id=self.client_id,
                       clean_session=True,protocol=mqtt.MQTTv311,reconnect_on_failure=False,manual_ack=True)
        self._client=client
        client.connect_timeout=self.config.connect_timeout
        client.max_queued_messages_set(self.config.outbound_limit)
        client.max_inflight_messages_set(min(20,self.config.outbound_limit))
        client.on_connect=lambda c,u,f,r,p:self._enqueue(epoch,'connected',int(r.value))
        client.on_disconnect=lambda c,u,f,r,p:self._enqueue(epoch,'disconnected',int(r.value))
        def message(c,u,m):
            if epoch!=self._epoch:return
            if len(m.payload)>self.config.max_payload_bytes:
                self._count('inbound_queue_drops');self._overflow.set();self._wake.set();return
            self._enqueue(epoch,'message',WireMessage(m.topic,bytes(m.payload),bool(m.retain),bool(m.dup),m.qos,m.mid))
        def published(c,u,mid,reason,props):
            with self._lock:
                if epoch!=self._epoch:return
                receipt=self._pending.pop(mid,None)
                if receipt:
                    if reason.is_failure:
                        receipt.error='puback_failure';self._metrics['outbound_publish_failures']+=1
                    receipt.done.set();self.completed.append(receipt)
                elif self._publishing:
                    self._early_acks[mid]=bool(reason.is_failure)
            self._wake.set()
        def subscribed(c,u,mid,reasons,props):
            self._enqueue(epoch,'subscribed',(mid,any(r.is_failure for r in reasons)))
        client.on_message=message;client.on_publish=published;client.on_subscribe=subscribed
        try:
            if self._will:client.will_set(self._will[0],self._will[1],qos=1,retain=self._will[2])
            ctx=self.config.tls.context()
            if ctx:client.tls_set_context(ctx)
            connection=self.config.connection
            if connection.username_ref or connection.password_ref:
                if not self._resolver:raise ValueError('credential resolver required')
                username=self._resolver(connection.username_ref) if connection.username_ref else None
                password=self._resolver(connection.password_ref) if connection.password_ref else None
                client.username_pw_set(username,password)
            client.connect(connection.host,connection.port,self.config.keepalive)
            client.loop_start()
        except Exception:
            self._count('connect_failures');self._log('connect_failure','connection_or_configuration')
            self._close(graceful=False,notify=False)
            raise ConnectionError('MQTT connection/setup failed') from None

    def pump(self,max_events=64):
        """Call on the daemon owner thread before daemon.tick(). No sleeps."""
        self._assert_owner()
        if self._overflow.is_set():
            self._close(graceful=False)
            self._overflow.clear()
            return 0
        processed=0
        while processed<max_events:
            try:epoch,kind,data=self._events.get_nowait()
            except Empty:break
            if epoch!=self._epoch:continue
            processed+=1
            if kind=='connected':
                if data:
                    self._count('connect_failures');self._log('connect_refused',data)
                    continue
                self.connected=True
                self._count('mqtt_connects')
                if self.metrics['mqtt_connects']>1:self._count('mqtt_reconnects')
                self._log('connect',data)
                self.connection_handler(True)
            elif kind=='disconnected':
                was_connected=self.connected;self.connected=False
                self._fail_pending('connection_lost_delivery_unknown')
                self._subscriptions.clear();self._sub_pending.clear()
                self._log('disconnect',data)
                if was_connected:self._count('mqtt_disconnects');self.connection_handler(False)
            elif kind=='subscribed':
                mid,failed=data;self._sub_pending.discard(mid)
                if failed:
                    self._sub_failed=True
                    self._count('subscription_failures');self._log('subscribe_failure','suback')
            elif kind=='message' and self.connected:
                self._count('inbound_messages')
                if data.topic.endswith('/set'):
                    if data.retained:self._count('retained_commands_rejected')
                    elif data.duplicate:self._count('duplicate_commands_rejected')
                self.handler(data)
                # ACK only after owner processing; no queued command is silently ACKed.
                if data.qos and self._client is not None and epoch==self._epoch:
                    self._client.ack(data.mid,data.qos)
        if self._events.empty():self._wake.clear()
        return processed

    def wait_for_event(self,timeout=0.05):
        """Bounded I/O wait for an external owner loop; never advances core fake time."""
        self._assert_owner();self._wake.wait(timeout)

    @property
    def subscriptions_ready(self): return self.connected and not self._sub_pending and not self._sub_failed

    def subscribe(self,topic):
        self._assert_owner()
        if not self.connected:raise ConnectionError('MQTT disconnected')
        if topic in self._subscriptions:return
        if not topic or any(c in topic for c in ('#','+','\x00')):raise ValueError('exact subscription required')
        rc,mid=self._client.subscribe(topic,qos=1)
        if rc:
            self._sub_failed=True
            self._count('subscription_failures');raise ConnectionError('MQTT subscribe rejected')
        self._subscriptions.add(topic);self._sub_pending.add(mid)

    def publish(self,topic,payload,retain=False):
        self._assert_owner()
        with self._lock:
            if not self.connected or len(self._pending)>=self.config.outbound_limit:
                self._metrics['outbound_publish_failures']+=1
                self._metrics['outbound_queue_drops']+=1
                self._log('publish_failure','disconnected_or_queue_full')
                raise ConnectionError('MQTT disconnected or publish queue full')
            if len(payload)>self.config.max_payload_bytes:
                self._metrics['outbound_publish_failures']+=1
                self._metrics['outbound_queue_drops']+=1
                raise ConnectionError('MQTT payload exceeds limit')
            self._publishing=True
        # Never hold our lock while entering Paho: its PUBACK callback runs under
        # Paho's own outgoing-message mutex. Reversing that order deadlocks.
        try:
            info=self._client.publish(topic,bytes(payload),qos=1,retain=retain)
        except Exception:
            with self._lock:
                self._publishing=False;self._early_acks.clear()
                self._metrics['outbound_publish_failures']+=1
                self._metrics['outbound_queue_drops']+=1
            raise ConnectionError('MQTT publish failed') from None
        with self._lock:
            self._publishing=False
            if info.rc:
                self._early_acks.clear()
                self._metrics['outbound_publish_failures']+=1
                self._metrics['outbound_queue_drops']+=1
                raise ConnectionError('MQTT publish rejected')
            receipt=PublishReceipt(info.mid)
            if info.mid in self._early_acks:
                if self._early_acks[info.mid]:
                    receipt.error='puback_failure';self._metrics['outbound_publish_failures']+=1
                receipt.done.set();self.completed.append(receipt)
            else:self._pending[info.mid]=receipt
            self._early_acks.clear()
            return receipt

    def flush(self,timeout=None):
        self._assert_owner()
        deadline=time.monotonic()+(self.config.shutdown_timeout if timeout is None else timeout)
        with self._lock:receipts=list(self._pending.values())
        for receipt in receipts:
            if not receipt.done.wait(max(0,deadline-time.monotonic())):return False
        return all(r.acknowledged for r in receipts)

    def disconnect(self):
        self._assert_owner()
        self.flush()
        self._close(graceful=True)

    def abort(self):
        """Unclean socket loss; no DISCONNECT/offline publish. Used to verify Will."""
        self._assert_owner();self._close(graceful=False)

    def _close(self,graceful,notify=True):
        client,self._client=self._client,None
        self._epoch+=1
        if client is not None:
            if graceful:client.disconnect()
            else:
                sock=client.socket()
                if sock is not None:
                    try:sock.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                    sock.close()
            client.loop_stop()
        self._fail_pending('closed_delivery_unknown')
        was_connected=self.connected;self.connected=False
        self._subscriptions.clear();self._sub_pending.clear()
        self._sub_failed=False
        while True:
            try:self._events.get_nowait()
            except Empty:break
        if was_connected:
            self._count('mqtt_disconnects')
            if notify:self.connection_handler(False)
