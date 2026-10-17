"""Connection options separate from the frozen daemon/device config contract."""
from dataclasses import dataclass
import ipaddress
import re
import ssl
from uuid import uuid4
from .config_loader import MqttConfig


@dataclass(frozen=True)
class TlsConfig:
    enabled: bool = False
    ca_file: str | None = None
    cert_file: str | None = None
    key_file: str | None = None

    def context(self):
        if not self.enabled:
            if any((self.ca_file,self.cert_file,self.key_file)): raise ValueError('TLS files require TLS enabled')
            return None
        if bool(self.cert_file)!=bool(self.key_file): raise ValueError('TLS client certificate/key pair required')
        context=ssl.create_default_context(cafile=self.ca_file)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        if self.cert_file: context.load_cert_chain(self.cert_file,self.key_file)
        # No option exists to disable certificate or hostname verification.
        return context


@dataclass(frozen=True)
class MqttRuntimeConfig:
    connection: MqttConfig
    keepalive: int = 15
    client_id: str | None = None
    tls: TlsConfig = TlsConfig()
    allow_non_loopback: bool = False
    inbound_limit: int = 256
    outbound_limit: int = 256
    max_payload_bytes: int = 65536
    connect_timeout: float = 2.0
    shutdown_timeout: float = 3.0

    def __post_init__(self):
        for value in (self.keepalive,self.inbound_limit,self.outbound_limit,self.max_payload_bytes):
            if type(value) is not int or value<=0: raise ValueError('positive runtime limits required')
        if self.keepalive>65535 or not 0<self.connect_timeout<=30 or not 0<self.shutdown_timeout<=30:
            raise ValueError('invalid runtime timeout')
        if self.client_id is not None and not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',self.client_id):
            raise ValueError('invalid MQTT client id')
        try: loopback=ipaddress.ip_address(self.connection.host).is_loopback
        except ValueError: loopback=self.connection.host=='localhost'
        if not loopback and not (self.allow_non_loopback and self.tls.enabled):
            raise ValueError('non-loopback requires explicit opt-in and verified TLS')

    def effective_client_id(self):
        # Stable for this transport's lifetime/reconnects, distinct for other instances.
        return self.client_id or 'airnanny-'+uuid4().hex
