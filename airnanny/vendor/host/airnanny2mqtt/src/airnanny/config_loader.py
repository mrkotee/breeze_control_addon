"""Strict offline JSON configuration; secret references are never resolved implicitly."""
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from .config import Configuration, DeviceConfig
from .context import ZigbeeContext


class ConfigError(ValueError): pass


def identifier(value):
    if not isinstance(value, str) or value == 'daemon' or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', value):
        raise ConfigError('invalid stable device id')


def prefix(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', value):
        raise ConfigError('invalid topic prefix')


def reference(value):
    if value is not None and (not isinstance(value, str) or not re.fullmatch(
            r'env:[A-Za-z_][A-Za-z_0-9]*|file:[^#\x00]+#[A-Za-z_][A-Za-z_0-9]*', value)):
        raise ConfigError('invalid secret reference')


@dataclass(frozen=True)
class MqttConfig:
    host: str = 'offline.invalid'
    port: int = 1883
    topic_prefix: str = 'airnanny'
    discovery_prefix: str = 'homeassistant'
    username_ref: str | None = field(default=None, repr=False)
    password_ref: str | None = field(default=None, repr=False)

    def __post_init__(self):
        prefix(self.topic_prefix); prefix(self.discovery_prefix)
        reference(self.username_ref); reference(self.password_ref)
        if not isinstance(self.host, str) or not self.host or any(c.isspace() for c in self.host):
            raise ConfigError('invalid offline broker host')
        if type(self.port) is not int or not 1 <= self.port <= 65535: raise ConfigError('invalid broker port')
        if (self.topic_prefix == self.discovery_prefix or self.topic_prefix.startswith(self.discovery_prefix+'/')
                or self.discovery_prefix.startswith(self.topic_prefix+'/')):
            raise ConfigError('overlapping topic namespaces')


@dataclass(frozen=True)
class RegisteredDevice:
    core: DeviceConfig
    friendly_name: str

    def __post_init__(self):
        identifier(self.core.name)
        if not isinstance(self.friendly_name, str) or not self.friendly_name.strip() or len(self.friendly_name)>128 or any(
                ord(c)<32 for c in self.friendly_name): raise ConfigError('invalid friendly name')


@dataclass(frozen=True)
class DaemonConfig:
    mqtt: MqttConfig
    devices: tuple[RegisteredDevice, ...]

    def __post_init__(self):
        if not self.devices: raise ConfigError('at least one device required')
        Configuration(tuple(d.core for d in self.devices))


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ConfigError('duplicate configuration key')
        result[key] = value
    return result


def _keys(obj, allowed, required=()):
    if not isinstance(obj, dict) or set(obj)-set(allowed) or set(required)-set(obj):
        raise ConfigError('invalid configuration fields')


def load_config(path: Path, key_resolver=None) -> DaemonConfig:
    """Optionally inject a local secret resolver; never read credentials or contact host."""
    try:
        raw = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_object)
        _keys(raw, ('mqtt','devices'), ('devices',))
        mqtt = raw.get('mqtt', {})
        _keys(mqtt, ('host','port','topic_prefix','discovery_prefix','username_ref','password_ref'))
        mqtt = MqttConfig(**mqtt)
        if not isinstance(raw['devices'], list): raise ConfigError('devices must be a list')
        devices = []
        for item in raw['devices']:
            _keys(item, ('device_id','friendly_name','context','controller_short','key_reference'),
                        ('device_id','friendly_name','context','controller_short','key_reference'))
            fields = ('identity','pan','extended_pan','channel','local_ieee','local_short',
                      'coordinator_ieee','coordinator_short','active_key_sequence')
            _keys(item['context'], fields, fields[:7])
            if any(type(v) is not int for k,v in item['context'].items() if k != 'identity'):
                raise ConfigError('context numbers must be integers')
            reference(item['key_reference'])
            ctx = ZigbeeContext(**item['context'])
            ctx.key_epochs = {ctx.active_key_sequence: 'initial'}
            if type(item['controller_short']) is not int: raise ConfigError('controller address must be integer')
            core = DeviceConfig(item['device_id'],ctx,item['controller_short'],item['key_reference'])
            devices.append(RegisteredDevice(core,item['friendly_name']))
        result = DaemonConfig(mqtt,tuple(devices))
        # Validate the complete configuration before resolving any key reference.
        if key_resolver is not None:
            for item in result.devices:
                c=item.core.context
                c.keys.put(c.active_key_sequence,key_resolver(item.core.key_reference))
        return result
    except (ValueError, TypeError, KeyError, AttributeError):
        # No user-provided values or resolver exception text in diagnostics.
        raise ConfigError('invalid offline configuration') from None
