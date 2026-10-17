"""One topic and payload contract shared by the adapter and HA discovery."""
import json
import re
from dataclasses import dataclass
from .commands import CommandRequest, CommandError
from .state import DeviceStateSnapshot

COMMANDS = ('power', 'fan', 'mode', 'temperature', 'night', 'humidifier')


def encode(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


@dataclass(frozen=True)
class Topics:
    prefix: str
    device_id: str

    def path(self, suffix): return f'{self.prefix}/{self.device_id}/{suffix}'
    @property
    def state(self): return self.path('state')
    @property
    def availability(self): return self.path('availability')
    @property
    def diagnostics(self): return self.path('diagnostics/state')
    @property
    def result(self): return self.path('command/result')
    def command(self, name):
        if name not in COMMANDS: raise ValueError('unknown command topic')
        return self.path(name + '/set')


def parse_command(name: str, payload: bytes) -> CommandRequest:
    if name not in COMMANDS or len(payload) > 64: raise CommandError('bad_argument')
    try: text = payload.decode('utf-8').strip(' \t\r\n')
    except UnicodeDecodeError: raise CommandError('bad_argument') from None
    text = text.lower()
    if name in ('power', 'night'):
        if text not in ('on', 'off'): raise CommandError('bad_argument')
    elif name == 'fan':
        if not re.fullmatch('[1-7]', text): raise CommandError('bad_argument')
        return CommandRequest('fan', int(text))
    elif name == 'temperature':
        if text != 'off' and not re.fullmatch(r'[0-9]{2}(?:\.[05])?', text):
            raise CommandError('bad_argument')
    return CommandRequest.parse('temp' if name == 'temperature' else name, text)


def state_payload(snapshot: DeviceStateSnapshot):
    target = snapshot.target
    return dict(status_valid=snapshot.status_valid, status_fresh=snapshot.status_fresh,
        status_age_ms=snapshot.status_age_ms,
        power=None if snapshot.power is None else 'on' if snapshot.power else 'off',
        fan=snapshot.fan, mode=snapshot.mode,
        temperature=target if isinstance(target, (int, float)) else None,
        temperature_control='off' if target == 'off' else 'on' if isinstance(target, (int, float)) else None,
        night=None if snapshot.night is None else 'on' if snapshot.night else 'off',
        humidifier=snapshot.humidifier, application_sequence=snapshot.application_sequence,
        rx_revision=snapshot.rx_revision, baseline_valid=snapshot.baseline_valid,
        baseline_pending=snapshot.baseline_pending, baseline_generation=snapshot.baseline_generation,
        baseline_source=snapshot.baseline_source)


def state_fingerprint(snapshot: DeviceStateSnapshot):
    data = state_payload(snapshot)
    # RX revision, age and sequence remain in published snapshots but do not alone
    # trigger a publication for every periodic identical status packet.
    for key in ('status_age_ms', 'rx_revision', 'application_sequence'): data.pop(key)
    return encode(data)
