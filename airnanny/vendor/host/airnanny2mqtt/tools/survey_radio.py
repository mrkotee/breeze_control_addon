"""Listen to the radio and report what it hears. Transmits nothing.

Placement questions cannot be answered by starting the service and seeing
whether a context recovers: that costs a recovery cycle, takes minutes, and
can leave a latched fault behind. Worse, it conflates two different problems.
A context that does not come up may be one we cannot hear, or one we can hear
perfectly but cannot answer because the channel at the dongle is busy. The
cures are opposite -- move the antenna toward the device, or away from the
interference -- so telling them apart first is worth a minute.

The firmware reports every frame it receives, with its signal strength, link
quality and whether it matched a configured context. This reads those reports
and summarises them. It sends no command, transmits nothing over the air,
and opens neither a durable store nor the service state.

Opening the port makes the firmware take a fresh boot, as it does for the
service, and closing it asks for the same safe reset. Nothing else changes.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.deps'), str(ROOT / 'src'), str(ROOT / 'tools')]
sys.dont_write_bytecode = True

from airnanny.radio_wire import parse_record                     # noqa: E402
from airnanny.serial_support import SerialChannel, SerialFault   # noqa: E402
from airnanny.real_radio import serial_port_factory              # noqa: E402
from run_radio_daemon import firmware_modules                    # noqa: E402

PAN_LABELS = {'0': 'ctx0 — second bedroom, PAN FA9B',
              '1': 'ctx1 — bedroom, PAN 0B7A'}


def signed_rssi(value):
    """The surface reports RSSI as an unsigned token; it is a negative dBm."""
    number = int(value)
    return number - 256 if number > 127 else number


class Readings:
    def __init__(self):
        self.rssi = []
        self.lqi = []
        self.frames = 0
        self.fcs_bad = 0
        self.unmatched = 0
        self.reasons = Counter()

    def add(self, fields):
        self.frames += 1
        if fields.get('fcs_ok') == '0':
            self.fcs_bad += 1
        if fields.get('match') == '0':
            self.unmatched += 1
            if fields.get('reason'):
                self.reasons[fields['reason']] += 1
        try:
            self.rssi.append(signed_rssi(fields['rssi']))
            self.lqi.append(int(fields['lqi']))
        except (KeyError, ValueError):
            pass

    def summary(self):
        out = {'frames': self.frames, 'fcs_bad': self.fcs_bad,
               'unmatched': self.unmatched}
        if self.rssi:
            out['rssi_mean'] = round(statistics.fmean(self.rssi), 1)
            out['rssi_best'] = max(self.rssi)
            out['rssi_worst'] = min(self.rssi)
            out['lqi_mean'] = round(statistics.fmean(self.lqi), 1)
            out['lqi_worst'] = min(self.lqi)
        if self.reasons:
            out['unmatched_reasons'] = dict(self.reasons)
        return out


def verdict(summary):
    """Plain words for the number that matters.

    LQI is the honest one here: it reflects what the demodulator actually
    managed to do with the frame, where RSSI alone counts interference as
    signal. Below about 40 a link exists but will not survive the retries a
    secured exchange needs.
    """
    if not summary.get('frames'):
        return 'nothing heard'
    lqi = summary.get('lqi_mean')
    if lqi is None:
        return 'heard, no quality reported'
    if lqi >= 80:
        return 'strong'
    if lqi >= 50:
        return 'workable'
    if lqi >= 30:
        return 'marginal - this is where secured recovery fails'
    return 'too weak to rely on'


def select_port(frozen, requested=None):
    _, list_ports = frozen.serial_modules()
    ports = list(list_ports.comports())
    pin = frozen.authority.DONGLE
    if not [p for p in ports if (p.vid, p.pid, p.serial_number)
            == (pin['vid'], pin['pid'], pin['serial'])]:
        raise SystemExit('dongle_absent: no port matches the pinned USB serial')
    selected = frozen.authority.select_device(ports)['port']
    if requested and selected != requested:
        raise SystemExit('requested_port_does_not_match_pinned_dongle')
    return selected


def listen(port, seconds):
    channel = SerialChannel(port)
    contexts = defaultdict(Readings)
    kinds = Counter()
    malformed = 0
    deadline = time.monotonic() + seconds
    fault = None
    while time.monotonic() < deadline:
        try:
            channel.pump()
        except SerialFault as exc:
            # The dongle went away mid-survey. Report what was already heard
            # rather than losing it to a traceback: a partial measurement
            # still answers the question that prompted it.
            fault = str(exc)
            break
        line = channel.pop_line()
        if line is None:
            time.sleep(0.005)
            continue
        try:
            kind, fields = parse_record(line)
        except SerialFault:
            malformed += 1
            continue
        kinds[kind] += 1
        if kind == 'RX':
            contexts[fields.get('ctx', '?')].add(fields)
    return contexts, kinds, malformed, fault


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--seconds', type=int, default=60,
                   help='how long to listen; 60 is usually enough to tell the cases apart')
    p.add_argument('--port', help='optional fixed port; otherwise the pinned dongle')
    p.add_argument('--json', action='store_true', help='machine-readable summary')
    args = p.parse_args(argv)
    if not 5 <= args.seconds <= 3600:
        p.error('listen for between 5 seconds and an hour')

    frozen = firmware_modules()
    name = select_port(frozen, args.port)
    port = serial_port_factory(name)
    try:
        # The firmware takes a fresh boot when the port opens; give it a
        # moment before counting, so the quiet start is not read as silence.
        time.sleep(2)
        contexts, kinds, malformed, fault = listen(port, args.seconds)
    finally:
        port.close()

    report = {'seconds': args.seconds, 'records': dict(kinds),
              'malformed_records': malformed, 'interrupted_by': fault,
              'contexts': {slot: readings.summary()
                           for slot, readings in sorted(contexts.items())}}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print('\nListened for %d seconds. Nothing was transmitted.\n' % args.seconds)
    if not kinds:
        print('The firmware said nothing at all. It may not have finished booting,')
        print('or the port is not the dongle. This is not a signal measurement.')
        return 1
    if fault:
        print('The survey ended early: %s\n' % fault)
    print('Records seen: %s' % ', '.join('%s=%d' % kv for kv in sorted(kinds.items())))
    if malformed:
        print('Malformed records: %d' % malformed)
    print()
    for slot in ('0', '1'):
        summary = report['contexts'].get(slot, {'frames': 0})
        print('%s' % PAN_LABELS.get(slot, 'ctx' + slot))
        print('  %s' % verdict(summary))
        if summary.get('frames'):
            print('  frames %d, RSSI mean %s dBm (best %s, worst %s), LQI mean %s (worst %s)'
                  % (summary['frames'], summary.get('rssi_mean'), summary.get('rssi_best'),
                     summary.get('rssi_worst'), summary.get('lqi_mean'), summary.get('lqi_worst')))
            if summary.get('fcs_bad'):
                print('  %d frames failed their checksum - interference, not distance'
                      % summary['fcs_bad'])
        print()
    other = {k: v for k, v in report['contexts'].items() if k not in ('0', '1')}
    if other:
        # Frames on the channel that belong to neither context are the other
        # half of the question: a busy channel is why a transmission cannot
        # start, however well we hear the devices.
        print('Frames on the channel matching neither context: %s'
              % ', '.join('%s=%d' % (k, v['frames']) for k, v in sorted(other.items())))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
