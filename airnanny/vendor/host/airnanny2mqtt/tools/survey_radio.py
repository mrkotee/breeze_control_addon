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

PAN_LABELS = {'ctx0': 'ctx0 - second bedroom, PAN FA9B',
              'ctx1': 'ctx1 - bedroom, PAN 0B7A'}
CONTEXT_PANS = {0xFA9B: 'ctx0', 0x0B7A: 'ctx1'}
# An 802.15.4 acknowledgement carries no addressing at all -- type, sequence
# number and checksum, nothing more -- so it cannot be attributed to a
# network. Counting these as foreign traffic would overstate how busy the
# channel is by exactly the amount our own units are talking.
# A PAN holds three talkers: the AirNanny itself as coordinator, its stock
# AirControl remote, and this dongle. Hearing the network is not the same as
# hearing the unit, and only the unit answers a discovery beacon request --
# so a survey that stops at the PAN can report a strong signal from a remote
# while the thing we need to reach is inaudible.
# The three low bits of the frame control field. A discovery request is a
# MAC command and the answer to it is a beacon, so which types are in the air
# separates "the unit never hears our request" from "it answers and something
# here does not accept the answer".
FRAME_TYPES = {0: 'beacon', 1: 'data', 2: 'ack', 3: 'mac-command'}
SOURCES = {0x0000: 'the AirNanny itself', 0xC9B7: 'stock remote (second bedroom)',
           0xF59F: 'stock remote (bedroom)', 0xA326: 'this dongle (ctx0)',
           0x6C55: 'this dongle (ctx1)'}
LABELS = {'unaddressed': 'acknowledgements',
          'broadcast': 'broadcasts',
          'unreadable': 'undecodable headers'}
BROADCAST_PAN = 0xFFFF


def mac_header(data):
    """Destination and source PAN and address from a raw MAC header.

    Read leniently, as a survey must: the strict parser accepts only legacy
    data frames, and beacons and acknowledgements are exactly the traffic
    that says whether a device is audible.

    Any field may be None when the frame does not carry it.
    """
    out = {'destination_pan': None, 'destination': None,
           'source_pan': None, 'source': None, 'type': None}
    if len(data) < 3:
        return out
    fcf = int.from_bytes(data[0:2], 'little')
    out['type'] = FRAME_TYPES.get(fcf & 0x07, 'reserved-%d' % (fcf & 0x07))
    destination_mode, source_mode = (fcf >> 10) & 3, (fcf >> 14) & 3
    compressed = bool(fcf & 0x40)
    offset = 3
    if destination_mode:
        if len(data) < offset + 2:
            return out
        out['destination_pan'] = int.from_bytes(data[offset:offset + 2], 'little')
        offset += 2
        width = 2 if destination_mode == 2 else 8
        if len(data) >= offset + width and destination_mode == 2:
            out['destination'] = int.from_bytes(data[offset:offset + 2], 'little')
        offset += width
    if source_mode:
        if compressed:
            out['source_pan'] = out['destination_pan']
        else:
            if len(data) < offset + 2:
                return out
            out['source_pan'] = int.from_bytes(data[offset:offset + 2], 'little')
            offset += 2
        if source_mode == 2 and len(data) >= offset + 2:
            out['source'] = int.from_bytes(data[offset:offset + 2], 'little')
    return out


def pan_ids(data):
    """Destination and source PAN only; kept for callers that want just those."""
    header = mac_header(data)
    return header['destination_pan'], header['source_pan']


def classify(mac_hex):
    """Which network a frame belongs to, by PAN rather than by context.

    The firmware reports `ctx=none` for anything it is not currently bound
    to, which during a survey is everything -- so grouping by that field
    would report silence while frames are arriving.
    """
    try:
        data = bytes.fromhex(mac_hex)
    except (ValueError, TypeError):
        return 'unreadable'
    destination, source = pan_ids(data)
    for pan in (destination, source):
        if pan in CONTEXT_PANS:
            return CONTEXT_PANS[pan]
    for pan in (source, destination):
        if pan is not None and pan != BROADCAST_PAN:
            return 'other:%04x' % pan
    if BROADCAST_PAN in (destination, source):
        return 'broadcast'
    return 'unaddressed'


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
        self.sources = Counter()
        self.types = Counter()

    def add(self, fields, source=None, frame_type=None):
        self.frames += 1
        self.sources[source] += 1
        self.types[frame_type] += 1
        if fields.get('fcs_ok') == '0':
            self.fcs_bad += 1
        if fields.get('match') == '0':
            self.unmatched += 1
            if fields.get('reason'):
                self.reasons[fields['reason']] += 1
        try:
            self.rssi.append(signed_rssi(fields['rssi']))
        except (KeyError, ValueError):
            pass
        try:
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
        # Guarded separately: a frame can report one without the other, and
        # one odd record must not discard a whole measurement.
        if self.lqi:
            out['lqi_mean'] = round(statistics.fmean(self.lqi), 1)
            out['lqi_worst'] = min(self.lqi)
        if self.reasons:
            out['unmatched_reasons'] = dict(self.reasons)
        out['sources'] = {('%04x' % k if k is not None else 'unknown'): v
                          for k, v in self.sources.most_common()}
        out['types'] = {k or 'unknown': v for k, v in self.types.most_common()}
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
            try:
                header = mac_header(bytes.fromhex(fields.get('mac', '')))
            except (ValueError, TypeError):
                header = {'source': None, 'type': None}
            contexts[classify(fields.get('mac', ''))].add(
                fields, header['source'], header['type'])
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
    for slot in ('ctx0', 'ctx1'):
        summary = report['contexts'].get(slot, {'frames': 0})
        print('%s' % PAN_LABELS[slot])
        print('  %s' % verdict(summary))
        if summary.get('frames'):
            print('  frames %d, RSSI mean %s dBm (best %s, worst %s), LQI mean %s (worst %s)'
                  % (summary['frames'], summary.get('rssi_mean'), summary.get('rssi_best'),
                     summary.get('rssi_worst'), summary.get('lqi_mean'), summary.get('lqi_worst')))
            if summary.get('fcs_bad'):
                print('  %d frames failed their checksum - interference, not distance'
                      % summary['fcs_bad'])
            if summary.get('types'):
                print('    frame types: %s'
                      % ', '.join('%s=%d' % kv for kv in summary['types'].items()))
            if not summary.get('types', {}).get('beacon'):
                # Discovery asks and the unit answers with a beacon. None in
                # the air means either it only beacons on request -- so our
                # request is not reaching it -- or it does not beacon at all.
                print('    no beacon heard from this network.')
            for address, count in (summary.get('sources') or {}).items():
                known = SOURCES.get(int(address, 16)) if address != 'unknown' else None
                print('    from %s: %d frames%s'
                      % (address, count, '  <- %s' % known if known else ''))
            if not any(a != 'unknown' and int(a, 16) == 0
                       for a in (summary.get('sources') or {})):
                # Discovery needs a beacon from the coordinator. Traffic from
                # its remote proves the network is live, not that the unit we
                # must reach can be heard from here.
                print('    NOTHING HEARD FROM THE UNIT ITSELF (address 0000).')
                print('    Only the unit answers a discovery beacon request.')
        print()
    other = {k: v for k, v in report['contexts'].items() if k not in ('ctx0', 'ctx1')}
    if other:
        # Frames on the channel that belong to neither context are the other
        # half of the question: a busy channel is why a transmission cannot
        # start, however well we hear the devices.
        print('Everything else on channel 21:')
        for key, summary in sorted(other.items(), key=lambda kv: -kv[1]['frames']):
            print('  %-16s %4d frames, RSSI mean %s dBm'
                  % (LABELS.get(key, key), summary['frames'], summary.get('rssi_mean', 'n/a')))
        print('')
        if any(key.startswith('other:') for key in other):
            print('A network listed by its own PAN is somebody else using this')
            print('channel, which is why a transmission may fail to start even')
            print('where the units themselves are heard clearly.')
        else:
            print('No foreign network is using this channel: every frame above')
            print('belongs to the two units or acknowledges one of them.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
