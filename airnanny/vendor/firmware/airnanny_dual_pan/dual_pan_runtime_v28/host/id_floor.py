"""Finding the smallest command id a dongle boot will still accept.

Command ids must STRICTLY INCREASE within one firmware boot: src/main.c
refuses `c.id <= last_id` with reason=id_reused. A host counter that starts at
1 every time is therefore refused on its first command against a dongle that
has not been power-cycled, and the Wire reports INFO_FIRST because the first
record it sees is an ERROR rather than an INFO.

Gate A hit this and grew a probe. Gate B then hit the identical failure on its
first live attempt, because the probe lived inside Gate A's runner. So it is
here now, in one copy: a routine subtle enough to be worth getting right once
is subtle enough to be worth not having twice.

Re-plugging the dongle would also clear it, but needing a manual action before
every run would undo the point of gates that can be re-run. The host is
entitled to find the floor instead: the rule is only that ids rise, not that
they are contiguous or start anywhere in particular.

Safe by inspection of the firmware's own fail path: an id_reused refusal does
NOT update last_id and does NOT call stop_all_loss, so a rejected probe leaves
the dongle exactly as it was.
"""
from rejoin_wire import Fault, PREFIX, utc

ID_PROBE_CEILING = 1 << 20
PROBE_REPLY_SECONDS = 3.0


def probe(wire, clock, records):
    """Raise `wire.id` to the floor this boot accepts, and hand it the boot.

    Runs OUTSIDE the Wire's own read path, deliberately: the Wire refuses a
    session whose first record is not INFO and treats any ERROR as fatal, both
    of which are right for a gate and both of which would abort the probe. So
    it speaks to the port directly and afterwards hands the Wire a clean
    buffer, the correct counter and the boot it just established from a real
    INFO -- a handover rather than a bypass, since from there the Wire checks
    the boot on every line and faults on BOOT_CHANGED.

    Every line seen is recorded, refusals included: a probe that discarded
    what it read would be deciding on evidence nobody else can check.
    """
    candidate, probes, boots = 1, [], set()
    while candidate <= ID_PROBE_CEILING:
        row = _raw_info(wire, clock, records, candidate)
        probes.append({'id': candidate, 'kind': row['kind'],
                       'reason': row['fields'].get('reason')})
        if row['fields'].get('boot'):
            boots.add(row['fields']['boot'])
        if row['kind'] == 'INFO':
            if len(boots) > 1:
                raise Fault('dongle_rebooted_during_id_probe:%r' % sorted(boots))
            wire.id = candidate             # next_id() -> candidate + 1
            wire.boot = row['fields']['boot']
            return {'floor': candidate, 'probes': probes,
                    'boot': row['fields']['boot']}
        if row['kind'] != 'ERROR' or row['fields'].get('reason') != 'id_reused':
            raise Fault('id_probe_unexpected_reply:%r' % row['raw'])
        candidate *= 2
    raise Fault('id_probe_exhausted_at:%d' % ID_PROBE_CEILING)


def _raw_info(wire, clock, records, i):
    """One INFO at id `i`, read straight off the port. Returns the reply that
    carries that id; anything else seen on the way is recorded and skipped,
    and whatever is left unparsed is handed back to the Wire."""
    line = '%s INFO id=%d' % (PREFIX, i)
    records.append({'kind': 'HOST_COMMAND', 'utc': utc(),
                    'monotonic': clock(), 'raw': line,
                    'note': 'id floor probe'})
    data = (line + '\n').encode('ascii')
    if wire.port.write(data) != len(data):
        raise Fault('USB_PARTIAL_WRITE')
    end = clock() + PROBE_REPLY_SECONDS
    buf = wire.buf
    while clock() < end:
        if b'\n' not in buf:
            buf += wire.port.read(wire.port.in_waiting or 1)
            if len(buf) > 16384:
                raise Fault('SERIAL_BUFFER_BOUND')
            continue
        raw, _, buf = buf.partition(b'\n')
        text = raw.rstrip(b'\r').decode('ascii')
        parts = text.split()
        if len(parts) < 2 or parts[0] != PREFIX:
            raise Fault('UNEXPECTED_SERIAL_PROTOCOL')
        fields = dict(t.split('=', 1) for t in parts[2:] if '=' in t)
        row = {'kind': parts[1], 'fields': fields, 'raw': text,
               'utc': utc(), 'note': 'seen during id floor probe'}
        records.append(row)
        if fields.get('id') == str(i) and parts[1] in ('INFO', 'ERROR'):
            wire.buf = buf
            return row
    wire.buf = buf
    raise Fault('id_probe_no_reply_at:%d' % i)
