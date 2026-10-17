"""Gate A driver. The port is injected, so the whole flow is testable offline.

This holds the sequence and nothing else: no hash pinning, no store writes, no
device selection. Those live in launch_gate_a.py, which is the guard and only
ever runs for real. Splitting them is what lets the sequence be driven against
the actual firmware through a fake port before it is ever driven against a
radio -- the same reason host/gate_a.py keeps the evaluation pure.

Gate A transmits NOTHING. It does not bind, does not publish an allowlist and
never keys the radio: it answers INFO and STATUS, listens, and reads the
counters. It never writes a store. That is the whole gate, and it is why it can
be re-run as often as the measurement needs without touching either network.

The second phase this driver used to have -- allowlist both tuples, measure the
immediate ACK -- moved to Gate B. See gate_a.evaluate for why: the ACK
measurement needs frames addressed to us, and nothing addresses a device that
has not joined and polled.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_a
import dual_store
import id_floor
from rejoin_wire import Wire, Fault, PREFIX

# The identity the guard refuses to drive anything else. The host carries its
# own copy of the wire version and checks it against the firmware's own `wire`
# field rather than trusting it; see include/radio_wire.h.
EXPECTED_INFO = {
    'identity': 'airnanny_dual_pan_runtime_v28',
    'version': '28',
    'wire': '10',
    'contexts': '2',
    'channel': '21',
    'crypto': 'host_only',
    'application_tx': 'typed_fan_once',
    'immediate_ack': '0',
    'pending_tx': '0',
}

# One window now, and a longer one: the survey is passive, so the only way to
# reach the per-PAN sample floor is to wait for both coordinators to talk. The
# first hardware run heard 492 frames in roughly 200 s of listening, so this is
# generous for the 30-per-PAN floor without being open-ended. The gate stops as
# soon as the floor is reached on both.
SURVEY_SECONDS = 300.0
# 32 bits of microseconds wrap at 71.583 minutes and the firmware stops on a
# backwards clock, so a gate is refused if it cannot finish inside the counter.
# See evidence/dual_pan_soak_clock_envelope.json.
CLOCK_WRAP_US = 2 ** 32
CLOCK_MARGIN_US = 120 * 1000000


class GateARunner:
    def __init__(self, port, clock, stores=None):
        self.clock = clock
        self.records = []
        self.w = Wire(port, clock, self.records)
        self.stores = stores
        self.info = None

    # -- plumbing ---------------------------------------------------------
    # INFO's field set is `id` alone: it is the handshake that reveals boot, so
    # requiring boot on it would be circular on the first call, and the
    # firmware refuses a second INFO that carries one. The host therefore omits
    # boot on INFO and checks the boot in the RESPONSE against what it already
    # knows, which is the stronger direction anyway -- the host verifies the
    # firmware rather than asserting to it.
    BOOTLESS = ('INFO',)

    # Command ids must STRICTLY INCREASE within one firmware boot:
    # src/main.c rejects `c.id <= last_id` with reason=id_reused. The host's
    # counter, though, starts at 1 every time a runner is constructed, so a
    # second gate run against a dongle that has not been power-cycled is
    # refused on its very first command. That is exactly what happened on
    # attempt 2: the firmware answered `ERROR id=1 reason=id_reused` and the
    # run ended before it had read anything.
    #
    # Re-plugging the dongle would clear it, but that is a manual action, and
    # needing one before every run would undo the point of making this gate
    # passive and repeatable. So the host finds the floor instead, which it is
    # entitled to do: the rule is only that ids rise, not that they are
    # contiguous or start anywhere in particular.
    #
    # The probe is safe by inspection of the firmware's own fail path: an
    # id_reused refusal does NOT update last_id and does NOT call
    # stop_all_loss, so a rejected probe leaves the dongle exactly as it was.
    # The probe itself lives in host/id_floor.py: Gate B hit the identical
    # failure on its first live attempt because this routine was inside Gate
    # A's runner. One copy, used by both.
    def probe_id_floor(self):
        return id_floor.probe(self.w, self.clock, self.records)

    def command(self, verb, fields='', expect=None):
        i = self.w.next_id()
        line = '%s %s id=%d' % (PREFIX, verb, i)
        if self.w.boot and verb not in self.BOOTLESS:
            line += ' boot=' + self.w.boot
        if fields:
            line += ' ' + fields
        self.w.send(line)
        want = expect or {'INFO': 'INFO', 'STATS': 'STATS'}.get(verb, 'STATUS')
        got = self.until(lambda r: r['kind'] == want
                         and r['fields'].get('id') == str(i), 3)['fields']
        if verb in self.BOOTLESS and self.w.boot and got.get('boot') != self.w.boot:
            raise Fault('boot_changed_mid_session:%r' % got.get('boot'))
        return got

    def until(self, predicate, seconds):
        end = self.clock() + seconds
        while self.clock() < end:
            row = self.w.read()
            if row:
                self.note(row)
                if predicate(row):
                    return row
        raise Fault('bounded_receipt_timeout')

    def note(self, row):
        # config_generation is deliberately NOT collected here. It is scoped to
        # the phase-2 slice by gate_a.config_generations; a session-wide
        # collection spans the publish and always looks unstable.
        if row['kind'] == 'ERROR':
            raise Fault('firmware_error:' + row['fields'].get('reason', '?'))

    def observe(self, seconds, stop=None):
        """Listen without commanding. Returns the records seen in the window."""
        start = len(self.records)
        end = self.clock() + seconds
        while self.clock() < end:
            row = self.w.read()
            if row:
                self.note(row)
                if stop and stop():
                    break
        return self.records[start:]

    def pan_counts(self, since=0):
        """Frames heard per PAN over the slice that becomes the evidence.

        By PAN rather than by `match`, for the reason in gate_a.frame_pan: in a
        passive gate nothing is addressed to us, so `match` is `foreign` for
        every frame and counting it would stop at zero forever.
        """
        out = {m: 0 for m in gate_a.BOUND_MATCHES}
        for r in self.records[since:]:
            if r['kind'] != 'RX':
                continue
            pan = gate_a.frame_pan(r['fields'].get('mac'))
            for m, p in gate_a.PAN_OF_CTX.items():
                if p == pan:
                    out[m] += 1
        return out

    def rx_counts(self, since=0):
        """Counted over the same slice that becomes the evidence. Counting over
        all records instead is off by however many frames arrived during the
        exchange that preceded the window -- both contexts are bound by then,
        so frames are already flowing -- and the collection would stop one
        sample short of the floor while believing it had reached it."""
        out = {'ctx0': 0, 'ctx1': 0}
        for r in self.records[since:]:
            if r['kind'] == 'RX' and r['fields'].get('match') in out:
                out[r['fields']['match']] += 1
        return out

    # -- the gate ---------------------------------------------------------
    def check_identity(self):
        self.info = self.command('INFO')
        wrong = {k: self.info.get(k) for k, v in EXPECTED_INFO.items()
                 if self.info.get(k) != v}
        if wrong:
            raise Fault('unexpected_firmware_identity:%r' % wrong)
        return self.info

    def check_clock_room(self, needed_us):
        """Refuse before any radio configuration if the measurement cannot
        finish inside the microsecond counter. A gate that stops halfway
        through because the clock wrapped has measured nothing and has still
        put the dongle on air."""
        # The clock is read from STATUS rather than INFO: INFO carries budgets
        # and identity, STATUS carries time_us.
        status = self.command('STATUS', 'session=0')
        now_us = int(status.get('time_us', 0))
        if now_us + needed_us + CLOCK_MARGIN_US >= CLOCK_WRAP_US:
            raise Fault('insufficient_clock_room:time_us=%d needed=%d'
                        % (now_us, needed_us))
        return now_us

    def survey(self):
        """The gate. Listen until both PANs have reached the sample floor, or
        the window expires. Nothing is bound and nothing is transmitted, so the
        ACK gate must be shut at the start and still shut at the end -- checked
        at both ends rather than once, because a gate that opened halfway
        through would otherwise go unnoticed."""
        if self.info.get('immediate_ack') != '0':
            raise Fault('ack_open_before_the_survey')
        start = len(self.records)

        def enough():
            c = self.pan_counts(start)
            return min(c.values()) >= gate_a.MIN_SURVEY_SAMPLES_PER_PAN
        self.observe(SURVEY_SECONDS, stop=enough)
        after = self.command('INFO')
        if after.get('immediate_ack') != '0':
            raise Fault('ack_opened_during_a_passive_gate')
        # The generation is compared with where it started, not with zero. A
        # dongle keeps a published allowlist for the life of a boot, so one
        # that has already run a gate on this boot legitimately starts at 2
        # with the ACK gate shut. What Gate A must show is that IT published
        # nothing, which is this comparison.
        if after.get('config_generation') != self.info.get('config_generation'):
            raise Fault('allowlist_published_during_a_passive_gate:%s->%s'
                        % (self.info.get('config_generation'),
                           after.get('config_generation')))
        return self.records[start:], after

    def execute(self):
        """The whole gate, in order, bounded. Returns the outcome; it does not
        decide what to do about it."""
        outcome = {'executed': False, 'error': None, 'passed': False}
        try:
            # The id floor first: a dongle that has not been power-cycled
            # since an earlier run refuses id=1, and everything after would
            # fail for a reason that has nothing to do with the radio.
            outcome['id_floor'] = self.probe_id_floor()
            outcome['info_before'] = self.check_identity()
            outcome['clock_us_at_start'] = self.check_clock_room(
                int(SURVEY_SECONDS * 1000000))
            outcome['executed'] = True

            records, info_after = self.survey()
            outcome['info_after_survey'] = info_after
            outcome['pan_counts'] = self.pan_counts(len(self.records) - len(records))

            outcome['stats'] = self.command('STATS')
            if outcome['stats'].get('routing_faults') != '0':
                raise Fault('routing_faults:%s' % outcome['stats']['routing_faults'])
            # A passive gate that transmitted is not a passive gate, and every
            # claim it makes about an unperturbed network is void.
            for counter in ('ctx0_tx_accepted', 'ctx1_tx_accepted'):
                if outcome['stats'].get(counter) not in (None, '0'):
                    raise Fault('gate_a_transmitted:%s=%s'
                                % (counter, outcome['stats'][counter]))

            verdict = gate_a.evaluate(records, outcome['stats'])
            outcome['verdict'] = verdict
            outcome['stats_coherence'] = verdict['stats_coherence']
            outcome['passed'] = verdict['passed']
        except (Fault, gate_a.GateAFault, dual_store.StoreFault) as e:
            outcome['error'] = '%s:%s' % (type(e).__name__, e)
        finally:
            # END is attempted whatever happened. Gate A binds nothing, so
            # there should be no session to close -- which is exactly why it is
            # still sent: if END reports something was open, this gate was not
            # as passive as it claims and that belongs in the record.
            try:
                outcome['end'] = self.command('END', 'session=1')
            except Exception as e:
                outcome['end_error'] = '%s:%s' % (type(e).__name__, e)
            outcome['records'] = self.records
        return outcome
