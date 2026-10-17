"""Gate C on the wire: Gate B's chain and readiness, then one FAN command per
context, ctx0 first, each while both parent links are kept alive.

The firmware will only take a TYPE07_FAN from a session that is >= 60 s old,
has >= 40 keepalive polls, polled within the last 2 s, and closed its
response window (rejoin_transport.c:77-79). That is Gate B's readiness, so
Gate C is Gate B continued in the same boot, never a separate session.

The baseline is the hard part. It is this network's remote's own TYPE07,
which the remote sends only when a button is pressed. So the runner asks the
operator for the press and keeps both links alive while it waits. If nothing
arrives, it stops without spending anything.

Every transmission is a chance to lose the run. The firmware stops a context
on the first failed TX (rejoin_transport.c:106): a lost ACK in attempt 2, an
ACK with a bad CRC in attempt 3, both on channel 21 next to 2.4 GHz Wi-Fi. So
this runner spends as few as the firmware allows:

- readiness polls every 1.45 s, which is the 40 per context in 60 s that the
  firmware requires and no more;
- the operator is asked for the first press DURING readiness, so the
  baseline is there when readiness ends rather than minutes later;
- while waiting for a press, polls are sparse (every 10 s): nothing needs
  them except the parent's link, whose timeout is 15360 s;
- around each command, a short dense stretch: a fresh poll of that context
  (the firmware wants one within 2 s), and the other context polled every
  1.25 s, because Gate C must show the peer alive through the command.

Needs Python >= 3.10 (dual_application imports the airnanny2mqtt core).
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import management                                   # noqa: F401  this tree's, first
import gate_b
import gate_c
from gate_b_runner import GateBRunner, READINESS_SECONDS
from rejoin_wire import Fault
from dual_application import ContextFanControl

READINESS_PERIOD_S = 1.45      # >= 40 polls per context in 60 s, and no more
SPARSE_PERIOD_S = 10.0         # while a person walks to a remote
DENSE_PERIOD_S = 1.25          # around a command
FIRST_PROMPT_AT_S = 45         # into readiness: the press lands as it ends
MIN_POLLS = 40                 # rejoin_transport.c:78, total_polls < 40
BASELINE_WAIT_S = 120          # how long the operator has for each press
CONFIRM_WAIT_S = 25            # Confirmation's own window is 20 s
FRESH_POLL_S = 1.0             # the firmware allows 2 s; send well inside it
PEER_AFTER_S = 5.0             # dense polling kept this long after confirmation


class GateCRunner(GateBRunner):
    def __init__(self, port, clock, ledgers, guard=None, prompt=print, press='FAN-'):
        super().__init__(port, clock, ledgers, guard=guard)
        self.prompt = prompt
        self.press = press
        self.adapters = {}
        self.prompted_at = {}
        self.fed = 0
        self.last_poll = {0: None, 1: None}
        self.polls_sent = {0: 0, 1: 0}
        self.due = None

    # -- keepalive that can be interleaved with anything else ------------
    def start_keepalive(self, period):
        t0 = self.clock()
        self.due = {}
        for ctx in (0, 1):
            r = self.ledgers[ctx].read()
            # Never sooner than a full period from now: the firmware refuses a
            # poll within 1 s of the previous one (idle_poll_bound), and
            # PARENT_LINK_ACTIVE counts as one.
            self.due[ctx] = {'at': t0 + max(period, 1.1) + 0.5 * ctx, 'period': period,
                             'generation': r['generation'],
                             'dsn': (r['sequences']['dsn'] + 64 + 32 * ctx) & 255}

    def set_period(self, period):
        for ctx in (0, 1):
            d = self.due[ctx]
            if d['period'] != period:
                d['period'] = period
                last = self.last_poll[ctx]
                earliest = (last + 1.1) if last is not None else self.clock()
                d['at'] = max(earliest, min(d['at'], self.clock() + period))

    def service(self):
        """One step: poll whichever context is due, read one record, and hand
        every new RX to the application adapters. Called in every wait."""
        for ctx in (0, 1):
            d = self.due[ctx]
            if self.clock() >= d['at']:
                d['dsn'] = (d['dsn'] + 1) & 255
                self.idle_poll(ctx, d['generation'], d['dsn'])
                self.last_poll[ctx] = self.clock()
                self.polls_sent[ctx] += 1
                d['at'] = self.clock() + d['period']
        self.w.read()
        self.feed()

    def feed(self):
        while self.fed < len(self.records):
            row = self.records[self.fed]
            self.fed += 1
            if row.get('kind') != 'RX' or not self.adapters:
                continue
            f = row['fields']
            for a in self.adapters.values():
                a.receive(bytes.fromhex(f['mac']), int(f['revision']), self.clock(),
                          int(f['time_us']))

    def wait(self, seconds, until):
        end = self.clock() + seconds
        while self.clock() < end:
            if until():
                return True
            self.service()
        return until()

    # -- one command, in two halves --------------------------------------
    def arm(self, ctx):
        """Take the radio-time floor for this context, start listening for its
        remote, and ask the operator for the press."""
        ledger = self.ledgers[ctx]
        floor = self.command('STATUS', ctx, 'session=1')
        if (floor.get(gate_b.RECOVERY_FIELD) != 'PARENT_LINK_ACTIVE'
                or floor.get('pending') != '0'):
            raise Fault('ctx%d not live before its command: %r' % (ctx, floor))
        a = ContextFanControl(ledger, self.w.boot, self.clock())
        a.radio_floor = int(floor['time_us'])
        self.adapters[ctx] = a
        self.prompted_at[ctx] = self.clock()
        self.prompt('>>> Нажмите %s на пульте сети %04X (ctx%d). Жду до %d с.'
                    % (self.press, ledger.identity['pan'], ctx, BASELINE_WAIT_S))
        return a

    def fire(self, ctx):
        ledger, a = self.ledgers[ctx], self.adapters[ctx]
        left = BASELINE_WAIT_S - (self.clock() - self.prompted_at[ctx])
        if not self.wait(max(left, 0), a.ready):
            raise Fault('no_baseline_from_the_remote:ctx=%d -- nothing was spent' % ctx)
        self.prompt('>>> Основа получена (ctx%d).' % ctx)
        # The dense stretch starts here: the peer must be seen alive through
        # the command, and this context needs a fresh poll right before it.
        self.set_period(DENSE_PERIOD_S)
        self.wait(2.0, lambda: False)              # the A7's status to the press settles
        if not a.ready():
            raise Fault('baseline_not_settled:ctx=%d' % ctx)
        if self.polls_sent[ctx] < MIN_POLLS:
            self.wait(DENSE_PERIOD_S * (MIN_POLLS - self.polls_sent[ctx]) + 2,
                      lambda: self.polls_sent[ctx] >= MIN_POLLS)
        self.wait(DENSE_PERIOD_S + 0.5,
                  lambda: self.last_poll[ctx] and self.clock() - self.last_poll[ctx] < FRESH_POLL_S)
        cmd_floor = self.command('STATUS', ctx, 'session=1')
        a.command_radio_floor = int(cmd_floor['time_us'])
        raw, intent = a.prepare(self.clock())
        a.handoff(self.clock())
        entry = self.store(ctx)
        fields = ('session=1 generation=%d epoch=%s attempt=%s guard=%s fc=%d hash=%s mac=%s'
                  % (ledger.read()['generation'], entry['epoch'], entry['attempt'],
                     entry['guard'], intent['fc'], intent['sha256'], raw.hex()))
        receipt = self.command('TYPE07_FAN', ctx, fields, raw, 'TYPE07_FAN')
        a.complete(receipt.get('result') == 'local_tx_ok', self.clock(),
                   int(receipt.get('rf_start_us', 0)))
        self.wait(CONFIRM_WAIT_S, lambda: (a.tick(self.clock()) or a.result is not None))
        self.wait(PEER_AFTER_S, lambda: False)    # the peer, after the confirmation too
        self.set_period(SPARSE_PERIOD_S)
        result = {'application_result': a.result or 'FAILED_OR_UNKNOWN',
                  'match_revision': a.confirmation.match_revision or None,
                  'match_radio_us': a.match_radio_us,
                  'from_fan': intent.get('from_fan'), 'requested': intent.get('requested'),
                  'remote_short': a.remote['short']}
        self.prompt('>>> ctx%d: %s (FAN %s -> %s)' % (ctx, result['application_result'],
                                                      result['from_fan'], result['requested']))
        return result

    def command_fan(self, ctx):
        """arm + fire, for a context whose readiness is already done."""
        self.arm(ctx)
        return self.fire(ctx)

    # -- the gate --------------------------------------------------------
    def polls_record(self):
        """polls_sent with string keys. The outcome is written as JSON and read
        back for comparison, and an int key comes back a string: attempt 4
        passed on air and then failed that readback on exactly this."""
        return {str(c): n for c, n in self.polls_sent.items()}

    def readiness(self, seconds):
        """Gate B's shared readiness at the firmware's minimum cadence, with
        ctx0's prompt issued near its end. Returns the readiness records."""
        start_index = len(self.records)
        t0 = self.clock()
        self.start_keepalive(READINESS_PERIOD_S)
        while self.clock() < t0 + seconds:
            if 0 not in self.adapters and self.clock() >= t0 + FIRST_PROMPT_AT_S:
                self.arm(0)
            self.service()
        return self.records[start_index:]

    def execute(self):
        outcome = {'executed': False, 'error': None, 'passed': False, 'results': {}}
        try:
            outcome['id_floor'] = self.probe_id_floor()
            outcome['info_before'] = self.check_identity()
            self.require_a_fresh_boot()
            outcome['executed'] = True
            outcome['commissioned'] = {str(ctx): self.commission(ctx) for ctx in (0, 1)}
            readiness = self.readiness(READINESS_SECONDS)
            if 0 not in self.adapters:
                self.arm(0)
            self.set_period(SPARSE_PERIOD_S)
            outcome['results']['0'] = self.fire(0)
            if outcome['results']['0']['application_result'] == 'CONFIRMED':
                self.arm(1)
                outcome['results']['1'] = self.fire(1)
            outcome['polls_sent'] = self.polls_record()
            outcome['stats'] = self.command('STATS')
            outcome['verdict_b'] = gate_b.evaluate(self.records, outcome['stats'],
                                                   ack_records=readiness)
            outcome['verdict'] = gate_c.evaluate(self.records, outcome['results'],
                                                 outcome['stats'])
            outcome['passed'] = outcome['verdict']['passed'] and outcome['verdict_b']['passed']
        except BaseException as e:
            # BaseException, not Exception: attempt 1 was cut by a Ctrl-C
            # (KeyboardInterrupt) after ctx0 was commissioned and left no outcome
            # at all. The record and END matter most exactly when a run is cut.
            outcome['error'] = '%s:%s' % (type(e).__name__, e)
            outcome['interrupted'] = not isinstance(e, Exception)
        finally:
            outcome['polls_sent'] = self.polls_record()
            try:
                outcome['end'] = self.command('END', fields='session=1')
            except Exception as e:
                outcome['end_error'] = '%s:%s' % (type(e).__name__, e)
            outcome['records'] = self.records
            outcome['sent_order'] = self.sent_order
            outcome['answers'] = self.answers
        return outcome
