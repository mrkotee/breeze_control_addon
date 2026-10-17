"""Gate D on the wire: Gate B's chain, then a 60-minute soak with both
contexts live and sparse keepalive.

The soak must start from a freshly booted dongle: the firmware's 32-bit
microsecond timer wraps at 71.58 min, and its session limit is 3900 s from
BIND. The chain takes seconds, so an hour of soak fits under both, and
the runner stops on its own before the session limit rather than finding it.

What the runner does during the hour:
- polls each context every `period` seconds (one minute by default), the
  other context half a period later;
- every five minutes reads STATUS for both contexts and STATS. These are
  answers over USB and cost no transmission;
- offers every frame the firmware attributed to a context to that
  context's ledger. A Leave becomes an explicit degraded terminal for that
  context, which is then polled no further. Never a rejoin;
- a keepalive poll that misses (no ACK, a bad ACK, a busy channel) is retried
  by the next one: V27 tolerates up to MAX_CONSECUTIVE_POLL_MISSES - 1 in a
  row (management.h), V26 stopped on the first. Only that many in a row end
  the context, and then the other one keeps going to the end.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import management                                   # noqa: F401  this tree's, first
import gate_b
import gate_d
from gate_c_runner import GateCRunner
from rejoin_wire import Fault

SOAK_SECONDS = gate_d.SOAK_SECONDS
DEFAULT_PERIOD_S = 60.0
SNAPSHOT_EVERY_S = 300.0
SESSION_LIMIT_S = 3900.0       # firmware max_run_seconds, from BIND
SESSION_MARGIN_S = 60.0
MAX_CONSECUTIVE_POLL_MISSES = gate_d.MAX_CONSECUTIVE_POLL_MISSES


class GateDRunner(GateCRunner):
    def __init__(self, port, clock, ledgers, guard=None, prompt=print, period=DEFAULT_PERIOD_S):
        super().__init__(port, clock, ledgers, guard=guard, prompt=prompt)
        self.period = period
        self.stopped = {}              # ctx -> why it is no longer polled
        self.misses_in_a_row = {0: 0, 1: 0}
        self.misses_total = {0: 0, 1: 0}
        self.leaves = []
        self.snapshots = []

    def service(self):
        for ctx in (0, 1):
            if ctx in self.stopped:
                continue
            d = self.due[ctx]
            if self.clock() >= d['at']:
                d['dsn'] = (d['dsn'] + 1) & 255
                done = self.idle_poll(ctx, d['generation'], d['dsn'])
                self.last_poll[ctx] = self.clock()
                self.polls_sent[ctx] += 1
                d['at'] = self.clock() + d['period']
                if done.get('result') == 'local_tx_ok':
                    self.misses_in_a_row[ctx] = 0
                elif self.misses_in_a_row[ctx] + 1 < MAX_CONSECUTIVE_POLL_MISSES:
                    # V27 retries a clean miss with the next poll (management.h
                    # MAX_CONSECUTIVE_POLL_MISSES); the context is still live.
                    self.misses_in_a_row[ctx] += 1
                    self.misses_total[ctx] += 1
                    self.prompt('>>> ctx%d: опрос без ACK (%s), %d подряд; прошивка '
                                'продолжает' % (ctx, done.get('result'), self.misses_in_a_row[ctx]))
                else:
                    self.misses_total[ctx] += 1
                    self.stopped[ctx] = 'poll_misses_in_a_row:%d' % MAX_CONSECUTIVE_POLL_MISSES
                    self.prompt('>>> ctx%d: %d опроса подряд без ACK, прошивка остановила '
                                'контекст; второй продолжает' % (ctx, MAX_CONSECUTIVE_POLL_MISSES))
        self.w.read()
        self.feed()

    def feed(self):
        while self.fed < len(self.records):
            row = self.records[self.fed]
            self.fed += 1
            if row.get('kind') != 'RX':
                continue
            f = row['fields']
            match = f.get('match')
            if match not in ('ctx0', 'ctx1'):
                continue
            ctx = int(match[3])
            seen = self.ledgers[ctx].observe_addressed(bytes.fromhex(f['mac']),
                                                       int(f['revision']))
            if seen == 'LEAVE':
                self.leaves.append({'ctx': ctx, 'revision': int(f['revision']),
                                    'time_us': int(f['time_us'])})
                self.stopped[ctx] = 'leave'
                self.prompt('>>> ctx%d: родитель прислал Leave; контекст переведён в '
                            'DEGRADED_LEAVE, rejoin не делается' % ctx)

    def snapshot(self, t0):
        status = {}
        for ctx in (0, 1):
            status[str(ctx)] = self.command('STATUS', ctx, 'session=1')
        s = {'at_s': round(self.clock() - t0, 1), 'status': status,
             'stats': self.command('STATS')}
        self.snapshots.append(s)
        return s

    def soak(self, seconds, session_started):
        t0 = self.clock()
        first = self.snapshot(t0)
        start_us = int(first['status']['0']['time_us'])
        self.start_keepalive(self.period)
        end = min(t0 + seconds, session_started + SESSION_LIMIT_S - SESSION_MARGIN_S)
        next_snap = t0 + SNAPSHOT_EVERY_S
        while self.clock() < end:
            if self.clock() >= next_snap:
                s = self.snapshot(t0)
                self.prompt('>>> soak %4.0f с из %d: ctx0 %s, ctx1 %s'
                            % (s['at_s'], seconds,
                               s['status']['0'].get(gate_b.RECOVERY_FIELD),
                               s['status']['1'].get(gate_b.RECOVERY_FIELD)))
                next_snap += SNAPSHOT_EVERY_S
            if len(self.stopped) == 2:
                break                      # nothing left to soak
            self.service()
        last = self.snapshot(t0)
        return t0, self.clock(), start_us, int(last['status']['0']['time_us'])

    def execute(self):
        outcome = {'executed': False, 'error': None, 'passed': False}
        try:
            outcome['id_floor'] = self.probe_id_floor()
            outcome['info_before'] = self.check_identity()
            self.require_a_fresh_boot()
            outcome['executed'] = True
            session_started = self.clock()
            outcome['commissioned'] = {str(ctx): self.commission(ctx) for ctx in (0, 1)}
            self.prompt('>>> Оба контекста активны. Soak %d мин, опрос раз в %.0f с.'
                        % (SOAK_SECONDS // 60, self.period))
            t0, t1, us0, us1 = self.soak(SOAK_SECONDS, session_started)
            outcome['soak'] = {'start_s': t0, 'end_s': t1, 'start_us': us0, 'end_us': us1,
                               'period_s': self.period}
            outcome['stats'] = self.snapshots[-1]['stats']
            outcome['verdict'] = gate_d.evaluate(
                self.records, self.snapshots, outcome['stats'], t0, t1, us0, us1,
                self.period, self.leaves)
            outcome['passed'] = outcome['verdict']['passed']
        except BaseException as e:
            outcome['error'] = '%s:%s' % (type(e).__name__, e)
            outcome['interrupted'] = not isinstance(e, Exception)
        finally:
            outcome['polls_sent'] = self.polls_record()
            outcome['stopped'] = {str(c): why for c, why in self.stopped.items()}
            outcome['poll_misses'] = {str(c): n for c, n in self.misses_total.items()}
            outcome['leaves'] = self.leaves
            outcome['snapshots'] = self.snapshots
            try:
                outcome['end'] = self.command('END', fields='session=1')
            except Exception as e:
                outcome['end_error'] = '%s:%s' % (type(e).__name__, e)
            outcome['records'] = self.records
            outcome['sent_order'] = self.sent_order
            outcome['answers'] = self.answers
        return outcome
