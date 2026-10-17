"""Gate E on the wire: one phase of the restart test.

Each phase is Gate B's chain on both contexts, then a short keepalive stretch
(Gate D's soak machinery at a 10 s period). Phase A ends WITHOUT END: the
launcher writes its record and the process dies, so the firmware sees the
port close the way it would if the host crashed. Phase B is a new process on
a new dongle boot and ends normally.
"""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import management                                   # noqa: F401  this tree's, first
import gate_b
from gate_d_runner import GateDRunner

KEEPALIVE_S = 60
PERIOD_S = 10.0


def phase_b_guard(run_id):
    """Phase B's guard, derived from the run id. A cycle cannot be opened twice
    under one guard (dual_ledger.begin_cycle), and both phases belong to one
    run, so B takes a second guard that anyone can recompute from the first."""
    return hashlib.sha256(('%s:phase-b' % run_id).encode()).hexdigest()[:32]


class GateERunner(GateDRunner):
    def __init__(self, port, clock, ledgers, guard=None, prompt=print):
        super().__init__(port, clock, ledgers, guard=guard, prompt=prompt, period=PERIOD_S)

    def execute_phase(self, end=True, keepalive_s=KEEPALIVE_S):
        outcome = {'executed': False, 'error': None, 'reached_active': {}}
        try:
            outcome['id_floor'] = self.probe_id_floor()
            outcome['info_before'] = self.check_identity()
            self.require_a_fresh_boot()
            outcome['executed'] = True
            session_started = self.clock()
            outcome['commissioned'] = {str(c): self.commission(c) for c in (0, 1)}
            outcome['reached_active'] = {
                str(c): outcome['commissioned'][str(c)].get(gate_b.RECOVERY_FIELD)
                == 'PARENT_LINK_ACTIVE' for c in (0, 1)}
            self.soak(keepalive_s, session_started)
            outcome['final_status'] = self.snapshots[-1]['status']
            outcome['stats'] = self.snapshots[-1]['stats']
        except BaseException as e:
            outcome['error'] = '%s:%s' % (type(e).__name__, e)
            outcome['interrupted'] = not isinstance(e, Exception)
        finally:
            outcome['polls_sent'] = self.polls_record()
            outcome['poll_misses'] = {str(c): n for c, n in self.misses_total.items()}
            outcome['stopped'] = {str(c): why for c, why in self.stopped.items()}
            outcome['snapshots'] = self.snapshots
            outcome['ended_cleanly'] = False
            if end:
                try:
                    outcome['end'] = self.command('END', fields='session=1')
                    outcome['ended_cleanly'] = True
                except Exception as e:
                    outcome['end_error'] = '%s:%s' % (type(e).__name__, e)
            outcome['records'] = self.records
            outcome['sent_order'] = self.sent_order
            outcome['answers'] = self.answers
        return outcome
