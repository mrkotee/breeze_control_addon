"""Fixed 60s one-shot health policy. No serial, security or retry machinery."""
from ledger import Fault
class Observation:
    def __init__(self,start):self.start=start;self.rows=[];self.success=0;self.skips=0;self.streak=0;self.buckets=[0]*6
    def record(self,now,dsn,result,preair=False):
        elapsed=now-self.start
        if not 0<=elapsed<60:raise Fault('OBSERVATION_slot_outside_fixed_window')
        if any(x['dsn']==dsn for x in self.rows):raise Fault('OBSERVATION_DSN_reuse')
        if result=='local_tx_ok':self.success+=1;self.streak=0;self.buckets[int(elapsed//10)]+=1
        else:raise Fault('OBSERVATION_terminal_poll_failure')
        self.rows.append({'elapsed_seconds':elapsed,'dsn':dsn,'result':result,'pre_air_cca':preair})
    def finish(self,now):
        if not 60<=now-self.start<62 or self.success<40 or self.skips>5 or self.streak>2 or not all(self.buckets):raise Fault('OBSERVATION_HEALTH_failed')
        return {'seconds':now-self.start,'success_ACK_polls':self.success,'cca_skips':self.skips,'success_per_10s':self.buckets,'timeline':self.rows,'complete':True}
