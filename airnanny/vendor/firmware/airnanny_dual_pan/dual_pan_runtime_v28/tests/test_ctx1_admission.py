import copy,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import launcher as r
class Tests(unittest.TestCase):
    def setUp(self):
        self.files={p.name:r.load(p) for p in r.PRIOR.glob('*.json')}
        self.current=r.load(r.CURRENT/'epoch.json')
    def mutated(self,fn):
        files=copy.deepcopy(self.files);fn(files)
        with patch.object(r,'load',side_effect=lambda p:copy.deepcopy(files[Path(p).name])):
            with self.assertRaises(r.Fault):r.closed_prior()
    def test_sealed_current_allowed_readonly(self):self.assertEqual(r.closed_prior(),self.current)
    def test_previous_application_or_ambiguous_result_rejected(self):
        for fn in (lambda f:f['outcome.json'].update(TYPE07=1),lambda f:f['outcome.json'].update(application_result='CONFIRMED'),lambda f:f['outcome.json'].update(error='unknown'),lambda f:f['outcome.json']['after_public_epoch'].update(application_intent={})):self.mutated(fn)
    def test_unrecovered_or_unhealthy_rejected(self):
        for fn in (lambda f:f['terminal.json'].update(V17_verified=False),lambda f:f['recovery.json'].update(verified=False),lambda f:f['terminal.json']['physical'].update(no_check_case=False)):self.mutated(fn)
    def test_unknown_RF_or_cleanup_rejected(self):
        for key,value in (('rf_start_us','0'),('cleanup','unknown'),('reboot_required','1'),('result','tx_watchdog_abort')):
            self.mutated(lambda f,k=key,v=value:[x for x in f['outcome.json']['records'] if x['kind']=='TXDONE'][-1]['fields'].update({k:v}))
    def test_dirty_END_rejected(self):
        for k,v in (('pending','1'),('quarantine','1'),('rx_drop','1'),('accepted_count','38'),('late_callbacks','1')):self.mutated(lambda f,k=k,v=v:f['outcome.json']['end'].update({k:v}))
    def test_incomplete_rejoin_or_timeout_proof_rejected(self):
        for fn in (lambda f:f['outcome.json']['after_public_epoch']['recovery'].update(proofs=[]),lambda f:f['outcome.json']['after_public_epoch']['recovery']['intents']['TIMEOUT'].update(result='unknown'),lambda f:f['outcome.json']['after_public_epoch']['recovery'].update(firmware_current_short_commit_required=True)):self.mutated(fn)
    def test_historical_readiness_never_live_credit(self):self.mutated(lambda f:f['outcome.json']['after_public_epoch']['recovery'].update(observation={'complete':True}))
    def reject_current(self,fn):
        current=copy.deepcopy(self.current);fn(current)
        with self.assertRaises(r.Fault):r.validate_epoch(current)
    def test_ctx0_key_domain_rejected(self):self.reject_current(lambda x:x.update(key_epoch_id='1ea30211ee014345a8288337a173a833'))
    def test_replay_floor_rollback_rejected(self):self.reject_current(lambda x:x['nwk_source_floors'].update({r.TC:1}))
    def test_ctx0_RAW_rejected(self):self.reject_current(lambda x:x['context'].update(raw_ieee='e2b0275f4d582069'))
    def test_stale_short_rejected(self):self.reject_current(lambda x:x['context'].update(short=0xa326))
    def test_epoch_or_generation_changed_rejected(self):
        for fn in (lambda x:x.update(generation=6),lambda x:x.update(keyseq=1),lambda x:x['context'].update(attempt='0'*32)):self.reject_current(fn)
    def test_cross_PAN_rejected(self):self.reject_current(lambda x:x['context'].update(pan=0xfa9b))
    def test_burned_counter_never_rolled_back(self):self.reject_current(lambda x:x.update(next_fc=32))
    def test_key_reference_never_replaced(self):self.mutated(lambda f:f['outcome.json']['after_public_epoch'].update(secret_ref='wrong'))
if __name__=='__main__':unittest.main()
