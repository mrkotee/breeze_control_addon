import unittest
from test_runner import Tests

class CcaRunner(Tests):
    def test_first_cca_then_second_poll_full_commissioning(self):
        d=self.make('cca_then_response').execute()
        self.assertTrue(d['primary'].startswith('A '),d.get('failure'))
        self.assertEqual(d['tx_counts']['ASSOCIATION_REQUEST'],1)
        self.assertEqual(d['tx_counts']['ASSOCIATION_EXT_POLL'],2)
        rows=[r for r in d['records'] if r['kind']=='HOST_COMMAND' and 'ASSOC POLL ' in r['raw']]
        cca=next(r for r in d['records'] if r['kind']=='TXDONE' and r['fields']['result']=='cca_fail')
        self.assertGreaterEqual(rows[1]['monotonic']-cca['completed_at'],.0032)
        self.assertEqual(d['public_epoch']['next_fc'],32)
        self.assertEqual(d['tx_counts']['DEVICE_ANNOUNCE'],1)
        self.assertEqual(d['next_protocol_state'],'MANAGEMENT_PENDING')
        from runner import durable,HERE
        durable(HERE/'evidence/fakeport_cca.json',dict(d,hardware=False,RF_TX=0,COM=0))
    def test_response_during_cca_backoff_cancels_second_poll(self):
        d=self.make('cca_response_between').execute()
        self.assertTrue(d['primary'].startswith('A '),d.get('failure'))
        self.assertEqual(d['tx_counts']['ASSOCIATION_EXT_POLL'],1)
    def test_second_cca_terminal_no_key(self):
        d=self.make('cca_twice').execute()
        self.assertTrue(d['primary'].startswith('F '))
        self.assertEqual(d['tx_counts']['ASSOCIATION_EXT_POLL'],2)
        self.assertEqual(self.p.polls,0)
        self.assertNotIn('DEVICE_ANNOUNCE',d['tx_counts'])
    def test_request_cca_no_retry(self):
        d=self.make('request_cca').execute()
        self.assertTrue(d['primary'].startswith('F '))
        self.assertEqual(d['tx_counts']['ASSOCIATION_REQUEST'],1)
        self.assertNotIn('ASSOCIATION_EXT_POLL',d['tx_counts'])
    def test_poll_no_ack_terminal_no_retry(self):
        d=self.make('poll_no_ack').execute()
        self.assertTrue(d['primary'].startswith('F '))
        self.assertEqual(d['tx_counts']['ASSOCIATION_EXT_POLL'],1)
    def test_failed_END_never_reports_management_pending(self):
        r=self.make();original=r.phase_set
        def fail(name):
            original(name)
            if name=='END':self.p.is_open=False
        r.phase_set=fail;d=r.execute()
        self.assertTrue(d['primary'].startswith('H '))
        self.assertEqual(d['next_protocol_state'],'STOP')

def load_tests(loader,tests,pattern):
    return unittest.TestSuite(CcaRunner(name) for name in CcaRunner.__dict__ if name.startswith('test_'))

if __name__=='__main__':unittest.main()
