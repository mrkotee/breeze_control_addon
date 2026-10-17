"""Actual firmware dispatcher regression for the V19 zero-air failure."""
import unittest
import copy
import uuid
import shutil
from unittest.mock import patch
from test_completion import CLI
import launcher as hw
import test_first_control as first

class BeaconTests(unittest.TestCase):
    def pending(self):
        c=CLI();self.addCleanup(c.close)
        c.command('BIND',f'generation=13 epoch={hw.EPOCH} attempt={hw.ATTEMPT} guard='+'2'*32+' short=27733')
        c.feed('@TIME 1100000');c.feed('@RANDOM 7');c.feed('@PREHOLD')
        c.command('ACTIVE_DISCOVERY_BEACON_REQUEST','generation=13 dsn=42')
        self.assertEqual(c.dbg['rf'],'0')
        return c
    def advance(self,c):c.feed('@TIME '+c.status()['cca_due_us'])
    def test_busy_then_idle_one_beacon_on_air(self):
        c=self.pending();self.advance(c)
        c.feed('@PREBUSY');self.assertEqual(c.dbg['owner'],'6')
        self.assertEqual(c.terminals(),[]);self.advance(c)
        c.feed('@RFSTART');c.feed('@SUCCESS')
        self.assertEqual(c.dbg['rf'],'1');self.assertEqual(c.dbg['tx'],'2')
        self.assertEqual(len(c.terminals()),1)
        self.assertEqual(c.terminals()[0]['fields']['result'],'local_tx_ok')
        self.assertEqual(len([r for r in c.records if r['kind']=='TXACCEPT']),1)
        self.assertEqual(c.terminals()[0]['fields']['cca_busy'],'1')
    def test_all_busy_bounded_four_attempts_zero_air(self):
        c=self.pending();self.advance(c)
        for i in range(4):
            c.feed('@PREBUSY')
            if i<3:self.advance(c)
        self.assertEqual(c.dbg['rf'],'0');self.assertEqual(c.dbg['tx'],'4')
        self.assertEqual(len(c.terminals()),1)
        self.assertEqual(c.terminals()[0]['fields']['result'],'cca_fail')
        self.assertEqual(c.status()['pending'],'0')
    def test_postair_failure_no_second_submission(self):
        c=self.pending();self.advance(c);c.feed('@RFSTART');c.feed('@PREBUSY')
        c.feed('@TIME 2100000')
        self.assertEqual(c.dbg['rf'],'1');self.assertEqual(c.dbg['tx'],'1')
        self.assertEqual(len(c.terminals()),1)
    def test_END_during_backoff_no_air(self):
        c=self.pending();c.command('END');c.feed('@TIME 2100000')
        self.assertEqual(c.dbg['rf'],'0');self.assertEqual(c.dbg['tx'],'0')
        self.assertEqual(c.terminals()[0]['fields']['result'],'tx_end_abort')
    def test_budget_expiry_no_air(self):
        c=self.pending();c.feed('@TIME 1140001')
        self.assertEqual(c.dbg['rf'],'0');self.assertEqual(len(c.terminals()),1)
        self.assertEqual(c.terminals()[0]['fields']['result'],'cca_fail')


class FanNoBackoff(first.NativeTests):
    def native_test_APPLICATION_preair_busy_still_no_retry(self):
        self.cli();self.bind();raw=self.prepare();self.feed('@APPLICATION_READY_UNIT_FIXTURE')
        self.feed('@PREHOLD');rows=self.appcommand(raw)
        self.assertTrue(any('TXACCEPT' in x for x in rows))
        rows=self.feed('@PREBUSY')
        self.assertTrue(any('cca_fail' in x for x in rows))
        self.assertIn('tx=1 ',self.debug);self.assertIn('rf=0 ',self.debug)
        self.feed('@TIME 63500000');self.assertIn('tx=1 ',self.debug)
        rows=self.appcommand(raw);self.assertTrue(any('ERROR' in x for x in rows))

def suite():
    s=unittest.TestSuite()
    for cls in (BeaconTests,):s.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
    s.addTest(FanNoBackoff('native_test_APPLICATION_preair_busy_still_no_retry'))
    return s
