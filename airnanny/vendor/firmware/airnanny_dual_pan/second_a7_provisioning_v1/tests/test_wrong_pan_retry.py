import copy
import json
import sys
import shutil
import uuid
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import retry_after_wrong_pan as retry


class RetryTests(unittest.TestCase):
    def setUp(self):
        test_root=(ROOT/'.local/tests').resolve()
        self.gate=test_root/('retry_'+uuid.uuid4().hex)
        self.gate.mkdir()
        self.assertEqual(self.gate.resolve().parent,test_root)
        self.addCleanup(shutil.rmtree,self.gate)
        self.run=self.gate/'runs'/retry.PREVIOUS;self.run.mkdir(parents=True)
        self.write(self.gate/'milestone.json',{'run_uuid':retry.PREVIOUS})
        original=retry.OLD_GATE/'runs'/retry.PREVIOUS
        for name in ('terminal.json','v17_recovery.json','restored.json','runtime/outcome.json'):
            self.write(self.run/name,json.loads((original/name).read_text()))
    def write(self,p,value):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value))
    def change(self,name,fn):
        p=self.run/name;value=json.loads(p.read_text());fn(value);self.write(p,value)
    def rejected(self):
        with self.assertRaises(ValueError):retry.closed_predecessor(self.gate)
    def test_clean_zero_TX_closure_accepted(self):self.assertEqual(retry.closed_predecessor(self.gate),self.run)
    def test_any_TX_prevents_continuation(self):
        self.change('runtime/outcome.json',lambda r:r.update(tx_counts={'ASSOCIATION_REQUEST':1}));self.rejected()
    def test_missing_or_unclean_END_prevents_continuation(self):
        self.change('runtime/outcome.json',lambda r:r['terminal_STATUS'].update(pending='1'));self.rejected()
    def test_any_association_or_key_epoch_prevents_continuation(self):
        self.write(self.run/'runtime/current/association/provision.json',{});self.rejected()
    def test_failed_physical_recovery_prevents_continuation(self):
        self.change('terminal.json',lambda r:r['physical'].update(both_healthy=False));self.rejected()
    def test_unverified_V17_prevents_continuation(self):
        self.change('v17_recovery.json',lambda r:r.update(verified=False));self.rejected()
    def test_unsealed_predecessor_prevents_continuation(self):
        self.change('terminal.json',lambda r:r.update(state='STARTED'));self.rejected()
    def test_extra_command_prevents_continuation(self):
        self.change('runtime/outcome.json',lambda r:r['records'].append({'kind':'HOST_COMMAND','raw':'RADIOV7 ASSOC REQUEST id=999'}));self.rejected()
    def test_wrong_predecessor_guard_prevents_continuation(self):
        self.write(self.gate/'milestone.json',{'run_uuid':'0'*32});self.rejected()
    def test_wrapper_separates_guard_without_opening_serial(self):
        with patch.object(retry.launcher,'main') as mocked,patch.object(retry.launcher,'GATE'),patch.object(retry.launcher,'software'):
            retry.main();self.assertEqual(retry.launcher.GATE,retry.NEW_GATE);self.assertIs(retry.launcher.software,retry.software);mocked.assert_called_once()


if __name__=='__main__':unittest.main()
