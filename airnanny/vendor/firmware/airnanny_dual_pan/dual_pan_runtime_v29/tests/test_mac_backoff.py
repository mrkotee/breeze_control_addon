import unittest,json,sys,copy,uuid,shutil
from pathlib import Path
from test_completion import CLI,R
sys.path.insert(0,str(R/'host'))
import ledger
from probe import Probe
from types import SimpleNamespace
def run_once(factory,m,clock):
 port=factory()
 try:return Probe(port,m,clock).execute()
 finally:port.close()
live=SimpleNamespace(run_once=run_once)
import support as v

class BackoffTests(unittest.TestCase):
 def cli(self):
  c=CLI();self.addCleanup(c.close);c.activate();return c
 def pending(self):
  c=self.cli();c.feed('@RANDOM 7');c.feed('@PREHOLD');c.poll();return c
 def next(self,c):
  s=c.status();c.feed('@TIME '+s['cca_due_us']);return c.status()
 def one_terminal(self,c,result):
  s=c.status();self.assertEqual(len(c.terminals()),1);self.assertEqual(c.terminals()[0]['fields']['result'],result);self.assertEqual(s['pending'],'0');self.assertEqual(s['accepted_count'],s['terminal_count'])
  for field in ('cca_attempts','cca_busy','cca_preair'):self.assertEqual(c.terminals()[0]['fields'][field],s[field])
  return s
 def test_idle_first_one_PSDU(self):
  c=self.cli();c.poll();self.one_terminal(c,'local_tx_ok');self.assertEqual(c.dbg['rf'],'1');self.assertEqual(c.dbg['tx'],'1')
 def busy_then_success(self,count):
  c=self.pending();self.next(c)
  for i in range(count):
   c.feed('@PREBUSY');self.assertEqual(c.dbg['owner'],'6');self.assertEqual(len(c.terminals()),0);self.next(c)
  c.feed('@RFSTART');c.feed('@SUCCESS');s=self.one_terminal(c,'local_tx_ok');self.assertEqual(c.dbg['rf'],'1');self.assertEqual(int(c.dbg['tx']),count+1);self.assertEqual(int(s['cca_busy']),count);self.assertEqual(len([x for x in c.records if x['kind']=='TXACCEPT']),1)
 def test_one_busy_then_idle(self):self.busy_then_success(1)
 def test_three_busy_then_idle(self):self.busy_then_success(3)
 def test_all_busy_one_terminal_no_RF(self):
  c=self.pending();self.next(c)
  for i in range(4):
   c.feed('@PREBUSY')
   if i<3:self.next(c)
  # V27: an all-busy poll is a clean miss (nothing went on air), retried by the
  # next poll rather than ending the context; V26 stopped here. Three in a row
  # still stop it -- tests/test_poll_misses.c.
  s=self.one_terminal(c,'cca_fail');self.assertEqual(c.dbg['rf'],'0');self.assertEqual(s['cca_attempts'],'4');self.assertEqual(s['cca_busy'],'4');self.assertEqual(s['state'],'RECOVERY')
 def test_no_ack_post_air_never_retransmits(self):
  c=self.pending();self.next(c);c.feed('@RFSTART');c.feed('@ACK_TIMEOUT');self.one_terminal(c,'no_ack');c.feed('@TIME 2000000');self.assertEqual(c.dbg['rf'],'1');self.assertEqual(c.dbg['tx'],'1')
 def test_postair_busy_no_second_CCA(self):
  c=self.pending();self.next(c);c.feed('@RFSTART');c.feed('@PREBUSY');self.one_terminal(c,'cca_fail');self.assertEqual(c.dbg['tx'],'1')
 def test_END_during_backoff_never_RF(self):
  c=self.pending();c.command('END');self.one_terminal(c,'tx_end_abort');c.feed('@TIME 2000000');self.assertEqual(c.dbg['tx'],'0');self.assertEqual(c.dbg['rf'],'0')
 def test_USB_during_backoff_never_RF(self):
  c=self.pending();c.feed('@CLOSE');self.one_terminal(c,'tx_usb_abort');self.assertEqual(c.dbg['rf'],'0')
 def test_acquisition_budget_delayed_main(self):
  c=self.pending();c.feed('@TIME 1140000');self.one_terminal(c,'cca_fail');self.assertEqual(c.dbg['rf'],'0')
 def test_missing_CCA_callback_watchdog_safe_abort(self):
  c=self.pending();self.next(c);c.feed('@TIME 1140001');s=self.one_terminal(c,'tx_watchdog_abort');self.assertEqual(s['quarantine'],'0');self.assertEqual(c.dbg['dma'],'0')
 def test_missing_CCA_callback_unproven_cleanup_quarantine(self):
  c=self.pending();self.next(c);c.feed('@SLEEPFAIL');c.feed('@TIME 1140001');s=c.status();self.assertEqual(s['quarantine'],'1');self.assertEqual(s['pending'],'1');self.assertEqual(len(c.terminals()),1);c.command('END');self.assertEqual(c.status()['pending'],'1')
 def test_late_callback_after_END_no_double_completion(self):
  c=self.pending();self.next(c);c.command('END');c.feed('@PREBUSY');c.feed('@SUCCESS');self.one_terminal(c,'tx_end_abort');self.assertEqual(c.dbg['tx'],'1')
 def test_response_poll_deadline_margin(self):
  c=self.cli();c.feed('@WINDOW 1110000');s=c.status();self.assertEqual(c.dbg['rf'],'0');self.assertEqual(s['state'],'STOPPED');self.assertEqual(len(c.terminals()),1)
 def test_response_poll_no_backoff_extension(self):
  c=self.cli();c.feed('@PREHOLD');c.feed('@WINDOW 1591520');c.feed('@PREBUSY');self.one_terminal(c,'cca_fail');self.assertEqual(c.dbg['tx'],'1')
 def test_invalid_ACK_no_retransmission(self):
  c=self.pending();self.next(c);c.feed('@RFSTART');c.feed('@INVALID_TX_ACK');self.one_terminal(c,'invalid_ack');self.assertEqual(c.dbg['tx'],'1')
 def test_unexpected_callback_during_backoff_STOP(self):
  c=self.pending();c.feed('@SUCCESS');self.one_terminal(c,'tx_terminal_abort');self.assertEqual(c.status()['state'],'STOPPED');self.assertEqual(c.dbg['tx'],'0')
 def test_future_Association_MAC_adapter_same_builder_one_RF(self):
  c=self.cli();c.feed('@PREHOLD');c.feed('@ASSOCIATION_TYPED_FIXTURE');c.feed('@PREBUSY');c.feed('@RFSTART');c.feed('@SUCCESS');self.one_terminal(c,'local_tx_ok');self.assertEqual(c.dbg['tx'],'2');self.assertEqual(c.dbg['rf'],'1')
 def test_busy_RF_START_END_race_orderings(self):
  import itertools
  for order in itertools.permutations(('BUSY','WD','END')):
   c=self.pending();self.next(c)
   for event in order:
    if event=='BUSY':c.feed('@PREBUSY')
    elif event=='WD':c.feed('@TIME 1140001')
    else:c.command('END')
   self.assertEqual(len(c.terminals()),1);self.assertEqual(c.status()['pending'],'0');self.assertEqual(c.dbg['rf'],'0')
 def test_driver_reject_no_acquired_DMA_no_CCA_retry(self):
  c=self.cli();c.feed('@DRIVER_FAIL');c.poll();s=self.one_terminal(c,'error');self.assertEqual(c.dbg['tx'],'0');self.assertEqual(c.dbg['dma'],'0');self.assertEqual(s['abort_calls'],'0')
 def test_ctx1_generation6_old5_rejected(self):
  c=CLI();self.addCleanup(c.close);c.generation=5;c.activate();self.assertEqual(c.status()['state'],'STOPPED');self.assertEqual(c.dbg['rf'],'0')
 def test_TYPE07_inaccessible(self):
  c=self.cli();rows=c.command('TYPE07');self.assertTrue(any(x['kind']=='ERROR' for x in rows));self.assertEqual(c.dbg['rf'],'0')
 def test_65s_steady_periodic_busy_one_RF_per_poll(self):
  c=self.cli();timeline=[]
  for i in range(65):
   now=1100000+i*1020000;c.feed('@TIME '+str(now));c.feed('@RANDOM 0')
   if i%7==0:
    c.feed('@PREHOLD');c.poll(i+1);c.feed('@PREBUSY');c.feed('@RFSTART');c.feed('@SUCCESS');c.feed('@INLINE')
   else:c.poll(i+1)
   s=c.status();self.assertEqual(s['pending'],'0');self.assertEqual(int(c.dbg['rf']),i+1);self.assertEqual(len(c.terminals()),i+1);timeline.append({'elapsed_us':now-1100000,'CCA_busy':i%7==0,'RF':int(c.dbg['rf'])})
  c.command('END');s=c.status();self.assertEqual(s['accepted_count'],s['terminal_count']);self.assertEqual(s['quarantine'],'0')
  (R/'evidence/synthetic_65s_backoff.json').write_text(json.dumps({'synthetic':True,'actual_C_dispatcher':True,'timeline':timeline,'END':s,'TYPE07':0},indent=2))
 def test_current_authority_offline_binding_readonly(self):
  r=v.old.fixture();r.update(generation=13,next_fc=672);r['context']['short']=0x6c55;r['recovery']={'gate':ledger.PREVIOUS,'state':'REJOINED'}
  root=R/'.local/tests'/uuid.uuid4().hex;root.mkdir(parents=True);self.addCleanup(shutil.rmtree,root);ledger.durable(root/'epoch.json',r);before=(root/'epoch.json').read_bytes();m=ledger.Ledger(root,v.old.KEY,v.GUARD);self.assertEqual(m.read()['next_fc'],672);self.assertEqual((root/'epoch.json').read_bytes(),before)
  r['generation']=11;ledger.durable(root/'epoch.json',r)
  with self.assertRaises(ledger.Fault):ledger.Ledger(root,v.old.KEY,v.GUARD)
class RecoveryTests(unittest.TestCase):
 def test_full_secured_recovery_60s_each_typed_frame_busy(self):
  for verb in ('REJOIN_REQUEST','DEVICE_ANNOUNCE','END_DEVICE_TIMEOUT','MANAGEMENT_POLL'):
   with self.subTest(verb=verb):
    root=R/'.local/tests'/uuid.uuid4().hex;root.mkdir(parents=True)
    try:
     r=v.old.fixture();r.update(generation=13,next_fc=672);r['context']['generation']=7;r['sequences'].update(nwk=9,aps=4,zdo=4,dsn=55)
     r['recovery']={'gate':ledger.PREVIOUS,'state':'REJOINED','intents':{'REJOIN':{'fc':224},'ANNOUNCE':{'fc':256}}};ledger.durable(root/'epoch.json',r)
     m=ledger.Ledger(root,v.old.KEY,v.GUARD);clock=v.Clock()
     class Port(v.Port):
      def write(self,data):
       if (' '+verb+' ').encode() in data:self.feed('@CCA_PRE')
       return super().write(data)
     port=Port(clock);out=live.run_once(lambda:port,m,clock=clock)
     self.assertTrue(out['ready'],out['error']);self.assertEqual(m.read()['generation'],14);self.assertEqual(m.read()['next_fc'],768);self.assertEqual(out['TYPE07'],0)
     intents=m.read()['recovery']['intents'];self.assertEqual([intents[k]['fc'] for k in ('REJOIN','ANNOUNCE','TIMEOUT')],[672,704,736]);self.assertEqual(out['end']['accepted_count'],out['end']['terminal_count'])
     for k in ('REJOIN_REQUEST','DEVICE_ANNOUNCE','END_DEVICE_TIMEOUT'):
      self.assertEqual(len([x for x in out['records'] if x['kind']=='TXACCEPT' and x['fields']['class']==k]),1)
     (R/'evidence'/('synthetic_recovery_'+verb.lower()+'.json')).write_text(json.dumps({'synthetic':True,'ready':True,'injected_preair_CCA_on':verb,'observation':m.read()['recovery']['observation'],'intents':{k:{'fc':i['fc'],'block_end':i['block_end']} for k,i in intents.items()},'END':out['end'],'TYPE07':0},indent=2))
    finally:shutil.rmtree(root)

if __name__=='__main__':unittest.main()

