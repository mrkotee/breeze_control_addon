import unittest,subprocess,itertools,json
from pathlib import Path
import sys,os
sys.path.insert(0,os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','host'))
from rejoin_wire import PREFIX
R=Path(__file__).resolve().parents[1]
BOOT='1'*32
class CLI:
    def __init__(self,old=False):
        self.p=subprocess.Popen([str(R/'build'/('v9_reference_cli.exe' if old else 'firmware_cli.exe'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        self.records=[];self.id=0;self.dbg={};self.generation=6 if old else 13
    def feed(self,line):
        self.p.stdin.write(line+'\n');self.p.stdin.flush();result=[]
        while True:
            s=self.p.stdout.readline().strip()
            if s.startswith('@END'):
                self.dbg=dict(x.split('=') for x in s.split()[1:]);break
            if not s:raise RuntimeError('native_dispatcher_EOF')
            row={'kind':s.split()[1],'fields':dict(x.split('=',1) for x in s.split()[2:]),'raw':s}
            self.records.append(row);result.append(row)
        return result
    # This harness drives ctx1 (short 0x6c55 = 27733). ctx is appended here, not
    # at the call sites, for the same reason as in host/probe.py: the firmware
    # refuses a per-context verb without it, and INFO/END refuse it.
    CTX=1
    def command(self,verb,fields=''):
        if verb not in ('INFO','END'):
            fields=(fields+' ' if fields else '')+f'ctx={self.CTX}'
        self.id+=1;return self.feed(f'{PREFIX} {verb} id={self.id} boot={BOOT} session=1'+(' '+fields if fields else ''))
    def activate(self):
        self.command('BIND',f'generation={self.generation} epoch=9985b15dcb574c59b87dc2fb379f317f attempt=cbef428849da4e87b48867ac616247d1 guard='+'2'*32+' short=27733')
        self.feed('@TIME 1100000');self.feed('@ACTIVE')
    def poll(self,dsn=23):return self.command('MANAGEMENT_POLL',f'generation={self.generation} dsn={dsn}')
    def status(self):return next(x['fields'] for x in self.command('STATUS') if x['kind']=='STATUS')
    def terminals(self):return [x for x in self.records if x['kind'] in ('TXDONE','AUTO_DONE')]
    def close(self):self.p.stdin.close();self.p.wait(timeout=3);self.p.stdout.close()
class CompletionTests(unittest.TestCase):
    def cli(self,old=False):
        c=CLI(old);self.addCleanup(c.close);c.activate();return c
    def test_missing_callback_safe_watchdog_cleanup(self):
        c=self.cli();c.feed('@HOLD');c.poll();self.assertEqual(c.status()['tx_owner'],'radio_submitted')
        c.feed('@TIME 2600001');s=c.status()
        self.assertEqual((s['state'],s['pending'],s['cleanup'],s['terminal_count']),('STOPPED','0','1','1'))
        self.assertEqual(c.terminals()[0]['fields']['result'],'tx_watchdog_abort');self.assertEqual(c.dbg['dma'],'0');self.assertEqual(c.dbg['ack_timer'],'0')
        c.command('END');c.feed('@TIME 4000000');self.assertEqual(len(c.terminals()),1);self.assertEqual(c.dbg['tx'],'1')
    def test_sleep_rejected_quarantine_no_buffer_reuse(self):
        c=self.cli();c.feed('@HOLD');c.poll();c.feed('@SLEEPFAIL');c.feed('@TIME 2600001');s=c.status()
        self.assertEqual((s['pending'],s['quarantine'],s['reboot_required'],s['cleanup']),('1','1','1','2'))
        self.assertEqual(c.terminals()[0]['fields']['cleanup'],'unproven');self.assertEqual(c.dbg['dma'],'1')
        c.command('END');c.poll(24);self.assertEqual(c.dbg['tx'],'1');self.assertEqual(len(c.terminals()),1)
    def test_sleep_accepted_but_DMA_not_quiescent_is_not_clean(self):
        c=self.cli();c.feed('@HOLD');c.poll();c.feed('@ASYNC_SLEEP');c.feed('@TIME 2600001')
        self.assertEqual(c.status()['tx_owner'],'aborting');c.feed('@TIME 2620001');s=c.status()
        self.assertEqual((s['quarantine'],s['pending']),('1','1'));self.assertEqual(len(c.terminals()),1)
    def test_bounded_asynchronous_sleep_completes(self):
        c=self.cli();c.feed('@HOLD');c.poll();c.feed('@ASYNC_SLEEP');c.feed('@TIME 2600001')
        self.assertEqual(len(c.terminals()),0);c.feed('@QUIESCENT');s=c.status();self.assertEqual(s['pending'],'0');self.assertEqual(len(c.terminals()),1)
    def test_callback_before_watchdog_wins_despite_delayed_main(self):
        c=self.cli();c.feed('@HOLD');c.poll();c.feed('@NO_SERVICE');c.feed('@TIME 2599999');c.feed('@SUCCESS');c.feed('@TIME 2600001');c.feed('@SERVICE')
        s=c.status();self.assertEqual((s['pending'],s['watchdog_fired'],s['abort_calls']),('0','0','0'));self.assertEqual(c.terminals()[0]['fields']['result'],'local_tx_ok')
    def test_late_callback_after_watchdog_no_second_completion(self):
        c=self.cli();c.feed('@HOLD');c.poll();c.feed('@TIME 2600001');c.feed('@SUCCESS');c.feed('@FAIL');s=c.status()
        self.assertEqual(len(c.terminals()),1);self.assertEqual(s['late_callbacks'],'2');self.assertEqual(s['state'],'STOPPED');self.assertEqual(s['pending'],'0')
    def test_END_queued_never_submits(self):
        c=self.cli();c.feed('@NO_SERVICE');c.poll();self.assertEqual(c.dbg['tx'],'0');c.command('END');s=c.status()
        self.assertEqual(c.dbg['tx'],'0');self.assertEqual(s['pending'],'0');self.assertEqual(c.terminals()[0]['fields']['result'],'tx_end_abort')
    def test_END_radio_submitted_and_waiting_ACK(self):
        for stage in ('SUBMITTED','ACK'):
            with self.subTest(stage=stage):
                c=self.cli();c.feed('@HOLD');c.poll()
                if stage=='ACK':c.feed('@WAITACK');self.assertEqual(c.status()['driver_phase'],'waiting_ack')
                c.command('END');s=c.status();self.assertEqual((s['pending'],s['immediate_ack']),('0','0'));self.assertEqual(len(c.terminals()),1)
    def test_USB_disconnect_active_has_one_terminal_owner(self):
        c=self.cli();c.feed('@HOLD');c.poll();c.feed('@CLOSE');s=c.status()
        self.assertEqual((s['pending'],s['terminal_count']),('0','1'));self.assertEqual(c.dbg['dma'],'0');self.assertEqual(c.terminals()[0]['fields']['result'],'tx_usb_abort')
    def test_callback_failure_and_ACK_timeout_exact_result(self):
        for cb,result in (('@FAIL','cca_fail'),('@ACK_TIMEOUT','no_ack')):
            with self.subTest(callback=cb):
                c=self.cli();c.feed('@HOLD');c.poll();c.feed(cb);s=c.status();self.assertEqual(c.terminals()[0]['fields']['result'],result);self.assertEqual(s['pending'],'0');self.assertEqual(s['abort_calls'],'0')
    def test_callback_ordering_permutations_single_terminal(self):
        groups=[('@SUCCESS','WD','END'),('@FAIL','WD','END'),('@ACK_TIMEOUT','WD','USB'),('@SUCCESS','@FAIL','WD'),('@SUCCESS','@ACK_TIMEOUT','END')]
        for group in groups:
            for order in itertools.permutations(group):
                with self.subTest(order=order):
                    c=self.cli();c.feed('@HOLD');c.poll()
                    for item in order:
                        if item=='WD':c.feed('@TIME 2600001')
                        elif item=='END':c.command('END')
                        elif item=='USB':c.feed('@CLOSE')
                        else:c.feed(item)
                    s=c.status();self.assertEqual(len(c.terminals()),1);self.assertEqual(s['pending'],'0');self.assertEqual(s['accepted_count'],s['terminal_count']);self.assertEqual(c.dbg['tx'],'1')
    def test_radio_completed_output_delayed_no_radio_pending(self):
        c=self.cli();c.feed('@HOLD');c.poll();c.feed('@NO_DRAIN');c.feed('@SUCCESS')
        self.assertEqual(c.dbg['owner'],'0');self.assertGreater(int(c.dbg['queue']),0)
        c.feed('@DRAIN');s=c.status();self.assertEqual((s['pending'],s['completion_output_queued']),('0','1'));self.assertEqual(len(c.terminals()),1)
        c.feed('@TIME 2100000');c.poll(24);s=c.status()
        self.assertEqual((s['callback_us'],s['abort_start_us'],s['callback_seen'],s['completion_output_queued']),('0','0','0','0'))
        c.feed('@SUCCESS');self.assertEqual(len(c.terminals()),2)
    def test_queue_watchdog_does_not_touch_driver(self):
        c=self.cli();c.feed('@NO_SERVICE');c.poll();c.feed('@TIME 2600001');c.feed('@SERVICE');s=c.status()
        self.assertEqual(s['pending'],'0');self.assertEqual(c.dbg['tx'],'0');self.assertEqual(s['abort_calls'],'0');self.assertEqual(c.terminals()[0]['fields']['result'],'tx_watchdog_abort')
    def test_completion_output_lost_internal_radio_owner_clean(self):
        c=self.cli();c.feed('@HOLD');c.poll();c.feed('@NO_DRAIN');c.feed('@FILL');c.feed('@SUCCESS');c.feed('@DRAIN');s=c.status()
        self.assertEqual((s['pending'],s['callback_seen'],s['completion_output_queued'],s['terminal_count'],s['out_drop']),('0','1','0','1','1'))
        self.assertEqual(len(c.terminals()),0);self.assertEqual(c.dbg['dma'],'0');self.assertEqual(s['state'],'STOPPED')
        self.assertEqual(s['tx_result'],'local_tx_ok')
    def test_output_drain_END_watchdog_callback_permutations(self):
        for order in itertools.permutations(('@SUCCESS','WD','END','DRAIN')):
            with self.subTest(order=order):
                c=self.cli();c.feed('@HOLD');c.poll();c.feed('@NO_DRAIN')
                for item in order:
                    if item=='WD':c.feed('@TIME 2600001')
                    elif item=='END':c.command('END')
                    elif item=='DRAIN':c.feed('@DRAIN')
                    else:c.feed(item)
                s=c.status();self.assertEqual(s['pending'],'0');self.assertEqual(len(c.terminals()),1);self.assertEqual(s['terminal_count'],'1')
    def soak(self,watchdog=False):
        c=self.cli()
        parent='6388de7a0b00009ff504'
        for i in range(60):
            now=1100000+i*1000000;c.feed('@TIME '+str(now));c.feed('@RX '+parent)
            if i==59 and not watchdog:
                c.feed('@HOLD');c.poll(i+1);c.feed('@NO_SERVICE');c.feed('@TIME '+str(now+1499999));c.feed('@PENDING');c.feed('@TIME '+str(now+1500001));c.feed('@SERVICE')
            else:c.poll(i+1)
            self.assertEqual(c.dbg['owner'],'0');self.assertEqual(c.dbg['queue'],'0')
        if watchdog:c.feed('@TIME 61100000');c.feed('@HOLD');c.poll(61);c.feed('@TIME 62600001')
        c.command('END');s=c.status();frames=[x['fields']['mac'] for x in c.records if x['kind']=='TXACCEPT']
        self.assertEqual(s['pending'],'0');self.assertEqual(s['accepted_count'],s['terminal_count']);self.assertEqual(s['immediate_ack'],'0')
        self.assertEqual(len({f[4:6] for f in frames}),len(frames));self.assertTrue(all(bytes.fromhex(f)[-1]==4 and len(f)==20 for f in frames))
        self.assertEqual(int(s['abort_calls']),int(watchdog));self.assertEqual(c.dbg['ack_timer'],'0');self.assertEqual(c.dbg['dma'],'0')
        return {'duration_us':int(s['time_us'])-100000,'polls':len(frames),'watchdog_injected':watchdog,'pending':s['pending'],'accepted':s['accepted_count'],'terminal':s['terminal_count'],'DSN_unique':True,'application_TX':0}
    def test_60_second_soak_success_callback_watchdog_race(self):
        result=self.soak();(R/'evidence/soak_callback_race.json').write_text(json.dumps(result,indent=2))
    def test_60_second_soak_missing_callback_near_end(self):
        result=self.soak(True);(R/'evidence/soak_watchdog_abort.json').write_text(json.dumps(result,indent=2))
if __name__=='__main__':unittest.main()
