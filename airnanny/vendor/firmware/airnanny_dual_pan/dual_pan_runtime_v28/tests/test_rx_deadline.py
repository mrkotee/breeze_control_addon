"""Actual dispatcher cutoff tests. No COM, RF or authority writes."""
import subprocess,unittest
from pathlib import Path
import sys as _sys,os as _os
_sys.path.insert(0,_os.path.join(_os.path.dirname(_os.path.abspath(__file__)),'..','host'))
from rejoin_wire import PREFIX
R=Path(__file__).resolve().parents[1]
START=29303281;END=START+261120
BEACON='0080517a0b0000ff4f00000022845f87a136004b1200ffffff00'
class DeadlineTests(unittest.TestCase):
 def run_case(self,commands):
  p=subprocess.run([str(R/'build/scan_replay.exe')],input=commands,text=True,capture_output=True,check=True)
  lines=p.stdout.splitlines();s=[x for x in lines if x.startswith(PREFIX+' STATUS ')][-1]
  self.assertLess(len(s),1152);self.assertIn('crc_first_us=',s);self.assertIn('crc_last_us=',s)
  return dict(x.split('=',1) for x in s.split()[2:])
 def frame(self,stamp,foreground,rev=56,mac=BEACON):return f'FRAME {stamp} {foreground} {rev} {mac}\n'
 def test_timely_queued_beacon_late_foreground(self):
  s=self.run_case(self.frame(START+1000,END+1));self.assertEqual((s['recovery'],s['beacon_revision']),('DISCOVERED','56'))
 def test_original_window_boundaries(self):
  for stamp,accept in ((START-1,False),(START,True),(END-1,True),(END,False),(END+1,False)):
   with self.subTest(stamp=stamp):
    s=self.run_case(self.frame(stamp,END+1));self.assertEqual(s['recovery'],'DISCOVERED' if accept else 'STOPPED')
 def test_wrong_context_and_stale_revision(self):
  wrong_pan=bytearray.fromhex(BEACON);wrong_pan[3]^=1
  wrong_ext=bytearray.fromhex(BEACON);wrong_ext[14]^=1
  for rev,mac in ((55,BEACON),(56,wrong_pan.hex()),(56,wrong_ext.hex())):
   s=self.run_case(self.frame(START+1000,END+1,rev,mac));self.assertEqual(s['recovery'],'STOPPED')
 def test_actual_V18_nonbeacon_RX(self):
  s=self.run_case(self.frame(29559872,29559872,56,'6388837a0b00009ff504')+self.frame(29560416,29560416,57,'020083')+f'TICK {END}\n')
  self.assertEqual((s['recovery'],s['beacon_revision']),('STOPPED','0'))
 def test_full_queue_timely_beacon_last(self):
  rows=''.join(f'QUEUE {START+100+i} {END+1} {56+i} '+('020083' if i<31 else BEACON)+'\n' for i in range(32))
  s=self.run_case(rows+f'TICK {END+1}\n');self.assertEqual((s['recovery'],s['beacon_revision']),('DISCOVERED','87'))
 def test_incomplete_predeadline_callback_grace_then_fail_closed(self):
  s=self.run_case(f'PENDING 1\nTICK {END+1999}\n');self.assertEqual(s['recovery'],'SCANNING')
  s=self.run_case(f'PENDING 1\nTICK {END+2000}\n');self.assertEqual(s['recovery'],'STOPPED');self.assertEqual(s['accepted_count'],'1')
  self.assertEqual(s['rx_cutoff_stalled'],'1')
 def test_completed_callback_within_grace(self):
  s=self.run_case(f'PENDING 1\nTICK {END+1}\nPENDING 0\n'+self.frame(END-1,END+1000));self.assertEqual(s['recovery'],'DISCOVERED')
 def test_no_scan_retry_after_stop(self):
  s=self.run_case(f'TICK {END}\n'+self.frame(END-1,END+1));self.assertEqual(s['recovery'],'STOPPED');self.assertEqual(s['accepted_count'],'1')
 def test_real_ISR_ring_and_CRC_snapshot(self):
  p=subprocess.run([str(R/'build/events_test.exe')],capture_output=True,text=True,check=True);self.assertIn('ACTUAL_GATE_EVENTS_PASS',p.stdout)
 def test_secured_response_windows_use_same_queue_cutoff(self):
  import support as v
  for mode,payload in ((1,b'\x07\x26\xa3\0'),(2,b'\x0c\0\x01')):
   raw=v.old.vector(payload,2462300,0x6c55).hex();deadline=START+491520
   for stamp,accepted,acked in ((deadline-1,True,True),(deadline,False,True),(deadline-1,False,False)):
    with self.subTest(mode=mode,stamp=stamp,acked=acked):
     s=self.run_case(f'WINDOW {mode}\nACKED {int(acked)}\n'+self.frame(stamp,deadline+1,56,raw))
     self.assertEqual(s['response_revision'],'56' if accepted else '0');self.assertEqual(s['state'],'RECOVERY' if accepted else 'STOPPED')
 def test_maximum_diagnostic_width_preserves_final_fields(self):
  from test_completion import CLI
  c=CLI();self.addCleanup(c.close);c.feed('@MAX_DIAGNOSTICS');s=c.status()
  self.assertEqual(s['crc_first_us'],'4294967295');self.assertEqual(s['crc_last_us'],'4294967295');self.assertEqual(s['rx_cutoff_stalled'],'0')
  self.assertLess(len(c.records[-1]['raw']),1152)
if __name__=='__main__':unittest.main()
