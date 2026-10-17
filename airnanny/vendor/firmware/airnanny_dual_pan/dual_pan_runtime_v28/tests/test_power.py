"""Actual C startup setter/getter and host refusal before any TX."""
import sys,unittest,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'tests'));sys.path.insert(0,str(R/'host'))
import support as v
from hardware_probe import HardwareProbe
from ledger import Fault
from test_completion import CLI
from rejoin_wire import PREFIX
class PowerTests(unittest.TestCase):
    def test_native_boot_reports_8dBm(self):
        c=CLI();self.addCleanup(c.close)
        rows=c.feed(f'{PREFIX} INFO id=1')
        info=next(x['fields'] for x in rows if x['kind']=='INFO')
        self.assertEqual(info['tx_power_dbm'],'8');self.assertEqual(info['identity'],'airnanny_ctx1_rejoin_tx8_v22')
        self.assertEqual(c.dbg['rf'],'0')
    def test_host_wrong_power_stops_before_pairing_or_TX(self):
        clock=v.Clock();port=v.Port(clock);self.addCleanup(port.close);port.feed('@POWER0')
        class Probe(HardwareProbe):
            def await_pairing(self,status):raise AssertionError('pairing_must_not_start')
        probe=Probe(port,object(),clock)
        with self.assertRaises(Fault):probe.command('INFO')
        self.assertFalse(probe.w.tx_counts)
    def test_native_setter_readback_failure_and_success(self):
        p=subprocess.run([str(R/'build/power_test.exe')],capture_output=True,text=True,check=True)
        self.assertIn('POWER8_CONFIG_READBACK_PASS',p.stdout)
    def test_radio_core_and_power_mapping_are_frozen(self):
        b=R.parent/'ctx1_rejoin_control_v22'
        for rel in ('src/tx_lifecycle.inc','src/cca_backoff.inc','src/rejoin_transport.c','radio_driver/nrf_802154_pib.c','radio_driver/nrf_802154_core.c'):
            self.assertEqual((R/rel).read_bytes(),(b/rel).read_bytes())
        self.assertIn('NRF_RADIO_TXPOWER_POS8DBM',(R/'radio_driver/nrf_802154_pib.c').read_text())
