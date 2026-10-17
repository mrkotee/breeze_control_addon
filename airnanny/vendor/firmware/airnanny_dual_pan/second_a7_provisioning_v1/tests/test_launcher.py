import contextlib
import io
import json
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import launcher


class LauncherTests(unittest.TestCase):
    def test_preflight_never_imports_serial_or_enumerates_ports(self):
        original=__import__
        def deny_serial(name,*args,**kwargs):
            if name=='serial' or name.startswith('serial.'):raise AssertionError('serial forbidden in offline preflight')
            return original(name,*args,**kwargs)
        with patch.object(launcher,'software',return_value=(ROOT/'releases/airnanny_ctx1_commission_v7.hex','synthetic-hash')),patch('builtins.__import__',side_effect=deny_serial):
            self.assertEqual(launcher.preflight()['COM_opened'],0)
    def test_missing_flash_blocks_execute_before_serial(self):
        original=__import__
        def deny_serial(name,*args,**kwargs):
            if name=='serial' or name.startswith('serial.'):raise AssertionError('serial forbidden before flash gate')
            return original(name,*args,**kwargs)
        with patch.object(sys,'argv',['launcher.py','execute','--run','f'*32]),patch.object(launcher,'software',return_value=(ROOT/'missing.hex','hash')),patch.object(launcher,'run_path',return_value=ROOT/'.local/nonexistent-run'),patch('builtins.__import__',side_effect=deny_serial):
            with self.assertRaises(FileNotFoundError):launcher.main()
    def test_run_identifier_cannot_escape_guard_directory(self):
        with self.assertRaises(ValueError):launcher.run_path('../ctx0')
    def test_device_requires_unique_verified_serial_VID_PID(self):
        p=SimpleNamespace(vid=0x1915,pid=0x1337,serial_number='C625E0B966C1',device='COM99')
        self.assertEqual(launcher.select_device([p]),'COM99')
        for ports in ([],[p,p],[SimpleNamespace(vid=p.vid,pid=p.pid,serial_number='wrong',device=p.device)]):
            with self.assertRaises(ValueError):launcher.select_device(ports)


if __name__=='__main__':unittest.main()
