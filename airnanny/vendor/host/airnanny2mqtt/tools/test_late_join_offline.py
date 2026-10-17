"""V33 end-to-end simulation: actual C dispatcher and disposable-key ledgers.

No serial modules, real key resolution or hardware authority are constructed.
Run separately from pytest: frozen host modules use global sibling imports.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
FW=ROOT.parents[1]/'firmware/airnanny_dual_pan/dual_pan_runtime_v33'
FROZEN=FW.parent/'dual_pan_runtime_v28'
sys.path[:0]=[str(ROOT/'.deps'),str(ROOT/'src'),str(ROOT/'.tmp/mqtt-python'),
    str(FROZEN/'host'),str(FROZEN/'tests'),str(ROOT/'tests')]
import management  # must precede every inherited discovery import
import dual_ledger
import dual_store
import test_dual_ledger as vectors
import test_recovery as old_vectors
from discovery import validate
import run_radio_service as launcher
from airnanny.application import Type07
from airnanny.aps import APS
from airnanny.config_loader import MqttConfig
from airnanny.mqtt import FakeMqttTransport, MemoryMqttBroker
from airnanny.mqtt_runtime import MqttRuntimeConfig
from airnanny.mac import MAC
from airnanny.nwk import NWK
from airnanny.security import decrypt
from airnanny.zcl import ZCL
from airnanny.radio_service import ServiceState,ServiceBlocked
from control_support import baseline,status
from test_dual_application import frame


class Clock:
    def __init__(self):self.ms=0
    def now_ms(self):return self.ms
    def monotonic(self):return self.ms/1000
    def advance(self,ms):self.ms+=ms
    def sleep(self,seconds):self.advance(int(seconds*1000))


class ParentPort:
    def __init__(self,clock,parents):
        self.clock,self.parents=clock,parents
        self.is_open=True;self.buffer=bytearray();self.phase={};self.commands=[]
        self.fc={0:3000000,1:3000000};self.fail=None;self.bad_mic=False
        self.failing=None;self.drop_reply=None;self.drop_terminal=None
        self.p=subprocess.Popen([str(FW/'build/firmware_cli.exe')],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))

    def feed(self,line):
        self.p.stdin.write(line+'\n');self.p.stdin.flush()
        rows=[]
        while True:
            row=self.p.stdout.readline()
            if not row:raise RuntimeError('offline_C_dispatcher_EOF')
            if row.startswith('@END'):break
            fields=dict(t.split('=',1) for t in row.split()[2:])
            if ' TXDONE ' not in row or self.drop_terminal!=fields.get('id'):
                self.buffer.extend(row.encode())
            rows.append(row)
        for row in rows:
            if ' TXDONE ' in row:
                fields=dict(t.split('=',1) for t in row.split()[2:])
                if self.failing==fields.get('id'):
                    self.failing=None;self.feed('@INLINE')
            if ' AUTO_DONE ' in row:
                fields=dict(t.split('=',1) for t in row.split()[2:])
                self.respond(int(fields['ctx']))

    def inject(self,raw):self.feed('@RX '+raw.hex())

    def respond(self,slot):
        if not self.parents[slot]:return
        phase=self.phase.get(slot)
        if phase not in ('REJOIN','TIMEOUT'):return
        if self.drop_reply==phase:
            self.drop_reply=None;self.phase[slot]=None;return
        plain=(b'\x07'+dual_store.PINNED[slot]['short'].to_bytes(2,'little')+b'\0'
               if phase=='REJOIN' else b'\x0c\0\x01')
        raw=vectors.answer(slot,plain,fc=self.fc[slot]);self.fc[slot]+=1
        if self.bad_mic:raw=raw[:-1]+bytes([raw[-1]^1])
        self.inject(raw)
        self.phase[slot]=None

    @property
    def in_waiting(self):return len(self.buffer)

    def write(self,data):
        line=data.decode().strip();tokens=line.split();verb=tokens[1]
        fields=dict(t.split('=',1) for t in tokens[2:]);slot=int(fields.get('ctx',0))
        self.commands.append((verb,fields))
        if verb=='REJOIN_REQUEST':self.phase[slot]='REJOIN'
        if verb=='END_DEVICE_TIMEOUT':self.phase[slot]='TIMEOUT'
        if self.fail==verb:
            self.feed('@NOACK');self.fail=None;self.failing=fields['id']
        if self.drop_terminal=='next_rejoin' and verb=='REJOIN_REQUEST':
            self.drop_terminal=fields['id']
        self.feed(line)
        if verb=='ACTIVE_DISCOVERY_BEACON_REQUEST' and self.parents[slot]:
            beacon=bytearray(old_vectors.BEACON)
            beacon[3:5]=dual_store.PINNED[slot]['pan'].to_bytes(2,'little')
            beacon[14:22]=bytes.fromhex(dual_store.PINNED[slot]['tc_ieee'])[::-1]
            self.inject(bytes(beacon))
        if verb=='TYPE07_FAN' and self.parents[slot]:
            # Real decryption with synthetic keys; reply to the actual target.
            raw=bytes.fromhex(fields['mac']);nwk=NWK.parse(MAC.parse(raw).payload)
            from airnanny.security import KeyStore
            keys=KeyStore();keys.put(0,vectors.KEYS[slot].value)
            _,plain=decrypt(nwk,keys)
            target=Type07(ZCL.parse(APS.parse(plain).payload).payload)
            self.application(slot,status(seq=target.sequence,fan=target.fan_raw+1))
        return len(data)

    def read(self,size):
        self.clock.advance(5)
        self.feed('@TIME '+str((100000+self.clock.ms*1000)&0xffffffff))
        data=bytes(self.buffer[:size]);del self.buffer[:size]
        return data

    def application(self,slot,app):
        self.clock.advance(1)
        self.feed('@TIME '+str((100000+self.clock.ms*1000)&0xffffffff))
        self.inject(frame(slot,app,self.fc[slot]));self.fc[slot]+=1

    def close(self):
        if not self.is_open:return
        self.is_open=False;self.p.stdin.close();self.p.wait(timeout=5);self.p.stdout.close()


class Rig:
    def __init__(self,root,healthy):
        self.clock=Clock();self.parents={0:healthy==0,1:healthy==1};self.ports=[]
        self.ledgers={};self.broker=MemoryMqttBroker();self.state=ServiceState(root/'state.json')
        for slot in (0,1):
            directory=root/f'ctx{slot}';directory.mkdir()
            identity=dual_store.PINNED[slot]
            record=vectors.record(slot,generation=40)
            record.update(key_epoch_id=identity['epoch'],keyseq=0,secret_ref=f'synthetic:{slot}',
                nwk_source_floors={})
            record['sequences']['zcl']=5
            record['context'].update(ctx=slot,raw_ieee=identity['raw_ieee'],tc_ieee=identity['tc_ieee'],
                attempt=identity['attempt'],generation=1)
            (directory/'epoch.json').write_text(json.dumps(record),encoding='utf-8')
            self.ledgers[slot]=dual_ledger.ContextLedger(slot,vectors.KEYS[slot],hardware=False,root=directory)
        pin=dict(vid=1,pid=2,serial='OFFLINE')
        authority=SimpleNamespace(DONGLE=pin,select_device=lambda ports:dict(port='OFFLINE'))
        frozen=SimpleNamespace(ledgers=lambda:self.ledgers,authority=authority,
            serial_modules=lambda:(SimpleNamespace(SerialException=OSError),
                SimpleNamespace(comports=lambda:[SimpleNamespace(vid=1,pid=2,serial_number='OFFLINE')])))
        def open_port(name):
            assert name=='OFFLINE'
            port=ParentPort(self.clock,self.parents);self.ports.append(port);return port
        def mqtt(options,**kwargs):
            transport=FakeMqttTransport(self.broker);transport.pump=lambda:None;return transport
        launcher.firmware_modules=lambda:frozen
        launcher.serial_port_factory=open_port
        launcher.time=self.clock
        launcher.Clock=lambda:self.clock
        launcher.PahoMqttTransport=mqtt
        launcher.LOCAL=root/'runtime'
        args=launcher.argument_parser().parse_args(['--firmware-version','33'])
        try:
            self.loop=launcher.establish(args,MqttRuntimeConfig(MqttConfig(host='127.0.0.1')),self.state)
        except BaseException:
            for diagnostic in launcher.LOCAL.glob('recovery_failure_*.private.json'):
                data=json.loads(diagnostic.read_text())
                print('OFFLINE_STARTUP_FAILURE',data.get('error'),[(r['kind'],
                    {k:v for k,v in r.get('fields',{}).items() if k in
                     ('ctx','generation','state','recovery','class','result','cleanup','id')})
                    for r in data.get('records',[]) if r['kind'] in ('STATUS','TXDONE','TXACCEPT')][-14:])
            for port in self.ports:port.close()
            raise
        self.port=self.ports[-1]
        self.wait(lambda:self.loop.radio.connected)

    def wait(self,predicate,ms=100000):
        deadline=self.clock.ms+ms
        while self.clock.ms<deadline:
            self.loop.pump()
            if self.loop.radio.state=='blocked':raise RuntimeError(self.loop.radio.reason)
            if predicate():return
            self.clock.advance(2)
        raise AssertionError(('offline deadline',self.loop.late_join.phase,self.loop.radio.reason,
            list(self.port.commands[-5:])))

    def close(self):
        self.loop.close()
        for port in self.ports:port.close()


class LateJoinTests(unittest.TestCase):
    def setUp(self):
        dual_ledger.SIMULATION_ROOT.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='v33-late-',dir=dual_ledger.SIMULATION_ROOT)
        self.root=Path(self.temp.name).resolve()
        assert self.root.is_relative_to(dual_ledger.SIMULATION_ROOT)
        self.addCleanup(self.temp.cleanup)

    def rig(self,healthy):
        rig=Rig(self.root,healthy);self.addCleanup(rig.close);return rig

    def exercise(self,healthy,*,failure=None,drop_reply=None,wrap=False):
        rig=self.rig(healthy);missing=1-healthy;radio=rig.loop.radio
        original_boot=radio.boot;original_device=rig.loop.daemon.adapters[
            ('second_bedroom','bedroom')[healthy]].device
        generation=rig.ledgers[healthy].read()['generation']
        before=rig.ledgers[missing].read()['next_fc']
        # Repeat absence within the same boot; no secured FC is spent.
        rig.wait(lambda:sum(v=='BIND' and f['ctx']==str(missing) for v,f in rig.port.commands)>=3)
        self.assertEqual(rig.ledgers[missing].read()['next_fc'],before)
        inactive=rig.loop.daemon.adapters[('second_bedroom','bedroom')[missing]]
        rig.broker.inject(inactive.topics.command('fan'),b'5')
        self.assertEqual(rig.ledgers[missing].read()['next_fc'],before)
        # Healthy commands coexist with the other slot's repeated discovery.
        rig.port.application(healthy,baseline(seq=10,fan=4));rig.port.application(healthy,status(seq=10,fan=4))
        rig.wait(lambda:original_device.snapshot().status_fresh)
        adapter=rig.loop.daemon.adapters[original_device.config.name]
        rig.broker.inject(adapter.topics.command('fan'),b'4')
        rig.wait(lambda:original_device.result is not None)
        self.assertEqual(type(original_device.result).__name__,'CommandCompleted',
            (original_device.result,radio.state,radio.reason,rig.port.commands[-2:]))
        if wrap:
            # Keep every observed clock step below half a uint32 period.
            target=(2**32-100000)//1000-200
            rig.loop.late_join.due=target+10000
            while rig.clock.ms<target:
                rig.wait(lambda:radio.recovery_ready())
                rig.clock.advance(min(900000,target-rig.clock.ms))
                rig.loop.pump()
                rig.wait(lambda:radio.recovery_ready())
            rig.loop.late_join.due=rig.clock.ms
        rig.port.fail=failure;rig.port.drop_reply=drop_reply
        rig.parents[missing]=True
        rig.wait(lambda:radio.active_slots=={0,1},ms=350000)
        rig.wait(lambda:inactive.context_available,ms=70000)
        self.assertIs(adapter.device,original_device)
        self.assertEqual(radio.boot,original_boot)
        self.assertEqual(rig.ledgers[healthy].read()['generation'],generation)
        burnt={'REJOIN_REQUEST':128,'DEVICE_ANNOUNCE':160,'END_DEVICE_TIMEOUT':192}.get(failure,
            {'REJOIN':128,'TIMEOUT':192}.get(drop_reply,96))
        self.assertEqual(rig.ledgers[missing].read()['next_fc'],before+burnt)
        self.assertIsNone(rig.state.read().get('late_join'))
        self.assertFalse(inactive.device.baseline.valid)
        rig.port.application(missing,baseline(seq=20,fan=4));rig.port.application(missing,status(seq=20,fan=4))
        rig.wait(lambda:inactive.device.snapshot().status_fresh and inactive.device.baseline.valid)
        rig.broker.inject(inactive.topics.command('fan'),b'4')
        rig.wait(lambda:inactive.device.result is not None)
        self.assertEqual(type(inactive.device.result).__name__,'CommandCompleted')
        ids=[int(f['id']) for _,f in rig.port.commands]
        self.assertEqual(ids,sorted(set(ids)))
        self.assertTrue(all(not l.hardware for l in rig.ledgers.values()))

    def test_missing_ctx1_returns_without_restarting_ctx0(self):self.exercise(0)
    def test_missing_ctx0_returns_without_restarting_ctx1(self):self.exercise(1)
    def test_clean_rejoin_miss_uses_new_guard_and_fc(self):self.exercise(0,failure='REJOIN_REQUEST')
    def test_clean_announce_miss_uses_new_guard_and_fc(self):self.exercise(1,failure='DEVICE_ANNOUNCE')
    def test_clean_timeout_miss_uses_new_guard_and_fc(self):self.exercise(0,failure='END_DEVICE_TIMEOUT')
    def test_absent_rejoin_response_retries_fresh_chain(self):self.exercise(1,drop_reply='REJOIN')
    def test_absent_timeout_response_retries_fresh_chain(self):self.exercise(0,drop_reply='TIMEOUT')
    def test_scan_and_recovery_cross_real_uint32_timer_wrap(self):self.exercise(1,wrap=True)

    def test_unknown_tx_terminal_blocks_without_new_cycle(self):
        rig=self.rig(0);radio=rig.loop.radio
        rig.parents[1]=True;rig.port.drop_terminal='next_rejoin'
        with self.assertRaisesRegex(RuntimeError,'radio_result_timeout'):
            rig.wait(lambda:radio.active_slots=={0,1})
        self.assertEqual(radio.state,'blocked')
        q=rig.ledgers[1].read()['recovery']
        self.assertEqual(q['intents']['REJOIN']['phase'],'BUILT_NEVER_RETRY')
        with self.assertRaisesRegex(ServiceBlocked,'interrupted_late_join'):
            rig.state.require_recovery(rig.ledgers)

    def test_both_absent_spends_no_secured_counter(self):
        from airnanny.radio_service import RecoveryDiscoveryUnavailable
        with self.assertRaises(RecoveryDiscoveryUnavailable):self.rig(None)
        for slot in (0,1):
            record=json.loads((self.root/f'ctx{slot}/epoch.json').read_text())
            self.assertEqual(record['next_fc'],2000)
            self.assertFalse(record['recovery']['intents'])

    def test_bad_mic_never_activates_or_advances_reply_floor(self):
        rig=self.rig(0);rig.parents[1]=True;rig.port.bad_mic=True
        with self.assertRaisesRegex(RuntimeError,'late_join_retry_not_proven_by_firmware'):
            rig.wait(lambda:rig.loop.radio.active_slots=={0,1})
        record=rig.ledgers[1].read()
        self.assertEqual(record['next_fc'],2032)
        self.assertFalse(record.get('nwk_source_floors'))

    def test_authenticated_leave_is_terminal(self):
        rig=self.rig(0);rig.parents[1]=True
        rig.wait(lambda:rig.loop.late_join.phase=='REJOIN' and rig.loop.late_join.waiting)
        raw=vectors.answer(1,b'\x04\x60',fc=3000100,fcf=0x1a09)
        rig.port.inject(raw)
        with self.assertRaisesRegex(RuntimeError,'radio_authenticated_leave'):
            rig.wait(lambda:rig.loop.radio.active_slots=={0,1})
        self.assertTrue(rig.ledgers[1].read()['recovery'].get('leave'))


if __name__=='__main__':
    source_paths=[*sorted((ROOT/'src/airnanny').glob('*.py')),ROOT/'tools/run_radio_service.py',Path(__file__),
        *sorted((FW/'src').glob('*')),*sorted((FW/'include').glob('*')),
        FW/'tests/firmware_cli.c',FW/'tools/native_build.py',
        *[FROZEN/'host'/name for name in ('dual_ledger.py','dual_store.py','management.py',
            'secured_frame.py','gate_b_runner.py','rejoin_wire.py','discovery.py')]]
    source_paths += [p for directory in ('radio_driver','tests') for p in (FW/directory).rglob('*')
                     if p.is_file() and p.suffix in ('.c','.h')]
    source_paths += [FROZEN/'tests'/name for name in ('test_dual_ledger.py','test_recovery.py','test_dual_application.py')]
    source_paths += [ROOT/'tests/control_support.py']
    sources={p.relative_to(ROOT.parents[1]).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
             for p in source_paths if p.is_file()}
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(LateJoinTests)
    names=[test.id().split('.')[-1] for test in suite]
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    assert all(hashlib.sha256((ROOT.parents[1]/name).read_bytes()).hexdigest()==digest
               for name,digest in sources.items()), 'source changed during offline proof'
    report=dict(status='OFFLINE_LATE_JOIN_PASS' if result.wasSuccessful() else 'FAILED',
        tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),hardware_performed=False,
        real_C_dispatcher=True,real_crypto_synthetic_keys=True,real_disposable_ledgers=True,
        firmware_cli_sha256=hashlib.sha256((FW/'build/firmware_cli.exe').read_bytes()).hexdigest(),
        cases=names,repository_source_sha256=sources)
    (ROOT/'evidence/radio_service_v33_late_join_offline.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(not result.wasSuccessful())
