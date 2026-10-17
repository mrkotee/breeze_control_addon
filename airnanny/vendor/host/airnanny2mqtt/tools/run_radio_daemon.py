"""V28/V29 daemon launcher. Explicit recovery, never implicit recommission on reopen.

--preflight is read-only and never opens a port or unwraps keys.
--recover performs the reviewed retained-key recovery state machine once on a
fresh boot. Hardware proof prompts for a real remote baseline and publishes
one adjacent FAN command per context through an independent MQTT wire client.
"""
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
FIRMWARE = REPO / 'firmware/airnanny_dual_pan/dual_pan_runtime_v28'
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / '.tmp/mqtt-python'))
sys.dont_write_bytecode = True

from airnanny.config_loader import MqttConfig
from airnanny.daemon import AirNannyDaemon
from airnanny.mqtt_runtime import MqttRuntimeConfig
from airnanny.paho_mqtt import PahoMqttTransport
from airnanny.radio_daemon import DurableApplicationIngress, RadioDaemonLoop
from airnanny.radio_runtime import restore_devices
from airnanny.real_radio import RealRadioTransport, serial_port_factory
from airnanny.real_radio import FIRMWARE_PROFILES
from airnanny.real_radio import bootstrap_port_factory

HEX_SHA = 'a8bcf8d3aa1b628ad6f54c063321175d1ff02bd1606fad25dbcf6a2f12dedb37'
V29_HEX_SHA = '8f27d4a606a53020a4f2a7189bc19ec5a2af75e7320f7879b03502761f623dfe'


class Clock:
    def now_ms(self):
        return int(time.monotonic() * 1000)


def firmware_modules():
    # Frozen host code uses absolute sibling imports. Load exactly this tree's
    # management first, as the reviewed issue #5 launchers do.
    sys.path.insert(0, str(FIRMWARE / 'host'))
    sys.path.insert(0, str(FIRMWARE))
    import management
    if Path(management.__file__).resolve() != FIRMWARE / 'host/management.py':
        raise RuntimeError('wrong frozen firmware module loaded')
    import launch_gate_b
    return launch_gate_b


def preflight(firmware_version=28):
    image_root = FIRMWARE.parent / f'dual_pan_runtime_v{firmware_version}'
    image = image_root / f'releases/airnanny_dual_pan_runtime_v{firmware_version}.hex'
    expected_sha = HEX_SHA if firmware_version == 28 else V29_HEX_SHA
    if hashlib.sha256(image.read_bytes()).hexdigest() != expected_sha:
        raise RuntimeError('firmware image binding mismatch')
    if firmware_version == 29:
        native = json.loads((image_root/'evidence/application_repeat_offline.json').read_text())
        if native.get('status') != 'OFFLINE_NATIVE_PASS' or native.get('hardware_performed') is not False:
            raise RuntimeError('V29 offline review binding missing')
    report = json.loads((FIRMWARE.parent / 'evidence/dual_pan_runtime_v1.json').read_text())
    if report.get('resulting_state') != 'DUAL_PAN_RADIO_RUNTIME_PROVEN':
        # The public evidence may use status/state; require the exact proof
        # marker rather than relying on a guessed field name.
        if 'DUAL_PAN_RADIO_RUNTIME_PROVEN' not in report.values():
            raise RuntimeError('issue #5 proof marker missing')
    frozen = firmware_modules()
    entries = frozen.dual_store.read_both()
    return dict(firmware=f'V{firmware_version}', wire=10, hex_sha256=expected_sha,
                contexts={str(slot): dict(pan=e['pan'], short=e['short'],
                                          generation=e['generation'], next_fc=e['next_fc'])
                          for slot, e in entries.items()})


def proof_client(connection, output):
    import paho.mqtt.client as mqtt
    import queue
    rows = queue.Queue(maxsize=512)
    failed = []
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='radio-proof-' + uuid4().hex,
                         reconnect_on_failure=False)
    def on_connect(c, u, flags, reason, properties):
        if reason.is_failure:
            failed.append('observer_connect_failed')
        else:
            c.subscribe(connection.topic_prefix + '/#', qos=1)
    def on_message(c, u, m):
        try:
            rows.put_nowait((m.topic, bytes(m.payload), bool(m.retain)))
        except queue.Full:
            failed.append('observer_queue_overflow')
    client.on_connect, client.on_message = on_connect, on_message
    client.connect(connection.host, connection.port, 15)
    client.loop_start()
    return client, rows, failed


def hardware_proof(loop, output, *, baseline_seconds=180, pump=None):
    daemon, radio = loop.daemon, loop.radio
    def pump_once():
        (pump or loop.pump)()
        if radio.stopped or radio.state in ('blocked','disconnected'):
            raise RuntimeError('radio_session_gap_during_proof')
    observer, queue, observer_faults = proof_client(daemon.config.mqtt, output)
    import queue as queue_module
    result = dict(status='STARTED', radio_rx_contexts=[], commands={}, mqtt_wire_results=[])
    try:
        deadline = time.monotonic() + 15
        while not (radio.connected and daemon.mqtt.connected):
            pump_once()
            if radio.state == 'blocked' or time.monotonic() > deadline:
                raise RuntimeError('daemon_or_radio_not_active')
            time.sleep(0.005)
        for slot in (0, 1):
            name = ('second_bedroom', 'bedroom')[slot]
            a = daemon.adapters[name]
            print(f'>>> ctx{slot}: нажмите FAN- на штатном пульте. Жду свежую основу и статус.', flush=True)
            deadline = time.monotonic() + baseline_seconds
            while True:
                pump_once()
                d, s = a.device, a.device.snapshot()
                if s.baseline_valid and not s.baseline_pending and s.status_fresh:
                    break
                if radio.state == 'blocked' or time.monotonic() > deadline:
                    raise RuntimeError('fresh_remote_baseline_timeout')
                time.sleep(0.005)
            target = s.fan + 1 if s.fan < 7 else s.fan - 1
            # The typed path requires a fresh MANAGEMENT_POLL and >=40 polls;
            # explicit recovery already held the reviewed shared readiness.
            until = time.monotonic() + 1.6
            while time.monotonic() < until:
                pump_once()
                time.sleep(0.005)
            wire_topic = a.topics.command('fan')
            observer.publish(wire_topic, str(target), qos=1, retain=False)
            deadline = time.monotonic() + (85 if radio.firmware_version >= 32 else 25)
            verdict = None
            while time.monotonic() < deadline and verdict is None:
                pump_once()
                if observer_faults:
                    raise RuntimeError(observer_faults[0])
                while True:
                    try:
                        topic, payload, retained = queue.get_nowait()
                    except queue_module.Empty:
                        break
                    if topic == a.topics.result:
                        item = json.loads(payload)
                        result['mqtt_wire_results'].append(dict(ctx=slot, retained=retained, **item))
                        if item['status'] in ('ok', 'error'):
                            verdict = item
                time.sleep(0.005)
            if not verdict or verdict['status'] != 'ok':
                raise RuntimeError('confirmed_MQTT_command_missing:ctx%d' % slot)
            result['commands'][str(slot)] = dict(requested=target, confirmation_revision=d.rx_revision,
                                                 status='CONFIRMED', request_id=verdict['request_id'])
            if radio.firmware_version >= 32:
                result['commands'][str(slot)]['attempts'] = d._attempt
            print(f'>>> ctx{slot}: MQTT-команда подтверждена свежим TYPE06.', flush=True)
        if not all(a.device.status is not None for a in daemon.adapters.values()):
            raise RuntimeError('both_status_streams_required')
        result['radio_rx_contexts'] = [0, 1]
        result['status'] = 'RADIO_MQTT_COMMANDS_CONFIRMED_AWAITING_PHYSICAL_HEALTH'
    except BaseException as exc:
        result['status'] = 'FAILED_OR_UNKNOWN'
        result['reason'] = type(exc).__name__  # no raw frames/secrets/exception text
        raise
    finally:
        output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        observer.disconnect()
        observer.loop_stop()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preflight', action='store_true')
    p.add_argument('--port', default='COM7')
    p.add_argument('--mqtt-port', type=int, default=1883)
    p.add_argument('--recover', action='store_true')
    p.add_argument('--hardware-proof', action='store_true')
    p.add_argument('--firmware-version', type=int, choices=(28,29), default=29)
    p.add_argument('--operator-statement')
    p.add_argument('--initial-command-id',type=int)
    p.add_argument('--duration', type=int, default=300)
    args = p.parse_args()
    report = preflight(args.firmware_version)
    print(json.dumps(report, indent=2), flush=True)
    if args.preflight:
        return
    if not args.recover and args.initial_command_id is None:
        p.error('V28/V29 attach requires an owned --initial-command-id; use --recover on a fresh boot')
    if not 1 <= args.duration <= 3600:
        p.error('duration must be bounded to 1..3600 seconds')
    frozen = firmware_modules()
    serial, list_ports = frozen.serial_modules()
    selected = frozen.authority.select_device(list(list_ports.comports()))
    if selected['port'] != args.port:
        raise RuntimeError('selected dongle does not match requested COM port')
    ledgers = frozen.ledgers()
    run = uuid4().hex
    local = ROOT / '.local/real_radio_transport' / run
    local.mkdir(parents=True, exist_ok=False)
    report['run'] = run
    report['device'] = selected
    if args.operator_statement:
        report['operator_statement'] = args.operator_statement
        report['flash_readback_verified'] = None
    (local / 'preflight.json').write_text(json.dumps(report, indent=2) + '\n')
    before = {str(slot): ledger.read() for slot, ledger in ledgers.items()}
    (local/'stores_before.private.json').write_text(json.dumps(before,indent=2)+'\n')
    port = serial_port_factory(args.port)
    loop = None
    initial_bytes = b''
    initial_command_id = args.initial_command_id or 0
    runner = None
    runtime_outcome = {'run': run, 'status': 'STARTED', 'hardware_performed': False}
    radio_records = deque(maxlen=4096)
    try:
        if args.recover:
            port.timeout = 0.05
            from gate_b_runner import GateBRunner
            class RecoveryRunner(GateBRunner):
                def check_identity(self):
                    self.info = self.command('INFO')
                    identity, capability, _ = FIRMWARE_PROFILES[args.firmware_version]
                    expected = dict(identity=identity, version=str(args.firmware_version),wire='10',
                                    contexts='2',channel='21',crypto='host_only',application_tx=capability,pending_tx='0')
                    if any(self.info.get(k)!=v for k,v in expected.items()):
                        raise RuntimeError('recovery firmware identity mismatch')
                    return self.info
            print('>>> Явное retained-key recovery обоих контекстов и 60 с readiness.', flush=True)
            runner = RecoveryRunner(port, time.monotonic, ledgers, guard=run)
            # A fresh boot must accept INFO id=1. The inherited id_floor probe
            # falsely documents reused-id INFO as safe; the C fail path stops
            # both contexts. Do not use that probe on any active firmware.
            runner.check_identity()
            runner.require_a_fresh_boot()
            runtime_outcome['hardware_performed'] = True
            for slot in (0, 1):
                runner.commission(slot)
            runner.keep_alive(60)
            # Drain the reviewed runner's buffered records before handing over.
            while runner.w.available():
                runner.w.read()
            initial_bytes = runner.w.buf
            initial_command_id = runner.w.id
            port.timeout = 0
        config, bindings, counters, remotes = restore_devices(ledgers, MqttConfig(host='127.0.0.1', port=args.mqtt_port),
                                                             repeat_commands=args.firmware_version==29)
        by_context = {f'dual-ctx{slot}': ledger for slot, ledger in ledgers.items()}
        radio = RealRadioTransport(Clock(), bindings, port_factory=bootstrap_port_factory(port),
                                   port_name=args.port, intent_hook=counters.intent,
                                   completion_hook=counters.local_complete,
                                   firmware_version=args.firmware_version,
                                   initial_command_id=initial_command_id,
                                   initial_bytes=initial_bytes)
        radio.record_observer = lambda kind, fields: radio_records.append(dict(kind=kind, fields=fields))
        mqtt = PahoMqttTransport(MqttRuntimeConfig(config.mqtt))
        daemon = AirNannyDaemon(config, radio.clock, radio, mqtt, counters)
        loop = RadioDaemonLoop(daemon, radio, DurableApplicationIngress(daemon, by_context, remotes),
                               verdict_hook=counters.application_result)
        loop.start()
        if args.hardware_proof:
            hardware_proof(loop, local / 'hardware_result.json')
        else:
            deadline = time.monotonic() + args.duration
            while time.monotonic() < deadline:
                loop.pump()
                if radio.state == 'blocked':
                    raise RuntimeError(radio.reason)
                if not mqtt.connected:
                    daemon.reconnect()
                time.sleep(0.005)
        runtime_outcome['status'] = 'FINISHED'
    except BaseException as exc:
        runtime_outcome['status'] = 'FAILED_OR_UNKNOWN'
        runtime_outcome['error_type'] = type(exc).__name__
        if isinstance(exc, RuntimeError):
            runtime_outcome['diagnostic'] = str(exc)
        raise
    finally:
        if loop:
            runtime_outcome['radio_state_before_close'] = loop.radio.state
            runtime_outcome['radio_reason_before_close'] = loop.radio.reason
        try:
            if loop:
                loop.close()
            else:
                port.close()
        finally:
            after = {str(slot): ledger.read() for slot, ledger in ledgers.items()}
            (local/'stores_after.private.json').write_text(json.dumps(after,indent=2)+'\n')
            if runner:
                (local/'recovery_records.private.json').write_text(json.dumps(runner.records,indent=2)+'\n')
            if loop:
                runtime_outcome['radio_reason'] = loop.radio.reason
                runtime_outcome['daemon_log'] = list(loop.daemon.log.records)
                (local/'radio_records.private.json').write_text(json.dumps(list(radio_records),indent=2)+'\n')
            (local/'runtime_outcome.private.json').write_text(json.dumps(runtime_outcome,indent=2)+'\n')
        print(f'>>> COM закрыт; V{args.firmware_version} остановлена. Run: ' + run, flush=True)


if __name__ == '__main__':
    main()
