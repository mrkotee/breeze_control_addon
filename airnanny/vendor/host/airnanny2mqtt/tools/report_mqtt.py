"""Summarize the offline pytest run and verify previous milestone hashes."""
import hashlib
import json
import platform
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    previous=json.loads((ROOT/'evidence/python_airnanny_control_core_v1.json').read_text())
    suite=ET.parse(ROOT/'evidence/mqtt_ha_pytest.xml').getroot().find('testsuite')
    totals={key:int(suite.attrib[key]) for key in ('tests','errors','failures','skipped')}
    groups={}
    for test in suite.findall('testcase'):
        name=test.attrib['classname'].split('.')[-1]
        groups[name]=groups.get(name,0)+1
    old=sum(v for k,v in groups.items() if not k.startswith('test_daemon'))
    new=totals['tests']-old
    frozen=all(sha(ROOT/name)==digest for name,digest in previous['source_sha256'].items())
    if old!=1104 or new<=0 or not frozen or any(totals[k] for k in ('errors','failures','skipped')):
        raise SystemExit('No PASS: frozen source or pytest regression mismatch')
    report=dict(verdict='A. OFFLINE MQTT/HA DAEMON PASS',date='2026-10-05',timezone='Europe/Moscow',
        python=platform.python_version(),pytest=dict(version=previous['pytest']['version'],**totals,
            prior_regressions=old,mqtt_ha_daemon_tests=new,groups=groups),
        frozen_codec_and_control_core_unchanged=frozen,lower_layer_changes=[],
        modules=['daemon','mqtt','mqtt_schema','ha_discovery','availability','config_loader','lifecycle'],
        transport_backends=['FakeRadioTransport via RadioSession','MemoryMqttBroker + FakeMqttTransport'],
        real_network_serial_hardware_used=False,new_dependencies=[],
        offline_guards=['socket.socket forbidden','socket.create_connection forbidden','socket.getaddrinfo forbidden',
                        'time.sleep forbidden','serial.Serial forbidden'],
        device_counts_tested=[2,5],discovery_entities_per_device=12,
        discovery_fixture_sha256=sha(ROOT/'fixtures/mqtt_ha_discovery_v1.json'),
        state_contract='one retained JSON snapshot; no per-entity state duplication; raw frames/keys excluded',
        command_topics=['power/set','fan/set','mode/set','temperature/set','night/set','humidifier/set'],
        retain=dict(state=True,availability=True,diagnostics=True,discovery=True,commands=False,results=False),
        process_availability='online/offline with offline retained Last Will',
        diagnostic_availability=['online','stale','unavailable'],
        ha_availability='both process and device binary availability must be online',
        temperature_off='JSON temperature null and temperature_control off; HA off button sends off; number10..30 step0.5 restores explicit target',
        request_ids='UUID session + increasing host counter; plain command payloads require no user id',
        command_delivery='retained and duplicate-flagged commands rejected; no radio retry',
        command_state='hold last released snapshot until core success; after failure require a newer post-terminal RX for state release',
        shutdown='stop ingress, terminal daemon_shutdown errors, suppress daemon-owned radio callbacks, offline publication, disconnect; instance is not restartable',
        reconnect='same contexts/devices; discovery/state republish, clean-session resubscribe, memory result outbox flush',
        secrets='references only; MQTT credentials are not resolved; injected local NWK resolver optional; logs never echo payload/config',
        limitations=['No real MQTT/HA interoperability or device hardware validation',
                     'HA discovery is structurally tested, not loaded into Home Assistant',
                     'Memory fake is not a complete MQTT wire/QoS/session implementation',
                     'Result outbox and fake retained store are process-local and not durable',
                     'State age/freshness are sampled at publication; held command state is historical; diagnostic availability is current',
                     'Shutdown while disconnected retains terminal results only in memory; broker publication cannot be guaranteed',
                     'No OS service runner, production counter storage, provisioning or real transport implementations'],
        source_sha256={})
    for directory in ('src','tests','tools','docs','fixtures'):
        for path in (ROOT/directory).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                report['source_sha256'][path.relative_to(ROOT).as_posix()]=sha(path)
    report['pytest_xml_sha256']=sha(ROOT/'evidence/mqtt_ha_pytest.xml')
    (ROOT/'evidence/python_mqtt_ha_daemon_v1.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('verdict','pytest','frozen_codec_and_control_core_unchanged')}))


if __name__=='__main__':main()
