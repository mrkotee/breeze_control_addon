"""Fail closed unless the frozen regression suite and real broker matrix passed."""
from collections import Counter
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
REQUIRED={'fan','temperature','humidifier','power','tx_failure','timeout','interleaved_devices',
          'discovery','retain_and_disconnect','will_and_shutdown','broker_restart','startup_refused_then_return'}


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def totals(filename):
    suite=ET.parse(ROOT/'evidence'/filename).getroot().find('testsuite')
    result={k:int(suite.attrib[k]) for k in ('tests','errors','failures','skipped')}
    result['groups']=dict(Counter(t.attrib['classname'].split('.')[-1] for t in suite.findall('testcase')))
    assert not any(result[k] for k in ('errors','failures','skipped')), 'No PASS: pytest failure or skip'
    return result


def deliverables():
    for directory in ('src','tests','integration_tests','tools','docs','fixtures'):
        for path in (ROOT/directory).rglob('*'):
            if path.is_file() and not {'__pycache__','node_modules'} & set(path.parts):yield path


def secret_scan(paths):
    secret_file=ROOT/'secrets.local.json'
    if not secret_file.exists():return 'local_secret_file_absent'
    values=[]
    def visit(value):
        if isinstance(value,dict):
            for item in value.values():visit(item)
        elif isinstance(value,list):
            for item in value:visit(item)
        elif isinstance(value,str):
            normalized=value.replace(':','').replace(' ','')
            if re.fullmatch('[0-9a-fA-F]{32}',normalized):values.append(normalized.lower())
    visit(json.loads(secret_file.read_text()))
    assert values, 'Local key scan found no recognizable key values'
    for path in paths:
        data=path.read_bytes().lower()
        for value in values:
            assert value.encode() not in data and ':'.join(value[i:i+2] for i in range(0,32,2)).encode() not in data, 'Secret scan failed'
    return 'no_local_nwk_key_values_in_deliverables'


def main():
    unit=totals('real_mqtt_unit_pytest.xml')
    integration=totals('real_mqtt_integration_pytest.xml')
    old=sum(count for name,count in unit['groups'].items() if name!='test_paho_boundary')
    assert old==1190 and unit['groups'].get('test_paho_boundary',0)>0
    previous=json.loads((ROOT/'evidence/python_mqtt_ha_daemon_v1.json').read_text())
    assert all(sha(ROOT/name)==digest for name,digest in previous['source_sha256'].items()), 'Frozen milestone changed'
    wire=json.loads((ROOT/'evidence/real_mqtt_wire_summary.json').read_text())
    assert {r['scenario'] for r in wire}==REQUIRED and len(wire)==integration['tests']==12
    brokers=json.loads((ROOT/'evidence/real_mqtt_broker_summary.json').read_text())
    assert len(brokers)==12 and all(r['process_stopped'] and r['host']=='127.0.0.1' and not r['persistence'] for r in brokers)
    paths=list(deliverables())
    artifacts=[ROOT/'pyproject.toml']+list((ROOT/'evidence').glob('real_mqtt_*'))
    scan=secret_scan(paths+artifacts)
    node=os.environ.get('AIRNANNY_TEST_NODE') or shutil.which('node')
    node_version=subprocess.check_output([node,'--version'],text=True).strip()
    broker_version=json.loads((ROOT/'tools/mqtt-broker/node_modules/aedes/package.json').read_text())['version']
    assert broker_version=='0.51.3' and version('paho-mqtt')=='2.1.0'
    report=dict(milestone='REAL MQTT BACKEND V1 + LOCAL BROKER INTEGRATION',
        verdict='A. REAL MQTT BACKEND PASS', date='2026-10-05',
        runtime=dict(python=platform.python_version(),pytest=version('pytest'),paho_mqtt=version('paho-mqtt'),
                     broker='Aedes',broker_version=broker_version,node=node_version),
        pytest=dict(unit=unit,integration=integration,prior_regressions=old,new_unit_tests=unit['tests']-old),
        frozen_codec_control_and_daemon_unchanged=True,lower_layer_changes=[],
        real_localhost_tcp=True,radio='FakeRadioTransport',hardware_serial_dongle_used=False,
        broker=dict(bind='127.0.0.1',port='per-test ephemeral',disk_persistence=False,anonymous_test_access=True,
                    max_connections=16,max_log_bytes=131072,all_processes_stopped=True),
        policy=dict(protocol='MQTT3.1.1',qos=1,clean_session=True,auto_reconnect=False,
                    owner_pumped_callbacks=True,inbound_limit=256,outbound_limit=256,payload_limit=65536,
                    result_retained=False,will_retained=True,live_retain_flag=False,replay_retain_flag=True),
        scenarios=wire,broker_lifecycle=brokers,secrets_scan=scan,
        ha_discovery_entities=24,ha_runtime_used=False,
        limitations=['TLS and broker authentication not runtime-validated',
                     'HA UI/rendering not validated; no discovery removal/tombstones',
                     'DUP mapping/no second fake radio send tested at callback boundary; broker retransmission not forced',
                     'QoS1 is not exactly-once; repeat intents without DUP have no global identity',
                     'In-memory daemon outbox remains unbounded and non-durable',
                     'Accepted but unacknowledged publishes fail receipts/counters with delivery unknown; no automatic result replay',
                     'Retained publish rejected at capacity may stay stale until republish/reconnect'],
        rejected_broker_trials=['aMQTT 0.11.3','aMQTT 0.12.1'],
        source_sha256={p.relative_to(ROOT).as_posix():sha(p) for p in paths},
        artifact_sha256={p.relative_to(ROOT).as_posix():sha(p) for p in artifacts})
    destination=ROOT/'evidence/python_real_mqtt_backend_v1.json'
    destination.write_text(json.dumps(report,indent=2)+'\n')
    secret_scan([destination])
    print(json.dumps({k:report[k] for k in ('verdict','runtime','pytest','secrets_scan')}))


if __name__=='__main__':main()
