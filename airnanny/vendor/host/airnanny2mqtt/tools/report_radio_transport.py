"""Issue #6 acceptance report bound to current runtime and reviewed V33 proof."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
if __package__:
    from .report_radio_service import current_runtime_sources
else:
    from report_radio_service import current_runtime_sources

ROOT=Path(__file__).resolve().parents[1]
STATE='END_TO_END_DAEMON_RADIO_INTEGRATION_PROVEN'
REQUIRED_TESTS={
    'fragmented_multiple_lines':'test_fragmented_crlf_and_multiple_lines',
    'malformed_records':'test_bad_ingress_closes_and_discards_entire_batch',
    'duplicate_result':'test_request_correlation_two_contexts_and_identical_duplicate',
    'unknown_request_id':'test_uncertain_result_fails_all_pending_once',
    'disconnect_during_tx':'test_disconnect_during_tx_shutdown_and_late_result',
    'disconnect_before_TYPE06':'test_disconnect_preserves_consumed_counter_and_never_confirms_without_type06',
    'reconnect_both_contexts':'test_reconnect_verifies_both_existing_contexts_preserves_consumed_slot',
    'ingress_overflow':'test_bad_ingress_closes_and_discards_entire_batch',
    'output_overflow':'test_egress_overflow_fails_closed_even_after_partial_write',
    'command_queue_full':'test_bounded_command_queue_rejects_without_sending',
    'held_result_rx_overflow':'test_pending_rx_before_result_has_bounded_capacity',
    'firmware_mismatch':'test_firmware_mismatch_or_fresh_boot_blocks_without_tx',
    'wrong_context':'test_explicit_rx_routing_for_remote_address_and_wrong_context',
    'shutdown_pending':'test_shutdown_pending_serial_command_is_failure_and_port_closed',
    'single_owner':'test_owner_thread_never_mutates_radio',
    'nonoptimistic_state':'test_simultaneous_state_and_two_nonoptimistic_commands',
    'durable_restore':'test_restore_uses_existing_keys_epochs_floors_and_sequences_without_defaults',
}


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def tests(path):
    tree=ET.parse(path).getroot()
    suites=list(tree) if tree.tag=='testsuites' else [tree]
    totals={k:sum(int(s.attrib.get(k,0)) for s in suites) for k in ('tests','errors','failures','skipped')}
    if not totals['tests'] or any(totals[k] for k in ('errors','failures','skipped')):
        raise ValueError('test_suite_not_green')
    names={t.attrib['name'].split('[')[0] for s in suites for t in s.findall('testcase')}
    return totals,names


def confirmed_commands(component):
    if set(component['commands'])!={'0','1'}:raise ValueError('both_commands_required')
    for slot,command in component['commands'].items():
        rows=[r for r in component['mqtt_wire_results'] if r['ctx']==int(slot)]
        if (command['status']!='CONFIRMED' or [r['status'] for r in rows]!=['accepted','ok']
                or any(r['retained'] or r['request_id']!=command['request_id'] for r in rows)):
            raise ValueError('application_confirmation_not_proven')


def validate_hardware(component):
    if (component['status']!='CONTINUOUS_RADIO_AND_CDC_RECOVERY_PROVEN'
            or (component.get('operator_health_after') or {}).get('healthy') is not True
            or component.get('captured_fan_only') is not False
            or component.get('saved_capture_loader') is not False):
        raise ValueError('current_live_hardware_proof_required')
    for key in ('service_closed','broker_stopped','idle_sleep_hold_released',
                'stores_identity_and_key_refs_preserved','source_floors_monotonic','tested_source_archive_verified'):
        if component.get(key) is not True:raise ValueError('hardware_integrity:'+key)
    for phase in ('initial','after_wrap','after_recovery'):confirmed_commands(component['commands'][phase])
    phases=component['phases']
    if (phases['timer_wrap']['elapsed_seconds']<4500 or phases['timer_wrap']['wraps']<1
            or phases['automatic_CDC_recovery']!='NEW_BOOT_BOTH_ACTIVE'):
        raise ValueError('recovery_and_timer_proof_required')
    if len(component['metrics'])!=2:raise ValueError('both_sessions_required')
    for metric in component['metrics']:
        if (metric['faults'] or set(metric['last_status'])!={'0','1'}
                or any(s['rx_drop'] or s['out_drop'] for s in metric['last_status'].values())
                or any(a['cleanup']!='safe' for a in metric['application_results'])):
            raise ValueError('hardware_runtime_fault')


def main():
    unit_path=ROOT/'evidence/radio_service_offline_pytest.xml'
    mqtt_path=ROOT/'evidence/radio_service_mqtt_pytest.xml'
    unit,names=tests(unit_path);mqtt,mqtt_names=tests(mqtt_path)
    if unit['tests']<1218 or not set(REQUIRED_TESTS.values())<=names:
        raise ValueError('required_regressions_missing')
    if not {'test_real_mqtt_wire_to_serial_two_contexts_and_disconnect',
            'test_v33_late_admission_real_mqtt_availability_and_confirmed_command'}<=mqtt_names:
        raise ValueError('real_mqtt_regressions_missing')
    preserved={}
    for name in ('python_airnanny_control_core_v1.json','python_mqtt_ha_daemon_v1.json','python_real_mqtt_backend_v1.json'):
        for path,digest in read(ROOT/'evidence'/name)['source_sha256'].items():
            if path.startswith('src/airnanny/'):
                if sha(ROOT/path)!=digest:raise ValueError('frozen_semantics_changed:'+path)
                preserved[path]=digest
    if len(preserved)<30:raise ValueError('frozen_control_MQTT_Paho_manifest_incomplete')
    hardware_path=ROOT/'evidence/radio_service_v33_soak_CDC_hardware.json'
    hardware=read(hardware_path);validate_hardware(hardware)
    if not current_runtime_sources(hardware):raise ValueError('runtime_changed_after_hardware_proof')
    image=ROOT.parents[1]/'firmware/airnanny_dual_pan/dual_pan_runtime_v33'
    image_sha=sha(image/'releases/airnanny_dual_pan_runtime_v33.hex')
    manifest=read(image/'evidence/build_manifest.json')
    if image_sha!=hardware['hex_sha256'] or image_sha.lower()!=manifest['hex_sha256'].lower():
        raise ValueError('firmware_proof_mismatch')
    for name,digest in manifest['input_sha256'].items():
        if not name.startswith('nrf sdk/') and sha(image/name).lower()!=digest.lower():
            raise ValueError('firmware_source_changed:'+name)
    late={}
    for slot in (0,1):
        path=ROOT/f'evidence/radio_service_v33_ctx{slot}_late_join_hardware.json';value=read(path)
        if (value['status']!=f'CTX{slot}_COLD_PARTIAL_STARTUP_AND_SAME_SESSION_LATE_JOIN_PROVEN'
                or value['physical_health_after']['healthy'] is not True or not current_runtime_sources(value)):
            raise ValueError('late_join_proof_missing')
        late[str(slot)]=dict(run=value['run'],evidence=path.relative_to(ROOT).as_posix(),sha256=sha(path))
    launcher=ROOT/'tools/run_radio_service.py'
    if 'FakeRadioTransport' in launcher.read_text(encoding='utf-8'):raise ValueError('fake_radio_in_normal_launcher')
    acceptance={name:'PASS' for name in ('fake_transport_not_required','real_serial_both_contexts',
        'existing_control_MQTT_tests_green','reconnect_preserves_counters_and_state',
        'application_success_requires_TYPE06','both_A7_controlled_through_daemon')}
    sources=[*sorted((ROOT/'src/airnanny').glob('*.py')),launcher,
             ROOT/'tools/report_radio_transport.py',ROOT/'docs/REAL_RADIO_TRANSPORT.md']
    result=dict(issue=6,date='2026-10-17',requirements_source='original issue body supplied by user',
        status=STATE,resulting_state=STATE,END_TO_END_DAEMON_RADIO_INTEGRATION_PROVEN=True,
        acceptance=acceptance,tests=unit,mqtt_loopback_integration=mqtt,
        required_protocol_tests={key:dict(status='PASS',test=name) for key,name in REQUIRED_TESTS.items()},
        real_radio_transport_implemented=True,launcher_uses_fake_radio=False,
        frozen_daemon_core_changed=False,frozen_source_sha256=preserved,
        firmware_wire_protocol_implemented=True,firmware_protocol_redesigned=False,
        firmware_extensions='explicit versioned capabilities; reviewed dispatcher-bound commands, same RADIOV10 transport',
        firmware=dict(identity=manifest['identity'],version=33,wire=10,hex_sha256=image_sha,
            normal_launcher='tools/run_radio_service.py --firmware-version 33',version_must_be_explicit=True),
        hardware_integration=dict(evidence=hardware_path.relative_to(ROOT).as_posix(),sha256=sha(hardware_path),
            run=hardware['run'],phases=hardware['phases'],commands=hardware['commands'],
            operator_health_after=hardware['operator_health_after'],service_closed=True,broker_stopped=True,
            source_floors_monotonic=True,stores_identity_and_key_refs_preserved=True,
            tested_source_archive_verified=True,current_runtime_matches_hardware_archive=True,
            captured_fan_only=False,saved_capture_loader=False),
        independent_late_join=late,
        recovery_policy='separate retained-key recovery state machine; no default contexts, new commissioning or replay of uncertain TX',
        deferred=[],scope_limits=['hardware setter proof is FAN, not all setters',
            'actual Home Assistant rendering and permanent installation are not acceptance requirements',
            'stock display disagreement is excluded by user',
            'controlled CDC close tested, physical cable/power loss not claimed'],
        source_sha256={p.relative_to(ROOT).as_posix():sha(p) for p in sources},
        pytest_xml_sha256=sha(unit_path),mqtt_pytest_xml_sha256=sha(mqtt_path))
    output=ROOT/'evidence/real_radio_transport_v1.json'
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'{STATE}: {unit["tests"]} unit; {mqtt["tests"]} real MQTT; six acceptance criteria PASS')


if __name__=='__main__':main()
