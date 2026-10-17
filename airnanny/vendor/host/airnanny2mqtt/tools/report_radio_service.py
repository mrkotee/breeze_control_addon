"""Export software checks and an optional completed physical V30 proof."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from airnanny.service_profile import service_profile


def suite(path):
    tree=ET.parse(path).getroot()
    suites=list(tree) if tree.tag=='testsuites' else [tree]
    result={field:sum(int(s.attrib.get(field,0)) for s in suites)
            for field in ('tests','failures','errors','skipped')}
    if result['failures'] or result['errors'] or not result['tests']:
        raise RuntimeError('checks_not_passed')
    return result


def current_runtime_sources(component):
    """Hardware evidence follows runtime code, independently of report tooling."""
    snapshot=component.get('tested_source_sha256') or {}
    required={p.relative_to(ROOT).as_posix() for p in (ROOT/'src/airnanny').glob('*.py')}
    required.add('tools/run_radio_service.py')
    return (len(required)>1 and required<=snapshot.keys()
            and all((ROOT/name).is_file() and hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==snapshot[name]
                    for name in required))


def physical(run, statement, firmware_version):
    d=ROOT/'.local/radio_service_proof'/run
    proof=json.loads((d/'proof.json').read_text(encoding='utf-8'))
    image=ROOT.parents[1]/f'firmware/airnanny_dual_pan/dual_pan_runtime_v{firmware_version}'
    assert proof['preflight']['firmware']==f'V{firmware_version}'
    assert proof['preflight']['hex_sha256']==hashlib.sha256((image/f'releases/airnanny_dual_pan_runtime_v{firmware_version}.hex').read_bytes()).hexdigest()
    if (proof['status']!='SOAK_AND_CDC_RECOVERY_PASSED_AWAITING_OPERATOR_HEALTH'
            or not proof['service_closed']):raise RuntimeError('physical_proof_incomplete')
    phases=proof['phases']
    assert phases['timer_wrap']['elapsed_seconds']>=4500 and phases['timer_wrap']['wraps']>=1
    assert phases['automatic_CDC_recovery']=='NEW_BOOT_BOTH_ACTIVE'
    commands=[]
    explicit_target=proof.get('fan_target') if proof.get('fan_policy')=='explicit_absolute_target' else None
    if proof.get('fan_policy')=='explicit_absolute_target':
        assert type(explicit_target) is int and 1<=explicit_target<=7
    for name in ('initial','after_wrap','after_recovery'):
        result=json.loads((d/(name+'_commands.json')).read_text(encoding='utf-8'))
        assert set(result['commands'])=={'0','1'}
        assert all(c['status']=='CONFIRMED' for c in result['commands'].values())
        if explicit_target is not None:
            assert all(c['requested']==explicit_target for c in result['commands'].values())
        assert all(not r['retained'] for r in result['mqtt_wire_results'])
        for slot,c in result['commands'].items():
            rows=[r for r in result['mqtt_wire_results'] if r['ctx']==int(slot) and r['request_id']==c['request_id']]
            assert [r['status'] for r in rows]==['accepted','ok']
        commands.append(dict(phase=name,commands=result['commands']))
    before=json.loads((d/'stores_before.private.json').read_text(encoding='utf-8'))
    after=json.loads((d/'stores_after.private.json').read_text(encoding='utf-8'))
    for slot in ('0','1'):
        a,b=before[slot],after[slot]
        assert all(a[k]==b[k] for k in ('key_epoch_id','keyseq','secret_ref'))
        assert all(b['context'][k]==v for k,v in a['context'].items() if k not in ('generation','short'))
        assert b['context']['generation']>=a['context']['generation']
        assert b['next_fc']>a['next_fc'] and b['generation']>a['generation']
        assert all(b['nwk_source_floors'].get(source,0)>=fc for source,fc in a['nwk_source_floors'].items())
    assert len(proof['metrics'])==2
    for m in proof['metrics']:
        assert not m['faults'] and set(m['last_status'])=={'0','1'}
        assert all(s['rx_drop']==s['out_drop']==0 for s in m['last_status'].values())
        allowed = ('local_tx_ok','no_ack','invalid_ack','cca_fail') if firmware_version>=32 else ('local_tx_ok',)
        assert all(a['result'] in allowed and a['cleanup']=='safe' for a in m['application_results'])
    captured=bool(proof.get('captured_fan_only',False))
    if captured:
        assert proof['idle_sleep_hold_acquired'] and proof['idle_sleep_hold_released']
        assert len(proof['session_checkpoints'])==len(proof['metrics'])
        for session in proof['session_checkpoints']:
            assert set(session)=={'0','1'}
            for checkpoint in session.values():
                if checkpoint['installed']:
                    assert checkpoint['template_live'] is False
                    assert checkpoint['prior_secured_bytes_replayed'] is False
                    assert checkpoint['security_stores_changed'] is False
                else:
                    assert checkpoint['reason']=='new_live_template_available'
    snapshot_path=d/'source_snapshot.json'
    source_verification={}
    if snapshot_path.exists():
        snapshot=json.loads(snapshot_path.read_text(encoding='utf-8'))
        archive=d/'source_archive';tested=archive if archive.is_dir() else ROOT
        assert snapshot and all(hashlib.sha256((tested/name).read_bytes()).hexdigest()==digest
                                for name,digest in snapshot.items())
        source_verification=dict(tested_source_sha256=snapshot,tested_source_archive_verified=archive.is_dir(),
            tested_source_matches_current=all((ROOT/name).exists() and hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest
                                              for name,digest in snapshot.items()))
    elif captured:
        raise RuntimeError('captured_proof_source_snapshot_required')
    # Health is an explicit operator observation, never inferred from RF.
    health=dict(healthy=True,statement=statement,run=run)
    with (d/'operator_health_after.json').open('x',encoding='utf-8') as stream:
        json.dump(health,stream,ensure_ascii=False,indent=2);stream.write('\n')
    return dict(status='CONTINUOUS_RADIO_AND_CDC_CAPTURED_FAN_PROVEN' if captured else 'CONTINUOUS_RADIO_AND_CDC_RECOVERY_PROVEN',run=run,
                operator_health_after=health,phases=phases,commands=commands,
                metrics=proof['metrics'],stores_identity_and_key_refs_preserved=True,
                source_floors_monotonic=True,
                counters={s:dict(before=before[s]['next_fc'],after=after[s]['next_fc']) for s in ('0','1')},
                recovery='controlled_actual_CDC_close',cable_and_power_loss_tested=False,
                captured_fan_only=captured,fan_policy=proof.get('fan_policy'),fan_target=explicit_target,
                session_checkpoints=proof.get('session_checkpoints'),**source_verification)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firmware-version',type=int,choices=(30,31,32,33),default=32)
    p.add_argument('--run');p.add_argument('--operator-healthy',action='store_true');p.add_argument('--statement')
    args=p.parse_args()
    image=ROOT.parents[1]/f'firmware/airnanny_dual_pan/dual_pan_runtime_v{args.firmware_version}'
    if args.run and (not args.operator_healthy or not args.statement):p.error('post-run operator health is required')
    result=dict(status='CONTINUOUS_SERVICE_SOFTWARE_VERIFIED_HARDWARE_PENDING',
                unit=suite(ROOT/'evidence/radio_service_offline_pytest.xml'),
                mqtt=suite(ROOT/'evidence/radio_service_mqtt_pytest.xml'),
                firmware=f'V{args.firmware_version}',native=json.loads((image/'evidence/persistent_offline.json').read_text(encoding='utf-8')))
    profile=service_profile(args.firmware_version)
    result['normal_service_profile']=dict(
        rollover_successor=profile.rollover_successor,
        recovery_stock_handoff=profile.recovery_stock_handoff,
        partial_startup=profile.partial_startup,
        late_join=args.firmware_version>=33,
        saved_capture_loader=False,
        hardware_verified=False,
        pending='normal_startup_with_current_session_templates_and_fresh_status')
    attempts=[]
    for path in sorted((ROOT/'.local/radio_service_proof').glob('*/proof.json')):
        proof=json.loads(path.read_text(encoding='utf-8'))
        attempts.append(dict(run=proof['run'],firmware=proof['preflight']['firmware'],
                             hex_sha256=proof['preflight']['hex_sha256'],status=proof['status'],phases=proof['phases'],
                             service_closed=proof['service_closed'],error_type=proof.get('error_type'),
                             metrics=proof['metrics']))
    result['hardware_attempts']=attempts
    late_join_path=ROOT/'evidence/radio_service_v33_late_join_offline.json'
    if late_join_path.exists():
        result['V33_late_join_software_component']=json.loads(late_join_path.read_text(encoding='utf-8'))
    if args.firmware_version==33:
        result['V33_late_join_hardware_components']={}
        for slot in (0,1):
            path=ROOT/f'evidence/radio_service_v33_ctx{slot}_late_join_hardware.json'
            if path.exists():
                result['V33_late_join_hardware_components'][str(slot)]=json.loads(path.read_text(encoding='utf-8'))
    component_path=ROOT/'evidence/radio_service_v32_retry_hardware.json'
    if args.firmware_version==32 and component_path.exists():
        result['hardware_components']=json.loads(component_path.read_text(encoding='utf-8'))
    cdc_path=ROOT/'evidence/radio_service_v32_cdc_hardware.json'
    if args.firmware_version==32 and cdc_path.exists():
        result['CDC_recovery_component']=json.loads(cdc_path.read_text(encoding='utf-8'))
    retry_success_path=ROOT/'evidence/radio_service_v32_retry_success_hardware.json'
    if args.firmware_version==32 and retry_success_path.exists():
        result['successful_RF_retry_component']=json.loads(retry_success_path.read_text(encoding='utf-8'))
    rollback_path=ROOT/'evidence/radio_service_v32_status_rollback_hardware.json'
    if args.firmware_version==32 and rollback_path.exists():
        result['application_status_rollback_component']=json.loads(rollback_path.read_text(encoding='utf-8'))
    for name,key in (('radio_service_v32_relay_capture_replay.json','relay_capture_software_replay'),
                     ('radio_service_v32_stock_rollover_observation.json','stock_rollover_observation'),
                     ('radio_service_v32_relay_runtime_hardware.json','updated_ingress_runtime_component'),
                     ('radio_service_v32_power_cycle_hardware.json','A7_power_cycle_component'),
                     ('radio_service_v32_power_cycle_interrupted.json','A7_power_cycle_interrupted_attempt'),
                     ('radio_service_v32_host_sleep_review.json','host_sleep_one_time_review'),
                     ('radio_service_v32_power_cycle_command_hardware.json','A7_power_cycle_and_command_component'),
                     ('radio_service_v32_partial_startup_attempts.json','partial_startup_attempts'),
                     ('radio_service_v32_partial_startup_hardware.json','partial_startup_component'),
                     ('radio_service_v32_application_wrap_approach.json','application_wrap_approach'),
                     ('radio_service_v32_zero_and_local_busy.json','zero_and_local_busy_attempt'),
                     ('radio_service_v32_wrap_stock_pending.json','application_wrap_stock_pending_attempt'),
                     ('radio_service_v32_wrap_stock_boundary.json','application_wrap_stock_boundary_attempt'),
                     ('radio_service_v32_probe_observer_wait_failure.json','probe_observer_wait_failure'),
                     ('radio_service_probe_queue.json','probe_wait_queue_regression'),
                     ('radio_service_v32_seed_255_diagnostic.json','seed_255_diagnostic_attempt'),
                     ('radio_service_v32_raw_stock_cursor_hardware.json','raw_stock_cursor_hardware_observation'),
                     ('radio_service_v32_cached_stock_replay.json','cached_stock_cursor_capture_replay'),
                     ('radio_service_v32_cached_stock_hardware.json','cached_stock_cursor_hardware_observation'),
                     ('radio_service_v32_start_marker_failure.json','operator_start_marker_failure'),
                     ('radio_service_v32_requested_fan5.json','requested_fan5_component'),
                     ('radio_service_v32_ctx1_wrap_stock_wait.json','ctx1_wrap_stock_wait_component'),
                     ('radio_service_v32_ctx1_stock_display_observation.json','ctx1_stock_display_observation'),
                     ('radio_service_v32_ctx1_handoff_approach.json','ctx1_live_handoff_approach_component'),
                     ('radio_service_v32_soak_target_restart.json','soak_target_restart'),
                     ('radio_service_v32_normal_startup_hardware.json','normal_profile_startup_component'),
                     ('radio_service_v32_normal_commands_hardware.json','normal_profile_commands_component'),
                     ('radio_service_v32_captured_fan_soak_hardware.json','captured_FAN_soak_CDC_component'),
                     ('radio_service_probe_operator_wait.json','probe_operator_pause_wait_regression'),
                     ('radio_service_v32_ctx0_application_wrap_boundary.json','ctx0_application_wrap_boundary_component'),
                     ('radio_service_v32_ctx1_application_wrap_boundary.json','ctx1_application_wrap_boundary_component'),
                     ('radio_service_v32_ctx1_application_wrap_hardware.json','ctx1_application_wrap_component'),
                     ('radio_service_v32_application_wrap_hardware.json','application_wrap_component')):
        path=ROOT/'evidence'/name
        if args.firmware_version==32 and path.exists():result[key]=json.loads(path.read_text(encoding='utf-8'))
    normal=result.get('normal_profile_commands_component') or {}
    normal_fan_proven=(normal.get('status')=='NORMAL_PROFILE_LIVE_FAN_COMMANDS_PROVEN'
        and (normal.get('physical_health_after') or {}).get('healthy') is True
        and bool(normal.get('tested_source_sha256'))
        and all((ROOT/name).is_file() and hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest
                for name,digest in normal.get('tested_source_sha256',{}).items()))
    result['normal_service_profile']['fan_commands_hardware_verified']=normal_fan_proven
    if normal_fan_proven:
        result['normal_service_profile']['pending']='cold_start_absent_parent_late_join'
    if args.run:
        checked=physical(args.run,args.statement,args.firmware_version)
        if checked['captured_fan_only']:
            result['captured_FAN_soak_CDC_component']=checked
            (ROOT/'evidence/radio_service_v32_captured_fan_soak_hardware.json').write_text(
                json.dumps(checked,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        else:
            result['hardware']=checked
            result['status']=checked['status']
    if args.firmware_version==33:
        path=ROOT/'evidence/radio_service_v33_soak_CDC_hardware.json'
        if path.exists():
            component=json.loads(path.read_text(encoding='utf-8'))
            result['V33_soak_CDC_component']=component
            proven=(component.get('status')=='CONTINUOUS_RADIO_AND_CDC_RECOVERY_PROVEN'
                and (component.get('operator_health_after') or {}).get('healthy') is True
                and component.get('hex_sha256')==hashlib.sha256((image/'releases/airnanny_dual_pan_runtime_v33.hex').read_bytes()).hexdigest()
                and current_runtime_sources(component))
            result['normal_service_profile']['fan_commands_hardware_verified']=proven
            result['normal_service_profile']['hardware_verified']=proven
            result['normal_service_profile']['hardware_scope']='two-PAN startup, live-template FAN, timer wrap and controlled CDC recovery'
            if proven:
                result['status']=component['status']
                result['normal_service_profile']['pending']=None
        components=result['V33_late_join_hardware_components']
        result['normal_service_profile']['both_late_join_directions_hardware_verified']=all(
            (components.get(str(slot)) or {}).get('status')==f'CTX{slot}_COLD_PARTIAL_STARTUP_AND_SAME_SESSION_LATE_JOIN_PROVEN'
            and ((components[str(slot)].get('physical_health_after') or {}).get('healthy') is True)
            and current_runtime_sources(components[str(slot)]) for slot in (0,1))
        result['unrestricted_all_setters_hardware_verified']=False
    paths=[ROOT/'src/airnanny'/name for name in ('real_radio.py','radio_daemon.py','radio_service.py',
                                              'radio_retry.py','radio_runtime.py','application_store.py','recovery_guard.py','recovery_application.py','service_profile.py','late_join.py','late_join_radio.py')]
    paths.extend(ROOT/'tools'/name for name in ('run_radio_service.py','run_radio_service_proof.py',
                                              'service_proof_commands.py','proof_power.py','proof_capture_checkpoint.py'))
    result['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    result['hex_sha256']=hashlib.sha256((image/f'releases/airnanny_dual_pan_runtime_v{args.firmware_version}.hex').read_bytes()).hexdigest()
    output='radio_service_v33.json' if args.firmware_version==33 else 'radio_service_v1.json'
    (ROOT/'evidence'/output).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(result['status'])


if __name__=='__main__':main()
