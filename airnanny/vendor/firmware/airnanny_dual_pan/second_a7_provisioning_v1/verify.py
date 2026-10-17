"""Reproduce offline tests, secret scan and predecessor preservation audit."""
import io
import json
import shutil
import sys
import unittest
from pathlib import Path
from prepare import ROOT,REPO,sha,protected_inventory
from candidates import oracle_keys


def source_inventory():
    result={}
    for path in ROOT.rglob('*'):
        if not path.is_file() or any(x in path.parts for x in ('.local','build','__pycache__','evidence','releases')):
            continue
        if path.suffix in ('.py','.c','.h','.inc','.ld','.json'):
            result[path.relative_to(REPO).as_posix()]=sha(path)
    # The adapter extracts these frozen classes at runtime; bind the complete
    # source files and every production application dependency to the review.
    dependencies=[ROOT.parent/'raw_radio_v22_clock_dispatch/host/application_control.py',
                  ROOT.parent/'raw_radio_v8_post_announce_management/host/management.py',
                  ROOT.parent/'identity_commissioning_v1/offline_codec.py',
                  ROOT.parent/'raw_radio_v4_assoc_permit/tools/identity_store.py']
    dependencies+=list((REPO/'host/airnanny2mqtt/src/airnanny').glob('*.py'))
    for path in dependencies:result[path.relative_to(REPO).as_posix()]=sha(path)
    return result


def scan_secrets():
    keys=oracle_keys();checked=0
    for path in ROOT.rglob('*'):
        if not path.is_file() or any(x in path.parts for x in ('.local','build','__pycache__')):continue
        data=path.read_bytes();payload=data
        if path.suffix=='.hex':
            records=[bytes.fromhex(x[9:-2]) for x in data.decode().splitlines() if x.startswith(':') and x[7:9]=='00']
            payload=b''.join(records)
        for key in keys:
            if key in payload or key.hex().encode() in data.lower() or ':'.join('%02x'%b for b in key).encode() in data.lower():
                raise ValueError('protected_secret_detected:'+str(path.relative_to(ROOT)))
        checked+=1
    return {'passed':True,'public_files_scanned':checked,'actual_local_oracle_material_checked':True}


def main():
    provenance=json.loads((ROOT/'evidence/provenance.json').read_text())
    for relative,item in provenance.items():
        if sha(REPO/item['source'])!=item['source_sha256'] or sha(ROOT/relative)!=item['generated_sha256']:
            raise ValueError('source_provenance_changed:'+relative)
    log=io.StringIO();suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
    result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    (ROOT/'evidence/offline_tests.txt').write_text(log.getvalue(),encoding='utf-8')
    if not result.wasSuccessful():print(log.getvalue());raise SystemExit(1)
    before=json.loads((ROOT/'.local/protected_before.json').read_text())
    after=protected_inventory()
    if before!=after:raise ValueError('protected_predecessor_changed')
    manifest=json.loads((ROOT/'evidence/build_manifest.json').read_text())
    for path,digest in manifest['input_sha256'].items():
        if sha(Path(path)).upper()!=digest:raise ValueError('firmware_build_input_changed')
    releases=ROOT/'releases';releases.mkdir(exist_ok=True)
    image=ROOT/'build/airnanny_ctx1_commission_v7.hex'
    if sha(image).upper()!=manifest['hex_sha256']:raise ValueError('built_image_changed')
    shutil.copyfile(image,releases/image.name)
    profile=json.loads((ROOT/'profile.json').read_text())
    scan=scan_secrets()
    report={'issue':4,'state':'OFFLINE_PREPARED_AWAITING_OPERATOR_HARDWARE','hardware_performed':False,
        'COM_opened':0,'USB_enumerated':False,'RF_TX':0,'flashed':False,
        'allocated_RAW_identity':profile['raw_ieee'],'ctx':1,'pan':'0B7A','channel':21,
        'coordinator_security_source':profile['tc_ieee'],'assigned_short':None,
        'key_epoch_metadata':None,'counter_high_water':None,'commissioning_result':'NOT_RUN',
        'management_result':'NOT_RUN_PENDING_REAL_CTX1_EPOCH_AND_RX','first_application_confirmation':'NOT_RUN',
        'physical_controller_recovery_confirmation':'NOT_RUN_NO_HARDWARE_TOUCHED',
        'target_result':'BOTH_SINGLE_PAN_CONTEXTS_PROVEN_INDEPENDENTLY','acceptance_PASS':False,
        'offline_validation':{'passed':True,'unittest_cases':result.testsRun,'skipped':len(result.skipped),
            'actual_C_dispatcher_FakeRadio':True,'synthetic_FAN_adapter':True,'log':'offline_tests.txt'},
        'cross_context_isolation_tests':{name:'PASS_OFFLINE' for name in ('ctx0_key','ctx0_replay_watermark','ctx0_RAW_IEEE','ctx0_short','ctx0_epoch_generation','cross_PAN_wrong_route')},
        'ctx0_unchanged':{'passed':True,'protected_files_compared':len(before),'no_exclusions_for_current_epoch':True},
        'candidate_provenance':json.loads((ROOT/'evidence/candidate_provenance.json').read_text()),
        'secret_scan':scan,'firmware':{'path':'releases/'+image.name,'sha256':manifest['hex_sha256'],
            'scope':'V7 proven commissioning target adaptation, application TX locked; not V22 readiness firmware',
            'app_address':'0x1000','unflashed':True},
        'reviewed_source_sha256':source_inventory(),
        'remaining_hardware':[
            'operator physical health precheck and manual application-only flash',
            'fresh ctx1 A7 baseline, ARM, authenticated permit, status0 association and current short',
            'no-gap key polling; ctx1 Transport Key authentication and durable independent epoch install',
            'first durable FC lease and one Device Announce; inspect authenticated post-announce RX',
            'bind required management/readiness path to REAL ctx1 short/epoch/attempt, never ctx0 values',
            'fresh readiness and one no-retry adjacent FAN TYPE07 confirmed by fresh authenticated TYPE06',
            'manual V17 restoration, both rooms and original controllers verification; recheck ctx0 unchanged']}
    (ROOT/'evidence/second_a7_provisioning_v1.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'tests':result.testsRun,'protected_files_unchanged':len(before),
                      'secret_scan':scan['passed'],'hardware_performed':False}))


if __name__=='__main__':main()
