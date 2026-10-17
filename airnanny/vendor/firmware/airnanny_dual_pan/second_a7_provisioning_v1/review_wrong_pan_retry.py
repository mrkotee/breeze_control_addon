"""Offline review and immutable closure summary for the zero-TX first attempt."""
import io
import json
import shutil
import unittest
from pathlib import Path
import retry_after_wrong_pan as retry
from verify import scan_secrets

ROOT=retry.ROOT


def main():
    path=retry.closed_predecessor()
    if not retry.FROZEN.exists():shutil.copyfile(ROOT/'evidence/second_a7_provisioning_v1.json',retry.FROZEN)
    if retry.launcher.sha(retry.FROZEN)!=retry.launcher.read(path/'software.json')['report_sha256']:
        raise ValueError('original_review_digest')
    log=io.StringIO();suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_wrong_pan_retry.py')
    result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    (ROOT/'evidence/wrong_pan_retry_tests.txt').write_text(log.getvalue())
    if not result.wasSuccessful():print(log.getvalue());raise SystemExit(1)
    protected=retry.launcher.protected_inventory()
    if protected!=retry.launcher.read(ROOT/'.local/protected_before.json'):
        raise ValueError('ctx0_changed')
    sources=('retry_after_wrong_pan.py','review_wrong_pan_retry.py','tests/test_wrong_pan_retry.py')
    review={'passed':True,'new_hardware_performed':False,'offline_tests':result.testsRun,
            'original_commissioning_and_firmware_unchanged':True,'same_stable_ctx1_RAW':True,
            'prior_guard':retry.PREVIOUS,'prior_outcome':'PERMIT_ABSENT_ZERO_TX_V17_RECOVERED',
            'ctx0_protected_files_unchanged':len(protected),'secret_scan':scan_secrets(),
            'source_sha256':{s:retry.launcher.sha(ROOT/s) for s in sources},
            'predecessor_sha256':{p.relative_to(path).as_posix():retry.launcher.sha(p) for p in path.rglob('*') if p.is_file()},
            'policy':{'new_guard_only':True,'old_guard_reuse':False,'fresh_baseline_and_permit_required':True,
                      'manual_flash_required':True,'pairing_target':'OTHER_A7_PAN0B7A_NOT_ISSUE3_FA9B'}}
    retry.REVIEW.write_text(json.dumps(review,indent=2)+'\n')
    # Keep the exact preparation review separately; the requested result now
    # records actual hardware work instead of continuing to claim NOT_RUN.
    report=retry.launcher.read(retry.FROZEN)
    report.update(state='FIRST_ATTEMPT_ZERO_TX_WRONG_PAN_V17_RECOVERED',hardware_performed=True,
                  COM_opened=2,USB_enumerated=True,flashed=True,commissioning_result='PERMIT_ABSENT_NO_ASSOCIATION',
                  management_result='NOT_REACHED',first_application_confirmation='NOT_SENT',
                  physical_controller_recovery_confirmation='V17_INFO_AND_OPERATOR_BOTH_PAIRS_CONFIRMED',
                  ctx0_unchanged={'passed':True,'protected_files_compared':len(protected),'no_exclusions_for_current_epoch':True})
    report['hardware_attempt']={'run':retry.PREVIOUS,'verdict':'G PRECONDITION STOP',
        'target_PAN':'0B7A','received_permit_PAN':'FA9B','target_permit_received':False,
        'operator_confirmed_pressed_issue3_A7':True,'RF_TX':0,'TYPE07':0,
        'baseline_authenticated':True,'ctx1_association_attempt_reserved':False,
        'installed_key_epoch':None,'NWK_FC_domain_created':False,
        'END_clean':True,'V17_INFO_verified':True,'both_pairs_healthy':True,'guard_permanently_closed':True,
        'forensics':retry.launcher.read(path/'permit_forensics.json'),
        'outcome_sha256':retry.launcher.sha(path/'runtime/outcome.json'),
        'terminal_sha256':retry.launcher.sha(path/'terminal.json')}
    report['next_attempt_preparation']={'review':'wrong_pan_retry_review.json','tests_passed':result.testsRun,
        'launcher':'retry_after_wrong_pan.py','new_guard_root':'.local/hardware_gate_v2',
        'hardware_performed':False,'manual_ctx1_flash_and_OTHER_A7_pairing_required':True}
    (ROOT/'evidence/second_a7_provisioning_v1.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'new_guard_review_passed':True,'new_tests':result.testsRun,'ctx0_unchanged':True,
                      'first_attempt_RF_TX':0,'V17_restored_and_verified':True,'next_hardware_performed':False}))


if __name__=='__main__':main()
