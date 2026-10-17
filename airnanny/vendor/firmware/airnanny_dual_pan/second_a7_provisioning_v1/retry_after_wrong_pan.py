"""Fresh guard after a sealed zero-TX foreign-PAN permit observation.

The old run stays immutable. Firmware and commissioning algorithm are unchanged.
No device access occurs unless an explicit launcher execute/inspect is requested.
"""
import json
from pathlib import Path
import launcher

ROOT=launcher.ROOT
PREVIOUS='65e522af759049afb3ba3300cb5d67b2'
OLD_GATE=ROOT/'.local/hardware_gate_v1'
NEW_GATE=ROOT/'.local/hardware_gate_v2'
FROZEN=ROOT/'evidence/offline_preparation.json'
REVIEW=ROOT/'evidence/wrong_pan_retry_review.json'


def closed_predecessor(root=OLD_GATE):
    root=Path(root);milestone=launcher.read(root/'milestone.json')
    if milestone.get('run_uuid')!=PREVIOUS:raise ValueError('exact_zero_TX_predecessor_required')
    path=root/'runs'/PREVIOUS
    terminal=launcher.read(path/'terminal.json');outcome=launcher.read(path/'runtime/outcome.json')
    physical=terminal.get('physical',{})
    if terminal.get('state')!='FINISHED' or not all(physical.get(k) is True for k in ('both_healthy','current_data','no_check_case','no_repairing')):
        raise ValueError('sealed_physical_recovery_required')
    if not launcher.read(path/'v17_recovery.json').get('verified') or launcher.read(path/'restored.json').get('sha256')!=launcher.V17_SHA:
        raise ValueError('verified_manual_V17_restore_required')
    if outcome.get('failure')!={'phase':'PERMIT','code':'PERMIT_ABSENT'} or outcome.get('primary')!='G PRECONDITION STOP':
        raise ValueError('only_foreign_permit_zero_TX_closure_allowed')
    if outcome.get('tx_counts')!={} or outcome.get('END_failure') or any(k in outcome for k in ('association','public_epoch','intent')):
        raise ValueError('no_association_key_or_secured_domain_required')
    if (path/'runtime/current/association/provision.json').exists() or (path/'runtime/current/key/security/epoch.json').exists():
        raise ValueError('no_existing_commissioning_authority_required')
    rows=outcome['records'];commands=[r['raw'].split()[1] for r in rows if r['kind']=='HOST_COMMAND']
    if commands!=['INFO','BASELINE_READY','ARM','END'] or any(r['kind'] in ('TXACCEPT','TXDONE','AUTO_ACCEPT','AUTO_DONE','RESPONSE') for r in rows):
        raise ValueError('exact_zero_TX_command_and_receipt_lineage')
    end=outcome.get('terminal_STATUS',{})
    if any(end.get(k)!=v for k,v in dict(state='STOPPED',session='0',pending='0',immediate_ack='0',used='0',rx_drop='0',out_drop='0',association_state='IDLE').items()):
        raise ValueError('clean_unbound_END_required')
    return path


def software():
    path=closed_predecessor();review=launcher.read(REVIEW)
    if not review.get('passed') or review.get('new_hardware_performed') is not False:
        raise ValueError('reviewed_fresh_guard_required')
    for relative,digest in review['source_sha256'].items():
        if launcher.sha(ROOT/relative)!=digest:raise ValueError('retry_review_source_changed')
    for relative,digest in review['predecessor_sha256'].items():
        if launcher.sha(path/relative)!=digest:raise ValueError('sealed_predecessor_changed')
    report=launcher.read(FROZEN)
    if launcher.sha(FROZEN)!=launcher.read(path/'software.json')['report_sha256']:
        raise ValueError('original_offline_review_binding_changed')
    if not report['offline_validation']['passed'] or report['hardware_performed'] is not False:
        raise ValueError('original_frozen_offline_review_required')
    for relative,digest in report['reviewed_source_sha256'].items():
        if launcher.sha(launcher.REPO/relative)!=digest:raise ValueError('original_reviewed_source_changed')
    image=ROOT/'releases/airnanny_ctx1_commission_v7.hex'
    if launcher.sha(image).upper()!=report['firmware']['sha256'] or launcher.sha(launcher.V17).upper()!=launcher.V17_SHA:
        raise ValueError('exact_original_images_required')
    if launcher.protected_inventory()!=launcher.read(ROOT/'.local/protected_before.json'):
        raise ValueError('ctx0_or_protected_predecessor_changed')
    return image,report['firmware']['sha256']


def main():
    launcher.GATE=NEW_GATE
    launcher.software=software
    launcher.main()


if __name__=='__main__':main()
