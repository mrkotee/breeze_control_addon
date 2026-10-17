"""One-shot ctx1 commissioning gate; firmware changes are operator-only.

preflight never imports serial or enumerates USB. No hardware command is run
implicitly. This gate stops at MANAGEMENT_PENDING and manual V17 recovery.
"""
import argparse
import json
import sys
from pathlib import Path
from prepare import ROOT, REPO, sha, identity_store, protected_inventory
from candidates import load_candidates
import runner
from recovery import inspect

GATE=ROOT/'.local/hardware_gate_v1'
V17=ROOT.parent.parent/'airnanny_v17/releases/airnanny_status_v17_machine_serial.hex'
V17_SHA='2FFFE202FC0B8766113CADF92156B76A98942B64A0E4F3D3692513F210575193'


def read(path):return json.loads(Path(path).read_text())


def software():
    report=read(ROOT/'evidence/second_a7_provisioning_v1.json')
    if report['offline_validation']['passed'] is not True or report['hardware_performed'] is not False:
        raise ValueError('offline_review_required')
    for relative,digest in report['reviewed_source_sha256'].items():
        if sha(REPO/relative)!=digest:raise ValueError('reviewed_source_changed:'+relative)
    image=ROOT/'releases/airnanny_ctx1_commission_v7.hex'
    if sha(image).upper()!=report['firmware']['sha256'] or sha(V17).upper()!=V17_SHA:
        raise ValueError('exact_images_required')
    if protected_inventory()!=read(ROOT/'.local/protected_before.json'):
        raise ValueError('ctx0_or_protected_predecessor_changed')
    return image,report['firmware']['sha256']


def preflight():
    image,digest=software();load_candidates()
    record=read(ROOT/'.local/identity/ctx1.json')
    if record['state']!='ALLOCATED_UNUSED' or record['attempt'] is not None:
        raise ValueError('unused_ctx1_identity_required')
    return {'state':'READY_FOR_MANUAL_COMMISSIONING_FLASH','image':str(image),'sha256':digest,
            'raw_ieee':record['raw_ieee'],'COM_opened':0,'RF_TX':0,
            'management_and_TYPE07_hardware_proof':'PENDING_CTX1_COMMISSIONING_OBSERVATION'}


def run_path(value):
    if not value or len(value)!=32 or any(x not in '0123456789abcdef' for x in value):
        raise ValueError('run_UUID')
    path=GATE/'runs'/value
    if read(GATE/'milestone.json')['run_uuid']!=value:raise ValueError('run_binding')
    return path


def immutable(path,value):
    if path.exists():raise ValueError('immutable_record_NO_RERUN')
    if not identity_store.durable(path,value):raise OSError('durability')


def select_device(ports):
    matches=[p for p in ports if p.vid==0x1915 and p.pid==0x1337 and p.serial_number=='C625E0B966C1']
    if len(matches)!=1:raise ValueError('positively_identified_single_dongle_required')
    return matches[0].device


def main():
    ap=argparse.ArgumentParser();ap.add_argument('action',choices=('preflight','start','record-flash','execute','record-restore','inspect-recovery','finish'))
    ap.add_argument('--run');ap.add_argument('--physical',type=Path);a=ap.parse_args()
    if a.action=='preflight':print(json.dumps(preflight()));return
    image,digest=software()
    if a.action=='start':
        preflight();physical=read(a.physical)
        if physical.get('manual_flash_only') is not True or physical.get('target_A7_PAN')!='0B7A' or physical.get('pairing_A7_only') is not True:
            raise ValueError('manual_target_health_precheck_required')
        path=runner.Guard(GATE).start(physical)
        immutable(path/'software.json',{'image_sha256':digest,'report_sha256':sha(ROOT/'evidence/second_a7_provisioning_v1.json')})
        print(json.dumps({'run':path.name,'manual_flash_required':str(image),'COM_opened':0}));return
    path=run_path(a.run)
    if a.action=='record-flash':
        if (path/'execute_claim.json').exists():raise ValueError('no_reflash_after_execute')
        immutable(path/'flashed.json',{'sha256':digest,'operator_completion':True,'application_only':True});return
    if a.action=='record-restore':
        if not (path/'runtime/outcome.json').exists():raise ValueError('outcome_required_before_restore')
        immutable(path/'restored.json',{'sha256':V17_SHA,'operator_completion':True,'manual':True});return
    if a.action=='finish':
        physical=read(a.physical)
        if not read(path/'v17_recovery.json')['verified'] or not all(physical.get(x) is True for x in ('both_healthy','current_data','no_check_case','no_repairing')):
            raise ValueError('both_physical_pairs_and_V17_required')
        g=runner.Guard(GATE);g.path=path;g.reconcile('FINISHED',physical=physical,issue4_PASS=False)
        print('COMMISSIONING_GATE_FINISHED; readiness/TYPE07/Issue4 acceptance still pending');return
    # The serial library and USB enumeration appear only in explicitly invoked
    # execute/inspect operations, after durable manual-flash/recovery markers.
    if a.action=='inspect-recovery':
        if read(path/'restored.json')['sha256']!=V17_SHA:raise ValueError('manual_V17_restore_required')
        immutable(path/'inspect_claim.json',{'one_INFO':True})
    else:
        if read(path/'flashed.json')!={'sha256':digest,'operator_completion':True,'application_only':True}:
            raise ValueError('manual_exact_ctx1_flash_required')
        if read(path/'software.json')!={'image_sha256':digest,'report_sha256':sha(ROOT/'evidence/second_a7_provisioning_v1.json')}:
            raise ValueError('start_software_binding_changed')
        runner.Guard(GATE).claim(a.run)
    sys.path.append('C:/Program Files/Python37/Lib/site-packages')
    import serial
    from serial.tools import list_ports
    port_name=select_device(list_ports.comports())
    with serial.Serial(port_name,115200,timeout=.02,write_timeout=2) as port:
        if a.action=='inspect-recovery':
            result=inspect(port);immutable(path/'v17_recovery.json',result);print(json.dumps(result));return
        tc,nwk=load_candidates()
        seed=read(ROOT/'.local/identity/ctx1.json');seed.update(target_pan=0x0b7a,coordinator_ieee='00124b0036a1875f')
        port.dtr=True
        result=runner.Runner(port,path/'runtime',seed,runner.ProtectedSecrets(path/'secrets'),tc,nwk).execute()
        print(result['primary']);print('STOP: restore V17 manually; no automatic management/rejoin/TYPE07')


if __name__=='__main__':main()
