"""Offline native protocol/failure review. Never opens COM or loads real keys."""
import json,sys,unittest,hashlib,shutil,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(R));sys.path.insert(0,str(R/'tests'));sys.path.insert(0,str(R/'host'))
import launcher as h
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    before=sha(h.CURRENT/'epoch.json')
    import test_first_control as first,test_discovery_cca as discovery
    suite=first.suite();suite.addTests(discovery.suite());groups={'first_control':first.suite().countTestCases(),'discovery_cca':discovery.suite().countTestCases()}
    for name in ('test_ctx1_admission','test_power','test_recovery','test_permit_observation','test_peer_scope','test_foreign_status_scope','test_clock_dispatch','test_completion','test_mac_backoff','test_rx_deadline'):
        m=__import__(name);tests=unittest.defaultTestLoader.loadTestsFromModule(m);groups[name]=tests.countTestCases();suite.addTests(tests)
    with (R/'evidence/offline_tests.txt').open('w') as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    if not result.wasSuccessful():
        print((R/'evidence/offline_tests.txt').read_text()[-9000:]);raise SystemExit(1)
    if sha(h.CURRENT/'epoch.json')!=before:raise ValueError('offline_current_mutation')
    if h.protected()!=h.load(h.DEP/'.local/protected_before.json'):raise ValueError('ctx0_changed')
    h.authority()
    image=R/'build/airnanny_ctx1_rejoin_tx8_v22.hex';shutil.copyfile(image,h.IMAGE)
    manifest=h.load(R/'evidence/build_manifest.json')
    if sha(image).upper()!=manifest['hex_sha256']:raise ValueError('image_manifest_mismatch')
    dependencies=[p for p in (R.parents[2]/'host/airnanny2mqtt/src/airnanny').glob('*.py')]
    dependencies+=[p for p in (h.DEP/'tools').glob('*.py')]
    dependencies+=[R.parent/'ctx1_rejoin_control_v22/evidence/review.json']
    dependencies+=[p for p in h.ORIGINAL_LEAVE.glob('*.json')]
    dependencies+=[h.DEP/'evidence/offline_preparation.json',h.DEP/'evidence/build_manifest.json',h.DEP/'prepare.py',h.V17]
    q={'passed':True,'hardware_performed':False,'COM_opened':0,'RF_TX':0,'tests':{'count':result.testsRun,'failures':0,'errors':0,'skipped':len(result.skipped),'groups':groups},'source_sha256':{str(p.relative_to(R)).replace('\\','/'):sha(p) for folder in ('src','include','radio_driver','host','tools','tests') for p in (R/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts},'dependency_sha256':{str(p):sha(p) for p in dependencies},'prior_sha256':{p.name:sha(p) for p in h.PRIOR.iterdir() if p.is_file()},'image_sha256':sha(h.IMAGE),'manifest_sha256':sha(R/'evidence/build_manifest.json'),'current_epoch_before_sha256':before,'ctx0_protected_files':len(h.protected()),'retained_key_not_loaded':True,'hardware_PASS':False}
    q['source_sha256']['launcher.py']=sha(R/'launcher.py')
    (R/'evidence/review.json').write_text(json.dumps(q,indent=2)+'\n')
    print(json.dumps({'tests':q['tests'],'image_sha256':q['image_sha256'],'ctx0_protected_files':q['ctx0_protected_files'],'CURRENT_unchanged':True,'RF_TX':0}))
if __name__=='__main__':main()
