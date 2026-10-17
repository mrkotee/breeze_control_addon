"""Part A offline checks and software verdict. No device/network/flash access."""
from pathlib import Path
import ast,hashlib,json,os,subprocess,sys
R=Path(__file__).resolve().parents[1];W=R.parents[3]
EX={'.git','.deps','.tmp','.venv','__pycache__','.pytest_cache'}
def inventory(p):
    out={}
    for directory,ds,fs in os.walk(p):
        ds[:]=[d for d in ds if d not in EX]
        for name in fs:
            f=Path(directory)/name;out[f.relative_to(p).as_posix()]=hashlib.sha256(f.read_bytes()).hexdigest()
    return out
roots={'sdk':W/'nrf sdk','v17':R.parent.parent/'airnanny_v17','radio_v1':R.parent/'dual_pan_mac_gate','radio_v2':R.parent/'raw_radio_v2','v3':R.parent/'raw_radio_v3_assoc','python':W/'breeze_control/host/airnanny2mqtt','commissioning_audit':R.parent/'identity_commissioning_v1'}
baseline=json.loads((R/'evidence/protected_baseline.json').read_text());protected={}
for k,p in roots.items():
    current=inventory(p);changes=[n for n in set(current)|set(baseline[k]) if current.get(n)!=baseline[k].get(n)]
    protected[k]={'files':len(current),'unchanged':not changes,'changes':changes};assert not changes,k
host={}
for name in ('test_permit_validator.py','test_attempt_plan.py','test_hardware_helper.py'):
    run=subprocess.run([sys.executable,str(R/'tests'/name)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True)
    host[name]={'returncode':run.returncode,'stdout':run.stdout};print(run.stdout);run.check_returncode()
main=(R/'src/main.c').read_text();protocol=(R/'src/assoc_protocol.c').read_text();binding=(R/'src/permit_binding.c').read_text()
v3core=(R.parent/'raw_radio_v3_assoc/src/assoc.c').read_bytes()
manifest=json.loads((R/'evidence/build_manifest.json').read_text())
checks={
 'frozen_builders_state_response':(R/'src/assoc.c').read_bytes()==v3core,
 'frozen_response_filter':(R/'src/assoc_filter.c').read_bytes()==(R.parent/'raw_radio_v3_assoc/src/assoc_filter.c').read_bytes(),
 'frozen_driver':inventory(R/'radio_driver')==inventory(R.parent/'raw_radio_v3_assoc/radio_driver'),
 'strict_typed_permit_command':'BEGIN_PERMIT_EVIDENCE' in protocol and '0x7f7fbu' in protocol,
 'hash_revision_cache_binding':'permit_hash_mismatch' in binding and 'permit_revision_missing' in binding,
 'freshness_10s_at_begin_and_request':'10000000' in binding and 'permit_binding_recheck' in main,
 'one_shot_consumed_at_begin':'r->used=true' in binding and 'permit_evidence_used' in binding,
 'validation_generation_monotonic':'generation<=c->last_generation' in binding,
 'narrow_ctx0_FA9B':'t->ctx!=0' in binding and 't->pan!=0xfa9b' in binding,
 'beacon_route_preserved':'fresh_target_beacon_required' in main and 'association_not_permitted' in main,
 'host_cryptographic_boundary_explicit':'admission_evidence=%s' in main and 'permit_gate=beacon_or_authenticated_zdo' in main,
 'one_driver_TX_call':main.count('nrf_802154_transmit_raw(')==1,
 'default_ack_off_and_initial_diagnostics':'set_ack(false)' in main and 'immediate_ack=%u pending_tx=%u' in main,
 'capture_loss_fail_closed':'capture_loss_requires_reboot' in main,
 'no_generic_unlock_fields':all('"'+x+'"' not in protocol for x in ('PERMIT','OWNED','TRUST_ME','mac','TX')),
 'application_locked_unkeyed':'application_tx=locked' in main and 'commissioning=unkeyed' in main,
 'no_firmware_crypto_keys_or_management':all(x not in main+binding+(R/'src/assoc.c').read_text() for x in ('AESCCM','zboss','zb_secur','TYPE07','Transport Key','Device Announce')),
 'bounded_two_poll_host_plan':'MAX_POLLS=2' in (R/'tools/attempt_plan.py').read_text(),
 'no_production_import':all('airnanny2mqtt' not in p.read_text() for p in (R/'tools').glob('*.py') if p.name not in ('verify.py','verify_v4.py')),
 'build_no_zboss':all('zboss' not in c['source'].lower() for c in manifest['compile_commands']),
 'hex_matches':hashlib.sha256((R/'build/airnanny_raw_assoc_permit_v4.hex').read_bytes()).hexdigest().upper()==manifest['hex_sha256'],
}
for p in (R/'tools').glob('*.py'):ast.parse(p.read_text())
assert all(checks.values()),[k for k,v in checks.items() if not v]
fixtures=json.loads((R.parent/'evidence/pairing_pre_association_forensics_v1.json').read_text())
positive=[{'name':'historical136','raw':fixtures['focus_frames']['136']['mac_no_fcs']}]+[{'name':'hardwareV1_'+str(x['revision']),'raw':x['mac']} for x in fixtures['hardware_decoded_permit_messages']]
positive += [{'name':'hardwareV2_'+str(x['revision']),'raw':x['mac']} for x in json.loads((R.parent/'evidence/pairing_trigger_observation_v2.json').read_text())['permit_messages']]
source={k:inventory(R/k) for k in ('src','include','tools','tests','radio_driver')}
out={'milestone':'AUTHENTICATED PERMIT ASSOCIATION GATE V1','verdict':'A AUTHENTICATED PERMIT ASSOCIATION SOFTWARE READY',
     'protected':protected,'static_checks':checks,'static_count':len(checks),'host_tests':host,
     'C_tests':json.loads((R/'evidence/offline_test_results.json').read_text()),'positive_fixtures':positive,
     'source_manifest':source,'build':manifest,'hardware':{'status':'not_started','identities_allocated':0,'serial_opens':0,'RF_TX':0},
     'trust_boundary':'Trusted host authenticates/decrypts current-context NWK bytes. Firmware only binds boot/revision/SHA256/outer fields/ctx/generation to immutable cached RX. SHA256 is not Zigbee MIC validation.',
     'policy':{'permit_duration':180,'significance':1,'freshness_s':10,'ctx':0,'pan':'fa9b','polls':2,'interval_ms':500,'timeout_ms':10000,'beacon_admission_preserved':True}}
(R/'evidence/software_result.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'verdict':out['verdict'],'checks':len(checks),'protected':protected},indent=2))
