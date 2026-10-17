"""Read-only export of a terminal real-radio proof; never operates COM/RF."""
import argparse
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def load(path):
    return json.loads(path.read_text())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',required=True)
    parser.add_argument('--operator-healthy',action='store_true')
    parser.add_argument('--statement',required=True)
    args=parser.parse_args()
    if len(args.run)!=32 or any(c not in '0123456789abcdef' for c in args.run):
        parser.error('exact terminal run id required')
    directory=ROOT/'.local/real_radio_transport'/args.run
    proof=load(directory/'hardware_result.json')
    outcome=load(directory/'runtime_outcome.private.json')
    before,after=(load(directory/name) for name in ('stores_before.private.json','stores_after.private.json'))
    assert proof['status']=='RADIO_MQTT_COMMANDS_CONFIRMED_AWAITING_PHYSICAL_HEALTH'
    assert outcome['status']=='FINISHED' and outcome['radio_state_before_close']=='active'
    assert outcome['radio_reason_before_close'] is None
    assert proof['radio_rx_contexts']==[0,1] and set(proof['commands'])=={'0','1'}
    rows=load(directory/'radio_records.private.json')
    statuses=[r['fields'] for r in rows if r['kind']=='STATUS']
    done={r['fields']['id']:r['fields'] for r in rows if r['kind']=='TXDONE'}
    app=[r['fields'] for r in rows if r['kind']=='TXACCEPT' and r['fields']['class']=='TYPE07_FAN']
    assert len(app)==2 and {r['ctx'] for r in app}=={'0','1'}
    assert all(s['rx_drop']=='0' and s['out_drop']=='0' and s['quarantine']=='0' and s['reboot_required']=='0' for s in statuses)
    assert not any(r['kind']=='ERROR' for r in rows)
    audits={}
    for slot in ('0','1'):
        b,a=before[slot],after[slot]
        audits[slot]=dict(epoch_preserved=b['key_epoch_id']==a['key_epoch_id'],
                         secret_reference_preserved=b['secret_ref']==a['secret_ref'],
                         keyseq_preserved=b['keyseq']==a['keyseq'],
                         raw_identity_preserved=b['context']['raw_ieee']==a['context']['raw_ieee'],
                         pan_short_preserved=all(b['context'][k]==a['context'][k] for k in ('pan','short')),
                         replay_floors_monotonic=all(a['nwk_source_floors'].get(k,-1)>=v for k,v in b['nwk_source_floors'].items()),
                         counter_monotonic=a['next_fc']>b['next_fc'])
        assert all(audits[slot].values())
        intent=a['recovery']['intents']['TYPE07']
        assert intent['phase']=='CONCLUDED' and intent['application_result']=='CONFIRMED'
        assert intent['result']=='local_tx_ok' and intent['match_revision']==proof['commands'][slot]['confirmation_revision']
        wire=[r for r in proof['mqtt_wire_results'] if r['ctx']==int(slot)]
        assert [r['status'] for r in wire]==['accepted','ok'] and not any(r['retained'] for r in wire)
    # Re-decode captured frames without consuming floors or touching stores.
    spec=importlib.util.spec_from_file_location('readonly_runtime',ROOT/'tools/run_radio_daemon.py')
    runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
    frozen=runtime.firmware_modules(); ledgers=frozen.ledgers()
    from management import decode_nwk
    from airnanny.aps import APS
    from airnanny.zcl import ZCL
    from airnanny.application import Type06,Type07
    confirmations={}
    for accept in app:
        slot=int(accept['ctx']); ledger=ledgers[slot]; receipt=done[accept['id']]
        assert receipt['result']=='local_tx_ok' and receipt['cleanup']=='safe' and receipt['reboot_required']=='0'
        raw=bytes.fromhex(accept['mac'])
        _,plain,meta=decode_nwk(raw,ledger.key,ledger.identity['keyseq'],pan=ledger.identity['pan'])
        frame=Type07(ZCL.parse(APS.parse(plain).payload).payload)
        assert meta['counter']==after[str(slot)]['recovery']['intents']['TYPE07']['fc']
        assert meta['source_ieee']==ledger.identity['raw_ieee']
        matches=[]
        for row in rows:
            if row['kind']!='RX':continue
            fields=row['fields']; raw=bytes.fromhex(fields['mac'])
            if len(raw)<5 or int.from_bytes(raw[3:5],'little')!=ledger.identity['pan']:continue
            if int(fields['time_us'])<=int(receipt['rf_start_us']):continue
            try:
                _,plain,source=decode_nwk(raw,ledger.key,ledger.identity['keyseq'],pan=ledger.identity['pan'])
                observed=Type06(ZCL.parse(APS.parse(plain).payload).payload)
            except Exception:continue
            if source['source_ieee']==ledger.identity['tc_ieee'] and observed.sequence==frame.sequence and frame.known_match(observed):
                matches.append(dict(wire_revision=int(fields['revision']),time_us=int(fields['time_us'])))
        assert matches,'fresh authenticated TYPE06 after RF start required'
        match=min(matches,key=lambda r:r['time_us'])
        confirmations[str(slot)]=dict(host_id=int(accept['id']),fc=meta['counter'],
                                      rf_start_us=int(receipt['rf_start_us']),local_completion_us=int(receipt['time_us']),
                                      matched_wire_revision=match['wire_revision'],matched_radio_us=match['time_us'],
                                      application_latency_ms=(match['time_us']-int(receipt['rf_start_us']))/1000)
    health=dict(healthy=args.operator_healthy,statement=args.statement)
    health_file=directory/'operator_health_after.json'
    if health_file.exists():assert load(health_file)==health
    else:
        with health_file.open('x',encoding='utf-8') as f:f.write(json.dumps(health,ensure_ascii=False,indent=2)+'\n')
    report=dict(issue=6,run=args.run,status='END_TO_END_DAEMON_RADIO_INTEGRATION_PROVEN' if args.operator_healthy else 'PHYSICAL_HEALTH_NOT_CONFIRMED',
                END_TO_END_DAEMON_RADIO_INTEGRATION_PROVEN=args.operator_healthy,
                hardware_performed=True,firmware='V29',operator_health_after=health,
                both_live_contexts_proven=True,mqtt_confirmed_commands=proof['commands'],
                mqtt_wire_results=proof['mqtt_wire_results'],confirmation_radio_evidence=confirmations,
                application_commands_sent=2,rx_record_counts=dict(Counter(r['fields']['ctx'] for r in rows if r['kind']=='RX')),
                all_tx_cleanup_safe=all(r['cleanup']=='safe' for r in done.values()),
                firmware_rx_output_loss_seen=False,com_closed=True,loopback_broker_stopped=True,
                durable_preservation_audit=audits,
                current_durable_state={c:dict(generation=r['generation'],next_fc=r['next_fc']) for c,r in after.items()},
                limitations=['bounded 3900s firmware session','CDC stop requires fresh boot and explicit recovery',
                             'repeat commands tested offline; hardware proof sends one per context'],
                private_evidence_sha256={name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in
                    ('preflight.json','hardware_result.json','runtime_outcome.private.json','radio_records.private.json',
                     'stores_before.private.json','stores_after.private.json','operator_health_after.json')})
    for name in ('real_radio_transport_hardware_attempt5.json','real_radio_transport_hardware_v1.json'):
        (ROOT/'evidence'/name).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(report['status'])
    print(json.dumps(confirmations,indent=2))


if __name__=='__main__':main()
