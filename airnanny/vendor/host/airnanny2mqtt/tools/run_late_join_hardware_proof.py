"""Operator-coordinated V33 cold partial startup and same-session late join.

Start only AFTER the operator confirms --missing-slot is powered off.
The operator writes power_on.json after restoring that A7. No saved captures.
Private transcripts/stores stay under .local; output is a component proof.
"""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import queue
import socket
import subprocess
import sys
import time
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import run_radio_service as launcher
from airnanny.config_loader import MqttConfig
from airnanny.mqtt_runtime import MqttRuntimeConfig
from proof_power import SystemAwake
from service_proof_commands import hardware_proof
from run_radio_daemon import proof_client
from run_radio_service_proof import Metrics


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--missing-slot',type=int,choices=(0,1),required=True)
    args=parser.parse_args()
    missing=args.missing_slot;healthy=1-missing
    run=uuid4().hex
    directory=ROOT/'.local/v33_late_join'/run
    directory.mkdir(parents=True)
    report=dict(run=run,status='STARTED',firmware_version=33,missing_slot=missing,
        hardware_performed=True,saved_capture_loader=False,fan_policy='preserve_current',
        physical_health_after=None)
    metrics=Metrics();service=None;ledgers=None;before=None;first=None
    sessions=[];last_progress=0;phase='STARTUP';peer=None;boot=None

    def save(name,value):
        path=directory/name;temp=path.with_suffix(path.suffix+'.tmp')
        temp.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
        temp.replace(path)

    def pump():
        nonlocal last_progress
        if (directory/'stop.json').exists():raise RuntimeError('operator_stop')
        service.pump()
        session=service.session
        if first is not None:
            if session is not first or first.radio.boot!=boot:
                raise RuntimeError('same_session_or_boot_not_preserved')
            if first.daemon.adapters[('second_bedroom','bedroom')[healthy]].device is not peer:
                raise RuntimeError('healthy_device_replaced')
        now=time.monotonic()
        if now-last_progress<2:return
        last_progress=now
        progress=dict(phase=phase,observed_unix=time.time(),state=service.state.read()['state'])
        if session:
            progress.update(boot=session.radio.boot,active_slots=sorted(session.radio.active_slots),
                readiness_polls=dict(session.radio.readiness_polls),
                late_join=dict(phase=session.late_join.phase,slot=session.late_join.slot,
                               attempt=session.late_join.attempt,waiting=session.late_join.waiting))
            progress['devices']={name:dict(status_fresh=a.device.snapshot().status_fresh,
                baseline_valid=a.device.baseline.valid,baseline_live=a.device.baseline.live,
                baseline_pending=a.device.baseline.remote_pending,fan=a.device.snapshot().fan)
                for name,a in session.daemon.adapters.items()}
        save('progress.json',progress)

    def wait_until(predicate,seconds,reason):
        deadline=time.monotonic()+seconds
        while True:
            pump()
            if predicate():return
            if time.monotonic()>deadline:raise RuntimeError(reason)
            time.sleep(.005)

    try:
        print('V33_LATE_JOIN_RUN '+run,flush=True)
        report['preflight']=launcher.preflight(33)
        runtime_args=launcher.argument_parser().parse_args(['--firmware-version','33'])
        profile=launcher.service_profile(33)
        report['profile']=dict(firmware_version=33,partial_startup=profile.partial_startup,
            recovery_stock_handoff=profile.recovery_stock_handoff,rollover_successor=profile.rollover_successor)
        sources=[*sorted((ROOT/'src/airnanny').glob('*.py')),
            *[ROOT/'tools'/name for name in ('run_radio_service.py','service_proof_commands.py',
                'run_radio_daemon.py','proof_power.py','run_radio_service_proof.py')],Path(__file__)]
        report['tested_source_sha256']={}
        for source in sources:
            relative=source.relative_to(ROOT);archive=directory/'source_archive'/relative
            archive.parent.mkdir(parents=True,exist_ok=True);archive.write_bytes(source.read_bytes())
            report['tested_source_sha256'][relative.as_posix()]=hashlib.sha256(source.read_bytes()).hexdigest()
        with ExitStack() as owned:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            config=directory/'broker.json'
            save('broker.json',dict(host='127.0.0.1',port=port,persistence=False,anonymous=True,max_log_bytes=131072))
            log=owned.enter_context((directory/'broker.log').open('wb'))
            broker=subprocess.Popen([
                'C:/Users/User/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe',
                str(ROOT/'tools/mqtt-broker/run.cjs'),str(config)],stdout=log,stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW)
            def stop_broker():
                if broker.poll() is None:broker.terminate()
                broker.wait(timeout=5);report['broker_stopped']=True
            owned.callback(stop_broker)
            deadline=time.monotonic()+10
            while not config.with_suffix('.ready').exists():
                if broker.poll() is not None or time.monotonic()>deadline:raise RuntimeError('test_broker_not_ready')
                time.sleep(.05)
            awake=SystemAwake();awake.acquire();report['sleep_hold_acquired']=True
            owned.callback(lambda:report.update(sleep_hold_released=awake.close()))
            owned.enter_context(launcher.ServiceLock(launcher.LOCAL/'owner.lock'))
            ledgers=launcher.firmware_modules().ledgers()
            before={str(s):l.read() for s,l in ledgers.items()};save('stores_before.private.json',before)
            options=MqttRuntimeConfig(MqttConfig(host='127.0.0.1',port=port))
            def factory(state):
                session=launcher.establish(runtime_args,options,state);sessions.append(session)
                previous=session.radio.record_observer
                def record(kind,fields):
                    metrics.record(kind,fields)
                    if kind=='TXDONE':
                        request=session.radio._pending.get(int(fields['id']))
                        if request and request.verb=='TYPE07_FAN':
                            metrics.app.append(dict(ctx=fields['ctx'],result=fields['result'],cleanup=fields['cleanup']))
                    previous(kind,fields)
                session.radio.record_observer=record
                return session
            service=launcher.PersistentRadioService(launcher.ServiceState(launcher.LOCAL/'state.json'),launcher.Clock(),factory)
            def close_service():
                if service.session:
                    save('runtime_records.private.json',list(service.session.records))
                    save('late_join_records.private.json',list(service.session.late_join.records))
                service.close();report['service_closed']=True
            owned.callback(close_service)
            wait_until(lambda:service.session is not None and service.session.radio.connected,
                       600,'bounded_startup_expired')
            first=service.session;boot=first.radio.boot
            if first.radio.active_slots!={healthy}:raise RuntimeError('cold_partial_startup_not_observed')
            peer=first.daemon.adapters[('second_bedroom','bedroom')[healthy]].device
            peer_binding=first.radio.by_slot[healthy]
            report.update(boot=boot,initial_active_slots=[healthy],
                inactive_fc_unchanged_after_startup=ledgers[missing].read()['next_fc']==before[str(missing)]['next_fc'])
            if not report['inactive_fc_unchanged_after_startup']:raise RuntimeError('absent_startup_spent_fc')
            phase='OFFLINE_COMMAND_REJECTION'
            observer,rows,faults=proof_client(options.connection,directory/'offline_command.json')
            try:
                wait_until(lambda:observer.is_connected() and first.daemon.mqtt.connected,15,'mqtt_not_ready')
                # Allow SUBACK to settle, then clear all pre-command traffic.
                until=time.monotonic()+1
                while time.monotonic()<until:pump();time.sleep(.005)
                while not rows.empty():rows.get_nowait()
                adapter=first.daemon.adapters[('second_bedroom','bedroom')[missing]]
                fc=ledgers[missing].read()['next_fc'];wire=[]
                observer.publish(adapter.topics.command('fan'),'5',qos=1,retain=False)
                def rejected():
                    if faults:raise RuntimeError('mqtt_observer_fault')
                    while True:
                        try:topic,payload,retained=rows.get_nowait()
                        except queue.Empty:break
                        if topic==adapter.topics.result:wire.append(dict(retained=retained,**json.loads(payload)))
                    return bool(wire)
                wait_until(rejected,15,'offline_command_result_missing')
                save('offline_command.json',wire)
                if (len(wire)!=1 or wire[0]['status']!='error' or wire[0].get('reason')!='context_unavailable'
                        or wire[0]['retained'] or ledgers[missing].read()['next_fc']!=fc):
                    raise RuntimeError('offline_command_rejection_or_fc_failed')
                report['offline_command_rejected_without_fc']=True
            finally:
                observer.disconnect();observer.loop_stop()
            phase='HEALTHY_COMMAND_WHILE_PEER_OFF'
            hardware_proof(first,directory/'healthy_command.json',slots=(healthy,),baseline_seconds=1800,pump=pump)
            report['healthy_command_while_peer_off']=True
            report['healthy_rx_before_return']=metrics.rx.get(str(healthy),0)
            phase='WAITING_FOR_OPERATOR_POWER_ON'
            print('V33_READY_FOR_POWER_ON ctx='+str(missing),flush=True)
            wait_until(lambda:(directory/'power_on.json').exists(),1800,'operator_power_on_timeout')
            report['operator_power_on']=json.loads((directory/'power_on.json').read_text(encoding='utf-8'))
            phase='AUTOMATIC_LATE_JOIN';returned_at=time.monotonic()
            wait_until(lambda:first.radio.context_available(f'dual-ctx{missing}'),900,'late_join_readiness_timeout')
            report.update(late_join_seconds=time.monotonic()-returned_at,
                active_slots_after_return=sorted(first.radio.active_slots),
                readiness_polls=dict(first.radio.readiness_polls),healthy_binding_preserved=first.radio.by_slot[healthy]==peer_binding,
                healthy_device_preserved=first.daemon.adapters[('second_bedroom','bedroom')[healthy]].device is peer,
                healthy_rx_after_return=metrics.rx.get(str(healthy),0))
            if not report['healthy_binding_preserved']:raise RuntimeError('healthy_binding_changed')
            if report['healthy_rx_after_return']<=report['healthy_rx_before_return']:
                raise RuntimeError('healthy_context_rx_not_observed_during_return')
            phase='COMMANDS_AFTER_LATE_JOIN'
            hardware_proof(first,directory/'joined_commands.json',baseline_seconds=1800,pump=pump)
            if metrics.faults:raise RuntimeError('firmware_fault_in_proof')
            report.update(status='PARTIAL_STARTUP_AND_LATE_JOIN_COMMANDS_CONFIRMED_AWAITING_OPERATOR_HEALTH',
                sessions=len(sessions),same_session=True)
    except BaseException as exc:
        report.update(status='FAILED_OR_UNKNOWN',error_type=type(exc).__name__,error_reason=str(exc),failed_phase=phase)
        raise
    finally:
        if ledgers and before:
            after={str(s):l.read() for s,l in ledgers.items()};save('stores_after.private.json',after)
            report['key_identity_preserved']=all(all(before[s][k]==after[s][k]
                for k in ('key_epoch_id','keyseq','secret_ref')) for s in ('0','1'))
            report['security_floors_monotonic']=all(all(after[s]['nwk_source_floors'].get(source,0)>=fc
                for source,fc in before[s]['nwk_source_floors'].items()) for s in ('0','1'))
        report['metrics']=dict(faults=list(metrics.faults),application_results=list(metrics.app),
            last_status=metrics.status,rx_contexts=dict(metrics.rx))
        report['tested_source_archive_verified']=all(hashlib.sha256(
            (directory/'source_archive'/name).read_bytes()).hexdigest()==digest
            for name,digest in report.get('tested_source_sha256',{}).items())
        save('report.json',report)
        print('V33_LATE_JOIN_CLOSED '+report['status'],flush=True)


if __name__=='__main__':main()
