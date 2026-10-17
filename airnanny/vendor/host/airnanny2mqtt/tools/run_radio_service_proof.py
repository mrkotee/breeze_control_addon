"""V30..V33 physical soak plus controlled CDC-close/recovery. No fake time/port.

Private stores and RF records stay in .local. The final public proof requires
the operator's post-run health statement in addition to this execution.
"""
import argparse
from collections import Counter, deque
import json
import hashlib
from pathlib import Path
import time
from types import SimpleNamespace
from uuid import uuid4
from run_radio_daemon import firmware_modules, Clock
from service_proof_commands import hardware_proof
from proof_power import SystemAwake
from proof_capture_checkpoint import install_confirmed_fan_checkpoint
from run_radio_service import preflight, establish, LOCAL, ROOT
from airnanny.service_profile import service_profile
from airnanny.config_loader import MqttConfig
from airnanny.mqtt_runtime import MqttRuntimeConfig
from airnanny.radio_service import ServiceState, ServiceLock, PersistentRadioService


class Metrics:
    def __init__(self):
        self.counts=Counter();self.rx=Counter();self.time=None;self.wraps=0
        self.app=deque(maxlen=16);self.status={};self.faults=deque(maxlen=16)

    def record(self,kind,f):
        self.counts[kind]+=1
        if kind=='RX' and f.get('ctx') in ('0','1'):self.rx[f['ctx']]+=1
        if kind=='STATUS':
            timestamp=int(f['time_us'])
            if self.time is not None and timestamp<self.time:self.wraps+=1
            self.time=timestamp
            self.status[f['ctx']]=dict(time_us=timestamp,generation=int(f['generation']),
                                       recovery=f['recovery'],rx_drop=int(f['rx_drop']),out_drop=int(f['out_drop']))
        if kind=='TXDONE' and f.get('application_tx')=='typed_type07_repeat':
            # Determine app ownership in the adapter's pending request instead
            # of calling every TXDONE an application result. Caller tags it.
            pass
        if kind=='ERROR':self.faults.append(f.get('reason','unknown'))


def wait(service,predicate,seconds=90):
    deadline=time.monotonic()+seconds
    next_progress=time.monotonic()+30
    while not predicate():
        service.pump()
        if time.monotonic()>deadline:raise RuntimeError('bounded_runtime_wait_expired')
        if time.monotonic()>=next_progress:
            next_progress=time.monotonic()+30
            state=service.state.read()
            print('STARTUP '+json.dumps({k:state.get(k) for k in ('state','reason','cycles','retry_delay_ms')}),flush=True)
        time.sleep(.005)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mqtt-port',type=int,required=True)
    p.add_argument('--firmware-version',type=int,choices=(30,31,32,33),default=32)
    p.add_argument('--soak-seconds',type=int,default=4800)
    p.add_argument('--startup-seconds',type=int,default=1800)
    p.add_argument('--operator-statement',required=True)
    p.add_argument('--rollover-successor',type=int,choices=(0,2),default=None)
    p.add_argument('--recovery-stock-handoff',action=argparse.BooleanOptionalAction,default=None)
    p.add_argument('--fan-checkpoint-ctx0')
    p.add_argument('--fan-checkpoint-ctx1')
    p.add_argument('--fan-target',type=int,choices=range(1,8))
    args=p.parse_args()
    profile=service_profile(args.firmware_version,rollover_successor=args.rollover_successor,
                            recovery_stock_handoff=args.recovery_stock_handoff)
    args.rollover_successor=profile.rollover_successor
    args.recovery_stock_handoff=profile.recovery_stock_handoff
    if args.soak_seconds<4500:p.error('physical wrap proof needs at least 4500 seconds')
    if not 90<=args.startup_seconds<=3600:p.error('startup window must be 90..3600 seconds')
    if args.firmware_version<32 and (args.rollover_successor or args.recovery_stock_handoff):
        p.error('successor 2 and recovery stock handoff require V32')
    checkpoints=(args.fan_checkpoint_ctx0,args.fan_checkpoint_ctx1)
    if any(checkpoints) and (not all(checkpoints) or args.firmware_version!=32):
        p.error('captured FAN-only proof requires two explicit V32 checkpoints')
    if any(checkpoints) and any(len(run)!=32 or any(c not in '0123456789abcdef' for c in run) for run in checkpoints):
        p.error('checkpoint must be an explicit local run id')
    run=uuid4().hex;directory=ROOT/'.local/radio_service_proof'/run
    directory.mkdir(parents=True,exist_ok=False)
    report=dict(run=run,status='STARTED',preflight=preflight(args.firmware_version),hardware_performed=True,
                operator_health_before=args.operator_statement,flash_readback_verified=None,
                phases={},disconnect_injection='controlled_actual_CDC_close',
                rollover_successor=args.rollover_successor,recovery_stock_handoff=args.recovery_stock_handoff,
                fan_policy='preserve_current' if args.fan_target is None else 'explicit_absolute_target',
                fan_target=args.fan_target,captured_fan_only=bool(any(checkpoints)),
                checkpoint_runs=list(checkpoints),session_checkpoints=[])
    sources=[*sorted((ROOT/'src/airnanny').glob('*.py')),
             ROOT/'tools/run_radio_service.py',Path(__file__),
             ROOT/'tools/service_proof_commands.py',ROOT/'tools/proof_power.py',
             ROOT/'tools/proof_capture_checkpoint.py']
    snapshot={
        str(path.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sources}
    (directory/'source_snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n',encoding='utf-8')
    for source in sources:
        archive=directory/'source_archive'/source.relative_to(ROOT)
        archive.parent.mkdir(parents=True,exist_ok=True);archive.write_bytes(source.read_bytes())
    print('SERVICE_PROOF_RUN '+run,flush=True)
    ledgers=firmware_modules().ledgers()
    (directory/'stores_before.private.json').write_text(json.dumps({str(s):l.read() for s,l in ledgers.items()},indent=2)+'\n')
    options=MqttRuntimeConfig(MqttConfig(host='127.0.0.1',port=args.mqtt_port))
    session_metrics=[]
    sessions=[]
    def factory(state):
        session=establish(SimpleNamespace(port=None,firmware_version=args.firmware_version,
                                         rollover_successor=args.rollover_successor,
                                         recovery_stock_handoff=args.recovery_stock_handoff),options,state)
        sessions.append(session)
        if all(checkpoints):
            try:
                applied={}
                for slot,name in enumerate(('second_bedroom','bedroom')):
                    applied[str(slot)]=install_confirmed_fan_checkpoint(
                        ROOT,checkpoints[slot],slot,session.daemon.adapters[name].device,ledgers)
                report['session_checkpoints'].append(applied)
            except BaseException:
                session.close()
                raise
        metrics=Metrics();session_metrics.append(metrics)
        observe=session.radio.record_observer
        def observed(kind,f):
            metrics.record(kind,f)
            if kind=='TXDONE':
                req=session.radio._pending.get(int(f['id']))
                if req and req.verb=='TYPE07_FAN':
                    metrics.app.append(dict(ctx=f['ctx'],result=f['result'],cleanup=f['cleanup'],
                                            rf_start_us=int(f['rf_start_us'])))
            observe(kind,f)
        session.radio.record_observer=observed
        return session
    with ServiceLock(LOCAL/'owner.lock'):
        state=ServiceState(LOCAL/'state.json')
        service=PersistentRadioService(state,Clock(),factory)
        awake=SystemAwake()
        phase='STARTUP';last_progress=0
        def both_ready():
            session=service.session
            return (session is not None and session.radio.connected
                    and session.radio.active_slots=={0,1}
                    and all(session.radio.context_available(f'dual-ctx{slot}') for slot in (0,1)))
        def proof_pump():
            nonlocal last_progress
            current=service.session
            if (directory/'operator_abort.json').exists() and current is not None:
                app_pending=any(request.verb=='TYPE07_FAN' for request in current.radio._pending.values())
                if not app_pending and not any(adapter.device.busy for adapter in current.daemon.adapters.values()):
                    raise RuntimeError('operator_aborted')
            service.pump()
            now=time.monotonic()
            if now-last_progress>=2:
                last_progress=now;session=service.session
                progress=dict(phase=phase,observed_unix=time.time(),state=state.read()['state'])
                if session:
                    progress.update(boot=session.radio.boot,active_slots=sorted(session.radio.active_slots))
                    progress['devices']={name:dict(status_fresh=a.device.snapshot().status_fresh,
                        baseline_valid=a.device.baseline.valid,baseline_live=a.device.baseline.live,
                        baseline_pending=a.device.baseline.remote_pending,fan=a.device.snapshot().fan)
                        for name,a in session.daemon.adapters.items()}
                (directory/'operator_progress.json').write_text(json.dumps(progress,indent=2)+'\n',encoding='utf-8')
        try:
            awake.acquire();report['idle_sleep_hold_acquired']=True
            wait(service,both_ready,args.startup_seconds)
            first=service.session;first_boot=first.radio.boot
            phase='INITIAL_COMMANDS'
            print(f'>>> V{args.firmware_version} ACTIVE. Initial two-PAN MQTT proof.',flush=True)
            hardware_proof(first,directory/'initial_commands.json',baseline_seconds=900,pump=proof_pump,fan_target=args.fan_target)
            report['phases']['initial_commands']='CONFIRMED_BOTH'
            phase='TIMER_SOAK'
            start=time.monotonic();next_progress=start
            while time.monotonic()-start<args.soak_seconds:
                proof_pump()
                if service.session is not first:raise RuntimeError('unexpected_recovery_during_wrap_soak')
                elapsed=int(time.monotonic()-start)
                if time.monotonic()>=next_progress:
                    next_progress=time.monotonic()+60
                    m=session_metrics[0]
                    progress=dict(elapsed_seconds=elapsed,timer_wraps=m.wraps,rx_contexts=dict(m.rx),radio=first.radio.state)
                    (directory/'progress.json').write_text(json.dumps(progress,indent=2)+'\n')
                    print('SOAK '+json.dumps(progress),flush=True)
                time.sleep(.005)
            m=session_metrics[0]
            if m.wraps<1 or set(m.rx)!={'0','1'} or m.faults:
                raise RuntimeError('continuous_two_context_wrap_not_proven')
            report['phases']['timer_wrap']=dict(elapsed_seconds=int(time.monotonic()-start),wraps=m.wraps,rx_contexts=dict(m.rx))
            print('>>> Timer wrap passed. Repeat two-PAN MQTT proof.',flush=True)
            phase='AFTER_WRAP_COMMANDS'
            hardware_proof(first,directory/'after_wrap_commands.json',baseline_seconds=900,pump=proof_pump,fan_target=args.fan_target)
            report['phases']['after_wrap_commands']='CONFIRMED_BOTH'
            # This intentionally closes the actual serial handle. V30 must
            # reboot itself; operator does not power-cycle or re-pair anything.
            first.radio._disconnect('serial_disconnected',retry=True)
            phase='CDC_RECOVERY'
            proof_pump()
            wait(service,both_ready,900 if args.firmware_version>=33 else 300)
            second=service.session
            if second is first or second.radio.boot==first_boot:
                raise RuntimeError('new_boot_and_new_adapter_required_after_CDC_loss')
            report['phases']['automatic_CDC_recovery']='NEW_BOOT_BOTH_ACTIVE'
            print('>>> Automatic recovery passed. Final two-PAN MQTT proof.',flush=True)
            phase='AFTER_RECOVERY_COMMANDS'
            hardware_proof(second,directory/'after_recovery_commands.json',baseline_seconds=900,pump=proof_pump,fan_target=args.fan_target)
            report['phases']['after_recovery_commands']='CONFIRMED_BOTH'
            report['status']='SOAK_AND_CDC_RECOVERY_PASSED_AWAITING_OPERATOR_HEALTH'
        except BaseException as exc:
            report['status']='FAILED_OR_UNKNOWN';report['error_type']=type(exc).__name__
            if isinstance(exc,RuntimeError) and str(exc)=='operator_aborted':report['error_reason']='operator_aborted'
            if isinstance(exc,RuntimeError) and str(exc)=='bounded_runtime_wait_expired':
                report['status']='STARTUP_READINESS_NOT_REACHED_IN_BOUNDED_WINDOW'
            if service.session and service.session.radio.state=='blocked':
                state.write('BLOCKED',reason=service.session.radio.reason)
            raise
        finally:
            for index,session in enumerate(sessions):
                diagnostic=dict(state=session.radio.state,reason=session.radio.reason,
                                poll_misses=session.radio._poll_misses,records=list(session.records))
                (directory/f'session_{index}.private.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
            report['metrics']=[dict(counts=dict(m.counts),rx_contexts=dict(m.rx),timer_wraps=m.wraps,
                                     last_status=m.status,application_results=list(m.app),faults=list(m.faults)) for m in session_metrics]
            service.close()
            report['service_closed']=True
            report['idle_sleep_hold_released']=awake.close()
            (directory/'stores_after.private.json').write_text(json.dumps({str(s):l.read() for s,l in ledgers.items()},indent=2)+'\n')
            (directory/'proof.json').write_text(json.dumps(report,indent=2)+'\n')
            print('SERVICE_PROOF_CLOSED run='+run,flush=True)


if __name__=='__main__':main()
