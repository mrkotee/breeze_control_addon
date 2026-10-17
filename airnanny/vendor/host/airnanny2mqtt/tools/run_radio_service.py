"""Continuous V30/V31/V32 service, retained-key recovery after transport loss.

No physical USB reset and no manual --recover per run. Protocol/security faults
latch in .local/radio_service/state.json. --preflight never opens the dongle.
"""
import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'.deps'),str(ROOT/'src'),str(ROOT/'.tmp/mqtt-python')]
sys.dont_write_bytecode=True
from run_radio_daemon import firmware_modules, preflight as prior_preflight, Clock
from airnanny import addon_keys
from airnanny.config_loader import MqttConfig
from airnanny.daemon import AirNannyDaemon
from airnanny.mqtt_runtime import MqttRuntimeConfig, TlsConfig
from airnanny.paho_mqtt import PahoMqttTransport
from airnanny.radio_daemon import DurableApplicationIngress, RadioDaemonLoop
from airnanny.radio_runtime import restore_devices
from airnanny.real_radio import RealRadioTransport, bootstrap_port_factory, serial_port_factory
from airnanny.recovery_guard import guard_recovery_reads
from airnanny.recovery_application import handoff_recovery_stock
from airnanny.service_profile import service_profile
from airnanny.radio_service import (ServiceState, ServiceLock, BoundedLedger, ServiceBlocked, OPERATOR_CLEARABLE,
                                   PersistentRadioService, StartupUnavailable, ReadinessPolls,
                                   ServiceDaemon, RadioServiceSession,
                                   discovery_retry_safe, RecoveryDiscoveryUnavailable,
                                   clean_recovery_loss_safe, RecoveryCleanTxLoss, response_timeout_retry_safe,
                                   discovery_slot_absent_safe, settle_recovery_poll)

# The add-on keeps service state on its own persistent volume, which is not
# inside this tree. Absent that variable the path is unchanged, so existing
# runs, proof tools and tests keep reading and writing the same directory.
LOCAL=Path(os.environ.get('AIRNANNY_STATE_DIR') or ROOT/'.local/radio_service')


def preflight(firmware_version=32):
    if firmware_version not in (30,31,32,33):
        raise ValueError('continuous firmware profile required')
    image_root=ROOT.parents[1]/f'firmware/airnanny_dual_pan/dual_pan_runtime_v{firmware_version}'
    prior=prior_preflight(29)
    manifest=json.loads((image_root/'evidence/build_manifest.json').read_text())
    image=image_root/f'releases/airnanny_dual_pan_runtime_v{firmware_version}.hex'
    digest=hashlib.sha256(image.read_bytes()).hexdigest()
    if (manifest['identity']!=f'airnanny_dual_pan_runtime_v{firmware_version}'
            or digest!=manifest['hex_sha256'].lower()):
        raise RuntimeError(f'V{firmware_version} firmware binding mismatch')
    native=json.loads((image_root/'evidence/persistent_offline.json').read_text())
    if native['status']!='OFFLINE_NATIVE_PASS' or native['hardware_performed'] is not False:
        raise RuntimeError(f'V{firmware_version} native proof missing')
    # Bind the build to current local source, including timing headers.
    for label,digest_at_build in manifest['input_sha256'].items():
        if label.startswith('nrf sdk/'):
            continue
        if hashlib.sha256((image_root/label).read_bytes()).hexdigest().upper()!=digest_at_build.upper():
            raise RuntimeError(f'V{firmware_version} source changed after build')
    return dict(firmware=f'V{firmware_version}',hex_sha256=digest,wire=10,contexts=prior['contexts'],
                mode='continuous',hardware_proven=False)


def context_ledgers(frozen):
    """Both contexts' writers, keyed from DPAPI or from supplied options.

    The frozen Gate B launcher unwraps DPAPI, which answers only on the
    machine that commissioned the units. Where a deployment supplies its own
    keys instead, the same construction is repeated here rather than edited
    into that file: the one component allowed to move a live store stays
    exactly as it was reviewed, and this wrapper carries the difference.

    The store still decides which key it wants. Its secret reference is read
    from the store itself and the supplied key is verified against that
    reference before a ledger exists, so a key meant for the other context
    cannot key this one.
    """
    if not addon_keys.configured():
        return frozen.ledgers()
    import dual_ledger
    import dual_store
    import gate_a_authority as authority
    from key_announce import Secret

    out = {}
    for ctx in (0, 1):
        record = authority.load(dual_store.STORE_PATHS[ctx])
        ref = record.get('secret_ref')
        if not ref:
            raise authority.AuthorityFault('no_secret_ref_in_ctx%d_store' % ctx)
        out[ctx] = dual_ledger.ContextLedger(
            ctx, Secret(addon_keys.resolve_key(ctx, ref)), hardware=True)
    if out[0].root == out[1].root:
        raise authority.AuthorityFault('the two contexts share a store root')
    return out


def establish(args, mqtt_options, state):
    firmware_version=getattr(args,'firmware_version',32)
    profile=service_profile(firmware_version,
        rollover_successor=getattr(args,'rollover_successor',None),
        recovery_stock_handoff=getattr(args,'recovery_stock_handoff',None),
        partial_startup=getattr(args,'partial_startup',None))
    partial_startup=profile.partial_startup
    stock_handoff=profile.recovery_stock_handoff
    rollover_successor=profile.rollover_successor
    frozen=firmware_modules()
    ledgers={slot:BoundedLedger.install(ledger) for slot,ledger in context_ledgers(frozen).items()}
    state.require_recovery(ledgers)
    state.require_monotonic_stores(ledgers)
    serial,list_ports=frozen.serial_modules()
    def selected_port():
        ports=list(list_ports.comports())
        pin=frozen.authority.DONGLE
        matches=[p for p in ports if (p.vid,p.pid,p.serial_number)==(pin['vid'],pin['pid'],pin['serial'])]
        if not matches:
            raise StartupUnavailable('dongle_absent')
        selected=frozen.authority.select_device(ports)
        if args.port and selected['port']!=args.port:
            raise RuntimeError('requested_port_does_not_match_pinned_dongle')
        return selected['port']
    # Closing CDC requests V30's safe software reboot, even after host process
    # death. No guessed INFO id is sent to an old boot. Re-select by USB serial
    # after enumeration because Windows can change the COM number.
    try:
        port=serial_port_factory(selected_port())
        port.close()
        time.sleep(2)
        name=selected_port()
        port=serial_port_factory(name)
    except (serial.SerialException, OSError):
        raise StartupUnavailable('serial_open_failed') from None
    loop=None
    runner=None
    guard=None
    records=deque(maxlen=4096)
    try:
        from gate_b_runner import GateBRunner
        class Recovery(GateBRunner):
            def __init__(self,*args,**kwargs):
                super().__init__(*args,**kwargs)
                from management import decode_nwk, InvalidTag
                guard_recovery_reads(self.w,self.ledgers,decode_nwk,error_type=ServiceBlocked,
                                     authentication_errors=(ValueError,AssertionError,InvalidTag))
            def check_identity(self):
                self.info=self.command('INFO')
                expected=dict(identity=f'airnanny_dual_pan_runtime_v{firmware_version}',version=str(firmware_version),wire='10',contexts='2',
                              channel='21',crypto='host_only',application_tx=('typed_type07_repeat_late_join' if firmware_version>=33 else 'typed_type07_repeat'),pending_tx='0',
                              max_run_seconds='0',max_total_polls_per_context='4294967295')
                if any(self.info.get(k)!=v for k,v in expected.items()):
                    raise RuntimeError('recovery_firmware_mismatch')
                return self.info
            def command(self,verb,ctx=None,fields='',raw=None,kind=None):
                if verb in ('CURRENT_SHORT_COMMIT','PARENT_LINK_ACTIVE'):
                    settle_recovery_poll(self,ctx)
                reply=super().command(verb,ctx,fields,raw,kind)
                if firmware_version>=31 and ctx is not None:
                    parent_tx=verb in ('REJOIN_REQUEST','DEVICE_ANNOUNCE','END_DEVICE_TIMEOUT','TYPE07_FAN')
                    parent_commit=verb in ('CURRENT_SHORT_COMMIT','PARENT_LINK_ACTIVE')
                    if parent_tx and reply.get('result')=='local_tx_ok' or parent_commit and reply.get('state')=='RECOVERY':
                        self.readiness_polls.misses[ctx]=0
                return reply
            def on_auto(self,row):
                super().on_auto(row)
                if row['kind']=='AUTO_DONE':
                    slot=int(row['fields']['ctx']);result=row['fields']['result']
                    if result=='local_tx_ok':self.readiness_polls.misses[slot]=0
                    elif result in ('no_ack','invalid_ack','cca_fail'):self.readiness_polls.misses[slot]+=1
                    else:raise RuntimeError('automatic_poll_failed_or_unknown')
            def idle_poll(self, ctx, generation, dsn):
                fields=super().idle_poll(ctx,generation,dsn)
                self.readiness_polls.completed(ctx,fields)
                return fields
            def keep_alive(self, seconds):
                end=self.clock()+seconds
                due={slot:self.clock()+1.25+.5*slot for slot in self.active_slots}
                dsn={slot:self.ledgers[slot].read()['sequences']['dsn'] for slot in self.active_slots}
                while self.clock()<end:
                    for slot in sorted(self.active_slots):
                        if self.clock()>=due[slot]:
                            dsn[slot]=(dsn[slot]+1)&255
                            self.idle_poll(slot,self.ledgers[slot].read()['generation'],dsn[slot])
                            due[slot]=self.clock()+1.25
                    self.w.read()
        guard=uuid4().hex
        port.timeout=.05
        runner=Recovery(port,time.monotonic,ledgers,guard=guard)
        runner.readiness_polls=ReadinessPolls(ledgers,guard,tolerate_active_loss=firmware_version>=32)
        # Bound runner transcript in long-lived process. It exists only for
        # one bounded recovery, then is released when the runtime takes over.
        runner.check_identity()
        runner.require_a_fresh_boot()
        state.begin(runner.info['boot'],guard)
        print('RECOVERING ctx0+ctx1; shared readiness 60s',flush=True)
        runner.active_slots=set()
        for slot in (0,1):
            try:
                runner.commission(slot)
                runner.active_slots.add(slot)
            except Exception as exc:
                if not (partial_startup and discovery_slot_absent_safe(exc,slot,ledgers[slot],guard,runner.records)):
                    raise
                print('STARTUP_OFFLINE ctx='+str(slot)+'; no secured request submitted',flush=True)
        if not runner.active_slots:
            raise RecoveryDiscoveryUnavailable('both_startup_parents_absent')
        runner.keep_alive(60)
        while runner.w.available():runner.w.read()
        initial_bytes,initial_id=runner.w.buf,runner.w.id
        port.timeout=0
        config,bindings,counters,remotes=restore_devices(ledgers,mqtt_options.connection,repeat_commands=True,retry_commands=firmware_version>=32,
                                                       active_slots=runner.active_slots)
        transport_type=RealRadioTransport
        if firmware_version>=33:
            from airnanny.late_join_radio import LateJoinRadioTransport
            transport_type=LateJoinRadioTransport
        radio=transport_type(Clock(),bindings,port_factory=bootstrap_port_factory(port),port_name=name,
                                 firmware_version=firmware_version,initial_command_id=initial_id,initial_bytes=initial_bytes,
                                 active_slots=runner.active_slots,
                                 initial_poll_misses=runner.readiness_polls.misses,
                                 intent_hook=counters.intent,completion_hook=counters.local_complete)
        radio.record_observer=lambda kind,fields:records.append(dict(kind=kind,fields=fields))
        def credentials(ref):
            if ref not in ('env:AIRNANNY_MQTT_USERNAME','env:AIRNANNY_MQTT_PASSWORD'):
                raise ValueError('unsupported credential reference')
            return os.environ[ref[4:]]
        mqtt=PahoMqttTransport(mqtt_options,credential_resolver=credentials)
        daemon=ServiceDaemon(config,radio.clock,radio,mqtt,counters,command_retries=firmware_version>=32,
                             rollover_successor=rollover_successor)
        by_context={f'dual-ctx{slot}':ledger for slot,ledger in ledgers.items()}
        loop=RadioServiceSession(daemon,radio,DurableApplicationIngress(daemon,by_context,remotes),verdict_hook=counters.application_result)
        loop.records=records
        if stock_handoff:
            loop.recovery_stock_handoff=handoff_recovery_stock(
                radio.receiver, runner.records, boot=runner.info['boot'],
                now=runner.clock(), active_contexts={f'dual-ctx{slot}' for slot in runner.active_slots})
        if firmware_version>=33:
            from airnanny.late_join import LateJoinRecovery
            from airnanny.recovery_guard import recovery_leave
            from discovery import validate
            from management import decode_nwk,InvalidTag
            def bind_fields(ledger):
                record=ledger.read();identity=ledger.identity
                return dict(generation=record['generation'],epoch=record['key_epoch_id'],
                    attempt=identity['attempt'],guard=record['recovery']['gate'],short=identity['short'])
            loop.late_join=LateJoinRecovery(loop,ledgers,state,
                validate_beacon=validate,bind_fields=bind_fields,
                leave_check=lambda row,subset:recovery_leave(row,subset,decode_nwk,
                    authentication_errors=(ValueError,AssertionError,InvalidTag)))
        loop.start()
        state.write('WAITING',reason='runtime_handshake',active_slots=sorted(runner.active_slots))
        return loop
    except BaseException as exc:
        diagnostic=dict(error_type=type(exc).__name__,error=str(exc),
                        records=runner.records if runner else [],
                        state=state.read())
        LOCAL.mkdir(parents=True,exist_ok=True)
        (LOCAL/('recovery_failure_'+uuid4().hex+'.private.json')).write_text(json.dumps(diagnostic,indent=2)+'\n')
        if loop:loop.close()
        else:port.close()
        if guard and discovery_retry_safe(exc,ledgers,guard):
            raise RecoveryDiscoveryUnavailable('target_beacon_unavailable') from None
        if guard and runner and clean_recovery_loss_safe(exc,ledgers,guard,runner.records):
            raise RecoveryCleanTxLoss('clean_recovery_RF_loss_new_cycle_required') from None
        if firmware_version>=32 and guard and runner and response_timeout_retry_safe(exc,ledgers,guard,runner.records):
            raise RecoveryCleanTxLoss('recovery_response_timeout_new_cycle_required') from None
        raise


def argument_parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preflight',action='store_true')
    p.add_argument('--firmware-version',type=int,choices=(30,31,32,33),default=32)
    p.add_argument('--port',help='optional fixed COM; otherwise identify by pinned USB serial')
    p.add_argument('--partial-startup',action=argparse.BooleanOptionalAction,default=None,help='serve recovered slots when another has no beacon; default on for V33 with automatic late join')
    p.add_argument('--recovery-stock-handoff',action=argparse.BooleanOptionalAction,default=None,help='retain current-session recovery stock templates; default on for V32; new live status still required')
    p.add_argument('--rollover-successor',type=int,choices=(0,2),default=None,help='application number after 255: default 2 for V32, 0 for older profiles')
    p.add_argument('--mqtt-host',default='127.0.0.1')
    p.add_argument('--mqtt-port',type=int,default=1883)
    p.add_argument('--mqtt-tls',action='store_true')
    p.add_argument('--mqtt-ca')
    p.add_argument('--duration',type=int,default=0,help='0 runs until stopped; positive seconds bound a hardware soak')
    return p


def main():
    p=argument_parser()
    args=p.parse_args()
    if args.duration<0:p.error('duration must be nonnegative')
    try:
        profile=service_profile(args.firmware_version,rollover_successor=args.rollover_successor,
            recovery_stock_handoff=args.recovery_stock_handoff,partial_startup=args.partial_startup)
    except ValueError as exc:
        p.error(str(exc))
    report=preflight(args.firmware_version)
    report['service_profile']=dict(firmware_version=profile.firmware_version,
        rollover_successor=profile.rollover_successor,recovery_stock_handoff=profile.recovery_stock_handoff,
        partial_startup=profile.partial_startup,captured_fan_checkpoint=False,
        late_join=profile.firmware_version>=33,normal_startup_hardware_verified=False)
    print(json.dumps(report,indent=2),flush=True)
    if args.preflight:return
    mqtt=MqttConfig(host=args.mqtt_host,port=args.mqtt_port,
                    username_ref='env:AIRNANNY_MQTT_USERNAME' if 'AIRNANNY_MQTT_USERNAME' in os.environ else None,
                    password_ref='env:AIRNANNY_MQTT_PASSWORD' if 'AIRNANNY_MQTT_PASSWORD' in os.environ else None)
    options=MqttRuntimeConfig(mqtt,tls=TlsConfig(enabled=args.mqtt_tls,ca_file=args.mqtt_ca),allow_non_loopback=args.mqtt_tls)
    with ServiceLock(LOCAL/'owner.lock'):
        state=ServiceState(LOCAL/'state.json')
        latched=state.read()
        if latched['state']=='BLOCKED':
            # Printed before anything is attempted, because an appliance gives
            # the operator nowhere else to read it, and the reason is the one
            # thing they need in order to act on it.
            reason=latched.get('reason') or 'unknown'
            print('LATCHED FAULT: '+reason,flush=True)
            if latched.get('review'): print('  review: '+json.dumps(latched['review'],ensure_ascii=False),flush=True)
            print('  '+('clear it by acknowledging exactly this reason' if reason in OPERATOR_CLEARABLE
                        else 'this one needs review; acknowledging it will not clear it'),flush=True)
        acknowledged=(os.environ.get('AIRNANNY_ACKNOWLEDGE_FAULT') or '').strip()
        if acknowledged:
            outcome=state.acknowledge(acknowledged)
            print({'cleared':'fault cleared by operator: '+acknowledged,
                   'mismatch':'not cleared: the latched fault is '+(latched.get('reason') or 'unknown')+', not '+acknowledged,
                   'not_clearable':'not cleared: '+acknowledged+' needs review, not acknowledgement',
                   'not_blocked':'nothing to clear; the service is not latched'}[outcome],flush=True)
        service=PersistentRadioService(state,Clock(),lambda s:establish(args,options,s))
        deadline=time.monotonic()+args.duration if args.duration else None
        try:
            while deadline is None or time.monotonic()<deadline:
                service.pump()
                time.sleep(.005)
        except KeyboardInterrupt:
            pass
        finally:
            service.close()


if __name__=='__main__':main()
