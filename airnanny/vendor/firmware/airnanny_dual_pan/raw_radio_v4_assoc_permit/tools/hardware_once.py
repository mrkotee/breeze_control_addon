"""Authorized V1 hardware attempt only. Requires software READY manifest and operator arm.
No retry, no key provisioning, no arbitrary TX. Keys only authenticate live NWK evidence.
"""
import csv,datetime,hashlib,json,os,sys,time
from dataclasses import asdict
from pathlib import Path
from permit_validator import PermitValidator,codec
from attempt_plan import begin_command,expected_request,expected_poll,validate_response
from identity_store import allocate,attempt,save_associated

R=Path(__file__).resolve().parents[1]
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def main():
    import serial
    sw=json.loads((R/'evidence/software_result.json').read_text())
    if sw['verdict']!='A AUTHENTICATED PERMIT ASSOCIATION SOFTWARE READY':raise RuntimeError('Part A not READY')
    if hashlib.sha256((R/'build/airnanny_raw_assoc_permit_v4.hex').read_bytes()).hexdigest().upper()!=sw['build']['hex_sha256']:raise RuntimeError('V4 hash mismatch')
    recovery=R.parent.parent/'airnanny_v17/releases/airnanny_status_v17_machine_serial.hex'
    if hashlib.sha256(recovery.read_bytes()).hexdigest().upper()!='2FFFE202FC0B8766113CADF92156B76A98942B64A0E4F3D3692513F210575193':raise RuntimeError('V17 recovery hash mismatch')
    E=R/'evidence/hardware_v1';E.mkdir(exist_ok=True)
    out=E/'attempt.json'
    if out.exists() or (E/'capture.log').exists() or (E/'arm.json').exists() or (E/'user_action.json').exists():raise RuntimeError('Existing attempt/markers: reconciliation required, not retry')
    inventory=json.loads((E/'forbidden_identities.json').read_text())
    if set(inventory)!=set(('physical_aircontrols','coordinators','v17_reference','other_raw')) or len(inventory['physical_aircontrols'])!=2 or len(inventory['coordinators'])!=2 or not inventory['v17_reference']:raise RuntimeError('Incomplete forbidden identity inventory')
    forbidden=[a for values in inventory.values() for a in values]
    keys=[]
    for line in (Path(os.environ['APPDATA'])/'Wireshark/zigbee_pc_keys').read_text().splitlines():
        if not line or line.startswith('#'):continue
        key=bytes.fromhex(next(csv.reader([line]))[0].replace(':','').replace('-','').replace(' ',''))
        if len(key)==16:keys.extend([key,key[::-1]])
    d={'started_utc':utc(),'records':[],'commands':[],'identity':None,'permit':None,'response':None,
       'marker':None,'rf_tx_request_count':0,'poll_tx_count':0,'bounds':{'max_polls':2,'interval_ms':500,'timeout_ms':10000},
       'software_hex_sha256':sw['build']['hex_sha256'],'V17_hex_sha256':'2FFFE202FC0B8766113CADF92156B76A98942B64A0E4F3D3692513F210575193'}
    validator=None;boot=None;session=0;identifier=0;buf=bytearray();pending=None;stage='baseline'
    started=time.monotonic();ready=False;armed=False;request_started=None;last_tx=None;response=None
    request_floor=None;polls=0;expected_mac=None;response_RX=None;failure=None;port=None;last_revision=None
    try:
        port=serial.Serial('COM7',115200,timeout=.05,write_timeout=2)
        with (E/'capture.log').open('wb') as log:
            port.dtr=True
            def send(command):
                if len(command)>=512:raise RuntimeError('command too long')
                d['commands'].append({'utc':utc(),'raw':command});port.write((command+'\n').encode('ascii'))
            def info():
                nonlocal identifier
                identifier+=1;send('RADIOV3 INFO id='+str(identifier))
            def action(verb):
                nonlocal identifier,pending
                if verb not in ('REQUEST','POLL','END','STATUS'):raise RuntimeError('not allowlisted')
                identifier+=1;send(f'RADIOV3 ASSOC {verb} boot={boot} id={identifier} session={session}');pending=(verb,identifier,time.monotonic())
            info()
            while time.monotonic()-started<600:
                now=time.monotonic()
                if boot is None and now-started>5:raise RuntimeError('initial INFO timeout')
                if pending and now-pending[2]>5:raise RuntimeError('typed command completion timeout')
                if (E/'stop.json').exists():raise RuntimeError('operator safety stop')
                if (E/'user_action.json').exists() and d['marker'] is None:
                    d['marker']=json.loads((E/'user_action.json').read_text(encoding='utf-8-sig'))
                if not ready and now-started>=15 and boot and validator:
                    ready=True;d['baseline_ready_utc']=utc();print('BASELINE_READY: current A7 authenticated context established, no identity allocated; wait for arm',flush=True)
                if ready and not armed and (E/'arm.json').exists():
                    armed=True;stage='waiting_permit';d['armed_utc']=utc();print('ARMED: next qualifying fresh authenticated A7 permit will initiate ONE attempt',flush=True)
                if request_started and now-request_started>=10:break
                if stage=='wait_response' and not pending and response:
                    break
                if stage=='wait_response' and not pending and polls<2 and last_tx and now-last_tx>=.5:
                    expected_mac=expected_poll(d['identity']['raw_ieee'],polls);polls+=1;action('POLL')
                data=port.read(port.in_waiting or 1)
                if not data:continue
                log.write(data);log.flush();buf.extend(data)
                while b'\n' in buf:
                    line,_,buf=buf.partition(b'\n');raw=line.rstrip(b'\r').decode('ascii',errors='replace')
                    item={'utc':utc(),'raw':raw}
                    if not raw.startswith('RADIOV3 '):d['records'].append(item);continue
                    parts=raw.split();kind=parts[1];f=dict(s.split('=',1) for s in parts[2:] if '=' in s)
                    item.update(kind=kind,fields=f);d['records'].append(item)
                    if kind!='RX':print(raw,flush=True)
                    if boot and f.get('boot')!=boot:raise RuntimeError('boot changed')
                    if kind=='INFO':
                        for k,v in {'identity':'airnanny_raw_assoc_permit_v4','version':'4','capability':'association_only','permit_gate':'beacon_or_authenticated_zdo','commissioning':'unkeyed','application_tx':'locked','transport_key':'unsupported','device_announce':'unsupported','channel':'21','session':'0','immediate_ack':'0','pending_tx':'0','rx_drop':'0','out_drop':'0'}.items():
                            if f.get(k)!=v:raise RuntimeError('initial runtime invariant '+k)
                        boot=f['boot'];d['initial_info']=item
                    elif kind=='ERROR':raise RuntimeError('firmware rejected typed command')
                    elif kind=='BEGIN':
                        if pending is None or pending[0]!='BEGIN' or int(f['id'])!=pending[1] or f.get('admission_evidence')!='zdo_permit' or int(f.get('permit_revision','0'))!=d['permit']['rx_revision'] or f.get('attempt')!=d['identity']['attempt']:raise RuntimeError('BEGIN binding mismatch')
                        session=int(f['session']);pending=None;request_floor=int(d['last_rx_revision']);expected_mac=expected_request(d['identity']['raw_ieee']);action('REQUEST');request_started=time.monotonic();stage='request'
                    elif kind=='TXACCEPT':
                        if pending is None or pending[0] not in ('REQUEST','POLL') or int(f['id'])!=pending[1] or int(f['session'])!=session or bytes.fromhex(f['mac'])!=expected_mac or f.get('retry')!='0':raise RuntimeError('SAFETY_FAIL unexpected TX')
                        if pending[0]=='REQUEST':d['rf_tx_request_count']+=1
                        else:d['poll_tx_count']+=1
                        if d['rf_tx_request_count']>1 or d['poll_tx_count']>2:raise RuntimeError('SAFETY_FAIL repeated TX')
                    elif kind=='TXDONE':
                        if pending is None or int(f['id'])!=pending[1] or int(f['session'])!=session:raise RuntimeError('unexpected TX completion')
                        if f.get('result')!='local_tx_ok':raise RuntimeError('TX/ACK INCONCLUSIVE: '+f.get('result','unknown'))
                        last_tx=time.monotonic();pending=None;stage='wait_response'
                    elif kind=='RESPONSE':
                        if int(f['session'])!=session or request_started is None:raise RuntimeError('unexpected response session')
                        d['response_summary']=item
                    elif kind=='RX':
                        revision=int(f['revision']);d['last_rx_revision']=revision
                        if last_revision is not None and revision!=last_revision+1:raise RuntimeError('RX revision gap: no missing-evidence TX allowed')
                        last_revision=revision
                        if f.get('channel')!='21':raise RuntimeError('wrong channel')
                        raw_mac=bytes.fromhex(f['mac']);observed=time.monotonic()
                        if request_started is None and (f['ack_started']!='0' or f['ack_completed']!='0'):raise RuntimeError('SAFETY_FAIL pre-request ACK')
                        if request_started and raw_mac[:2]==b'\x63\xcc':
                            try:result=validate_response(raw_mac,d['identity']['raw_ieee'],'00124b0036a148e5',revision,request_floor)
                            except ValueError:result=None
                            if result:
                                if int(f['session'])!=session:raise RuntimeError('valid response wrong session')
                                response=result;response_RX=item;d['response']=result;d['response_RX']=item
                        if request_started is not None:continue  # no commissioning/data decryption after request
                        if validator is None and boot:
                            for key in keys:
                                trial=PermitValidator(boot=boot,pan=0xfa9b,coordinator='00124b0036a148e5',key=key,key_sequence=0,key_epoch='live_selected_epoch0',generation=1,revision_floor=int(d['initial_info']['fields']['rx_revision']))
                                try:trial.prime_observation(raw_mac,revision)
                                except Exception:continue
                                validator=trial;d['current_coordinator_evidence']={'revision':revision,'authenticated_source':'00124b0036a148e5','pan':'fa9b','key_sequence':0,'security_frame_counter':validator.highest_fc};break
                        elif validator:
                            if armed and d['permit'] is None:
                                try:e=validator.validate(raw=raw_mac,boot=boot,revision=revision,observed=observed,now=time.monotonic(),generation=1)
                                except Exception:e=None
                                if e:
                                    d['permit']=validator.reserve(e,time.monotonic())
                                    allocated=allocate(R/'.local/hardware_v1',0,forbidden)
                                    if allocated['state']!='ALLOCATED_UNUSED':raise RuntimeError('existing reserved/uncertain identity; no retry')
                                    d['identity']=attempt(R/'.local/hardware_v1',0,forbidden)
                                    if time.monotonic()-e.observed_timestamp>10:raise RuntimeError('evidence expired during durable reservation')
                                    identifier+=1;send(begin_command(e,d['identity'],identifier));pending=('BEGIN',identifier,time.monotonic());stage='begin'
                            if d['permit'] is None:
                                try:validator.prime_observation(raw_mac,revision)
                                except Exception:pass
            if pending and pending[0] in ('REQUEST','POLL'):raise RuntimeError('TX/ACK INCONCLUSIVE: terminal local completion pending')
            if response and (response_RX['fields'].get('ack_started')!='1' or response_RX['fields'].get('ack_completed')!='1' or response_RX['fields'].get('deadline_miss')!='0'):raise RuntimeError('TX/ACK INCONCLUSIVE: response immediate ACK diagnostics')
            if d['permit'] is None:d['outcome']='NO_QUALIFYING_PERMIT_NO_TX'
            elif response:
                if response['status']==0:
                    d['associated_record']=save_associated(R/'.local/hardware_v1',0,d['identity']['attempt'],0xfa9b,'00124b0036a148e5',response['assigned_short']);d['outcome']='FRESH_RAW_IDENTITY_ADMISSION_PASS_CANDIDATE'
                else:d['outcome']='A7_REJECTED_FRESH_IDENTITY'
            else:d['outcome']='ASSOCIATION_INCONCLUSIVE_NO_RESPONSE'
    except Exception as exc:
        failure=str(exc);d['error']=failure;d['outcome']='TX_ACK_INCONCLUSIVE' if failure.startswith('TX/ACK INCONCLUSIVE') else 'STOP_REQUIRES_REVIEW'
    finally:
        # Same CDC connection, sequential END then INFO with bounded draining.
        # No REQUEST/POLL or commissioning during cleanup.
        try:
            if port is not None and boot:
                commands=[]
                if session:
                    identifier+=1;cmd=f'RADIOV3 ASSOC END boot={boot} id={identifier} session={session}'
                    commands.append(cmd)
                identifier+=1;cmd='RADIOV3 INFO id='+str(identifier)
                commands.append(cmd);terminal=bytearray()
                for cmd in commands:
                    d['commands'].append({'utc':utc(),'raw':cmd});port.write((cmd+'\n').encode('ascii'))
                    deadline=time.monotonic()+2
                    while time.monotonic()<deadline:terminal.extend(port.read(port.in_waiting or 1))
                with (E/'capture.log').open('ab') as log:log.write(terminal)
                d['terminal_raw']=terminal.decode('ascii',errors='replace');print(d['terminal_raw'],flush=True)
                infos=[line for line in d['terminal_raw'].splitlines() if line.startswith('RADIOV3 INFO ')]
                if not infos:raise RuntimeError('terminal INFO missing')
                fields=dict(s.split('=',1) for s in infos[-1].split() if '=' in s)
                d['terminal_info']=fields
                if fields.get('boot')!=boot or fields.get('immediate_ack')!='0' or fields.get('pending_tx')!='0' or fields.get('rx_drop')!='0' or fields.get('out_drop')!='0':raise RuntimeError('terminal ACK/pending/loss invariant violated')
        except Exception as exc:d['terminal_error']=str(exc)
        if port is not None:port.close()
        if (E/'user_action.json').exists():d['marker']=json.loads((E/'user_action.json').read_text(encoding='utf-8-sig'))
        d['ended_utc']=utc();d['partial_line_hex']=bytes(buf).hex();out.write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')
    print('ATTEMPT_ENDED '+d.get('outcome','unknown')+' '+str(out),flush=True)
    return 1 if failure else 0
if __name__=='__main__':raise SystemExit(main())
