"""Narrow V7 live orchestration. No serial import until explicit execute.

SingleBoot and V7 firmware are read-only. One invocation, no reconnect or retry.
All key validation/install/build uses the reviewed V7 host modules.
"""
import sys,time,json,uuid,hashlib,datetime
from pathlib import Path
HERE=Path(__file__).resolve().parent;V7=HERE
sys.path.insert(0,str(V7/'host'));sys.path.insert(0,str(V7/'tools'))
from single_boot import SingleBoot,Stop,RAW,TC,OLD_ATTEMPT,Secret,ProtectedSecrets,durable,store,plan
from key_announce import Replay,Rx,validate_transport,short_poll,oracle
from cryptography.exceptions import InvalidTag
V7_HASH='A48EBFD3C8A931C7C7D326EFACFC3589C67D1FDA293DE987751957453CD7DCBD'
V17_HASH='2FFFE202FC0B8766113CADF92156B76A98942B64A0E4F3D3692513F210575193'
SEED=HERE.parent/'raw_radio_v4_assoc_permit/.local/hardware_v1/ctx0.json'
SEED_HASH='da13f9035f9f924c423f8b63e60e38c9e895cd7a1e22165c7f8819c2e0d15f6c'
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def write_result(outcome,state):
    text='# SINGLE-PAN COMMISSIONING RESULT\n\n'
    text+='Hardware outcome: **'+outcome['primary']+'**. Recovery guard: '+state+'.\n\n'
    text+='Final protocol state: '+outcome['next_protocol_state']+'.\n\n'
    text+='Exact sanitized baseline, permit, current association, polling timestamps, protected key references, durability generations, FC high-water, encrypted announce, TX/ACK receipts and passive RX records are in `evidence/single_pan_commissioning_result.json`.\n\n'
    text+='V17 local INFO verified; both original physical pairs confirmed operational. Operator recovery actions: '+json.dumps(outcome['physical_recovery']['recovery_actions'],ensure_ascii=False)+'.\n\nSTOP after recovery.\n'
    (HERE/'SINGLE_PAN_COMMISSIONING_RESULT.md').write_text(text,encoding='utf-8')
class Fault(Stop):pass
class Guard:
    """Append-only records; permanent milestone claim prevents any second gate."""
    def __init__(self,root):self.root=Path(root);self.path=None;self.number=0
    def start(self,physical):
        self.root.mkdir(parents=True,exist_ok=True)
        with store.locked(self.root):
            if (self.root/'milestone.json').exists():raise Fault('OUTER_GUARD_NO_RERUN')
            if not all(physical.get(k) is True for k in ('both_healthy','automation_paused','no_check_case','current_data','settings_confirmed')):raise Fault('PHYSICAL_PRECHECK')
            self.path=self.root/'runs'/uuid.uuid4().hex;self.path.mkdir(parents=True)
            durable(self.path/'000_NOT_STARTED.json',{'state':'NOT_STARTED','utc':utc(),'physical':physical})
            durable(self.root/'milestone.json',{'run_uuid':self.path.name,'state':'STARTED','utc':utc(),'raw':RAW})
            self.event('STARTED',physical=physical)
        return self.path
    def claim(self,identifier):
        record=load(self.root/'milestone.json')
        if identifier!=record['run_uuid'] or record['state']!='STARTED':raise Fault('GUARD_RUN_BINDING')
        self.path=self.root/'runs'/identifier
        with store.locked(self.root):
            if (self.path/'execute_claim.json').exists():raise Fault('EXECUTION_ALREADY_CLAIMED')
            self.number=len(list(self.path.glob('[0-9][0-9][0-9]_*.json')))
            durable(self.path/'execute_claim.json',{'utc':utc(),'one_boot':True})
    def event(self,state,**fields):
        target=self.path/f'{self.number+1:03}_{state}.json'
        if target.exists():raise Fault('JOURNAL_OVERWRITE')
        durable(target,dict(utc=utc(),state=state,**fields));self.number+=1
    def reconcile(self,state,**fields):
        if state not in ('FINISHED','FAILED','UNCERTAIN'):raise Fault('TERMINAL_STATE')
        if (self.path/'terminal.json').exists():raise Fault('TERMINAL_IMMUTABLE')
        durable(self.path/'terminal.json',dict(utc=utc(),state=state,**fields))

class Wire:
    """One port, bounded ASCII inbox; RX processed in wire order, no lost batches."""
    def __init__(self,port,clock,records):
        self.port=port;self.clock=clock;self.records=records;self.buf=b'';self.boot=None;self.rx_revision=None
        self.id=0;self.responses=set();self.active=None;self.tx_counts={};self.on_rx=None;self.ingress=None;self.last_session=0
    def next_id(self):self.id+=1;return self.id
    def send(self,line,raw=None,kind=None):
        if not line.startswith('RADIOV7 ') or len(line)>=1024:raise Fault('COMMAND_SHAPE')
        if self.active:raise Fault('TX_BUSY')
        fields=dict(x.split('=',1) for x in line.split() if '=' in x)
        if int(fields['id'])!=self.id or ('boot' in fields and fields['boot']!=self.boot):raise Fault('SEND_BINDING')
        if raw is not None:self.active={'id':self.id,'mac':raw.hex(),'class':kind,'accept':False,'sent_at':self.clock()}
        self.records.append({'kind':'HOST_COMMAND','utc':utc(),'monotonic':self.clock(),'raw':line})
        data=(line+'\n').encode('ascii')
        if self.port.write(data)!=len(data):raise Fault('USB_PARTIAL_WRITE')
    def read(self):
        if hasattr(self.port,'is_open') and not self.port.is_open:raise Fault('USB_DISCONNECTED')
        if b'\n' not in self.buf:
            if not self.buf:self.ingress=self.clock()
            self.buf+=self.port.read(self.port.in_waiting or 1)
        if len(self.buf)>16384:raise Fault('SERIAL_BUFFER_BOUND')
        if b'\n' not in self.buf:return None
        line,_,self.buf=self.buf.partition(b'\n')
        if len(line)>1024:raise Fault('SERIAL_LINE_BOUND')
        raw=line.rstrip(b'\r').decode('ascii');parts=raw.split()
        if len(parts)<2 or parts[0]!='RADIOV7':raise Fault('UNEXPECTED_SERIAL_PROTOCOL')
        f={}
        for token in parts[2:]:
            k,v=token.split('=',1)
            if k in f:raise Fault('DUPLICATE_FIELD')
            f[k]=v
        row={'kind':parts[1],'fields':f,'raw':raw,'utc':utc(),'observed':self.ingress};self.records.append(row)
        if self.boot is None:
            if row['kind']!='INFO':raise Fault('INFO_FIRST')
            self.boot=f['boot']
        if f.get('boot')!=self.boot:raise Fault('BOOT_CHANGED')
        if f.get('rx_drop','0')!='0' or f.get('out_drop','0')!='0':raise Fault('CAPTURE_LOSS')
        if row['kind']=='ERROR':raise Fault('FIRMWARE_ERROR')
        if row['kind']=='RX':
            rev=int(f['revision'])
            if self.rx_revision is not None and rev!=self.rx_revision+1:raise Fault('RX_REVISION_GAP')
            self.rx_revision=rev
            if f.get('channel')!='21' or f.get('fcs_ok')!='1':raise Fault('RX_CONTEXT')
            if self.on_rx:self.on_rx(row)
        elif row['kind'] in ('TXACCEPT','TXDONE'):
            active=self.active
            if not active or int(f['id'])!=active['id'] or f.get('session')!='1':raise Fault('DUPLICATE_OR_UNEXPECTED_RECEIPT')
            if row['kind']=='TXACCEPT':
                if active['accept'] or f.get('mac')!=active['mac'] or f.get('class')!=active['class'] or f.get('retry')!='0':raise Fault('TX_BYTES_OR_CLASS')
                active['accept']=True;self.tx_counts[active['class']]=self.tx_counts.get(active['class'],0)+1
            else:
                if not active['accept']:raise Fault('DONE_WITHOUT_ACCEPT')
                row['completed_at']=self.clock()
                row['host_completion_latency_ms']=(self.clock()-active['sent_at'])*1000
                row['RF_ACK_timing']='not exposed by frozen V7; host latency is not RF timing'
                self.active=None
        elif 'id' in f:
            receipt=(row['kind'],int(f['id']))
            if receipt in self.responses:raise Fault('DUPLICATE_FIRMWARE_RECEIPT')
            self.responses.add(receipt)
            if row['kind'] in ('INFO','STATUS'):
                new=int(f['session'])
                if new not in (0,1) or new<self.last_session:raise Fault('SESSION_CHANGED')
                self.last_session=new
        return row
    def available(self):return b'\n' in self.buf or self.port.in_waiting>0

class Runner:
    def __init__(self,port,root,seed,backend,tc,permit,guard=None,clock=time.monotonic,marker=lambda message:print(message,flush=True)):
        if seed.get('raw_ieee')!=RAW or seed.get('generation')!=0 or seed.get('attempt') is not None or seed.get('state')!='ALLOCATED_UNUSED' or seed.get('ever_secured_tx') or any(k in seed for k in ('next_fc','key_epoch_id','secret_ref')):raise Fault('SEED_BINDING')
        self.root=Path(root);self.clock=clock;self.guard=guard;self.marker=marker;self.phase='PRECHECK'
        self.data={'records':[],'phases':[],'candidate_rejections':[],'primary':None,'recovery_required':True,'RAW':RAW,'hardware':True}
        self.w=Wire(port,clock,self.data['records']);self.h=SingleBoot(self.root/'current',seed,backend,tc,permit,clock)
        self.w.on_rx=self.rx;self.deferred=[];self.timestamps={};self.started=None
    def phase_set(self,name):
        self.phase=name;self.data['phases'].append({'phase':name,'utc':utc(),'monotonic':self.clock()})
    def wait(self,kind,identifier,timeout=3):
        deadline=self.clock()+timeout
        while self.clock()<deadline:
            r=self.w.read()
            if r and r['kind']==kind and int(r['fields'].get('id','-1'))==identifier:return r['fields']
        raise Fault('SERIAL_TIMEOUT')
    def command(self,line,raw=None,kind=None):
        identifier=self.w.id;self.w.send(line,raw,kind);f=self.wait('TXDONE' if raw is not None else 'STATUS',identifier)
        if raw is not None:self.h.local_done(f['result'])
        return f
    def drain_ready(self):
        while self.w.available():self.w.read()
    def until(self,predicate,timeout,reason):
        deadline=self.clock()+timeout
        while not predicate():
            if self.clock()>=deadline:raise Fault(reason)
            self.w.read()
    def rx(self,row):
        f=row['fields'];raw=bytes.fromhex(f['mac']);rev=int(f['revision'])
        if self.h.session is None and (f.get('ack_started')!='0' or f.get('ack_completed')!='0'):raise Fault('UNEXPECTED_PREASSOCIATION_ACK')
        if self.h.stage=='ASSOCIATED_UNKEYED':self.deferred.append(row);return
        if self.phase in ('PASSIVE_OBSERVE','END','RECOVERY'):return
        if self.h.stage=='WAIT_NETWORK_KEY':
            try:m=oracle.Mac.parse(raw)
            except ValueError:m=None
            candidate=m is not None and len(m.payload)>=10 and m.payload[:2]==b'\x48\x00' and m.payload[8]==0x21
            if candidate:
                if f.get('session')!=str(self.h.session):raise Fault('KEY_RX_SESSION')
                if self.clock()-self.h.kp.started>=10:raise Fault('KEY_WINDOW_EXPIRED')
                # Preview uses the SAME explicit TC key and predicate, never try-all.
                # On valid input SingleBoot performs authoritative replay/install.
                ledger=self.h.kp.epoch.replay();preview=Replay(ledger.floors)
                try:validate_transport(Rx(1,self.h.kp.c.attempt,self.h.kp.c.generation,rev,raw),self.h.kp.c,self.h.tc_key,preview)
                except (InvalidTag,ValueError):
                    if preview.floors!=ledger.floors:ledger.save(preview.floors)
                    self.data['candidate_rejections'].append({'revision':rev,'result':'MIC_OR_BINDING_OR_REPLAY_REJECTED'})
                    return
                self.phase_set('KEY_VALIDATE');self.phase_set('KEY_DURABILITY')
        accepted=self.h.receive(raw,rev,f,observed=row['observed'])
        if accepted and self.h.stage=='KEY_INSTALLED':self.timestamps['valid_transport_key']=self.clock()
        if self.h.response and 'association_response' not in self.timestamps:self.timestamps['association_response']=self.h.assoc_response_at
    def execute(self):
        error=None
        try:
            ident=self.w.next_id();self.w.send(f'RADIOV7 INFO id={ident}');info=self.wait('INFO',ident);self.h.attach(info)
            self.w.rx_revision=int(info['rx_revision']);self.data['INFO']=info
            self.phase_set('BASELINE');self.until(lambda:self.h.stage=='BASELINE_READY',20,'BASELINE_ABSENT')
            self.data['baseline']=self.h.baseline.__dict__;self.data['baseline_trace']=self.h.trace
            self.command(self.h.baseline_line(self.w.next_id()))
            self.phase_set('ARM');f=self.command(self.h.arm_line(self.w.next_id()));self.h.arm_ack(f)
            self.data['ARM']=f;self.marker('PERMIT_ARMED: enable selected A7 pairing ONCE now')
            self.phase_set('PERMIT');self.until(lambda:self.h.stage=='PERMIT_READY',90,'PERMIT_ABSENT')
            import dataclasses
            self.data['permit']=dataclasses.asdict(self.h.permit)
            self.phase_set('REASSOCIATION');f=self.command(self.h.begin_line(self.w.next_id()));self.h.begin_ack(f)
            self.started=self.clock();self.command(self.h.request_line(self.w.next_id()),plan.expected_request(RAW),'ASSOCIATION_REQUEST')
            polls=0
            while self.h.response is None:
                self.drain_ready()
                if self.h.response:break
                if self.clock()-self.started>=10:raise Fault('ASSOCIATION_TIMEOUT')
                if self.h.association_poll_due():
                    self.command(self.h.extended_poll_line(self.w.next_id()),plan.expected_poll(RAW,polls),'ASSOCIATION_EXT_POLL');polls+=1
                else:self.w.read()
            response_raw,response_revision,response_ack=self.h.response
            confirmations=[r for r in self.data['records'] if r['kind']=='RESPONSE' and int(r['fields']['revision'])==response_revision]
            if len(confirmations)!=1:raise Fault('RESPONSE_REVISION_BINDING')
            rf=confirmations[0]['fields']
            if rf.get('session')!='1' or rf.get('status')!='0' or int(rf['assigned_short'],16)!=int.from_bytes(response_raw[22:24],'little') or (rf.get('ack_started'),rf.get('ack_completed'),rf.get('deadline_miss'))!=('1','1','0'):raise Fault('RESPONSE_REVISION_BINDING')
            self.data['bound_response_revision']=response_revision
            self.phase_set('SHORT_COMMIT');line=self.h.commit_line(self.w.next_id());self.timestamps['short_durable_commit']=self.clock()
            self.data['association']=self.h.provision.read();f=self.command(line);self.h.commit_ack(f);self.timestamps['assoc_commit_ack']=self.clock()
            deferred=self.deferred;self.deferred=[]
            for row in deferred:self.rx(row)
            self.phase_set('KEY_POLL')
            while self.h.stage=='WAIT_NETWORK_KEY':
                self.drain_ready()
                if self.h.stage!='WAIT_NETWORK_KEY':break
                elapsed=self.clock()-self.h.kp.started
                if elapsed>=10:raise Fault('KEY_NOT_RECEIVED')
                if self.h.kp.polls<8 and (self.h.kp.last_poll is None or self.clock()-self.h.kp.last_poll>=.501):
                    line=self.h.poll_line(self.w.next_id())
                    if 'first_key_poll' not in self.timestamps:self.timestamps['first_key_poll']=self.clock()
                    self.command(line,short_poll(self.h.kp.c,224+self.h.kp.polls-1),'POST_ASSOC_KEY_POLL')
                else:self.w.read()
            self.phase_set('KEY_DURABILITY');f=self.command(self.h.key_line(self.w.next_id()));self.h.key_ack(f)
            self.phase_set('FC_RESERVE');self.phase_set('ANNOUNCE_BUILD');self.data['self_check']=self.h.build()
            self.phase_set('ANNOUNCE_HANDOFF');line=self.h.announce_line(self.w.next_id());self.data['intent']=self.h.kp.intent
            self.command(line,self.h.kp.raw,'DEVICE_ANNOUNCE');self.data['primary']='A SINGLE-BOOT NETWORK KEY + ANNOUNCE PASS'
            self.phase_set('PASSIVE_OBSERVE');deadline=self.clock()+10
            while self.clock()<deadline:self.w.read()
        except Exception as exc:
            error=exc;code=exc.args[0] if isinstance(exc,Fault) else type(exc).__name__
            self.data['failure']={'phase':self.phase,'code':code}
            if self.h.kp and self.h.kp.sent:self.data['primary']='E SECURED ANNOUNCE INCONCLUSIVE'
            elif self.phase=='KEY_DURABILITY':self.data['primary']='D KEY DURABILITY FAIL'
            elif self.phase in ('KEY_POLL','KEY_VALIDATE'):
                self.data['primary']='C TRANSPORT KEY REJECTED' if self.data['candidate_rejections'] else 'B TRANSPORT KEY NOT RECEIVED'
            elif self.phase in ('REASSOCIATION','SHORT_COMMIT'):self.data['primary']='F ASSOCIATION FAILED'
            else:self.data['primary']='G PRECONDITION STOP'
            if isinstance(exc,Fault) and code in ('BOOT_CHANGED','SESSION_CHANGED','KEY_RX_SESSION','RESPONSE_REVISION_BINDING','TX_BYTES_OR_CLASS','DUPLICATE_OR_UNEXPECTED_RECEIPT','DUPLICATE_FIRMWARE_RECEIPT','CAPTURE_LOSS','RX_REVISION_GAP','UNEXPECTED_PREASSOCIATION_ACK'):self.data['primary']='H SAFETY FAIL'
        finally:
            self.phase_set('END')
            try:
                if self.w.boot:
                    session=self.h.session or self.w.last_session
                    f=self.command(f'RADIOV7 END id={self.w.next_id()} boot={self.w.boot} session={session}')
                    if f.get('pending')!='0' or f.get('immediate_ack')!='0' or f.get('state')!='STOPPED':raise Fault('END_NOT_TERMINAL')
                    self.data['terminal_STATUS']=f
            except Exception as exc:self.data['END_failure']={'type':type(exc).__name__}
            self.phase_set('RECOVERY');self.data['timestamps']=self.timestamps;self.data['timings']=self.h.timings() if self.h.assoc_response_at is not None else {}
            self.data['tx_counts']=self.w.tx_counts;self.data['next_protocol_state']='MANAGEMENT_PENDING' if self.data['primary'].startswith('A ') else 'STOP'
            if self.h.kp and self.h.kp.epoch.path.exists():self.data['public_epoch']=self.h.kp.epoch.read()
            if self.data.get('END_failure') and self.data['primary'].startswith('A '):
                self.data['primary']='H SAFETY FAIL';self.data['next_protocol_state']='STOP'
            try:
                self.root.mkdir(parents=True,exist_ok=True);durable(self.root/'outcome.json',self.data)
                if self.guard:self.guard.event('UNCERTAIN',primary=self.data['primary'],recovery_required=True)
            except Exception as exc:self.data['journal_failure']={'type':type(exc).__name__}
            finally:self.marker('RESTORE_V17_REQUIRED: no retry; original pairs must be physically confirmed')
        return self.data
