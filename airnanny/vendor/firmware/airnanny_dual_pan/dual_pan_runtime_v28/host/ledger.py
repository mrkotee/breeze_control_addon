"""Retained-epoch security authority. No serial/RF or implicit real-state access."""
import sys,hashlib,uuid,copy
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(R/'host'))
import recovery_model as base
from recovery_model import RAW,TC,EPOCH,ATTEMPT,le,ieee,encrypt,decode_nwk,Secret,store,durable,load,Fault
from discovery import DiscoveryEvidence,FRESH_US,RESPONSE_US
PREVIOUS='3411be0b68c840239dc78b46c2732d1e'
GATE_ROOT=R/'.local/peer_scope_gate_v1'
class Ledger(base.Model):
    def __init__(self,root,key,guard,save=durable,simulation=True,predecessor=PREVIOUS,initial_generation=13,initial_min_fc=672,initial_short=0x6c55):
        self.root=Path(root).resolve();self.path=self.root/'epoch.json';self.key=key;self.guard=guard;self.save=save
        if simulation:
            if not self.root.is_relative_to((R/'.local/tests').resolve()):raise Fault('simulation_NO_REAL_AUTHORITY')
        else:raise Fault('OFFLINE_ONLY_no_hardware_authority')
        self.predecessor=predecessor;self.initial_generation=initial_generation;self.initial_min_fc=initial_min_fc;self.initial_short=initial_short
        self.failed=bool(self.read().get('recovery') and self.read()['recovery'].get('gate')!=self.predecessor);self.events=[];self.revisions=set();self.baseline=None
        self.check(self.read())
        self.scope_counts={'foreign_status_fresh':0,'foreign_status_duplicate':0,'foreign_peer_fresh':0,'foreign_peer_duplicate':0,'foreign_peer_control_fresh':0,'foreign_peer_control_duplicate':0}
    def check(self,r):
        c=r['context']
        if (r['key_epoch_id']!=EPOCH or r['keyseq']!=0 or r['next_fc']<32 or r['next_fc']>0xffffffff or
            r['state']!='MANAGEMENT_PENDING' or c['ctx']!=1 or c['attempt']!=ATTEMPT or c['raw_ieee']!=RAW or
            c['tc_ieee']!=TC or c['pan']!=0x0b7a or c['channel']!=21 or not base.valid_short(c['short']) or
            r['management_blocker']['leave_options']!=0x60 or r['nwk_source_floors'].get(TC,0)<=2462210):raise Fault('retained_epoch_context')
        q=r.get('recovery',{})
        if not 6<=r['generation']<0xffffffff:raise Fault('generation_continuity')
        if q.get('gate')==self.predecessor:
            if r['generation']!=self.initial_generation or r['next_fc']<self.initial_min_fc or c['short']!=self.initial_short:raise Fault('reviewed_generation7_start')
        elif q.get('gate')!=self.guard:
            if q or r['generation']!=self.initial_generation or r['next_fc']<self.initial_min_fc or c['short']!=self.initial_short:raise Fault('recovery_lineage')
        for entry in r.get('recovery_history',[]):
            if entry['gate']==self.guard:raise Fault('historical_guard_NO_RERUN')
    def baseline_receive(self,raw,observed):
        from management import ordinary
        try:m,p,meta=decode_nwk(raw,self.key)
        except Exception:return
        try:self.consume(meta['source_ieee'],meta['counter'])
        except Fault as exc:
            if str(exc)=='NWK_replay':return
            raise
        if meta['source_ieee']==TC and meta['nwk_src']==0 and m.src==le(0) and ordinary(p):
            self.baseline={'observed':observed,'fc':meta['counter'],'keyseq':meta['keyseq'],'source':TC}
    def begin_discovery(self,now):
        if not self.baseline or not 0<=now-self.baseline['observed']<=5:raise Fault('fresh_authenticated_parent_baseline_required')
        def mutate(r):
            previous=r.get('recovery')
            if previous is None:
                previous={'gate':self.predecessor,'state':'SEALED_AUTHENTICATED_LEAVE','NWK_FC':r['management_blocker']['NWK_FC']}
            if previous.get('gate')!=self.predecessor or self.guard==self.predecessor:raise Fault('NO_RERUN')
            r.setdefault('recovery_history',[]).append(copy.deepcopy(previous))
            dsn=r['sequences']['dsn'];r['sequences']['dsn']=(dsn+1)&255
            r['recovery']={'state':'DISCOVERING','gate':self.guard,'started':now,'old_short':r['context']['short'],
                'scan_dsn':dsn,'intents':{},'polls':[],'proofs':[],'original_blocker_preserved':True,'baseline':self.baseline,
                'initial_generation':r['generation'],'predecessor':self.predecessor,'epoch':EPOCH}
        r=self.change(mutate);return r['recovery']['scan_dsn']
    def prepare(self,evidence,now_us):
        if not isinstance(evidence,DiscoveryEvidence):raise Fault('typed_discovery_required')
        def mutate(r):
            q=r['recovery']
            if q['state']!='DISCOVERING' or evidence.guard!=self.guard or not evidence.time_us<=now_us<=evidence.time_us+FRESH_US:raise Fault('one_shot_discovery_binding')
            q.update(state='REJOIN_PREPARED',discovery=evidence.public())
        self.change(mutate)
    def _build(self,kind):
        expected={'REJOIN':'REJOIN_PREPARED','ANNOUNCE':'REJOINED','TIMEOUT':'ANNOUNCED'}
        if kind not in expected:raise Fault('NO_GENERIC_OR_TYPE07')
        def reserve(r):
            q=r['recovery']
            if q['state']!=expected[kind] or kind in q['intents']:raise Fault('one_shot_state')
            if kind!='REJOIN' and q.get('firmware_current_short_commit_required',True):raise Fault('short_receipt_required')
            fc=r['next_fc'];seq=dict(r['sequences'])
            if fc+31>0xfffffffe:raise Fault('FC_exhaustion')
            r['next_fc']=fc+32
            r['sequences']['nwk']=(seq['nwk']+1)&255
            r['sequences']['dsn']=(seq['dsn']+(6 if kind in ('REJOIN','TIMEOUT') else 1))&255
            if kind=='ANNOUNCE':
                for name in ('aps','zdo'):r['sequences'][name]=(seq[name]+1)&255
            q['intents'][kind]={'fc':fc,'block_end':fc+31,'sequences':seq,'short':r['context']['short'],
                'phase':'BURNED_BEFORE_CRYPTO','token':uuid.uuid4().hex,'epoch':EPOCH,'keyseq':0,
                'generation':r['generation'],'gate':self.guard}
        r=self.change(reserve);i=r['recovery']['intents'][kind];seq=i['sequences'];short=i['short'];fc=i['fc']
        mac=b'\x61\x88'+bytes([seq['dsn']])+le(0x0b7a)+le(0)+le(short)
        if kind=='ANNOUNCE':
            h=b'\x08\x02'+le(0xfffd)+le(short)+b'\x3c'+bytes([seq['nwk']])
            p=b'\x08\0\x13\0\0\0\0'+bytes([seq['aps'],seq['zdo']])+le(short)+ieee(RAW)+b'\x80'
        else:
            h=b'\x09\x1a'+le(0)+le(short)+b'\x01'+bytes([seq['nwk']])+ieee(TC)+ieee(RAW)
            p=b'\x06\x80' if kind=='REJOIN' else b'\x0b\x08\0'
        try:
            raw=mac+encrypt(h,b'\x28'+le(fc,4)+ieee(RAW)+b'\0',p,self.key)
            _,plain,meta=decode_nwk(raw,self.key)
            if plain!=p or meta['counter']!=fc or meta['source_ieee']!=RAW or len(raw)!={'REJOIN':53,'ANNOUNCE':55,'TIMEOUT':54}[kind]:raise Fault('self_check')
        except Exception:self.failed=True;raise
        def built(r):
            j=r['recovery']['intents'][kind]
            if j['token']!=i['token'] or j['phase']!='BURNED_BEFORE_CRYPTO' or j['generation']!=r['generation'] or j['gate']!=self.guard:raise Fault('intent_lineage')
            j.update(phase='BUILT_NEVER_RETRY',sha256=hashlib.sha256(raw).hexdigest())
        self.change(built);return raw,fc
    def tx_result(self,kind,result,radio_end_us):
        super().tx_result(kind,result,radio_end_us/1e6)
        if result!='local_tx_ok':raise Fault('unknown_or_failed_TX_burned')
        if kind in ('REJOIN','TIMEOUT'):
            def stamp(r):
                q=r['recovery'];q['intents'][kind]['handed_at']=radio_end_us/1e6
                q['response_deadline']=(radio_end_us+RESPONSE_US)/1e6
                q['radio_window']={'kind':kind,'start_us':radio_end_us,'deadline_us':radio_end_us+RESPONSE_US,'accepted':0}
            self.change(stamp)
    def auto_poll(self,raw,number,time_us,pending,dsn):
        def mutate(r):
            q=r['recovery'];w=q['radio_window'];i=q['intents'][w['kind']]
            expected=(i['sequences']['dsn']+number)&255
            if not 1<=number<=5 or number!=w['accepted']+1 or dsn!=expected or raw!=b'\x63\x88'+bytes([expected])+le(0x0b7a)+le(0)+le(i['short'])+b'\x04':raise Fault('auto_poll_bytes_sequence')
            due=w['start_us']+50000+(number-1)*100000
            if not due<=time_us<=due+20000 or time_us>=w['deadline_us']:raise Fault('auto_poll_radio_deadline')
            w['accepted']=number
            if pending:q['polls'].append({'at':time_us/1e6,'dsn':dsn,'short':i['short'],'period':.1,'pending_ACK':True})
        self.change(mutate)
    def reserve_idle_poll(self,now):
        def mutate(r):
            q=r['recovery']
            if q['state'] not in ('PARENT_LINK_ACTIVE','APPLICATION_TEST_READY'):raise Fault('idle_parent_not_active')
            dsn=r['sequences']['dsn'];r['sequences']['dsn']=(dsn+1)&255
            previous=q.get('last_idle_intent')
            if previous and previous.get('phase') not in ('LOCAL_MAC_ACK','CCA_SKIP_PREAIR'):raise Fault('unknown_poll_NO_RETRY')
            q['last_idle_intent']={'dsn':dsn,'at':now,'short':r['context']['short'],'generation':r['generation'],'gate':self.guard,'phase':'HANDED_NO_RETRY'}
        r=self.change(mutate);i=r['recovery']['last_idle_intent']
        return b'\x63\x88'+bytes([i['dsn']])+le(0x0b7a)+le(0)+le(i['short'])+b'\x04'
    def idle_result(self,dsn,result,receipt):
        def mutate(r):
            i=r['recovery']['last_idle_intent']
            if i['dsn']!=dsn or i['generation']!=r['generation'] or i['gate']!=self.guard or i['phase']!='HANDED_NO_RETRY':raise Fault('poll_receipt_lineage')
            if result!='local_tx_ok':raise Fault('terminal_MAC_failure_no_retry')
            phase='LOCAL_MAC_ACK'
            i.update(phase=phase,result=result,receipt=dict(receipt))
        self.change(mutate)
    def observation_complete(self,policy):
        if policy['seconds']<60 or policy['success_ACK_polls']<40 or policy['cca_skips']>5 or not all(policy['success_per_10s']) or policy.get('complete') is not True:raise Fault('continuous_60s_health_required')
        self.change(lambda r:r['recovery'].update(observation=policy))
    def ready(self,firmware_short_committed=False,drops=0,unauthorized_tx=0):
        r=self.usable();q=r['recovery'];proofs=q.get('proofs',[])
        valid=(q['state']=='PARENT_LINK_ACTIVE' and firmware_short_committed and not drops and not unauthorized_tx and
               q.get('observation',{}).get('complete') and len(proofs)==2 and proofs[0]['fc']<proofs[1]['fc'] and
               all(p['clean_ack'] for p in proofs) and not q.get('firmware_current_short_commit_required',True))
        # APPLICATION_TEST_READY is deferred until END + V17 + physical health.
        if valid:self.change(lambda r:r['recovery'].update(readiness_candidate=True))
        return bool(valid)
    def receive(self,*args,**kwargs):
        # Only exact MIC-authenticated TC status or the known peer's group
        # control uplink can take this path. RAW-addressed and ambiguous frames
        # retain inherited checks. Fresh foreign FC consumes the global floor.
        from context_scope import foreign_status,foreign_peer_group_control
        from peer_type07_scope import foreign_peer_type07
        r=self.usable()
        other=foreign_status(args[0],self.key,r['keyseq'],r['context']['short'])
        scope='foreign_status'
        if other is None:
            other=foreign_peer_group_control(args[0],self.key,r['keyseq'],r['context']['short'])
            scope='foreign_peer'
        if other is None:
            other=foreign_peer_type07(args[0],self.key,r['keyseq'],r['context']['short'])
            scope='foreign_peer_control'
        if other is not None:
            try:self.consume(other['source_ieee'],other['counter'])
            except Fault as exc:
                if str(exc)=='NWK_replay' and other['counter']<0xffffffff:
                    self.scope_counts[scope+'_duplicate']+=1
                    return 'AUTHENTICATED_OTHER_CONTEXT_DUPLICATE'
                raise
            self.events.append({'revision':args[1],'source':other['source_ieee'],'fc':other['counter'],'MIC_PASS':True,'classification':'OTHER_CONTEXT'})
            self.scope_counts[scope+'_fresh']+=1
            return 'AUTHENTICATED_OTHER_CONTEXT'
        result=super().receive(*args,**kwargs)
        if result=='UNIMPLEMENTED_AUTHENTICATED_TRAFFIC':
            from management import ordinary
            _,p,_=decode_nwk(args[0],self.key)
            if ordinary(p):return 'RAW_ORDINARY'
            raise Fault('unimplemented_addressed_management_STOP')
        return result
