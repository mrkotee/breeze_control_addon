"""Offline recovery reference model. NO live authority, serial, RF or key loader.

The constructor accepts only a disposable synthetic store underneath this
sibling's .local/tests. It cannot reserve a counter or alter the installed epoch.
This is a protocol model, not a hardware-ready implementation.
"""
import sys, json, hashlib, uuid
from pathlib import Path
R = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(R/'host'))
from management import (RAW, TC, EPOCH, ATTEMPT, RUN, CURRENT, RUN_ROOT,
                        oracle, Secret, encrypt, decode_nwk, ieee, le, store, durable)
FAST_POLL_SECONDS = .100
RESPONSE_WAIT_SECONDS = 32 * 960 * 16e-6
FIRST_POLL_SECONDS = .050
IDLE_POLL_SECONDS = 1.0
TIMEOUT_ENUM = 8
TIMEOUT_SECONDS = 15360
CONFIGURATION = 0
MAX_RUN_SECONDS = 360
TERMINAL = {'REJECTED', 'NO_RESPONSE', 'LEAVE_REPEATED', 'SECURITY_FAIL', 'DURABILITY_FAIL', 'TX_UNKNOWN', 'STOPPED'}
BLOCKED = 'MANAGEMENT_BLOCKED_BY_LEAVE'

class Fault(ValueError): pass

def load(path): return json.loads(Path(path).read_text(encoding='utf-8'))
def valid_short(value): return type(value) is int and 0 < value < 0xfff8
def clean_ack(ack):
    return ack is not None and all(ack.get(k) == v for k, v in
        [('ack_started', '1'), ('ack_completed', '1'), ('deadline_miss', '0')])

def legacy_beacon(raw):
    """Exact legacy coordinator layout; Appendix/other layouts stop for review.

    This parser alone DOES NOT establish a fresh discovery result. Source short0
    and Extended PAN ID are unauthenticated hints; a current authenticated parent
    baseline and a completed active scan are separate future live prerequisites.
    """
    m = oracle.Mac.parse(raw)
    if m.fcf != 0x8000 or m.src_pan != le(0x0b7a) or m.src != le(0):
        raise Fault('beacon_context')
    p = m.payload
    if len(p) != 19: raise Fault('appendix_or_unsupported_beacon_layout')
    if p[2:4] != b'\0\0' or p[4:6] != b'\0\x22' or p[7:15] != ieee(TC):
        raise Fault('beacon_profile_version_extpan_or_MAC_lists')
    if p[6] & 0x7b or not p[6] & 0x80:
        raise Fault('beacon_reserved_depth_or_no_child_capacity')
    return {'mechanism': 'SECURED_NWK_REJOIN_LEGACY', 'pan': 0x0b7a,
            'channel': 21, 'parent_short': 0, 'extpan': TC,
            'appendix_present': False, 'beacon_sha256': hashlib.sha256(raw).hexdigest()}

class Model:
    def __init__(self, root, key, save=durable):
        root = Path(root).resolve()
        allowed = (R/'.local/tests').resolve()
        if not root.is_relative_to(allowed) or root == allowed:
            raise Fault('synthetic_disposable_store_only_NO_REAL_AUTHORITY')
        self.root = root; self.path = root/'epoch.json'; self.key = key; self.save = save
        # A model session never resumes after a crash, even if a prior atomic
        # write succeeded before the caller observed failure. Readback is allowed;
        # all subsequent sends are denied in a restarted session.
        self.failed = bool(self.read().get('recovery'))
        self.events = []; self.revisions = set()
        self.check(self.read())
    def read(self): return load(self.path)
    def check(self, r):
        c = r['context']
        if (r.get('fixture') != 'SYNTHETIC_ONLY' or r['key_epoch_id'] != EPOCH or
            c['raw_ieee'] != RAW or c['tc_ieee'] != TC or c['attempt'] != ATTEMPT or
            c['pan'] != 0x0b7a or c['channel'] != 21 or c['ctx'] != 1 or
            r['keyseq'] != 0 or not valid_short(c['short']) or r['next_fc'] < 32):
            raise Fault('epoch_context')
    def write(self, r):
        try:
            result = self.save(self.path, r)
            if result is False or self.read() != r:
                raise OSError('durable_readback_mismatch')
        except Exception:
            self.failed = True
            raise Fault('DURABILITY_FAIL_no_further_TX') from None
    def usable(self):
        if self.failed: raise Fault('DURABILITY_FAIL_no_further_TX')
        r = self.read(); self.check(r)
        if r.get('recovery', {}).get('state') in TERMINAL: raise Fault('terminal_NO_RERUN')
        return r
    def change(self, fn):
        with store.locked(self.root):
            r = self.usable(); fn(r); self.write(r)
            return r
    def prepare(self, discovery, gate, now=0):
        if (discovery.get('active_scan_completed') is not True or
            discovery.get('fresh_current_authenticated_parent') is not True or
            discovery.get('mechanism') != 'SECURED_NWK_REJOIN_LEGACY' or
            discovery.get('appendix_present') is not False or
            discovery.get('pan') != 0x0b7a or discovery.get('channel') != 21 or
            discovery.get('parent_short') != 0 or discovery.get('extpan') != TC):
            raise Fault('fresh_completed_discovery_and_current_key_required')
        if len(gate) != 32 or any(x not in '0123456789abcdef' for x in gate): raise Fault('gate')
        def mutate(r):
            if r.get('recovery'): raise Fault('one_recovery_model_NO_RERUN')
            b = r['management_blocker']
            if (b['source_ieee'] != TC or b['leave_options'] != 0x60 or
                r['nwk_source_floors'].get(TC, 0) <= b['NWK_FC']): raise Fault('consumed_parent_Leave_required')
            r['recovery'] = {'state': 'REJOIN_PREPARED', 'gate': gate,
                'old_short': r['context']['short'], 'started': now,
                'discovery': discovery, 'intents': {}, 'polls': [], 'proofs': [],
                'original_blocker_preserved': True}
        self.change(mutate)
    def _build(self, kind):
        expected = {'REJOIN': 'REJOIN_PREPARED', 'ANNOUNCE': 'REJOINED', 'TIMEOUT': 'ANNOUNCED'}
        if kind not in expected: raise Fault('typed_allowlist_NO_TYPE07_OR_GENERIC_TX')
        def reserve(r):
            q = r['recovery']
            if q['state'] != expected[kind] or kind in q['intents']: raise Fault('one_shot_state')
            if kind != 'REJOIN' and q.get('firmware_current_short_commit_required',True):
                raise Fault('firmware_current_short_receipt_required')
            fc = r['next_fc']
            if fc + 31 > 0xfffffffe: raise Fault('FC_exhaustion')
            seq = dict(r['sequences'])
            r['next_fc'] = fc + 32
            # Advance only the sequences used by this exact envelope.
            for name in ('nwk', 'dsn') + (('aps', 'zdo') if kind == 'ANNOUNCE' else ()):
                r['sequences'][name] = (seq[name] + 1) & 255
            q['intents'][kind] = {'fc': fc, 'block_end': fc+31, 'sequences': seq,
                'phase': 'BURNED_BEFORE_CRYPTO', 'token': uuid.uuid4().hex,
                'short': r['context']['short'], 'epoch': r['key_epoch_id'], 'keyseq': r['keyseq']}
        r = self.change(reserve); i = r['recovery']['intents'][kind]
        seq = i['sequences']; short = i['short']; fc = i['fc']
        mac = b'\x61\x88'+bytes([seq['dsn']])+le(0x0b7a)+le(0)+le(short)
        if kind == 'ANNOUNCE':
            h = b'\x08\x02'+le(0xfffd)+le(short)+b'\x3c'+bytes([seq['nwk']])
            plain = b'\x08\0\x13\0\0\0\0'+bytes([seq['aps'], seq['zdo']])+le(short)+ieee(RAW)+b'\x80'
        else:
            h = b'\x09\x1a'+le(0)+le(short)+b'\x01'+bytes([seq['nwk']])+ieee(TC)+ieee(RAW)
            plain = b'\x06\x80' if kind == 'REJOIN' else b'\x0b\x08\0'
        aux = b'\x28'+le(fc,4)+ieee(RAW)+bytes([r['keyseq']])
        try:
            raw = mac + encrypt(h, aux, plain, self.key)
            _, p, meta = decode_nwk(raw, self.key, r['keyseq'])
            if (p != plain or meta['source_ieee'] != RAW or meta['counter'] != fc or
                len(raw) != {'REJOIN':53, 'ANNOUNCE':55, 'TIMEOUT':54}[kind]): raise Fault('crypto_self_check')
        except Exception:
            self.failed = True
            raise
        def built(r):
            j = r['recovery']['intents'][kind]
            if j['token'] != i['token'] or j['phase'] != 'BURNED_BEFORE_CRYPTO': raise Fault('intent_binding')
            j.update(phase='BUILT_NEVER_RETRY', sha256=hashlib.sha256(raw).hexdigest())
        self.change(built)
        return raw, fc
    def build_rejoin(self): return self._build('REJOIN')
    def build_announce(self): return self._build('ANNOUNCE')
    def build_timeout(self): return self._build('TIMEOUT')
    def confirm_short_install(self, short, generation):
        """Synthetic receipt check only; no command or hardware action occurs."""
        def mutate(r):
            q=r['recovery']
            if (q['state']!='REJOINED' or not q['firmware_current_short_commit_required'] or
                short!=r['context']['short'] or generation!=r['generation']):
                raise Fault('firmware_current_short_receipt_binding')
            q.update(firmware_current_short_commit_required=False,
                     short_install_receipt={'short':short,'generation':generation})
        self.change(mutate)
    def handoff(self, kind, now):
        def mutate(r):
            q = r['recovery']; i = q['intents'][kind]
            if i['phase'] != 'BUILT_NEVER_RETRY': raise Fault('NO_RETRANSMISSION')
            i.update(phase='HANDED_NO_RETRY', handed_at=now)
            if kind in ('REJOIN', 'TIMEOUT'):
                q.update(state='REJOIN_REQUEST_SENT' if kind == 'REJOIN' else 'TIMEOUT_NEGOTIATION',
                         response_deadline=now+RESPONSE_WAIT_SECONDS)
        self.change(mutate)
    def tx_result(self, kind, result, now):
        def mutate(r):
            q = r['recovery']; i = q['intents'][kind]
            if i['phase'] != 'HANDED_NO_RETRY': raise Fault('receipt_binding')
            i.update(phase='LOCAL_MAC_ACK' if result == 'local_tx_ok' else 'UNKNOWN_OR_FAILED_BURNED', result=result)
            if result != 'local_tx_ok': q['state'] = 'TX_UNKNOWN'
            elif kind == 'ANNOUNCE': q['state'] = 'ANNOUNCED'
            # Rejoin/timeout MAC ACK by itself never advances membership/lifetime.
        self.change(mutate)
    def poll(self, now):
        def mutate(r):
            q = r['recovery']; phase = q['state']; polls = q['polls']
            if phase not in ('REJOIN_REQUEST_SENT','REJOINED','ANNOUNCED','TIMEOUT_NEGOTIATION','PARENT_LINK_ACTIVE','APPLICATION_TEST_READY'):
                raise Fault('poll_state')
            if now < q['started'] or now-q['started'] >= MAX_RUN_SECONDS: raise Fault('bounded_session')
            if phase in ('REJOIN_REQUEST_SENT','TIMEOUT_NEGOTIATION') and now >= q['response_deadline']:
                raise Fault('response_window_expired')
            period = IDLE_POLL_SECONDS if phase in ('PARENT_LINK_ACTIVE','APPLICATION_TEST_READY') else FAST_POLL_SECONDS
            if polls and now-polls[-1]['at'] < period-1e-9: raise Fault('poll_rate_bound')
            if len(polls) >= 160: raise Fault('poll_count_bound')
            dsn = r['sequences']['dsn']; r['sequences']['dsn'] = (dsn+1)&255
            polls.append({'at':now,'dsn':dsn,'short':r['context']['short'],'period':period})
        r = self.change(mutate); p = r['recovery']['polls'][-1]
        return b'\x63\x88'+bytes([p['dsn']])+le(0x0b7a)+le(0)+le(p['short'])+b'\x04'
    def consume(self, source, fc):
        def mutate(r):
            if fc < r['nwk_source_floors'].get(source,0) or fc >= 0xffffffff: raise Fault('NWK_replay')
            r['nwk_source_floors'][source] = fc+1
        self.change(mutate)
    def receive(self, raw, revision, now, ack=None, indirect_poll_dsn=None):
        r = self.usable()
        try: m, p, meta = decode_nwk(raw, self.key, r['keyseq'])
        except (ValueError, AssertionError): return 'AUTH_REJECTED'
        except Exception as exc:
            from cryptography.exceptions import InvalidTag
            if isinstance(exc, InvalidTag): return 'AUTH_REJECTED'
            raise
        try: self.consume(meta['source_ieee'], meta['counter'])
        except Fault as exc:
            if str(exc) == 'NWK_replay': return 'REPLAY_REJECTED'
            raise
        r = self.read(); short = r['context']['short']; q = r.get('recovery',{})
        self.events.append({'revision':revision,'source':meta['source_ieee'],'fc':meta['counter'], 'MIC_PASS':True})
        addressed = (m.fcf == 0x8861 and m.src == le(0) and m.dst == le(short) and
            meta['nwk_src'] == 0 and meta['nwk_dst'] == short and meta['source_ieee'] == TC)
        if not addressed: return 'AUTHENTICATED_OTHER_CONTEXT'
        if meta['nwk_fcf'] & 3 == 1 and len(p) == 2 and p[0] == 4:
            def leave(r):
                q = r.get('recovery')
                if q:
                    q.update(state='LEAVE_REPEATED', leave={'revision':revision,'fc':meta['counter'],'options':p[1]})
                else: r['management_blocker'] = dict(state=BLOCKED,source_ieee=TC,NWK_FC=meta['counter'],leave_options=p[1])
            self.change(leave); return 'LEAVE_REPEATED' if q else BLOCKED
        if meta['nwk_fcf'] != 0x1a09 or m.payload[8:16] != ieee(RAW) or m.payload[16:24] != ieee(TC):
            return 'UNIMPLEMENTED_AUTHENTICATED_TRAFFIC'
        if not clean_ack(ack): raise Fault('MAC_ACK_not_clean')
        if revision in self.revisions: raise Fault('RX_revision_reused')
        self.revisions.add(revision)
        if not q or q['state'] not in ('REJOIN_REQUEST_SENT','TIMEOUT_NEGOTIATION'): return 'UNSOLICITED_RESPONSE_IGNORED'
        if now >= q['response_deadline']: self.expire(now); return 'NO_RESPONSE'
        kind = 'REJOIN' if q['state']=='REJOIN_REQUEST_SENT' else 'TIMEOUT'
        if q['intents'][kind]['phase'] != 'LOCAL_MAC_ACK': raise Fault('request_receipt_required')
        polls = q['polls']
        if not any(x['dsn']==indirect_poll_dsn and x['at']<=now and x['at']>=q['intents'][kind]['handed_at'] for x in polls):
            raise Fault('queued_response_requires_current_poll_proof')
        if kind == 'REJOIN':
            if len(p)!=4 or p[0]!=7: return 'UNIMPLEMENTED_AUTHENTICATED_TRAFFIC'
            newshort = int.from_bytes(p[1:3],'little'); status=p[3]
            if status != 0:
                self.change(lambda r:r['recovery'].update(state='REJECTED', rejoin_status=status)); return 'REJECTED'
            if not valid_short(newshort): raise Fault('success_with_invalid_current_short')
            def commit(r):
                # Response, new current address and membership state in ONE atomic file.
                r['context']['short']=newshort; r['context']['generation']=r['context'].get('generation',4)+1
                r['generation']+=1
                r['recovery'].update(state='REJOINED', current_short=newshort,
                    rejoin_response={'revision':revision,'fc':meta['counter'],'status':0,'clean_ack':True},
                    firmware_current_short_commit_required=True)
            self.change(commit); return 'REJOINED'
        if len(p)!=3 or p[0]!=12: return 'UNIMPLEMENTED_AUTHENTICATED_TRAFFIC'
        if p[1]!=0 or p[2]&0xf8 or not p[2]&3:
            self.change(lambda r:r['recovery'].update(state='REJECTED', timeout_status=p[1],parent_information=p[2])); return 'TIMEOUT_REJECTED'
        if not p[2]&1:
            # Timeout-request keepalive is normative, but unimplemented by this
            # one-shot model. Never falsely claim that data polls refresh it.
            self.change(lambda r:r['recovery'].update(state='REJECTED',parent_information=p[2],reason='EDT_keepalive_backend_missing'))
            return 'KEEPALIVE_METHOD_UNIMPLEMENTED'
        def active(r):
            r['recovery'].update(state='PARENT_LINK_ACTIVE',lifetime={'enum':8,'configuration':0,
                'seconds':15360,'parent_information':p[2],'keepalive_method':'MAC_DATA_POLL',
                'idle_poll_seconds':IDLE_POLL_SECONDS,'keepalive_ceiling_seconds':TIMEOUT_SECONDS/3,
                'response_revision':revision,'response_fc':meta['counter']})
            r['recovery']['proofs']=[r['recovery']['rejoin_response'],
                {'revision':revision,'fc':meta['counter'],'status':0,'clean_ack':True,'indirect_poll_dsn':indirect_poll_dsn}]
        self.change(active); return 'PARENT_LINK_ACTIVE'
    def expire(self, now):
        def mutate(r):
            q = r['recovery']
            if q['state'] in ('REJOIN_REQUEST_SENT','TIMEOUT_NEGOTIATION') and now >= q['response_deadline']:
                q['state']='NO_RESPONSE'
        self.change(mutate)
    def ready(self, firmware_short_committed=False, drops=0, unauthorized_tx=0):
        r = self.usable(); q = r.get('recovery',{})
        if q.get('state') != 'PARENT_LINK_ACTIVE' or not firmware_short_committed or drops or unauthorized_tx: return False
        proofs=q.get('proofs',[])
        # Stronger protocol-specific proof: two authenticated responses to own
        # requests, the second retrieved indirectly to the committed current short.
        if len(proofs)!=2 or proofs[0]['fc']>=proofs[1]['fc'] or not all(p['clean_ack'] for p in proofs): return False
        self.change(lambda r:r['recovery'].update(state='APPLICATION_TEST_READY',firmware_current_short_commit_required=False))
        return True
