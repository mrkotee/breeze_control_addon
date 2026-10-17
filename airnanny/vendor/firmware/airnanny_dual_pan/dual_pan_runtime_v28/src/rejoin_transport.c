/* Crypto-blind recovery transport; only host validates MIC and semantics. */
#include "management.h"
#include "dual_identity.h"
#include "radio_wire.h"
#include <string.h>
/* Bit 13 of the field mask, matching the position of "ctx" in names[]. */
#define CTX_BIT 8192u
static uint16_t u16(const uint8_t *p){return p[0]|(uint16_t)p[1]<<8;}
static uint32_t u32(const uint8_t *p){return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void put16(uint8_t *p,uint16_t n){p[0]=n;p[1]=n>>8;}
static bool hx(const char *s,uint8_t *o,size_t n){if(strlen(s)!=2*n)return false;for(size_t i=0;i<n;i++){unsigned v=0;for(unsigned j=0;j<2;j++){char c=s[2*i+j];unsigned d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:16;if(d>15)return false;v=16*v+d;}o[i]=v;}return true;}
static bool num(const char *s,uint32_t *o){uint64_t n=0;if(!*s)return false;for(;*s;s++){if(*s<'0'||*s>'9')return false;n=n*10+*s-'0';if(n>UINT32_MAX)return false;}*o=n;return true;}
const char *management_parse(const char *s,management_command_t *c){
 if(!s||strlen(s)>=ASSOC_COMMAND_MAX)return "length";for(const char *p=s;*p;p++)if(*p<32||*p>126)return "ascii";
 char b[ASSOC_COMMAND_MAX];strcpy(b,s);memset(c,0,sizeof(*c));char *p=strtok(b," ");if(!p||strcmp(p,RADIO_PREFIX))return "prefix";
 p=strtok(NULL," ");if(!p)return "verb";const char *verbs[]={"INFO","BIND","ACTIVE_DISCOVERY_BEACON_REQUEST","DISCOVERY_COMMIT","REJOIN_REQUEST","CURRENT_SHORT_COMMIT","DEVICE_ANNOUNCE","END_DEVICE_TIMEOUT","PARENT_LINK_ACTIVE","MANAGEMENT_POLL","STATUS","END","TYPE07_FAN","STATS"};unsigned k;
 for(k=0;k<MANAGEMENT_VERB_COUNT;k++)if(!strcmp(p,verbs[k]))break;if(k==MANAGEMENT_VERB_COUNT)return "verb";c->kind=k;
 const char *names[]={"id","boot","session","generation","epoch","attempt","guard","dsn","fc","hash","mac","revision","short","ctx"};unsigned mask=0;
 while((p=strtok(NULL," "))){char *v=strchr(p,'=');if(!v)return "field";*v++=0;unsigned i;for(i=0;i<14;i++)if(!strcmp(p,names[i]))break;if(i==14||(mask&(1u<<i)))return "field";mask|=1u<<i;
  if(i==1||i==4||i==5||i==6){uint8_t t[16];if(!hx(v,t,16))return "token";strcpy(i==1?c->boot:i==4?c->epoch:i==5?c->attempt:c->guard,v);}
  else if(i==9){if(!hx(v,c->hash,32))return "hash";}
  else if(i==10){size_t n=strlen(v)/2;if(n>68||strlen(v)%2||!hx(v,c->mac,n))return "mac";c->mac_length=n;}
  else {uint32_t n;if(!num(v,&n))return "number";switch(i){case 0:c->id=n;break;case 2:c->session=n;break;case 3:c->generation=n;break;case 7:if(n>255)return "dsn";c->dsn=n;break;case 8:c->fc=n;break;case 11:c->revision=n;break;case 12:if(!n||n>=0xfff8)return "short";c->short_address=n;break;case 13:if(n>=DUAL_CONTEXTS)return "ctx";c->ctx=n;c->has_ctx=true;break;default:return "field";}}
 }
 /* `want` is the ctx-free field set of each verb; ctx is decided separately
  * below, because the rule is about scope rather than about this verb's
  * arguments. */
 unsigned want=k==M_INFO?1:k==M_BIND?127|4096:k==M_BEACON||k==M_POLL?143:k==M_DISCOVERY_COMMIT?15|2048|512:k==M_SHORT_COMMIT?15|2048|4096:k==M_ACTIVE?15|2048:k==M_STATUS||k==M_END?7:k==M_STATS?3:15|16|32|64|256|512|1024;
 /* ctx is mandatory on every per-context verb. V25 had one global context, so
  * a verb needed no scope; with two, a verb that omits it would have to be
  * guessed, and guessing is what sends a frame into the wrong network with the
  * wrong key. Optional only on STATUS: a report may describe the single bound
  * context, an action may never default. Refused outright on INFO and END,
  * which are global -- accepting a ctx there would imply a scope they do not
  * have, and silently ignoring it is worse than refusing it. */
 if(k==M_INFO||k==M_END||k==M_STATS){if(mask&CTX_BIT)return "ctx_not_scoped";return mask==want?NULL:"field_set";}
 if(k==M_STATUS)return (mask==want||mask==(want|CTX_BIT))?NULL:"field_set";
 if(!(mask&CTX_BIT))return "ctx_required";
 return mask==(want|CTX_BIT)?NULL:"field_set";
}
bool management_beacon(const commission_t *s,const uint8_t *m,size_t n){
 const key_gate_t *k=&s->keys;
 if(n<26||u16(m)!=0x8000||u16(m+3)!=k->pan||u16(m+5)!=0)return false;
 uint16_t sf=u16(m+7);if((sf&0x2fff)!=0x0fff||!(sf&0x4000)||m[9]&0x7f||m[10]&0x88)return false;
 size_t i=11+2*(m[10]&7)+8*((m[10]>>4)&7);
 return i+15==n&&m[i]==0&&m[i+1]==0x22&&!(m[i+2]&0x7b)&&(m[i+2]&0x80)&&!memcmp(m+i+3,k->tc,8)&&m[i+11]==255&&m[i+12]==255&&m[i+13]==255;
}
const char *management_resume(commission_t *s,const management_command_t *c,uint32_t now){
 const dual_identity_t *id=dual_identity(c->ctx);
 if(!id)return "unknown_context";
 if(s->phase!=G_IDLE||s->association.session||c->session!=1||c->generation<DUAL_GENERATION_FLOOR||
    !dual_identity_short_plausible(c->ctx,c->short_address)||
    !dual_identity_epoch_matches(c->ctx,c->epoch)||
    !dual_identity_attempt_matches(c->ctx,c->attempt))return "current_context_only";
 s->phase=G_MANAGEMENT;s->generation=c->generation;s->association.session=1;s->association.state=A_ASSOCIATED;s->association.result.short_address=c->short_address;
 s->keys.state=K_MANAGEMENT;s->keys.session=1;s->keys.ctx=(uint8_t)c->ctx;s->keys.generation=c->generation;s->keys.pan=id->pan;s->keys.short_address=c->short_address;s->keys.keyseq=id->keyseq;
 memcpy(s->keys.raw,id->raw_ieee,8);memcpy(s->keys.tc,id->tc_ieee,8);strcpy(s->keys.epoch,c->epoch);strcpy(s->attempt,c->attempt);
 s->recovery.phase=R_BOUND;s->recovery.start_us=now;s->recovery.poll_misses=0;s->recovery.poll_misses_total=0;strcpy(s->recovery.guard,c->guard);return NULL;
}
const char *management_control(commission_t *s,const management_command_t *c,uint32_t now){
 recovery_transport_t *q=&s->recovery;if(s->phase!=G_MANAGEMENT||c->session!=1||q->pending)return "control_state";
 if(c->kind==M_DISCOVERY_COMMIT){if(c->generation!=s->generation||q->phase!=R_DISCOVERED||c->revision!=q->beacon_revision||memcmp(c->hash,q->beacon_hash,32)||now-q->beacon_time>2000000u)return "discovery_binding";q->phase=R_PREPARED;return NULL;}
 if(c->kind==M_SHORT_COMMIT){if(q->phase!=R_WAIT_REJOIN||s->generation==UINT32_MAX||c->generation!=s->generation+1||!q->response_revision||c->revision!=q->response_revision||now-q->response_time>2000000u)return "short_binding";s->generation=c->generation;s->keys.generation=c->generation;s->keys.short_address=c->short_address;s->association.result.short_address=c->short_address;q->phase=R_REJOINED;q->window=false;return NULL;}
 if(c->kind==M_ACTIVE){if(q->phase!=R_WAIT_TIMEOUT||c->generation!=s->generation||!q->response_revision||c->revision!=q->response_revision||now-q->response_time>2000000u)return "timeout_binding";q->phase=R_ACTIVE;q->window=false;q->last_idle_poll=now;return NULL;}
 return "control_verb";
}
const char *management_tx(commission_t *s,const management_command_t *c,uint32_t now,uint8_t *out,size_t *n){
 recovery_transport_t *q=&s->recovery;key_gate_t *k=&s->keys;
 if(s->phase!=G_MANAGEMENT||c->session!=1||c->generation!=s->generation||q->pending||now-q->start_us>=SESSION_LIMIT_US)return "state_or_deadline";
 if(c->kind==M_BEACON){if(q->phase!=R_BOUND||q->scan_attempts>=3)return "one_scan_only";uint8_t b[]={3,8,c->dsn,255,255,255,255,7};memcpy(out,b,8);*n=8;q->scan_once=true;q->scan_attempts++;q->phase=R_SCANNING;}
 else if(c->kind==M_POLL){if(q->phase!=R_ACTIVE||now-q->last_idle_poll<1000000u||q->total_polls>=MAX_TOTAL_POLLS_PER_CONTEXT)return "idle_poll_bound";uint8_t b[]={0x63,0x88,c->dsn,0,0,0,0,0,0,4};put16(b+3,k->pan);put16(b+7,k->short_address);memcpy(out,b,10);*n=10;q->last_idle_poll=now;q->total_polls++;}
 else {
  if(strcmp(c->epoch,k->epoch)||strcmp(c->attempt,s->attempt)||strcmp(c->guard,q->guard)||c->fc<32||c->fc==UINT32_MAX||(q->last_fc&&(q->last_fc>UINT32_MAX-32||c->fc<q->last_fc+32)))return "intent_binding";
  if(c->kind==M_APP){
   /* Crypto-blind: only the fixed reviewed encrypted envelope is accepted.
    * Host authenticates baseline and checks FAN-only plaintext before handoff. */
   if(q->phase!=R_ACTIVE||q->application_once||!q->announce_once||!q->timeout_once||
      q->window||q->total_polls<40||now-q->last_idle_poll>2000000u||
      now-q->start_us<60000000u||c->mac_length!=68)return "application_live_readiness";
   uint8_t hash[32];permit_hash(c->mac,68,hash);if(memcmp(hash,c->hash,32))return "hash";
   const uint8_t *m=c->mac,*a=m+17;
   if(u16(m)!=0x8861||u16(m+3)!=k->pan||u16(m+5)!=0||
      u16(m+7)!=k->short_address||u16(m+9)!=0x2208||u16(m+11)!=0xfffd||
      u16(m+13)!=k->short_address||m[15]!=60||a[0]!=0x28||
      u32(a+1)!=c->fc||memcmp(a+5,k->raw,8)||a[13]!=k->keyseq)return "application_context";
   memcpy(out,m,68);*n=68;q->last_fc=c->fc;q->application_once=true;
   q->request_id=c->id;q->pending=true;return NULL;
  }
  size_t wanted=c->kind==M_REJOIN?53:c->kind==M_ANNOUNCE?55:c->kind==M_TIMEOUT?54:0;if(!wanted||c->mac_length!=wanted)return "typed_length";
  if(c->kind==M_REJOIN&&(q->phase!=R_PREPARED||q->rejoin_once||now-q->beacon_time>2000000u))return "rejoin_state";
  if(c->kind==M_ANNOUNCE&&(q->phase!=R_REJOINED||q->announce_once))return "announce_state";
  if(c->kind==M_TIMEOUT&&(q->phase!=R_ANNOUNCED||q->timeout_once))return "timeout_state";
  uint8_t hash[32];permit_hash(c->mac,wanted,hash);if(memcmp(hash,c->hash,32))return "hash";
  const uint8_t *m=c->mac;size_t h=c->kind==M_ANNOUNCE?8:24;const uint8_t *a=m+9+h;
  if(u16(m)!=0x8861||u16(m+3)!=k->pan||u16(m+5)!=0||u16(m+7)!=k->short_address||u16(m+9)!=(h==8?0x0208:0x1a09)||u16(m+11)!=(h==8?0xfffd:0)||u16(m+13)!=k->short_address||m[15]!=(h==8?60:1))return "outer_context";
  if(h==24&&(memcmp(m+17,k->tc,8)||memcmp(m+25,k->raw,8)))return "IEEE_context";
  if(a[0]!=0x28||u32(a+1)!=c->fc||memcmp(a+5,k->raw,8)||a[13]!=k->keyseq)return "aux_context";
  memcpy(out,m,wanted);*n=wanted;q->last_fc=c->fc;
  if(c->kind==M_REJOIN){q->rejoin_once=true;q->phase=R_WAIT_REJOIN;}
  else if(c->kind==M_TIMEOUT){q->timeout_once=true;q->phase=R_WAIT_TIMEOUT;}else q->announce_once=true;
  q->poll_dsn=(uint8_t)(m[2]+1);q->polls=0;q->response_revision=0;q->response_time=0;
 }
 q->request_id=c->id;q->pending=true;return NULL;
}
void management_done(commission_t *s,bool ok,bool clean_miss,unsigned kind,uint32_t now){
 recovery_transport_t *q=&s->recovery;q->pending=false;
 /* V27: see MAX_CONSECUTIVE_POLL_MISSES. A missed poll is not a lost frame:
  * nothing was spent, and the next poll asks again. */
 if(!ok&&kind==M_POLL&&clean_miss&&q->poll_misses+1u<MAX_CONSECUTIVE_POLL_MISSES){q->poll_misses++;q->poll_misses_total++;return;}
 if(!ok){commission_stop(s);return;}
 if(kind==M_POLL)q->poll_misses=0;
 if(kind==M_BEACON){q->tx_end_us=now;q->deadline_us=now+SCAN_US;}
 else if(kind==M_REJOIN||kind==M_TIMEOUT){q->tx_end_us=now;q->deadline_us=now+RESPONSE_US;q->poll_due=now+50000u;q->window=true;}
 else if(kind==M_ANNOUNCE)q->phase=R_ANNOUNCED;
}
bool management_auto_poll(commission_t *s,uint32_t now,uint8_t out[10]){
 recovery_transport_t *q=&s->recovery;if(s->phase!=G_MANAGEMENT||!q->window||q->pending||now<q->poll_due||now>=q->deadline_us||q->polls>=5)return false;
 if(now-q->poll_due>20000u){commission_stop(s);return false;}
 uint8_t b[]={0x63,0x88,q->poll_dsn,0,0,0,0,0,0,4};put16(b+3,s->keys.pan);put16(b+7,s->keys.short_address);memcpy(out,b,10);q->poll_dsn++;q->polls++;q->total_polls++;q->poll_due+=100000u;q->pending=true;return true;
}
void management_tick(commission_t *s,uint32_t now){
 recovery_transport_t *q=&s->recovery;if(s->phase!=G_MANAGEMENT)return;
 if(now-q->start_us>=SESSION_LIMIT_US){commission_stop(s);return;}
 if(q->phase==R_SCANNING&&q->deadline_us&&now>=q->deadline_us){if(q->beacon_revision)q->phase=R_DISCOVERED;else if(q->scan_attempts<3){q->phase=R_BOUND;q->deadline_us=0;}else commission_stop(s);}
 if(q->window&&now>=q->deadline_us){q->window=false;if(!q->response_revision)commission_stop(s);}
 if((q->phase==R_WAIT_REJOIN||q->phase==R_WAIT_TIMEOUT)&&q->response_revision&&now-q->response_time>2000000u)commission_stop(s);
}
void management_observe(commission_t *s,const uint8_t *m,size_t n,uint32_t rev,uint32_t time,bool ack){
 recovery_transport_t *q=&s->recovery;if(s->phase!=G_MANAGEMENT)return;
 if(q->phase==R_SCANNING&&q->deadline_us&&time>=q->tx_end_us&&time<q->deadline_us&&rev>q->scan_floor&&management_beacon(s,m,n)){q->beacon_revision=rev;q->beacon_time=time;permit_hash(m,n,q->beacon_hash);}
 if((q->phase==R_WAIT_REJOIN||q->phase==R_WAIT_TIMEOUT)&&!q->response_revision&&q->deadline_us&&time>=q->tx_end_us&&time<q->deadline_us&&ack&&n==(q->phase==R_WAIT_REJOIN?55:54)&&u16(m)==0x8861&&u16(m+3)==s->keys.pan&&u16(m+5)==s->keys.short_address&&u16(m+7)==0&&u16(m+9)==0x1a09&&u16(m+11)==s->keys.short_address&&u16(m+13)==0&&!memcmp(m+17,s->keys.raw,8)&&!memcmp(m+25,s->keys.tc,8)&&m[33]==0x28&&!memcmp(m+38,s->keys.tc,8)&&m[46]==s->keys.keyseq){q->response_revision=rev;q->response_time=time;}
}
bool commission_observe(commission_t *s,const uint8_t *m,size_t n,uint32_t r,bool a){(void)s;(void)m;(void)n;(void)r;(void)a;return false;}
void commission_stop(commission_t *s){s->phase=G_STOPPED;s->keys.state=K_STOPPED;s->keys.pending=false;s->recovery.phase=R_STOPPED;s->recovery.window=false;s->recovery.pending=false;}
const char *recovery_name(recovery_phase_t p){static const char *n[]={"IDLE","BOUND","SCANNING","DISCOVERED","REJOIN_PREPARED","WAIT_REJOIN","REJOINED","ANNOUNCED","WAIT_TIMEOUT","PARENT_LINK_ACTIVE","STOPPED"};return p<=R_STOPPED?n[p]:"INVALID";}
const char *commission_name(commission_phase_t p){return p==G_IDLE?"IDLE":p==G_MANAGEMENT?"RECOVERY":p==G_STOPPED?"STOPPED":"INVALID";}
const char *management_class(unsigned k){return k==M_BEACON?"ACTIVE_DISCOVERY_BEACON_REQUEST":k==M_REJOIN?"REJOIN_REQUEST":k==M_ANNOUNCE?"DEVICE_ANNOUNCE":k==M_TIMEOUT?"END_DEVICE_TIMEOUT":k==M_POLL?"MANAGEMENT_POLL":k==M_APP?"TYPE07_FAN":"INVALID";}
