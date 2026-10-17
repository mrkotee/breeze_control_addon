#include "assoc.h"
#include <string.h>
static uint16_t le16(const uint8_t *p){return (uint16_t)(p[0]|(uint16_t)p[1]<<8);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
bool assoc_ieee_valid(const uint8_t a[8])
{ if(!a || (a[7]&1))return false;uint8_t any=0,all=255;for(unsigned i=0;i<8;i++){any|=a[i];all&=a[i];}return any && all!=255; }
bool assoc_target_valid(const assoc_target_t *t)
{
    return t && t->pan!=0xffff && t->coordinator_short==0 && t->ctx<2 && t->capability==0x80 &&
        assoc_ieee_valid(t->raw_ieee) && assoc_ieee_valid(t->coordinator_ieee) && memcmp(t->raw_ieee,t->coordinator_ieee,8) &&
        t->max_polls<=8 && t->poll_interval_ms>=100 && t->poll_interval_ms<=5000 && t->timeout_ms>=1000 && t->timeout_ms<=30000;
}
size_t assoc_build_request(const assoc_target_t *t,uint32_t dsn,uint8_t *out,size_t cap)
{
    if(!assoc_target_valid(t) || dsn>255 || !out || cap<19)return 0;
    put16(out,0xc823);out[2]=(uint8_t)dsn;put16(out+3,t->pan);put16(out+5,0);put16(out+7,0xffff);
    memcpy(out+9,t->raw_ieee,8);out[17]=1;out[18]=0x80;return 19;
}
size_t assoc_build_poll(const assoc_target_t *t,uint32_t dsn,uint8_t *out,size_t cap)
{
    if(!assoc_target_valid(t) || dsn>255 || !out || cap<16)return 0;
    put16(out,0xc863);out[2]=(uint8_t)dsn;put16(out+3,t->pan);put16(out+5,0);memcpy(out+7,t->raw_ieee,8);out[15]=4;return 16;
}
bool assoc_beacon_parse(const uint8_t *m,size_t n,assoc_beacon_t *o)
{
    if(!m || !o || n<11 || n>125 || le16(m)!=0x8000)return false;
    assoc_beacon_t b={0};b.pan=le16(m+3);b.source_short=le16(m+5);b.dsn=m[2];
    uint16_t sf=le16(m+7);b.permit=(sf&0x8000)!=0;b.coordinator=(sf&0x4000)!=0;
    size_t i=9;unsigned gts=m[i++]&7;
    if(gts){if(i+1+3*gts>n)return false;i+=1+3*gts;}
    if(i>=n)return false;
    uint8_t pending=m[i++];
    if(pending&0x88)return false;
    i+=2*(pending&7)+8*((pending>>4)&7);
    if(i+15!=n || m[i]!=0 || m[i+1]!=0x22 || b.pan==0xffff || b.source_short!=0)return false;
    b.router_capacity=(m[i+2]&4)!=0;b.end_capacity=(m[i+2]&0x80)!=0;memcpy(b.extpan,m+i+3,8);*o=b;return true;
}
bool assoc_response_parse(const uint8_t *m,size_t n,const assoc_target_t *t,uint32_t rev,uint32_t floor,assoc_result_t *o)
{
    if(!m || !t || !o || n!=25 || rev<=floor || le16(m)!=0xcc63 || le16(m+3)!=t->pan ||
        memcmp(m+5,t->raw_ieee,8) || memcmp(m+13,t->coordinator_ieee,8) || m[21]!=2 || m[24]>2)return false;
    uint16_t a=le16(m+22);if(m[24]==0 && (a==0 || a>=0xfff8))return false;
    memset(o,0,sizeof(*o));o->status=m[24];o->short_address=a;o->dsn=m[2];o->rx_revision=rev;memcpy(o->coordinator,m+13,8);return true;
}
void assoc_init(assoc_t *s){memset(s,0,sizeof(*s));s->state=A_IDLE;}
bool assoc_active(const assoc_t *s){return s->state==A_TARGET_SELECTED || s->state==A_REQUEST_SENT || s->state==A_WAIT_RESPONSE;}
const char *assoc_begin(assoc_t *s,const assoc_target_t *t,uint32_t generation)
{
    if(assoc_active(s) || s->tx_pending)return "session_busy";
    if(!assoc_target_valid(t) || !generation || generation<=s->session)return "invalid_target_or_generation";
    assoc_init(s);s->target=*t;s->session=generation;s->state=A_TARGET_SELECTED;return NULL;
}
const char *assoc_request(assoc_t *s,uint32_t now,uint32_t rev,uint8_t *out,size_t cap,size_t *n)
{
    if(s->state!=A_TARGET_SELECTED || s->request_once || s->tx_pending)return "request_not_allowed";
    *n=assoc_build_request(&s->target,s->target.dsn,out,cap);if(!*n)return "builder_invalid";
    s->target.dsn++;s->request_once=true;s->attempt_floor=rev;s->start_us=now;s->last_poll_us=now;
    s->tx_pending=true;s->tx_kind=TX_REQUEST;s->state=A_REQUEST_SENT;return NULL;
}
const char *assoc_poll(assoc_t *s,uint32_t now,uint8_t *out,size_t cap,size_t *n)
{
    assoc_tick(s,now);
    if(s->state!=A_WAIT_RESPONSE || !s->local_ok || s->tx_pending)return "poll_not_allowed";
    if(s->polls>=s->target.max_polls)return "poll_limit";
    uint32_t delay=s->poll_cca_retry?ASSOC_CCA_RECOVERY_US:s->target.poll_interval_ms*1000u;
    if((uint32_t)(now-s->last_poll_us)<delay)return "poll_too_soon";
    *n=assoc_build_poll(&s->target,s->target.dsn,out,cap);if(!*n)return "builder_invalid";
    s->target.dsn++;s->polls++;s->poll_cca_retry=false;s->last_poll_us=now;s->tx_pending=true;s->tx_kind=TX_POLL;return NULL;
}
static void finish_response(assoc_t *s)
{ if(s->local_ok && s->response_seen && !s->tx_pending && s->state==A_WAIT_RESPONSE)s->state=s->result.status?A_REJECTED:A_ASSOCIATED; }
void assoc_local_done(assoc_t *s,assoc_tx_result_t r)
{
    if(!s->tx_pending)return;
    assoc_tx_kind_t kind=s->tx_kind;s->tx_pending=false;s->tx_kind=TX_NONE;
    if(s->state!=A_REQUEST_SENT && s->state!=A_WAIT_RESPONSE)return;
    /* Only the first submitted Data Request's proven pre-air CCA failure.
       Budget was consumed at submission. REQUEST and all other errors stay terminal. */
    if(r==ATX_CCA_FAIL && kind==TX_POLL && s->local_ok && s->state==A_WAIT_RESPONSE &&
       s->polls==1 && s->target.max_polls==2){
        s->poll_cca_retry=true;finish_response(s);return;
    }
    if(r!=ATX_OK){s->state=r==ATX_CCA_FAIL?A_ERROR:A_UNCERTAIN;return;}
    if(kind==TX_REQUEST){s->local_ok=true;s->state=A_WAIT_RESPONSE;}
    finish_response(s);
}
bool assoc_observe(assoc_t *s,const uint8_t *m,size_t n,uint32_t rev)
{
    if(s->state!=A_REQUEST_SENT && s->state!=A_WAIT_RESPONSE)return false;
    assoc_result_t r;if(!assoc_response_parse(m,n,&s->target,rev,s->attempt_floor,&r))return false;
    if(s->response_seen)return false; /* first valid result is immutable */
    s->result=r;s->response_seen=true;finish_response(s);return true;
}
void assoc_tick(assoc_t *s,uint32_t now)
{
    if((s->state==A_REQUEST_SENT || s->state==A_WAIT_RESPONSE) && (uint32_t)(now-s->start_us)>=s->target.timeout_ms*1000u)
        s->state=s->tx_pending?A_UNCERTAIN:A_TIMEOUT;
}
void assoc_cancel(assoc_t *s){if(assoc_active(s))s->state=s->tx_pending?A_UNCERTAIN:A_CANCELLED;}
const char *assoc_state_name(assoc_state_t s)
{static const char *n[]={"IDLE","TARGET_SELECTED","ASSOCIATION_REQUEST_SENT","WAIT_ASSOC_RESPONSE","ASSOCIATED_UNKEYED","REJECTED","TIMEOUT","UNCERTAIN_TX","CANCELLED","ERROR"};return s<=A_ERROR?n[s]:"ERROR";}
const char *assoc_tx_name(assoc_tx_result_t r)
{static const char *n[]={"local_tx_ok","no_ack","cca_fail","invalid_ack","aborted","error"};return r<=ATX_ERROR?n[r]:"error";}
