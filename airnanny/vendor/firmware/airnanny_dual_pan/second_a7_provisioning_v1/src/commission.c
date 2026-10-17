/* State/lineage glue only. Wire builders, response parser and key checks copied. */
#include "commission.h"
#include <string.h>
static const uint8_t raw_identity[]={0x37,0x14,0xa4,0x75,0xbb,0x56,0x7a,0x02};
static const uint8_t tc_identity[]={0x5f,0x87,0xa1,0x36,0,0x4b,0x12,0};
static bool exact_target(const assoc_target_t *t){
    bool raw_ok=!memcmp(t->raw_ieee,raw_identity,8);
#if defined(COMMISSION_HISTORICAL_ORACLE) && defined(ASSOC_HOST_TEST)
    const uint8_t old[]={0x1f,0x71,0x9c,0x36,0,0x4b,0x12,0};raw_ok=raw_ok||!memcmp(t->raw_ieee,old,8);
#endif
    return raw_ok&&t->ctx==1&&t->pan==0x0b7a&&t->coordinator_short==0&&t->capability==0x80&&
        !memcmp(t->coordinator_ieee,tc_identity,8)&&!memcmp(t->extpan,tc_identity,8)&&
        t->max_polls==2&&t->poll_interval_ms==500&&t->timeout_ms==10000;
}
const char *commission_baseline(commission_t *s,const commission_command_t *c,uint32_t rev){
    if(s->phase!=G_IDLE||s->association.session||c->key.ctx!=1||c->key.generation!=3||
        !c->baseline_revision||c->baseline_revision>rev)return "baseline_assertion";
    s->baseline_revision=c->baseline_revision;s->generation=3;s->phase=G_BASELINE;return NULL;
}
const char *commission_arm(commission_t *s,const commission_command_t *c,uint32_t rev){
    if(s->phase!=G_BASELINE||c->key.ctx!=1||c->key.generation!=s->generation||
        c->baseline_revision!=s->baseline_revision||rev<s->baseline_revision)return "arm_state";
    s->arm_floor=rev;s->phase=G_ARMED;return NULL;
}
const char *commission_begin(commission_t *s,const assoc_command_t *c){
    if(s->phase!=G_ARMED||s->association.session||c->kind!=C_BEGIN_PERMIT||
        c->validation_generation!=s->generation||c->permit_revision<=s->arm_floor||
        !exact_target(&c->target))return "fresh_same_identity_permit_required";
    const char *e=assoc_begin(&s->association,&c->target,1);
    if(!e){strcpy(s->attempt,c->attempt);s->phase=G_ASSOC;}return e;
}
bool commission_observe(commission_t *s,const uint8_t *m,size_t n,uint32_t rev,bool ack_clean){
    if(s->phase!=G_ASSOC)return false;
    if(!assoc_observe(&s->association,m,n,rev))return false;
    s->response_ack_clean=ack_clean;
    if(!ack_clean)commission_stop(s);
    return true;
}
static bool lineage(const commission_t *s,const commission_command_t *c){
    return c->session==s->association.session&&c->key.ctx==s->association.target.ctx&&
        !strcmp(c->attempt,s->attempt)&&c->pan==s->association.target.pan&&
        c->short_address==s->association.result.short_address&&
        !memcmp(c->raw,s->association.target.raw_ieee,8)&&!memcmp(c->tc,s->association.target.coordinator_ieee,8);
}
const char *commission_commit(commission_t *s,const commission_command_t *c,uint32_t now){
    if(s->phase!=G_ASSOC||s->association.state!=A_ASSOCIATED||!s->association.local_ok||
        s->association.tx_pending||!s->response_ack_clean||s->association.result.status||
        !lineage(s,c)||c->key.generation!=s->generation+1||c->key.max_polls!=8||
        c->key.interval!=500||c->key.timeout!=10000)return "association_commit_binding";
    /* Host has durably saved exactly the response-derived short. No RX stop. */
    key_command_t derived=c->key;
    derived.short_address=s->association.result.short_address;
    const char *e=key_bind(&s->keys,&derived,now);
    if(!e){s->keys.session=s->association.session;s->generation=c->key.generation;s->phase=G_WAIT_KEY;}return e;
}
const char *commission_key(commission_t *s,const commission_command_t *c){
    if(s->phase!=G_WAIT_KEY||!lineage(s,c)||c->key.generation!=s->generation+2||c->key.keyseq!=0)return "key_lineage";
    const char *e=key_installed(&s->keys,&c->key);
    if(!e){s->generation=c->key.generation;s->phase=G_KEY;}return e;
}
const char *commission_poll(commission_t *s,const commission_command_t *c,uint32_t now,uint8_t out[10]){
    if(s->phase!=G_WAIT_KEY||!lineage(s,c))return "poll_lineage";
    return key_poll(&s->keys,&c->key,now,out);
}
const char *commission_announce(commission_t *s,const commission_command_t *c,uint32_t now,uint8_t out[55]){
    if(s->phase!=G_KEY||!lineage(s,c))return "announce_lineage";
    const char *e=key_announce(&s->keys,&c->key,now,out);
    if(!e)s->phase=G_ANNOUNCE_UNCERTAIN;return e;
}
void commission_done(commission_t *s,unsigned kind,assoc_tx_result_t r){
    if(kind<2){
        assoc_t *a=&s->association;
        bool poll_cca=s->phase==G_ASSOC && kind==1 && r==ATX_CCA_FAIL &&
            a->tx_pending && a->tx_kind==TX_POLL && a->state==A_WAIT_RESPONSE &&
            a->local_ok && a->polls==1 && a->target.max_polls==2;
        assoc_local_done(a,r);
        if((r!=ATX_OK && !poll_cca)||a->state==A_REJECTED)commission_stop(s);
    }
    else{key_done(&s->keys,kind==3,r==ATX_OK);
        if(kind==3&&s->phase!=G_STOPPED)s->phase=r==ATX_OK?G_MANAGEMENT:G_ANNOUNCE_UNCERTAIN;
        else if(r!=ATX_OK)commission_stop(s);}
}
void commission_stop(commission_t *s){assoc_cancel(&s->association);s->keys.state=K_STOPPED;s->phase=G_STOPPED;}
const char *commission_name(commission_phase_t p){
    const char *n[]={"IDLE","BASELINE_READY","PERMIT_ARMED","ASSOCIATION","WAIT_NETWORK_KEY","KEY_INSTALLED","ANNOUNCE_UNCERTAIN","MANAGEMENT_PENDING","STOPPED"};return p<=G_STOPPED?n[p]:"INVALID";
}
