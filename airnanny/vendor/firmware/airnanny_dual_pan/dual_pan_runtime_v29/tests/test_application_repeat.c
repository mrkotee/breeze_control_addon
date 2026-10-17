/* Offline checks on the real V29 typed predicate; no SDK/device/key access. */
#include "management.h"
#include "dual_identity.h"
#include <stdio.h>
#include <string.h>
static int checks, failures;
static void check(bool pass,const char *name){checks++;if(!pass){failures++;printf("FAIL %s\n",name);}}
static void u16put(uint8_t *p,uint16_t v){p[0]=v;p[1]=v>>8;}
static void u32put(uint8_t *p,uint32_t v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void setup(commission_t *s,unsigned ctx){
 memset(s,0,sizeof(*s));const dual_identity_t *id=dual_identity(ctx);
 s->phase=G_MANAGEMENT;s->generation=13;s->keys.pan=id->pan;s->keys.short_address=ctx?0x6c55:0xa326;
 memcpy(s->keys.raw,id->raw_ieee,8);s->keys.keyseq=id->keyseq;strcpy(s->keys.epoch,id->epoch);strcpy(s->attempt,id->attempt);
 s->recovery.phase=R_ACTIVE;s->recovery.announce_once=s->recovery.timeout_once=true;
 s->recovery.total_polls=40;s->recovery.last_idle_poll=70000000u;s->recovery.last_fc=64;
 strcpy(s->recovery.guard,"22222222222222222222222222222222");
}
static void request(management_command_t *c,const commission_t *s,unsigned ctx,uint32_t fc){
 memset(c,0,sizeof(*c));c->kind=M_APP;c->ctx=ctx;c->has_ctx=true;c->session=1;c->generation=s->generation;
 c->fc=fc;c->id=fc;c->mac_length=68;strcpy(c->epoch,s->keys.epoch);strcpy(c->attempt,s->attempt);strcpy(c->guard,s->recovery.guard);
 uint8_t *m=c->mac;u16put(m,0x8861);u16put(m+3,s->keys.pan);u16put(m+7,s->keys.short_address);
 u16put(m+9,0x2208);u16put(m+11,0xfffd);u16put(m+13,s->keys.short_address);m[15]=60;
 m[17]=0x28;u32put(m+18,fc);memcpy(m+22,s->keys.raw,8);m[30]=s->keys.keyseq;
 permit_hash(m,68,c->hash);
}
int main(void){
 uint8_t out[68];size_t n=0;commission_t pair[2];management_command_t c;
 for(unsigned ctx=0;ctx<2;ctx++){
  setup(&pair[0],0);setup(&pair[1],1);commission_t peer=pair[1-ctx];
  for(unsigned round=0;round<3;round++){
   uint32_t fc=96+round*32;request(&c,&pair[ctx],ctx,fc);
   check(management_tx(&pair[ctx],&c,70000000u,out,&n)==NULL,"fresh FC command accepted");
   check(pair[ctx].recovery.pending&&n==68&&!memcmp(out,c.mac,68),"exact one outstanding frame");
   check(management_tx(&pair[ctx],&c,70000000u,out,&n)!=NULL,"pending command cannot be resubmitted");
   management_done(&pair[ctx],true,false,M_APP,70000100u);
   check(management_tx(&pair[ctx],&c,70000100u,out,&n)!=NULL,"consumed FC never reused");
   check(!memcmp(&pair[1-ctx],&peer,sizeof(peer)),"peer context unchanged");
  }
  request(&c,&pair[ctx],ctx,192);c.mac[3]^=1;permit_hash(c.mac,68,c.hash);
  check(management_tx(&pair[ctx],&c,70000000u,out,&n)!=NULL,"wrong PAN rejected");
  request(&c,&pair[ctx],ctx,192);c.mac[22]^=1;permit_hash(c.mac,68,c.hash);
  check(management_tx(&pair[ctx],&c,70000000u,out,&n)!=NULL,"wrong RAW nonce source rejected");
  request(&c,&pair[ctx],ctx,192);c.guard[0]='3';
  check(management_tx(&pair[ctx],&c,70000000u,out,&n)!=NULL,"wrong guard rejected");
  request(&c,&pair[ctx],ctx,192);c.hash[0]^=1;
  check(management_tx(&pair[ctx],&c,70000000u,out,&n)!=NULL,"wrong hash rejected");
  request(&c,&pair[ctx],ctx,192);c.generation++;
  check(management_tx(&pair[ctx],&c,70000000u,out,&n)!=NULL,"stale generation rejected");
  request(&c,&pair[ctx],ctx,192);
  check(management_tx(&pair[ctx],&c,73000000u,out,&n)!=NULL,"stale poll still rejected");
  pair[ctx].recovery.last_idle_poll=1000000;
  check(management_tx(&pair[ctx],&c,1000000u,out,&n)!=NULL,"initial readiness still required");
  pair[ctx].recovery.last_idle_poll=70000000;
  check(management_tx(&pair[ctx],&c,70000000u,out,&n)==NULL,"next unique intent accepted");
  management_done(&pair[ctx],false,false,M_APP,70000100u);
  check(pair[ctx].phase==G_STOPPED,"failed app TX still stops context");
  request(&c,&pair[ctx],ctx,224);
  check(management_tx(&pair[ctx],&c,70000000u,out,&n)!=NULL,"unknown/failed command cannot be retried");
 }
 printf("application_repeat: %d checks, %d failures\n",checks,failures);return failures!=0;
}
