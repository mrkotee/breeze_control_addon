#include "assoc.h"
#include "gate_events.h"
#include "nrf_802154_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#endif
static unsigned long checks;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"failed %s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)
static uint32_t seed=0x12345678;
static uint32_t rnd(void){seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;return seed;}
static size_t unhex(const char *s,uint8_t *o){size_t n=strlen(s)/2;for(size_t i=0;i<n;i++){unsigned v;sscanf(s+2*i,"%2x",&v);o[i]=v;}return n;}
static assoc_target_t target(void)
{
    assoc_target_t t={.pan=0xfa9b,.capability=0x80,.dsn=30,.max_polls=2,.poll_interval_ms=500,.timeout_ms=10000};
    unhex("1f719c36004b1200",t.raw_ieee);unhex("e548a136004b1200",t.coordinator_ieee);memcpy(t.extpan,t.coordinator_ieee,8);return t;
}
static void response(uint8_t *out,assoc_target_t *t,uint16_t a,uint8_t status)
{out[0]=0x63;out[1]=0xcc;out[2]=212;out[3]=t->pan;out[4]=t->pan>>8;memcpy(out+5,t->raw_ieee,8);memcpy(out+13,t->coordinator_ieee,8);out[21]=2;out[22]=a;out[23]=a>>8;out[24]=status;}
static void builders(void)
{
    assoc_target_t t=target();uint8_t out[127],expected[127];
    size_t n=unhex("23c81e9bfa0000ffff1f719c36004b12000180",expected);
    CHECK(assoc_build_request(&t,30,out,sizeof(out))==n);CHECK(!memcmp(out,expected,n));
    n=unhex("63c81f9bfa00001f719c36004b120004",expected);
    CHECK(assoc_build_poll(&t,31,out,sizeof(out))==n);CHECK(!memcmp(out,expected,n));
    for(unsigned d=0;d<256;d++){CHECK(assoc_build_request(&t,d,out,19)==19);CHECK(out[2]==d && out[17]==1 && out[18]==0x80);CHECK(assoc_build_poll(&t,d,out,16)==16);CHECK(out[2]==d && out[15]==4);}
    CHECK(!assoc_build_request(&t,256,out,127));CHECK(!assoc_build_poll(&t,UINT32_MAX,out,127));
    for(unsigned cap=0;cap<19;cap++)CHECK(!assoc_build_request(&t,30,out,cap));
    for(unsigned cap=0;cap<16;cap++)CHECK(!assoc_build_poll(&t,30,out,cap));
    for(unsigned c=0;c<256;c++){t.capability=c;CHECK((assoc_build_request(&t,0,out,127)!=0)==(c==0x80));}t=target();
    t.pan=0xffff;CHECK(!assoc_build_request(&t,0,out,127));t=target();t.coordinator_short=1;CHECK(!assoc_build_poll(&t,0,out,127));t=target();
    memset(t.raw_ieee,0,8);CHECK(!assoc_target_valid(&t));memset(t.raw_ieee,255,8);CHECK(!assoc_target_valid(&t));t=target();t.raw_ieee[7]=1;CHECK(!assoc_target_valid(&t));
    t=target();t.raw_ieee[7]=2;CHECK(assoc_build_request(&t,2,out,127)==19);CHECK(out[16]==2);CHECK(assoc_build_poll(&t,3,out,127)==16);CHECK(out[14]==2);
    CHECK(!assoc_build_request(NULL,0,out,127));CHECK(!assoc_build_poll(&t,0,NULL,127));
}
static void parsing(void)
{
    assoc_target_t t=target();uint8_t r[125];assoc_result_t o;
    unhex("63ccd49bfa1f719c36004b1200e548a136004b120002b7c900",r);
    CHECK(assoc_response_parse(r,25,&t,11,10,&o));CHECK(o.short_address==0xc9b7 && !o.status && o.dsn==212 && o.rx_revision==11);
    CHECK(!assoc_response_parse(r,25,&t,10,10,&o));CHECK(!assoc_response_parse(r,25,&t,9,10,&o));
    for(unsigned n=0;n<=125;n++)CHECK(assoc_response_parse(r,n,&t,11,10,&o)==(n==25));
    for(unsigned a=0;a<=65535;a++){response(r,&t,a,0);CHECK(assoc_response_parse(r,25,&t,11,10,&o)==(a>0 && a<0xfff8));}
    for(unsigned status=0;status<=255;status++){response(r,&t,status?0xffff:0xc9b7,status);CHECK(assoc_response_parse(r,25,&t,11,10,&o)==(status<=2));}
    response(r,&t,0xc9b7,0);
    for(unsigned fc=0;fc<=65535;fc++){r[0]=fc;r[1]=fc>>8;CHECK(assoc_response_parse(r,25,&t,11,10,&o)==(fc==0xcc63));}
    response(r,&t,0xc9b7,0);for(unsigned i=3;i<=21;i++){uint8_t orig=r[i];for(unsigned v=0;v<256;v++){r[i]=v;CHECK(assoc_response_parse(r,25,&t,11,10,&o)==(v==orig));}r[i]=orig;}
    CHECK(!assoc_response_parse(NULL,25,&t,11,10,&o));CHECK(!assoc_response_parse(r,25,&t,11,10,NULL));
    assoc_beacon_t b;size_t n=unhex("0080199bfa0000ffcf0000002284e548a136004b1200ffffff00",r);
    CHECK(n==26);CHECK(assoc_beacon_parse(r,n,&b));CHECK(b.pan==0xfa9b && b.source_short==0 && b.coordinator && b.permit && b.end_capacity && b.router_capacity);CHECK(!memcmp(b.extpan,t.coordinator_ieee,8));
    for(unsigned len=0;len<26;len++)CHECK(!assoc_beacon_parse(r,len,&b));r[8]&=0x7f;CHECK(assoc_beacon_parse(r,n,&b) && !b.permit);r[8]|=0x80;r[9]=7;CHECK(!assoc_beacon_parse(r,n,&b));
}
static void states(void)
{
    assoc_target_t t=target();uint8_t m[125],r[25];size_t n;assoc_t s;response(r,&t,0xc9b7,0);
    assoc_init(&s);CHECK(!assoc_begin(&s,&t,1));CHECK(s.state==A_TARGET_SELECTED);CHECK(assoc_begin(&s,&t,2));
    CHECK(!assoc_request(&s,100,5,m,125,&n));CHECK(s.state==A_REQUEST_SENT && s.request_once && s.tx_pending);CHECK(assoc_request(&s,101,5,m,125,&n));CHECK(assoc_poll(&s,999999,m,125,&n));
    CHECK(!assoc_observe(&s,r,25,5));CHECK(assoc_observe(&s,r,25,6));CHECK(s.state==A_REQUEST_SENT);assoc_local_done(&s,ATX_OK);CHECK(s.state==A_ASSOCIATED && s.local_ok);CHECK(!assoc_observe(&s,r,25,7));CHECK(assoc_poll(&s,1000000,m,125,&n));
    for(unsigned result=ATX_NO_ACK;result<=ATX_ERROR;result++){assoc_init(&s);CHECK(!assoc_begin(&s,&t,1));CHECK(!assoc_request(&s,100,0,m,125,&n));assoc_local_done(&s,result);CHECK(s.state==(result==ATX_CCA_FAIL?A_ERROR:A_UNCERTAIN));CHECK(assoc_request(&s,101,1,m,125,&n));CHECK(!assoc_observe(&s,r,25,1));}
    assoc_init(&s);CHECK(!assoc_begin(&s,&t,1));CHECK(!assoc_request(&s,100,0,m,125,&n));assoc_local_done(&s,ATX_OK);CHECK(s.state==A_WAIT_RESPONSE);assoc_tick(&s,100+10000000);CHECK(s.state==A_TIMEOUT);CHECK(assoc_request(&s,10000001,1,m,125,&n));
    assoc_init(&s);CHECK(!assoc_begin(&s,&t,1));CHECK(!assoc_request(&s,100,0,m,125,&n));assoc_tick(&s,100+10000000);CHECK(s.state==A_UNCERTAIN);CHECK(s.tx_pending);CHECK(assoc_begin(&s,&t,2));assoc_local_done(&s,ATX_OK);CHECK(s.state==A_UNCERTAIN && !s.tx_pending);
    assoc_init(&s);CHECK(!assoc_begin(&s,&t,1));CHECK(!assoc_request(&s,100,10,m,125,&n));assoc_local_done(&s,ATX_OK);CHECK(assoc_poll(&s,499999,m,125,&n));CHECK(!assoc_poll(&s,500100,m,125,&n));CHECK(s.polls==1 && n==16);CHECK(assoc_poll(&s,1000100,m,125,&n));assoc_local_done(&s,ATX_OK);CHECK(!assoc_poll(&s,1000100,m,125,&n));assoc_local_done(&s,ATX_OK);CHECK(assoc_poll(&s,1500100,m,125,&n));CHECK(s.polls==2 && s.state==A_WAIT_RESPONSE);
    response(r,&t,0xffff,1);CHECK(assoc_observe(&s,r,25,11));CHECK(s.state==A_REJECTED && s.result.status==1);
    assoc_init(&s);CHECK(!assoc_begin(&s,&t,1));assoc_cancel(&s);CHECK(s.state==A_CANCELLED);CHECK(assoc_begin(&s,&t,1));CHECK(!assoc_begin(&s,&t,2));CHECK(!assoc_request(&s,1,100,m,125,&n));assoc_cancel(&s);CHECK(s.state==A_UNCERTAIN);assoc_local_done(&s,ATX_OK);CHECK(s.state==A_UNCERTAIN);
    assoc_init(&s);CHECK(s.state==A_IDLE && s.session==0);CHECK(!assoc_observe(&s,r,25,UINT32_MAX));
    t.raw_ieee[7]=2;CHECK(!assoc_begin(&s,&t,3));CHECK(!assoc_request(&s,UINT32_MAX-100,5,m,125,&n));assoc_local_done(&s,ATX_OK);CHECK(!assoc_observe(&s,r,25,6));CHECK(!assoc_poll(&s,500000,m,125,&n));CHECK(s.state==A_WAIT_RESPONSE);
}
static void filtering(void)
{
    assoc_t s;assoc_target_t t=target();uint8_t raw[128]={27},out[125];size_t n;assoc_init(&s);assoc_filter_bind(&s);response(raw+1,&t,0xc9b7,0);uint8_t received=3;
    CHECK(assoc_filter_part(raw,&received)!=NRF_802154_RX_ERROR_NONE);CHECK(!assoc_begin(&s,&t,1));CHECK(!assoc_request(&s,1,0,out,125,&n));received=3;CHECK(assoc_filter_part(raw,&received)==NRF_802154_RX_ERROR_NONE && received==26);CHECK(assoc_filter_part(raw,&received)==NRF_802154_RX_ERROR_NONE);
    for(unsigned fc=0;fc<=65535;fc++){raw[1]=fc;raw[2]=fc>>8;received=26;CHECK((assoc_filter_part(raw,&received)==NRF_802154_RX_ERROR_NONE)==(fc==0xcc63));}response(raw+1,&t,0xc9b7,0);
    raw[6]^=1;CHECK(assoc_filter_part(raw,&received)!=NRF_802154_RX_ERROR_NONE);raw[6]^=1;raw[0]=26;CHECK(assoc_filter_part(raw,&received)!=NRF_802154_RX_ERROR_NONE);raw[0]=27;assoc_cancel(&s);CHECK(assoc_filter_part(raw,&received)!=NRF_802154_RX_ERROR_NONE);
}
static void protocol(void)
{
    assoc_command_t c;
    CHECK(!assoc_command_parse("RADIOV3 INFO id=1",&c));CHECK(c.kind==C_INFO && c.id==1);
    const char *good="RADIOV3 ASSOC BEGIN boot=11111111111111111111111111111111 id=2 ctx=0 raw_ieee=0200000000000001 target_pan=1234 extpan=00124b0036a148e5 coordinator_ieee=00124b0036a148e5 coordinator_short=0000 policy=local_experimental_v1 attempt=22222222222222222222222222222222 beacon_revision=3 max_polls=2 poll_interval_ms=500 timeout_ms=10000 dsn=30";
    CHECK(!assoc_command_parse(good,&c));CHECK(c.target.raw_ieee[0]==1 && c.target.raw_ieee[7]==2 && c.target.capability==0x80);
    const char *bad[]={"RADIOV3 TX id=1","RADIOV3 PROVISION TX mac=00","RADIOV3 INFO id=1 id=2","RADIOV3 INFO id=-1","RADIOV3 INFO id=4294967296","RADIOV3 INFO id=1 mac=00","RADIOV3 ASSOC REQUEST boot=11111111111111111111111111111111 id=3 session=0","RADIOV3 ASSOC REQUEST boot=1 id=3 session=1","RADIOV3 ASSOC REQUEST boot=11111111111111111111111111111111 id=3 session=1 raw_ieee=0000000000000000","RADIOV3 INFO\tid=1"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++)CHECK(assoc_command_parse(bad[i],&c));
    CHECK(!assoc_command_parse("RADIOV3 ASSOC POLL boot=11111111111111111111111111111111 id=3 session=1",&c));
    char copy[512];strcpy(copy,good);char *v=strstr(copy,"coordinator_short=0000");v[20]='1';CHECK(assoc_command_parse(copy,&c));
    memset(copy,'x',511);copy[511]=0;CHECK(assoc_command_parse(copy,&c));
}
static void fuzz(void)
{
    assoc_target_t t=target();assoc_result_t result;assoc_beacon_t b;assoc_command_t c;
    for(unsigned trial=0;trial<100000;trial++){
        struct {uint32_t a;uint8_t mac[125];uint32_t z;} input={.a=0xaaaaaaaa,.z=0xbbbbbbbb};
        size_t len=rnd()%126;for(size_t i=0;i<len;i++)input.mac[i]=(uint8_t)rnd();
        CHECK(!assoc_response_parse(input.mac,len,&t,2,1,&result));(void)assoc_beacon_parse(input.mac,len,&b);CHECK(input.a==0xaaaaaaaa && input.z==0xbbbbbbbb);
        char text[512];size_t n=rnd()%512;for(size_t i=0;i<n;i++)text[i]=(char)(1+rnd()%255);text[n]=0;CHECK(assoc_command_parse(text,&c));
    }
}
static void guard_reads(void)
{
#if defined(_WIN32)
    SYSTEM_INFO info;GetSystemInfo(&info);size_t page=info.dwPageSize;
    uint8_t *mem=VirtualAlloc(NULL,page*2,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);CHECK(mem!=NULL);DWORD old;CHECK(VirtualProtect(mem+page,page,PAGE_NOACCESS,&old));
    assoc_target_t t=target();assoc_result_t r;assoc_beacon_t b;assoc_command_t cmd;
    for(unsigned n=0;n<=125;n++){
        uint8_t *p=mem+page-n;for(unsigned i=0;i<n;i++)p[i]=(uint8_t)rnd();
        (void)assoc_response_parse(p,n,&t,2,1,&r);(void)assoc_beacon_parse(p,n,&b);CHECK(true);
    }
    for(unsigned n=0;n<512;n++){
        char *p=(char *)(mem+page-n-1);memset(p,'x',n);p[n]=0;CHECK(assoc_command_parse(p,&cmd));
    }
    assoc_t s;assoc_init(&s);CHECK(!assoc_begin(&s,&t,1));uint8_t out[125];size_t n;CHECK(!assoc_request(&s,1,0,out,125,&n));assoc_filter_bind(&s);
    uint8_t *p=mem+page-3;p[0]=27;p[1]=0x63;p[2]=0xcc;uint8_t received=3;CHECK(assoc_filter_part(p,&received)==NRF_802154_RX_ERROR_NONE && received==26);
    p=mem+page-26;p[0]=27;response(p+1,&t,0xc9b7,0);received=26;CHECK(assoc_filter_part(p,&received)==NRF_802154_RX_ERROR_NONE);
    CHECK(VirtualFree(mem,0,MEM_RELEASE));
#endif
}
int main(void){builders();parsing();states();filtering();protocol();fuzz();guard_reads();printf("ASSOC checks=%lu fuzz=100000 PASS\n",checks);return 0;}
