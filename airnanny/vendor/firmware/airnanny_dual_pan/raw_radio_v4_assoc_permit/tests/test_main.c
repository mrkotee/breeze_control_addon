/* Executes the actual firmware dispatcher/queue/CDC handlers with device APIs mocked. */
#define ASSOC_HOST_TEST
#define main firmware_entry_not_executed
#include "../src/main.c"
#undef main
#include <stdlib.h>
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"main failed line%d: %s\n",__LINE__,#x);exit(1);}}while(0)
static uint32_t now=100000,rev=3,drops;
static gate_event_t mock_event;static bool have_event;
void gate_hw_init(void){}
uint32_t gate_hw_now_us(void){return now;}
uint32_t gate_hw_revision(void){return rev;}
uint32_t gate_hw_dropped(void){return drops;}
uint32_t gate_hw_crc_errors(void){return 0;}
void gate_hw_session(const assoc_t *s){assoc_filter_bind(s);}
bool gate_hw_pop(gate_event_t *o){if(!have_event)return false;*o=mock_event;have_event=false;return true;}
void gate_hw_rx_begin(const uint8_t *p){(void)p;}
void gate_hw_receive(uint8_t *p,int8_t r,uint8_t l){(void)p;(void)r;(void)l;}
void gate_hw_ack_started(void){}
void gate_hw_ack_completed(void){}
void gate_hw_deadline_miss(void){}
void gate_hw_crc_error(void){}
static void reset(void)
{
    permit_cache_clear(&permit_cache);admission_zdo=immediate_ack=false;admission_revision=admission_generation=0;assoc_init(&session);memset(&tx,0,sizeof(tx));oh=ot=out_drop=last_id=0;has_id=busy=false;used_count=0;open=true;ack_enabled=mock_inline=false;memset(beacons,0,sizeof(beacons));now=100000;rev=3;drops=0;mock_transmits=0;mock_driver_ok=mock_sleep_ok=mock_receive_ok=true;gate_hw_session(&session);
    strcpy(boot,"11111111111111111111111111111111");
}
static const char *reply(void){return output[(oh-1)%16];}
static void beacon(bool permit_on)
{
    uint8_t m[]={0x00,0x80,0x19,0x34,0x12,0,0,0xff,0xcf,0,0,0,0x22,0x84,0xe5,0x48,0xa1,0x36,0,0x4b,0x12,0,0xff,0xff,0xff,0};
    if(!permit_on)m[8]&=0x7f;
    memset(&mock_event,0,sizeof(mock_event));memcpy(mock_event.mac,m,sizeof(m));mock_event.length=sizeof(m);mock_event.time_us=now;mock_event.revision=rev;have_event=true;receive_service();ot=oh;
}
static void begin(unsigned id)
{
    char cmd[512];snprintf(cmd,sizeof(cmd),"RADIOV3 ASSOC BEGIN boot=%s id=%u ctx=0 raw_ieee=0200000000000001 target_pan=1234 extpan=00124b0036a148e5 coordinator_ieee=00124b0036a148e5 coordinator_short=0000 policy=local_experimental_v1 attempt=22222222222222222222222222222222 beacon_revision=3 max_polls=2 poll_interval_ms=500 timeout_ms=10000 dsn=30",boot,id);command(cmd);
}
static void action(const char *verb,unsigned id,unsigned generation)
{char cmd[160];snprintf(cmd,sizeof(cmd),"RADIOV3 ASSOC %s boot=%s id=%u session=%u",verb,boot,id,generation);command(cmd);}
static void respond(unsigned generation,unsigned revision)
{
    memset(&mock_event,0,sizeof(mock_event));uint8_t *m=mock_event.mac;m[0]=0x63;m[1]=0xcc;m[2]=42;m[3]=0x34;m[4]=0x12;memcpy(m+5,session.target.raw_ieee,8);memcpy(m+13,session.target.coordinator_ieee,8);m[21]=2;m[22]=0x34;m[23]=0x56;m[24]=0;
    mock_event.length=25;mock_event.revision=revision;mock_event.session=generation;have_event=true;receive_service();
}
static void permit_fixture(void)
{
    const uint8_t raw[]={0x41,0x88,0x07,0x9b,0xfa,0xff,0xff,0,0,0x08,0x02,0xfc,0xff,0,0,0x3c,0xb4,0x28,0x38,0x12,0x1f,0,0xe5,0x48,0xa1,0x36,0,0x4b,0x12,0,0,0xec,0xca,0xd0,0x24,0xa6,0x16,0x7c,0xb4,0x52,0,0x2e,0x5d,0x27,0x54,0x91};
    memset(&mock_event,0,sizeof(mock_event));memcpy(mock_event.mac,raw,sizeof(raw));mock_event.length=sizeof(raw);mock_event.revision=3;mock_event.time_us=now;have_event=true;receive_service();ot=oh;
}
static void begin_permit(unsigned id,unsigned revision,unsigned ctx,bool corrupt_hash,const char *boot_text)
{
    char hash[65],cmd[512];uint8_t digest[32];memcpy(digest,permit_cache.records[0].hash,32);if(corrupt_hash)digest[0]^=1;hex_le(digest,32,hash,false);
    int n=snprintf(cmd,sizeof(cmd),"RADIOV3 ASSOC BEGIN_PERMIT_EVIDENCE boot=%s id=%u ctx=%u raw_ieee=0200000000000001 target_pan=fa9b extpan=00124b0036a148e5 coordinator_ieee=00124b0036a148e5 coordinator_short=0000 policy=local_experimental_v1 attempt=22222222222222222222222222222222 permit_revision=%u raw_hash=%s validation_generation=1 max_polls=2 poll_interval_ms=500 timeout_ms=10000 dsn=30",boot_text,id,ctx,revision,hash);
    CHECK(n>0 && (size_t)n<sizeof(cmd));command(cmd);
}
int main(void)
{
    reset();begin(1);CHECK(strstr(reply(),"fresh_target_beacon_required"));CHECK(!session.session && !mock_transmits && !ack_enabled);
    beacon(false);begin(2);CHECK(strstr(reply(),"association_not_permitted"));CHECK(!mock_transmits);
    beacon(true);begin(3);CHECK(session.state==A_TARGET_SELECTED && session.session==1);CHECK(!ack_enabled && !memcmp(mock_ieee,session.target.raw_ieee,8));
    action("REQUEST",4,2);CHECK(strstr(reply(),"session_mismatch") && !mock_transmits);action("REQUEST",5,1);CHECK(tx.state==1 && ack_enabled && session.request_once);CHECK(strstr(reply(),"class=association_request"));tx_service();CHECK(!mock_transmits);ot=oh;tx_service();CHECK(mock_transmits==1 && tx.state==2);CHECK(mock_sent[0]==21 && mock_sent[1]==0x23 && mock_sent[2]==0xc8);
    nrf_802154_transmitted_raw(tx.raw,NULL,0,0);tx_service();CHECK(tx.state==0 && session.state==A_WAIT_RESPONSE);CHECK(strstr(reply(),"local_tx_ok"));ot=oh;
    action("REQUEST",6,1);CHECK(strstr(reply(),"request_not_allowed") && mock_transmits==1);ot=oh;
    action("POLL",7,1);CHECK(strstr(reply(),"poll_too_soon"));ot=oh;now+=500000;action("POLL",8,1);CHECK(tx.state==1);ot=oh;tx_service();CHECK(mock_transmits==2 && mock_sent[0]==18 && mock_sent[1]==0x63 && mock_sent[2]==0xc8 && mock_sent[16]==4);
    respond(0,4);CHECK(!session.response_seen);ot=oh;respond(1,3);CHECK(!session.response_seen);ot=oh;respond(1,4);CHECK(session.response_seen && session.state==A_WAIT_RESPONSE);ot=oh;nrf_802154_transmitted_raw(tx.raw,NULL,0,0);tx_service();CHECK(session.state==A_ASSOCIATED);action("STATUS",9,1);CHECK(strstr(reply(),"ASSOCIATED_UNKEYED") && strstr(reply(),"application_tx=locked"));ot=oh;action("END",10,1);CHECK(!ack_enabled);ot=oh;begin(11);CHECK(strstr(reply(),"identity_or_attempt_used_this_boot"));
    reset();beacon(true);begin(1);ot=oh;now+=10000001;action("REQUEST",2,1);CHECK(strstr(reply(),"fresh_target_beacon_required") && !mock_transmits && !session.request_once);
    reset();beacon(true);begin(1);ot=oh;action("REQUEST",2,1);ot=oh;tx_service();nrf_802154_transmit_failed(tx.raw,NRF_802154_TX_ERROR_NO_ACK);tx_service();CHECK(session.state==A_UNCERTAIN);CHECK(strstr(reply(),"no_ack") && mock_transmits==1);
    reset();beacon(true);begin(1);ot=oh;action("REQUEST",2,1);ot=oh;mock_driver_ok=false;tx_service();CHECK(tx.state==1 && !mock_transmits);assoc_tick(&session,now+10000000);tx_service();CHECK(!tx.state && session.state==A_UNCERTAIN && !mock_transmits);
    reset();beacon(true);begin(1);ot=oh;action("REQUEST",2,1);ot=oh;tx_service();cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE);CHECK(!open && !ack_enabled && session.state==A_UNCERTAIN);nrf_802154_transmitted_raw(tx.raw,NULL,0,0);tx_service();CHECK(session.state==A_UNCERTAIN);cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN);action("REQUEST",3,1);CHECK(strstr(reply(),"request_not_allowed"));
    reset();beacon(true);begin(1);ot=oh;action("REQUEST",2,1);oh=ot+16;strcpy(line,"overflow\n");CHECK(!emit());CHECK(session.state==A_UNCERTAIN && !ack_enabled);tx_service();CHECK(!mock_transmits);
    reset();command("RADIOV3 INFO id=1");CHECK(strstr(reply(),"capability=association_only") && strstr(reply(),"commissioning=unkeyed"));ot=oh;command("RADIOV3 INFO id=1");CHECK(strstr(reply(),"id_reused"));ot=oh;command("RADIOV3 ASSOC STATUS boot=00000000000000000000000000000000 id=2 session=1");CHECK(strstr(reply(),"boot_mismatch"));
    reset();command("RADIOV3 INFO id=1");busy=true;char saved[ASSOC_LINE_MAX];strcpy(saved,output[ot%16]);cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE);CHECK(busy && oh==ot+1);cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN);command("RADIOV3 INFO id=2");CHECK(!strcmp(saved,output[ot%16]));cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_TX_DONE);CHECK(!busy && ot==1);
    reset();beacon(true);begin(1);ot=oh;action("REQUEST",2,1);ot=oh;mock_inline=true;tx_service();CHECK(mock_transmits==1 && tx.state==0 && session.state==A_WAIT_RESPONSE);CHECK(strstr(reply(),"local_tx_ok"));nrf_802154_transmitted_raw(tx.raw,NULL,0,0);CHECK(tx.state==0);
    reset();permit_fixture();begin_permit(1,3,0,true,boot);CHECK(strstr(reply(),"permit_hash_mismatch") && !session.session && !ack_enabled);
    ot=oh;begin_permit(2,4,0,false,boot);CHECK(strstr(reply(),"permit_revision_missing"));
    ot=oh;begin_permit(3,3,1,false,boot);CHECK(strstr(reply(),"permit_target_mismatch"));
    ot=oh;begin_permit(4,3,0,false,"00000000000000000000000000000000");CHECK(strstr(reply(),"boot_mismatch"));
    ot=oh;begin_permit(5,3,0,false,boot);CHECK(session.session==1 && session.state==A_TARGET_SELECTED && admission_zdo && !ack_enabled);CHECK(strstr(reply(),"admission_evidence=zdo_permit"));CHECK(permit_cache.records[0].used);
    ot=oh;action("REQUEST",6,1);CHECK(tx.state==1 && session.request_once && ack_enabled);ot=oh;tx_service();CHECK(mock_transmits==1 && mock_sent[1]==0x23 && mock_sent[2]==0xc8);nrf_802154_transmitted_raw(tx.raw,NULL,0,0);tx_service();CHECK(session.state==A_WAIT_RESPONSE);
    ot=oh;action("REQUEST",7,1);CHECK(strstr(reply(),"request_not_allowed") && mock_transmits==1);ot=oh;action("END",8,1);CHECK(!ack_enabled);ot=oh;begin_permit(9,3,0,false,boot);CHECK(strstr(reply(),"permit_evidence_used"));
    reset();permit_fixture();begin_permit(1,3,0,false,boot);ot=oh;now+=10000001;action("REQUEST",2,1);CHECK(strstr(reply(),"permit_evidence_stale") && !mock_transmits);
    reset();permit_fixture();begin_permit(1,3,0,false,boot);ot=oh;action("END",2,1);ot=oh;begin_permit(3,3,0,false,boot);CHECK(strstr(reply(),"permit_evidence_used"));
    reset();begin_permit(1,3,0,false,boot);CHECK(strstr(reply(),"permit_revision_missing") && !mock_transmits);
    reset();command("RADIOV3 ASSOC BEGIN_PERMIT_EVIDENCE id=1 PERMIT=1");CHECK(strstr(reply(),"unknown_or_duplicate_field") && !session.session);
    reset();permit_fixture();drops=1;begin_permit(1,3,0,false,boot);CHECK(strstr(reply(),"capture_loss_requires_reboot") && !session.session && !mock_transmits);
    reset();command("RADIOV3 INFO id=1");CHECK(strstr(reply(),"immediate_ack=0 pending_tx=0 session=0"));
    printf("MAIN checks=%u PASS\n",checks);return 0;
}
