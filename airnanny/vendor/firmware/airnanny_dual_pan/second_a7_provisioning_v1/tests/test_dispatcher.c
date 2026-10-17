/* Actual V6 dispatcher, callbacks, filter; offline FakeRadio only. */
#define COMMISSION_UNIT_TEST
#include "firmware_cli.c"
#include "synthetic_dispatch.h"
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"line%d: %s\n",__LINE__,#x);exit(1);}}while(0)
static void reset(void){
    memset(&session,0,sizeof(session));memset(&tx,0,sizeof(tx));memset(&permit_cache,0,sizeof(permit_cache));
    oh=ot=out_drop=last_id=0;busy=has_id=false;open=true;has_event=false;
    mock_revision=mock_drops=mock_transmits=mock_sleeps=mock_receives=0;mock_time=100000;mock_inline=true;
    mock_driver_ok=mock_sleep_ok=mock_receive_ok=true;set_ack(false);
    strcpy(boot,"11111111111111111111111111111111");gate_hw_session(&session);
}
static void feed(const char *s){
    if(!strncmp(s,"@RX ",4)){
        size_t n=strlen(s+4)/2;uint8_t raw[128]={0};raw[0]=n+2;memset(&event,0,sizeof(event));
        for(size_t i=0;i<n;i++)raw[i+1]=event.mac[i]=digit(s[4+2*i])*16+digit(s[5+2*i]);
        uint8_t received=126;bool clean=immediate_ack&&assoc_filter_part(raw,&received)==NRF_802154_RX_ERROR_NONE;
        event.length=n;event.session=session.association.session;event.revision=++mock_revision;event.time_us=mock_time;
        event.ack_started=event.ack_completed=clean;has_event=true;receive_service();
    }else if(!strncmp(s,"@TIME ",6))mock_time=strtoul(s+6,NULL,10);
    else command(s);
    ot=oh;tx_service();ot=oh;
}
static void ready(void){reset();for(unsigned i=0;i<sizeof(scenario)/sizeof(*scenario)-1;i++)feed(scenario[i]);CHECK(session.phase==G_KEY);}
int main(void){
    ready();CHECK(session.association.session==1&&session.keys.session==1);CHECK(session.keys.short_address==0x1234);
    CHECK(mock_sleeps==1&&mock_receives==1); /* Only pre-request V4 address setup: NO RX restart across response/key. */
    unsigned count=mock_transmits;feed(scenario[sizeof(scenario)/sizeof(*scenario)-1]);CHECK(mock_transmits==count+1&&session.phase==G_MANAGEMENT);
    const char *ann=scenario[sizeof(scenario)/sizeof(*scenario)-1];commission_command_t command_value;
    CHECK(!commission_parse(ann,&command_value));
    for(unsigned i=0;i<55;i++){
        ready();commission_command_t c=command_value;c.key.mac[i]^=1;uint8_t out[55];
        CHECK(commission_announce(&session,&c,mock_time,out));CHECK(!session.keys.used);
    }
    const unsigned visible[]={0,1,3,4,5,6,7,8,9,10,11,12,13,14,15,17,18,19,20,21,22,23,24,25,26,27,28,29,30};
    for(unsigned i=0;i<sizeof(visible)/sizeof(*visible);i++){
        ready();commission_command_t c=command_value;c.key.mac[visible[i]]^=1;permit_hash(c.key.mac,55,c.key.hash);uint8_t out[55];
        CHECK(commission_announce(&session,&c,mock_time,out));CHECK(!session.keys.used);
    }
    ready();mock_driver_ok=false;feed(ann);CHECK(session.phase==G_ANNOUNCE_UNCERTAIN&&session.keys.used);count=mock_transmits;tx_service();CHECK(mock_transmits==count);
    ready();mock_inline=false;command(ann);CHECK(tx.state==1);uint8_t saved[128];memcpy(saved,tx.raw,sizeof(saved));
    command(ann);CHECK(!memcmp(saved,tx.raw,sizeof(saved)));ot=oh;tx_service();CHECK(tx.state==2);
    nrf_802154_transmitted_raw(saved,NULL,0,0);CHECK(tx.state==2); /* foreign callback can't own static buffer */
    nrf_802154_transmitted_raw(tx.raw,NULL,0,0);CHECK(tx.state==3);tx_service();CHECK(session.phase==G_MANAGEMENT);
    ready();command(ann);ot=oh;busy=true;count=mock_transmits;tx_service();CHECK(mock_transmits==count&&tx.state==1);
    mock_time+=2000001;tx_service();CHECK(!tx.state&&session.phase==G_STOPPED);CHECK(mock_transmits==count);
    ready();command(ann);ot=oh;cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE);tx_service();CHECK(session.phase==G_STOPPED&&!immediate_ack);
    reset();oh=16;ot=0;strcpy(line,"overflow\n");emit();CHECK(out_drop==1&&session.phase==G_STOPPED);
    /* Exact V4 response ACK envelope, all FCFs, preserved stage ownership. */
    reset();session.phase=G_ASSOC;session.association.state=A_WAIT_RESPONSE;
    session.association.target.pan=0x0b7a;
    const uint8_t me[]={0x37,0x14,0xa4,0x75,0xbb,0x56,0x7a,0x02},tc[]={0x5f,0x87,0xa1,0x36,0,0x4b,0x12,0};
    memcpy(session.association.target.raw_ieee,me,8);memcpy(session.association.target.coordinator_ieee,tc,8);
    uint8_t response[128]={27,0x63,0xcc,1,0x9b,0xfa};memcpy(response+6,me,8);memcpy(response+14,tc,8);response[22]=2;response[23]=0x34;response[24]=0x12;
    uint8_t received=3;CHECK(assoc_filter_part(response,&received)==NRF_802154_RX_ERROR_NONE&&received==26);
    for(unsigned f=0;f<65536;f++){response[1]=f;response[2]=f>>8;received=26;CHECK((assoc_filter_part(response,&received)==NRF_802154_RX_ERROR_NONE)==(f==0xcc63));}
    /* Deterministic parser fuzz cannot create transmission permissions. */
    reset();uint32_t seed=0x12345678;char fuzz[1024];
    for(unsigned j=0;j<50000;j++){
        seed=seed*1664525u+1013904223u;unsigned n=seed%1024;
        for(unsigned i=0;i<n;i++){seed=seed*1664525u+1013904223u;fuzz[i]=(char)(32+(seed%95));}fuzz[n]=0;
        command(fuzz);ot=oh;CHECK(mock_transmits==0&&!tx.state&&session.phase==G_IDLE);
    }
    printf("V6 dispatcher PASS checks=%u fuzz=50000 fcf=65536\n",checks);return 0;
}
