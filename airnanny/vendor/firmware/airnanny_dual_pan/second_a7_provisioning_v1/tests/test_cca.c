/* Offline actual dispatcher + static queue/callback/filter ownership regression. */
#define COMMISSION_UNIT_TEST
#ifdef V6_BEHAVIOR
#include "../../raw_radio_v6_single_boot_commission/tests/firmware_cli.c"
#else
#include "firmware_cli.c"
#endif
#include "synthetic_dispatch.h"
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"line%d: %s\n",__LINE__,#x);exit(1);}}while(0)
static void reset_cca(void){
    memset(&session,0,sizeof(session));memset(&tx,0,sizeof(tx));memset(&permit_cache,0,sizeof(permit_cache));
    oh=ot=out_drop=last_id=0;busy=has_id=false;open=true;has_event=false;
    mock_revision=mock_drops=mock_transmits=mock_sleeps=mock_receives=0;mock_time=100000;mock_inline=true;
    mock_driver_ok=mock_sleep_ok=mock_receive_ok=true;set_ack(false);
    strcpy(boot,"11111111111111111111111111111111");gate_hw_session(&session);
}
static void invoke(const char *s){
    char converted[2048];strcpy(converted,s);
#ifdef V6_BEHAVIOR
    if(!strncmp(converted,"RADIOV7",7))converted[6]='6';
#endif
    if(!strncmp(s,"@RX ",4)){
        size_t n=strlen(s+4)/2;uint8_t raw[128]={0};raw[0]=n+2;memset(&event,0,sizeof(event));
        for(size_t i=0;i<n;i++)raw[i+1]=event.mac[i]=digit(s[4+2*i])*16+digit(s[5+2*i]);
        uint8_t received=126;bool clean=immediate_ack&&assoc_filter_part(raw,&received)==NRF_802154_RX_ERROR_NONE;
        event.length=n;event.session=session.association.session;event.revision=++mock_revision;event.time_us=mock_time;
        event.ack_started=event.ack_completed=clean;has_event=true;receive_service();
    }else if(!strncmp(s,"@TIME ",6))mock_time=strtoul(s+6,NULL,10);
    else command(converted);
    ot=oh;tx_service();ot=oh;
}
static void prepared(void){reset_cca();for(unsigned i=0;i<8;i++)invoke(scenario[i]);CHECK(session.phase==G_ASSOC);CHECK(session.association.local_ok);CHECK(mock_transmits==1);}
static void poll(unsigned id){char line[128];snprintf(line,sizeof(line),"RADIOV7 ASSOC POLL id=%u boot=11111111111111111111111111111111 session=1",id);invoke(line);}
static void failed(nrf_802154_tx_error_t e){CHECK(tx.state==2);nrf_802154_transmit_failed(tx.raw,e);CHECK(tx.state==3);ot=oh;tx_service();ot=oh;CHECK(tx.state==0);}
int main(void){
    prepared();mock_inline=false;poll(5);CHECK(tx.raw[3]==31);failed(NRF_802154_TX_ERROR_BUSY_CHANNEL);
#ifdef V6_BEHAVIOR
    CHECK(session.phase==G_STOPPED&&session.association.state==A_ERROR);unsigned count=mock_transmits;
    mock_time+=500000;poll(6);CHECK(mock_transmits==count);printf("V6 frozen second-poll forbidden checks=%u\n",checks);return 0;
#else
    CHECK(session.phase==G_ASSOC&&session.association.state==A_WAIT_RESPONSE);
    CHECK(session.association.polls==1&&session.association.poll_cca_retry);CHECK(immediate_ack);
    CHECK(session.keys.state==K_IDLE&&session.generation==3&&mock_transmits==2);
    unsigned count=mock_transmits;mock_time+=3199;poll(6);CHECK(mock_transmits==count&&session.association.polls==1);
    mock_time++;mock_inline=true;poll(7);CHECK(mock_transmits==count+1&&tx.raw[3]==32);
    CHECK(session.association.polls==2&&!session.association.poll_cca_retry);
    invoke(scenario[9]);CHECK(event.ack_started&&event.ack_completed);CHECK(session.association.state==A_ASSOCIATED);
    /* New short from exact response, no historic fallback, no radio restart. */
    char commit[2048];strcpy(commit,scenario[10]);char *id=strstr(commit,"id=6");CHECK(id);id[3]='8';invoke(commit);
    CHECK(session.phase==G_WAIT_KEY&&session.keys.short_address==0x1234);
    CHECK(mock_sleeps==1&&mock_receives==1);CHECK(!session.keys.used);
    /* Second CCA failure is terminal, third poll forbidden. */
    prepared();mock_inline=false;poll(5);failed(NRF_802154_TX_ERROR_BUSY_CHANNEL);mock_time+=3200;poll(6);
    failed(NRF_802154_TX_ERROR_BUSY_CHANNEL);CHECK(session.phase==G_STOPPED&&session.association.state==A_ERROR);
    count=mock_transmits;mock_time+=500000;poll(7);CHECK(mock_transmits==count&&session.association.polls==2);
    /* Response after failed poll cancels another submission and gets exact ACK. */
    prepared();mock_inline=false;poll(5);failed(NRF_802154_TX_ERROR_BUSY_CHANNEL);invoke(scenario[9]);
    CHECK(event.ack_started&&event.ack_completed&&session.association.state==A_ASSOCIATED);
    count=mock_transmits;mock_time+=3200;poll(6);CHECK(mock_transmits==count&&session.association.polls==1);
    /* Response already in RX queue before TXDONE remains accepted. */
    prepared();mock_inline=false;poll(5);invoke(scenario[9]);CHECK(session.association.response_seen);
    failed(NRF_802154_TX_ERROR_BUSY_CHANNEL);CHECK(session.association.state==A_ASSOCIATED&&session.phase==G_ASSOC);
    /* Non-CCA completions remain terminal, never retry. */
    nrf_802154_tx_error_t errors[]={NRF_802154_TX_ERROR_NO_ACK,NRF_802154_TX_ERROR_INVALID_ACK,NRF_802154_TX_ERROR_ABORTED};
    for(unsigned i=0;i<3;i++){prepared();mock_inline=false;poll(5);failed(errors[i]);CHECK(session.phase==G_STOPPED);
        count=mock_transmits;mock_time+=500000;poll(6);CHECK(mock_transmits==count);}
    prepared();mock_driver_ok=false;poll(5);CHECK(session.phase==G_STOPPED&&session.association.state==A_UNCERTAIN);
    /* Missing completion and USB close fail closed; no second TX. */
    prepared();mock_inline=false;poll(5);count=mock_transmits;mock_time+=2000001;ot=oh;tx_service();
    CHECK(session.phase==G_STOPPED);poll(6);CHECK(mock_transmits==count);
    prepared();mock_inline=false;poll(5);count=mock_transmits;cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE);
    mock_time+=3200;poll(6);CHECK(session.phase==G_STOPPED&&!immediate_ack&&mock_transmits==count);
    /* Request CCA must not enter poll recovery. */
    reset_cca();for(unsigned i=0;i<6;i++)invoke(scenario[i]);mock_inline=false;invoke(scenario[6]);
    failed(NRF_802154_TX_ERROR_BUSY_CHANNEL);CHECK(session.phase==G_STOPPED&&session.association.state==A_ERROR);
    count=mock_transmits;mock_time+=500000;poll(5);CHECK(mock_transmits==count);
    /* Deadline still wins even when one budget slot remains. */
    prepared();mock_inline=false;poll(5);failed(NRF_802154_TX_ERROR_BUSY_CHANNEL);mock_time=10100000;poll(6);
    CHECK(session.association.state==A_TIMEOUT&&mock_transmits==2);
    printf("V7 CCA dispatcher PASS checks=%u\n",checks);return 0;
#endif
}
