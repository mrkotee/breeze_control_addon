/* Dedicated MAC association gate. Never processes secured/application payloads. */
#include "gate_events.h"
#include "permit_binding.h"
#ifdef ASSOC_HOST_TEST
#include "assoc_main_mock.h"
#else
#include "nrf.h"
#include "nrf_802154.h"
#include "app_usbd.h"
#include "app_usbd_cdc_acm.h"
#include "app_usbd_serial_num.h"
#include "nrf_drv_clock.h"
#include "app_error.h"
#endif
#include <stdio.h>
#include <string.h>
static void cdc_event(app_usbd_class_inst_t const *,app_usbd_cdc_acm_user_event_t);
APP_USBD_CDC_ACM_GLOBAL_DEF(cdc,cdc_event,0,1,NRF_DRV_USBD_EPIN2,NRF_DRV_USBD_EPIN1,NRF_DRV_USBD_EPOUT1,APP_USBD_CDC_COMM_PROTOCOL_AT_V250);
static char input[ASSOC_COMMAND_MAX],pending_command[ASSOC_COMMAND_MAX],boot[33],line[ASSOC_LINE_MAX];
static char output[16][ASSOC_LINE_MAX];static uint32_t oh,ot,out_drop,last_id;
static uint8_t byte;static size_t input_length;
static bool open,busy,discard,command_pending,has_id,line_error,command_overflow;
static assoc_t session;
static permit_cache_t permit_cache;
static bool admission_zdo;
static bool immediate_ack;
static void set_ack(bool value){immediate_ack=value;nrf_802154_auto_ack_set(value);}
static uint32_t admission_revision,admission_generation;
static uint8_t used_ieee[8][8];static char used_attempt[8][33];static unsigned used_count;
typedef struct {bool valid;assoc_beacon_t b;uint32_t revision,time;} observed_t;
static observed_t beacons[8];
typedef struct {uint8_t raw[128];uint32_t id,session,start_us;assoc_tx_kind_t kind;volatile uint8_t state;assoc_tx_result_t result;} tx_t;
static tx_t tx;
static uint32_t irq_lock(void){uint32_t p=__get_PRIMASK();__disable_irq();return p;}
static void irq_unlock(uint32_t p){__DMB();__set_PRIMASK(p);}
static void stop_loss(void)
{uint32_t p=irq_lock();if(session.session)session.state=session.request_once?A_UNCERTAIN:A_ERROR;irq_unlock(p);set_ack(false);}
static bool emit(void)
{
    if(oh-ot==16){if(out_drop!=UINT32_MAX)out_drop++;stop_loss();return false;}
    memcpy(output[oh%16],line,strlen(line)+1);oh++;return true;
}
static void hex_le(const uint8_t *a,size_t n,char *out,bool canonical)
{static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){uint8_t v=a[canonical?n-1-i:i];out[2*i]=h[v>>4];out[2*i+1]=h[v&15];}out[2*n]=0;}
static void random_boot(void)
{
    uint8_t a[16];NRF_RNG->CONFIG=1;NRF_RNG->TASKS_START=1;
    for(unsigned i=0;i<16;i++){unsigned budget=1000000;while(!NRF_RNG->EVENTS_VALRDY && --budget){}if(!budget)APP_ERROR_HANDLER(NRF_ERROR_TIMEOUT);a[i]=(uint8_t)NRF_RNG->VALUE;NRF_RNG->EVENTS_VALRDY=0;}
    NRF_RNG->TASKS_STOP=1;hex_le(a,16,boot,false);
}
static observed_t *find_beacon(uint16_t pan)
{for(unsigned i=0;i<8;i++)if(beacons[i].valid && beacons[i].b.pan==pan)return &beacons[i];return NULL;}
static const char *permit(const assoc_target_t *t,uint32_t revision,bool exact)
{
    observed_t *o=find_beacon(t->pan);
    if(!o || (exact && o->revision!=revision) || (uint32_t)(gate_hw_now_us()-o->time)>10000000)return "fresh_target_beacon_required";
    if(memcmp(o->b.extpan,t->extpan,8) || o->b.source_short!=0 || !o->b.coordinator)return "target_beacon_mismatch";
    if(!o->b.permit || !o->b.end_capacity)return "association_not_permitted";
    return NULL;
}
static void status(uint32_t id)
{
    char raw_ieee[17],coordinator[17],extpan[17];hex_le(session.target.raw_ieee,8,raw_ieee,true);hex_le(session.target.coordinator_ieee,8,coordinator,true);hex_le(session.target.extpan,8,extpan,true);
    snprintf(line,sizeof(line),"RADIOV3 STATUS boot=%s id=%lu session=%lu ctx=%u raw_ieee=%s target_pan=%04x extpan=%s coordinator_ieee=%s state=%s request_once=%u local_tx_ok=%u polls=%lu max_polls=%lu pending=%u response_seen=%u association_status=%u assigned_short=%04x response_revision=%lu rx_revision=%lu rx_drop=%lu out_drop=%lu crc_error=%lu commissioning=unkeyed application_tx=locked\n",boot,(unsigned long)id,(unsigned long)session.session,session.target.ctx,raw_ieee,session.target.pan,extpan,coordinator,assoc_state_name(session.state),session.request_once,session.local_ok,(unsigned long)session.polls,(unsigned long)session.target.max_polls,session.tx_pending,session.response_seen,session.result.status,session.result.short_address,(unsigned long)session.result.rx_revision,(unsigned long)gate_hw_revision(),(unsigned long)gate_hw_dropped(),(unsigned long)out_drop,(unsigned long)gate_hw_crc_errors());emit();
}
static void command(const char *str)
{
    assoc_command_t c;const char *error=assoc_command_parse(str,&c);
    if(error){snprintf(line,sizeof(line),"RADIOV3 ERROR boot=%s reason=%s\n",boot,error);emit();return;}
    if(c.kind!=C_INFO && strcmp(c.boot,boot))error="boot_mismatch";
    else if(has_id && c.id<=last_id)error="id_reused";
    if(error){snprintf(line,sizeof(line),"RADIOV3 ERROR boot=%s id=%lu reason=%s\n",boot,(unsigned long)c.id,error);emit();return;}
    has_id=true;last_id=c.id;
    if(c.kind==C_INFO){snprintf(line,sizeof(line),"RADIOV3 INFO boot=%s id=%lu identity=airnanny_raw_assoc_permit_v4 version=4 capability=association_only commissioning=unkeyed application_tx=locked channel=21 role_capability=80 permit_gate=beacon_or_authenticated_zdo transport_key=unsupported device_announce=unsupported immediate_ack=%u pending_tx=%u session=%lu rx_revision=%lu rx_drop=%lu out_drop=%lu timing=unvalidated\n",boot,(unsigned long)c.id,(unsigned)immediate_ack,(unsigned)(tx.state || session.tx_pending),(unsigned long)session.session,(unsigned long)gate_hw_revision(),(unsigned long)gate_hw_dropped(),(unsigned long)out_drop);emit();return;}
    if(c.kind==C_BEGIN || c.kind==C_BEGIN_PERMIT){
        if(out_drop || gate_hw_dropped())error="capture_loss_requires_reboot";
        else if(assoc_active(&session) || tx.state || session.tx_pending)error="session_or_tx_busy";
        else if(session.session==UINT32_MAX || used_count==8)error="boot_attempt_limit";
        else if(gate_hw_revision()==UINT32_MAX)error="revision_exhausted";
        else error=c.kind==C_BEGIN?permit(&c.target,c.beacon_revision,true):permit_binding_check(&permit_cache,&c.target,c.permit_revision,c.raw_hash,c.validation_generation,gate_hw_now_us(),false);
        for(unsigned i=0;!error && i<used_count;i++)if(!memcmp(c.target.raw_ieee,used_ieee[i],8) || !strcmp(c.attempt,used_attempt[i]))error="identity_or_attempt_used_this_boot";
        if(!error){
            set_ack(false);
            if(c.kind==C_BEGIN_PERMIT){error=permit_binding_check(&permit_cache,&c.target,c.permit_revision,c.raw_hash,c.validation_generation,gate_hw_now_us(),true);}
            if(error){}
            else if(!nrf_802154_sleep() || nrf_802154_state_get()!=NRF_802154_STATE_SLEEP)error="radio_busy_retry_begin_only";
            else{
                uint32_t p=irq_lock();error=assoc_begin(&session,&c.target,session.session+1);irq_unlock(p);
                if(!error){admission_zdo=c.kind==C_BEGIN_PERMIT;admission_revision=c.permit_revision;admission_generation=c.validation_generation;memcpy(used_ieee[used_count],c.target.raw_ieee,8);memcpy(used_attempt[used_count++],c.attempt,33);nrf_802154_extended_address_set(c.target.raw_ieee);uint8_t pan[]={c.target.pan,c.target.pan>>8};nrf_802154_pan_id_set(pan);uint8_t short_address[]={0xff,0xff};nrf_802154_short_address_set(short_address);}
                if(!nrf_802154_receive()){error="receive_start_failed";stop_loss();}
            }
        }
        if(!error){snprintf(line,sizeof(line),"RADIOV3 BEGIN boot=%s id=%lu session=%lu ctx=%u state=TARGET_SELECTED attempt=%s capability=80 polling=manual max_polls=%lu poll_interval_ms=%lu timeout_ms=%lu beacon_revision=%lu admission_evidence=%s permit_revision=%lu validation_generation=%lu timing=unvalidated\n",boot,(unsigned long)c.id,(unsigned long)session.session,c.target.ctx,c.attempt,(unsigned long)c.target.max_polls,(unsigned long)c.target.poll_interval_ms,(unsigned long)c.target.timeout_ms,(unsigned long)c.beacon_revision,admission_zdo?"zdo_permit":"beacon",(unsigned long)admission_revision,(unsigned long)admission_generation);emit();return;}
    }else if(c.session!=session.session || !session.session)error="session_mismatch";
    else if(c.kind==C_STATUS){status(c.id);return;}
    else if(c.kind==C_END){uint32_t p=irq_lock();assoc_cancel(&session);irq_unlock(p);set_ack(false);status(c.id);return;}
    else{
        if(tx.state)error="tx_busy";
        else if(c.kind==C_REQUEST)error=admission_zdo?permit_binding_recheck(&permit_cache,&session.target,admission_revision,gate_hw_now_us()):permit(&session.target,0,false);
        size_t n=0;
        if(!error){uint32_t p=irq_lock();
            error=c.kind==C_REQUEST?assoc_request(&session,gate_hw_now_us(),gate_hw_revision(),tx.raw+1,125,&n):assoc_poll(&session,gate_hw_now_us(),tx.raw+1,125,&n);
            if(!error){tx.raw[0]=(uint8_t)(n+2);tx.id=c.id;tx.session=session.session;tx.kind=session.tx_kind;tx.start_us=gate_hw_now_us();tx.state=1;}irq_unlock(p);}
        if(!error){char mac[251];hex_le(tx.raw+1,n,mac,false);set_ack(true);snprintf(line,sizeof(line),"RADIOV3 TXACCEPT boot=%s id=%lu session=%lu class=%s mac=%s ar=1 retry=0\n",boot,(unsigned long)c.id,(unsigned long)session.session,c.kind==C_REQUEST?"association_request":"extended_data_request",mac);emit();return;}
    }
    snprintf(line,sizeof(line),"RADIOV3 ERROR boot=%s id=%lu session=%lu reason=%s\n",boot,(unsigned long)c.id,(unsigned long)session.session,error?error:"internal");emit();
}
static void tx_service(void)
{
    if(tx.state==1 && (session.state==A_UNCERTAIN || session.state==A_CANCELLED || session.state==A_ERROR || !open)){
        tx.result=ATX_ABORTED;tx.state=3;
    }
    if(tx.state==1 && !busy && oh==ot){
        tx.state=2; /* immutable buffer published before driver; callback can be synchronous */
        if(!nrf_802154_transmit_raw(tx.raw,true) && tx.state==2)tx.state=1;
    }
    if(tx.state==3){
        uint32_t p=irq_lock();assoc_tx_result_t r=tx.result;assoc_local_done(&session,r);irq_unlock(p);
        snprintf(line,sizeof(line),"RADIOV3 TXDONE boot=%s id=%lu session=%lu result=%s ar=1 retry=0\n",boot,(unsigned long)tx.id,(unsigned long)tx.session,assoc_tx_name(r));emit();tx.state=0;
    }
}
void nrf_802154_transmitted_raw(const uint8_t *p,uint8_t *ack,int8_t r,uint8_t l)
{(void)r;(void)l;if(p==tx.raw && tx.state==2){tx.result=ATX_OK;__DMB();tx.state=3;}if(ack)nrf_802154_buffer_free_raw(ack);}
void nrf_802154_transmit_failed(const uint8_t *p,nrf_802154_tx_error_t e)
{
    if(p!=tx.raw || tx.state!=2)return;
    switch(e){case NRF_802154_TX_ERROR_NO_ACK:tx.result=ATX_NO_ACK;break;case NRF_802154_TX_ERROR_BUSY_CHANNEL:tx.result=ATX_CCA_FAIL;break;case NRF_802154_TX_ERROR_INVALID_ACK:tx.result=ATX_INVALID_ACK;break;case NRF_802154_TX_ERROR_ABORTED:tx.result=ATX_ABORTED;break;default:tx.result=ATX_ERROR;}
    __DMB();tx.state=3;
}
static void receive_service(void)
{
    gate_event_t e;if(!gate_hw_pop(&e))return;
    permit_cache_observe(&permit_cache,e.mac,e.length,e.revision,e.time_us);
    assoc_beacon_t b;if(assoc_beacon_parse(e.mac,e.length,&b)){
        observed_t *o=find_beacon(b.pan);if(!o){for(unsigned i=0;i<8;i++)if(!beacons[i].valid){o=&beacons[i];break;}}
        if(o){o->valid=true;o->b=b;o->revision=e.revision;o->time=e.time_us;}
        char ext[17];hex_le(b.extpan,8,ext,true);snprintf(line,sizeof(line),"RADIOV3 BEACON boot=%s revision=%lu channel=21 pan=%04x extpan=%s coordinator_short=%04x coordinator_ieee=unknown association_permit=%u coordinator=%u end_capacity=%u router_capacity=%u time_us=%lu\n",boot,(unsigned long)e.revision,b.pan,ext,b.source_short,b.permit,b.coordinator,b.end_capacity,b.router_capacity,(unsigned long)e.time_us);if(open)emit();
    }
    if(e.session==session.session){uint32_t p=irq_lock();bool accepted=assoc_observe(&session,e.mac,e.length,e.revision);irq_unlock(p);
        if(accepted){snprintf(line,sizeof(line),"RADIOV3 RESPONSE boot=%s session=%lu revision=%lu status=%u assigned_short=%04x dsn=%u state=%s ack_started=%u ack_completed=%u deadline_miss=%u\n",boot,(unsigned long)session.session,(unsigned long)e.revision,session.result.status,session.result.short_address,session.result.dsn,assoc_state_name(session.state),e.ack_started,e.ack_completed,e.deadline_miss);if(open)emit();}}
    char mac[251];hex_le(e.mac,e.length,mac,false);snprintf(line,sizeof(line),"RADIOV3 RX boot=%s session=%lu revision=%lu channel=21 time_us=%lu rssi=%d lqi=%u fcs_ok=1 ack_started=%u ack_completed=%u deadline_miss=%u mac=%s\n",boot,(unsigned long)e.session,(unsigned long)e.revision,(unsigned long)e.time_us,e.rssi,e.lqi,e.ack_started,e.ack_completed,e.deadline_miss,mac);if(open)emit();
}
static void cdc_event(app_usbd_class_inst_t const *inst,app_usbd_cdc_acm_user_event_t event)
{
    (void)inst;
    if(event==APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN){open=true;input_length=0;discard=false;app_usbd_cdc_acm_read(&cdc,&byte,1);}
    else if(event==APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE){
        open=false;command_pending=false;input_length=0;discard=false;
        /* Keep the asynchronous CDC buffer immutable until TX_DONE. If abort produces
           no completion, the transport fails closed and needs a device reboot. */
        oh=busy?ot+1:ot;
        assoc_cancel(&session);set_ack(false);
    }
    else if(event==APP_USBD_CDC_ACM_USER_EVT_TX_DONE){busy=false;if(ot!=oh)ot++;}
    else if(event==APP_USBD_CDC_ACM_USER_EVT_RX_DONE){do{
        if(byte=='\r' || byte=='\n'){
            if(discard)line_error=true;
            else if(input_length){input[input_length]=0;if(command_pending)command_overflow=true;else{memcpy(pending_command,input,input_length+1);command_pending=true;}}
            input_length=0;discard=false;
        }else if(byte<32 || byte>126)discard=true;
        else if(input_length<sizeof(input)-1 && !discard)input[input_length++]=(char)byte;
        else discard=true;
    }while(app_usbd_cdc_acm_read(&cdc,&byte,1)==NRF_SUCCESS);}
}
static void usb_event(app_usbd_event_type_t e)
{
    if(e==APP_USBD_EVT_POWER_DETECTED){if(!nrf_drv_usbd_is_enabled())app_usbd_enable();}
    else if(e==APP_USBD_EVT_POWER_READY)app_usbd_start();
    else if(e==APP_USBD_EVT_POWER_REMOVED){open=false;assoc_cancel(&session);set_ack(false);app_usbd_stop();}
    else if(e==APP_USBD_EVT_STOPPED)app_usbd_disable();
}
void nrf_802154_received_timestamp_raw(uint8_t *p,int8_t r,uint8_t l,uint32_t ts){(void)ts;gate_hw_receive(p,r,l);}
void nrf_802154_tx_ack_started(const uint8_t *p){(void)p;gate_hw_ack_started();}
void nrf_802154_receive_failed(nrf_802154_rx_error_t e){if(e==NRF_802154_RX_ERROR_INVALID_FCS)gate_hw_crc_error();}
int main(void)
{
    static const app_usbd_config_t usb={.ev_state_proc=usb_event};APP_ERROR_CHECK(nrf_drv_clock_init());app_usbd_serial_num_generate();
    APP_ERROR_CHECK(app_usbd_init(&usb));APP_ERROR_CHECK(app_usbd_class_append(app_usbd_cdc_acm_class_inst_get(&cdc)));
    assoc_init(&session);random_boot();nrf_802154_init();nrf_802154_channel_set(21);set_ack(false);nrf_802154_promiscuous_set(true);gate_hw_session(&session);gate_hw_init();nrf_802154_receive();APP_ERROR_CHECK(app_usbd_power_events_enable());
    uint32_t last_drop=0,last_clock=gate_hw_now_us();
    for(;;){
        app_usbd_event_queue_process();
        uint32_t clock=gate_hw_now_us();
        if(clock<last_clock){memset(beacons,0,sizeof(beacons));permit_cache_clear(&permit_cache);stop_loss();}
        last_clock=clock;
        uint32_t p=irq_lock();assoc_tick(&session,clock);irq_unlock(p);
        uint32_t drop=gate_hw_dropped();if(drop!=last_drop){last_drop=drop;stop_loss();}
        if(!assoc_active(&session))set_ack(false);
        tx_service();receive_service();
        if(open && oh-ot<12){
            if(line_error || command_overflow){line_error=command_overflow=command_pending=false;snprintf(line,sizeof(line),"RADIOV3 ERROR boot=%s reason=input_overflow_or_nonascii\n",boot);emit();stop_loss();}
            else if(command_pending){command_pending=false;command(pending_command);}
        }
        if(open && !busy && oh!=ot && app_usbd_cdc_acm_write(&cdc,output[ot%16],strlen(output[ot%16]))==NRF_SUCCESS)busy=true;
    }
}
