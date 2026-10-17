/* Single-boot narrow V4/V5 commissioning transport. Host-only crypto. */
#include "gate_events.h"
#include "commission.h"
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
static commission_t session;
static permit_cache_t permit_cache;
static uint32_t admission_revision;
static bool immediate_ack;
static void set_ack(bool value){immediate_ack=value;nrf_802154_auto_ack_set(value);}
typedef struct {uint8_t raw[128];uint32_t id,session,start_us;unsigned kind;volatile uint8_t state;assoc_tx_result_t result;} tx_t;
static tx_t tx;
static uint32_t irq_lock(void){uint32_t p=__get_PRIMASK();__disable_irq();return p;}
static void irq_unlock(uint32_t p){__DMB();__set_PRIMASK(p);}
static void stop_loss(void)
{uint32_t p=irq_lock();commission_stop(&session);irq_unlock(p);set_ack(false);}
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
static void status(uint32_t id)
{
    snprintf(line,sizeof(line),"RADIOV7 STATUS boot=%s id=%lu session=%lu state=%s association_state=%s key_state=%s generation=%lu assigned_short=%04x polls=%lu pending=%u used=%u immediate_ack=%u application_tx=locked rx_revision=%lu rx_drop=%lu out_drop=%lu crc_error=%lu\n",boot,(unsigned long)id,(unsigned long)session.association.session,commission_name(session.phase),assoc_state_name(session.association.state),key_name(session.keys.state),(unsigned long)session.generation,session.association.result.short_address,(unsigned long)session.keys.polls,tx.state!=0,session.keys.used,immediate_ack,(unsigned long)gate_hw_revision(),(unsigned long)gate_hw_dropped(),(unsigned long)out_drop,(unsigned long)gate_hw_crc_errors());emit();
}
static void command(const char *str)
{
    commission_command_t c;const char *error=commission_parse(str,&c);
    if(error){snprintf(line,sizeof(line),"RADIOV7 ERROR boot=%s reason=%s\n",boot,error);emit();return;}
    if(c.kind!=GC_INFO && strcmp(c.boot,boot))error="boot_mismatch";
    else if(has_id && c.id<=last_id)error="id_reused";
    if(error)goto fail;
    has_id=true;last_id=c.id;
    if(c.kind==GC_INFO){snprintf(line,sizeof(line),"RADIOV7 INFO boot=%s id=%lu identity=airnanny_ctx1_commission_v7 version=7 channel=21 application_tx=locked role_capability=80 crypto=host_only immediate_ack=%u pending_tx=%u session=%lu rx_revision=%lu rx_drop=%lu out_drop=%lu baseline_current_a7=%u permit_ready=%u timing=unvalidated\n",boot,(unsigned long)c.id,immediate_ack,tx.state!=0,(unsigned long)session.association.session,(unsigned long)gate_hw_revision(),(unsigned long)gate_hw_dropped(),(unsigned long)out_drop,session.phase>=G_BASELINE&&session.phase!=G_STOPPED,session.phase==G_ASSOC);emit();return;}
    if(c.kind==GC_STATUS){status(c.id);return;}
    if(c.kind==GC_END){if(c.session!=session.association.session){error="session_mismatch";goto fail;}stop_loss();status(c.id);return;}
    if(out_drop||gate_hw_dropped()||gate_hw_revision()==UINT32_MAX){error="capture_loss_requires_reboot";goto fail;}
    if(tx.state){error="tx_busy";goto fail;}
    if(c.kind==GC_ASSOC && c.association.kind==C_BEGIN_PERMIT){
        assoc_command_t *a=&c.association;
        error=permit_binding_check(&permit_cache,&a->target,a->permit_revision,a->raw_hash,a->validation_generation,gate_hw_now_us(),false);
        if(!error){uint32_t p=irq_lock();error=commission_begin(&session,a);irq_unlock(p);}
        if(error)goto fail;
        set_ack(false);
        error=permit_binding_check(&permit_cache,&a->target,a->permit_revision,a->raw_hash,a->validation_generation,gate_hw_now_us(),true);
        if(!error && (!nrf_802154_sleep() || nrf_802154_state_get()!=NRF_802154_STATE_SLEEP))error="radio_busy_no_retry";
        if(!error){
            admission_revision=a->permit_revision;
            nrf_802154_extended_address_set(a->target.raw_ieee);
            uint8_t pan[]={a->target.pan,a->target.pan>>8},short_address[]={255,255};
            nrf_802154_pan_id_set(pan);nrf_802154_short_address_set(short_address);
            if(!nrf_802154_receive())error="receive_start_failed";
        }
        if(error){stop_loss();goto fail;}
        status(c.id);return;
    }
    uint32_t p=irq_lock();size_t n=0;unsigned kind=0;
    if(c.kind==GC_BASELINE)error=commission_baseline(&session,&c,gate_hw_revision());
    else if(c.kind==GC_ARM)error=commission_arm(&session,&c,gate_hw_revision());
    else if(c.kind==GC_COMMIT){
        error=commission_commit(&session,&c,gate_hw_now_us());
        if(!error){uint8_t address[]={session.keys.short_address,session.keys.short_address>>8};nrf_802154_short_address_set(address);}
        /* Deliberately no sleep(), END, receive restart or USB reopen here. */
    }else if(c.kind==GC_KEY)error=commission_key(&session,&c);
    else if(c.kind==GC_ASSOC){
        assoc_command_t *a=&c.association;
        if(c.session!=session.association.session||session.phase!=G_ASSOC)error="association_session";
        else if(a->kind==C_REQUEST){
            error=permit_binding_recheck(&permit_cache,&session.association.target,admission_revision,gate_hw_now_us());
            if(!error)error=assoc_request(&session.association,gate_hw_now_us(),gate_hw_revision(),tx.raw+1,125,&n);
        }else{kind=1;error=assoc_poll(&session.association,gate_hw_now_us(),tx.raw+1,125,&n);}
    }else if(c.kind==GC_POLL){kind=2;n=10;error=commission_poll(&session,&c,gate_hw_now_us(),tx.raw+1);}
    else if(c.kind==GC_ANNOUNCE){kind=3;n=55;error=commission_announce(&session,&c,gate_hw_now_us(),tx.raw+1);}
    else error="verb";
    if(!error&&n){tx.raw[0]=n+2;tx.id=c.id;tx.session=session.association.session;tx.kind=kind;tx.start_us=gate_hw_now_us();tx.state=1;}
    irq_unlock(p);
    if(!error&&n){char mac[251];const char *classes[]={"ASSOCIATION_REQUEST","ASSOCIATION_EXT_POLL","POST_ASSOC_KEY_POLL","DEVICE_ANNOUNCE"};hex_le(tx.raw+1,n,mac,false);set_ack(true);snprintf(line,sizeof(line),"RADIOV7 TXACCEPT boot=%s id=%lu session=%lu class=%s mac=%s retry=0\n",boot,(unsigned long)c.id,(unsigned long)tx.session,classes[kind],mac);emit();return;}
    if(!error){status(c.id);return;}
fail:
    snprintf(line,sizeof(line),"RADIOV7 ERROR boot=%s id=%lu reason=%s\n",boot,(unsigned long)c.id,error?error:"internal");emit();
}
static void tx_service(void)
{
    if(tx.state && (uint32_t)(gate_hw_now_us()-tx.start_us)>2000000u){stop_loss();if(tx.state==1){tx.result=ATX_ABORTED;tx.state=3;}}
    if(tx.state==1 && (session.phase==G_STOPPED || !open)){tx.result=ATX_ABORTED;tx.state=3;}
    if(tx.state==1 && !busy && oh==ot){
        tx.state=2;
        /* V5 fail-closed queue behavior for ALL classes; never retry driver reject. */
        if(!nrf_802154_transmit_raw(tx.raw,true) && tx.state==2){tx.result=ATX_ERROR;tx.state=3;}
    }
    if(tx.state==3){uint32_t p=irq_lock();commission_done(&session,tx.kind,tx.result);irq_unlock(p);snprintf(line,sizeof(line),"RADIOV7 TXDONE boot=%s id=%lu session=%lu result=%s management_complete=0 application_tx=locked\n",boot,(unsigned long)tx.id,(unsigned long)tx.session,assoc_tx_name(tx.result));emit();tx.state=0;}
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
    if(e.session==session.association.session){uint32_t p=irq_lock();bool accepted=commission_observe(&session,e.mac,e.length,e.revision,e.ack_started&&e.ack_completed&&!e.deadline_miss);irq_unlock(p);
        if(accepted){snprintf(line,sizeof(line),"RADIOV7 RESPONSE boot=%s session=%lu revision=%lu status=%u assigned_short=%04x ack_started=%u ack_completed=%u deadline_miss=%u\n",boot,(unsigned long)e.session,(unsigned long)e.revision,session.association.result.status,session.association.result.short_address,e.ack_started,e.ack_completed,e.deadline_miss);if(open)emit();}}
    char mac[251];hex_le(e.mac,e.length,mac,false);snprintf(line,sizeof(line),"RADIOV7 RX boot=%s session=%lu revision=%lu channel=21 time_us=%lu rssi=%d lqi=%u fcs_ok=1 ack_started=%u ack_completed=%u deadline_miss=%u mac=%s\n",boot,(unsigned long)e.session,(unsigned long)e.revision,(unsigned long)e.time_us,e.rssi,e.lqi,e.ack_started,e.ack_completed,e.deadline_miss,mac);if(open)emit();
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
        stop_loss();set_ack(false);
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
    else if(e==APP_USBD_EVT_POWER_REMOVED){open=false;stop_loss();set_ack(false);app_usbd_stop();}
    else if(e==APP_USBD_EVT_STOPPED)app_usbd_disable();
}
void nrf_802154_received_timestamp_raw(uint8_t *p,int8_t r,uint8_t l,uint32_t ts){(void)ts;gate_hw_receive(p,r,l);}
void nrf_802154_tx_ack_started(const uint8_t *p){(void)p;gate_hw_ack_started();}
void nrf_802154_receive_failed(nrf_802154_rx_error_t e){if(e==NRF_802154_RX_ERROR_INVALID_FCS)gate_hw_crc_error();}
int main(void)
{
    static const app_usbd_config_t usb={.ev_state_proc=usb_event};APP_ERROR_CHECK(nrf_drv_clock_init());app_usbd_serial_num_generate();
    APP_ERROR_CHECK(app_usbd_init(&usb));APP_ERROR_CHECK(app_usbd_class_append(app_usbd_cdc_acm_class_inst_get(&cdc)));
    memset(&session,0,sizeof(session));random_boot();nrf_802154_init();nrf_802154_channel_set(21);set_ack(false);nrf_802154_promiscuous_set(true);gate_hw_session(&session);gate_hw_init();nrf_802154_receive();APP_ERROR_CHECK(app_usbd_power_events_enable());
    uint32_t last_drop=0,last_clock=gate_hw_now_us();
    for(;;){
        app_usbd_event_queue_process();
        uint32_t clock=gate_hw_now_us();
        if(clock<last_clock){stop_loss();}
        last_clock=clock;
        assoc_tick(&session.association,clock);
        if(session.association.state==A_TIMEOUT||session.association.state==A_UNCERTAIN||session.association.state==A_REJECTED)stop_loss();
        if(session.keys.state==K_UNKEYED && (uint32_t)(clock-session.keys.start_us)>session.keys.timeout*1000u)stop_loss();
        uint32_t drop=gate_hw_dropped();if(drop!=last_drop){last_drop=drop;stop_loss();}
        set_ack(open && session.phase!=G_STOPPED && (assoc_active(&session.association)||session.keys.state==K_UNKEYED||session.keys.state==K_INSTALLED||session.keys.state==K_QUEUED||session.keys.state==K_MANAGEMENT));
        tx_service();receive_service();
        if(open && oh-ot<12){
            if(line_error || command_overflow){line_error=command_overflow=command_pending=false;snprintf(line,sizeof(line),"RADIOV7 ERROR boot=%s reason=input_overflow_or_nonascii\n",boot);emit();stop_loss();}
            else if(command_pending){command_pending=false;command(pending_command);}
        }
        if(open && !busy && oh!=ot && app_usbd_cdc_acm_write(&cdc,output[ot%16],strlen(output[ot%16]))==NRF_SUCCESS)busy=true;
    }
}
