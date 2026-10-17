/* Offline IPC fixture ONLY. Includes actual dispatcher, queue and callbacks.
 * Never compiled into firmware. FakeRadio has no actual device access. */
#ifndef ASSOC_HOST_TEST
#define ASSOC_HOST_TEST
#endif
#define main firmware_entry_not_executed
#ifdef V9_REFERENCE
#include "../../raw_radio_v9_rejoin/src/main.c"
#else
#include "../src/main.c"
#endif
#undef main
#include <stdlib.h>
static bool next_cca;
static bool manual_completion=false,service_enabled=true,drain_enabled=true;
static uint32_t mock_time=100000,mock_revision=0,mock_drops=0;
static uint32_t mock_crc;
/* The inherited suites drive one context, ctx1, which is the context they
 * bind with ctx=1. */
#define H 1u
static gate_event_t event;static bool has_event,bad_ack;
static gate_event_t mock_ring[32];static unsigned mock_head,mock_tail;
void gate_hw_init(void){}
uint32_t gate_hw_now_us(void){return mock_time;}
uint32_t gate_hw_revision(void){return mock_revision;}
uint32_t gate_hw_dropped(void){return mock_drops;}
uint32_t gate_hw_crc_errors(void){return 0;}
gate_crc_t gate_hw_crc_snapshot(void){gate_crc_t c={mock_crc,mock_crc,mock_crc};return c;}
static bool mock_pending_cutoff;
bool gate_hw_cutoff_drained(uint32_t deadline){return !mock_pending_cutoff&&(!has_event||event.time_us>=deadline)&&(mock_tail==mock_head||mock_ring[mock_tail%32].time_us>=deadline);}
void gate_hw_session(const commission_t *s){assoc_filter_bind(s);}
static uint32_t mock_config_generation;
void gate_hw_config_generation(uint32_t g){mock_config_generation=g;}
bool gate_hw_pop(gate_event_t *out){if(mock_tail!=mock_head){*out=mock_ring[mock_tail++%32];return true;}if(!has_event)return false;*out=event;has_event=false;return true;}
void gate_hw_rx_begin(const uint8_t *p){(void)p;}
void gate_hw_receive(uint8_t *p,int8_t r,uint8_t l){(void)p;(void)r;(void)l;}
void gate_hw_ack_started(void){}
void gate_hw_ack_completed(void){}
void gate_hw_deadline_miss(void){}
void gate_hw_crc_error(void){}
static void flush_output(void){while(ot!=oh){fputs(output[ot%32],stdout);ot++;}fflush(stdout);}
static unsigned digit(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:99;}
#ifdef COMMISSION_UNIT_TEST
int offline_cli_unused(void){
#else
int main(void){
 if(!radio_power_configure())return 9;
#endif
    memset(sessions,0,sizeof(sessions));gate_hw_session(&sessions[0]);open=true;
    mock_inline=true;strcpy(boot,"11111111111111111111111111111111");
    char input_line[2048];
    while(fgets(input_line,sizeof(input_line),stdin)){
        input_line[strcspn(input_line,"\r\n")]=0;
        if(!strncmp(input_line,"@RX ",4)){
            const char *hex=input_line+4;size_t n=strlen(hex)/2;if(n>125||strlen(hex)%2)return 2;
            memset(&event,0,sizeof(event));uint8_t raw[128]={0};raw[0]=n+2;
            for(size_t i=0;i<n;i++){unsigned a=digit(hex[2*i]),b=digit(hex[2*i+1]);if(a>15||b>15)return 2;raw[i+1]=event.mac[i]=a*16+b;}
            /* Model the predicate the image actually uses, and classify the
             * frame the way gate_events.c does, rather than asserting a
             * context. assoc_filter_part is V25's single-context predicate and
             * is no longer on the admission path. */
            uint8_t received=126;bool ack=immediate_ack&&dual_admit_part(raw,&received)==NRF_802154_RX_ERROR_NONE;
            dual_header_t hdr;event.match=dual_addr_match(raw+1,n,dual_config_current(),&hdr);event.header=hdr;
            event.length=n;event.revision=++mock_revision;event.session=sessions[H].association.session;event.time_us=mock_time;
            /* Stamp the published configuration generation onto the event, as
             * gate_events.c does on the real capture path. Without this the
             * field reads 0 in every fixture record, and the Gate A criterion
             * "the radio was not reconfigured mid-measurement" could not be
             * exercised offline at all. */
            event.config_generation=mock_config_generation;
            event.ack_started=event.ack_completed=ack;event.deadline_miss=bad_ack;has_event=true;receive_service();
        }else if(!strncmp(input_line,"@RX_BUSY_UNTIL ",15)){mock_rx_busy_until=(uint32_t)strtoul(input_line+15,NULL,10);}
        else if(!strncmp(input_line,"@TIME ",6)){mock_time=(uint32_t)strtoul(input_line+6,NULL,10);management_tick(&sessions[H],mock_time);}
        else if(!strcmp(input_line,"@MAX_DIAGNOSTICS")){
            service_enabled=false;commission_stop(&sessions[H]);mock_time=mock_revision=mock_drops=mock_crc=UINT32_MAX;
            sessions[H].generation=sessions[H].keys.polls=sessions[H].recovery.tx_end_us=sessions[H].recovery.deadline_us=sessions[H].recovery.beacon_revision=sessions[H].recovery.response_revision=UINT32_MAX;
            accepted_count=terminal_count=late_callbacks=abort_calls=UINT32_MAX;
            tx.state=OWNER_QUARANTINED;tx.id=tx.start_us=tx.rf_start_us=tx.end_us=tx.abort_started_us=tx.cca_due_us=UINT32_MAX;
            tx.callback_seen=true;tx.abort_reason=ABORT_WATCHDOG;tx.cca_attempts=tx.cca_busy=tx.cca_be=255;
        }
        else if(!strcmp(input_line,"@APPLICATION_READY_UNIT_FIXTURE")){
            mock_time=61100000;sessions[H].recovery.phase=R_ACTIVE;
            sessions[H].recovery.announce_once=sessions[H].recovery.timeout_once=true;
            sessions[H].recovery.total_polls=40;sessions[H].recovery.last_idle_poll=mock_time;
        }
        else if(!strncmp(input_line,"@LAST_FC ",9)){sessions[H].recovery.last_fc=(uint32_t)strtoul(input_line+9,NULL,10);}
        else if(!strcmp(input_line,"@ACTIVE")){sessions[H].recovery.phase=R_ACTIVE;sessions[H].recovery.last_idle_poll=mock_time-1000000u;}
        else if(!strcmp(input_line,"@HOLD")){mock_inline=false;manual_completion=true;}
        else if(!strcmp(input_line,"@INLINE")){mock_inline=true;manual_completion=false;}
        else if(!strcmp(input_line,"@SUCCESS")||!strcmp(input_line,"@PENDING")){uint8_t a[]={5,!strcmp(input_line,"@PENDING")?18:2,0,tx.raw[3],0,0};mock_dma=false;mock_ack_timer=false;nrf_802154_transmitted_raw(tx.raw,a,0,0);}
        else if(!strcmp(input_line,"@FAIL")){mock_dma=false;mock_ack_timer=false;nrf_802154_transmit_failed(tx.raw,NRF_802154_TX_ERROR_BUSY_CHANNEL);}
        else if(!strcmp(input_line,"@ACK_TIMEOUT")){mock_dma=false;mock_ack_timer=false;nrf_802154_transmit_failed(tx.raw,NRF_802154_TX_ERROR_NO_ACK);}
        else if(!strcmp(input_line,"@WAITACK")){mock_waiting_ack=true;}
        else if(!strcmp(input_line,"@ASYNC_SLEEP")){mock_async_sleep=true;}
        else if(!strcmp(input_line,"@QUIESCENT")){mock_core_sleep=true;mock_radio_disabled=true;mock_dma=false;mock_ack_timer=false;}
        else if(!strcmp(input_line,"@NO_SERVICE"))service_enabled=false;
        else if(!strcmp(input_line,"@SERVICE"))service_enabled=true;
        else if(!strcmp(input_line,"@NO_DRAIN")){drain_enabled=false;busy=true;}
        else if(!strcmp(input_line,"@FILL")){while(oh-ot<32){snprintf(line,sizeof(line),RADIO_PREFIX " TEST_QUEUE boot=%s value=1\n",boot);emit();}}
        else if(!strcmp(input_line,"@DRAIN")){drain_enabled=true;busy=false;}
        else if(!strcmp(input_line,"@DRIVER_FAIL"))mock_driver_ok=false;
        else if(!strcmp(input_line,"@ASSOCIATION_TYPED_FIXTURE")){
            assoc_target_t target={.pan=0x0b7a,.capability=0x80,.poll_interval_ms=100,.timeout_ms=1000};
            uint8_t raw_ieee[]={0x37,0x14,0x56,0xbb,0x75,0x56,0x7a,0x02},tc[]={0x5f,0x87,0xa1,0x36,0,0x4b,0x12,0};
            memcpy(target.raw_ieee,raw_ieee,8);memcpy(target.coordinator_ieee,tc,8);
            memset(&tx,0,sizeof(tx));size_t n=assoc_build_request(&target,42,tx.raw+1,125);if(n!=19)return 3;
            tx.raw[0]=n+2;tx.kind=M_INFO;tx.session=1;tx.start_us=gate_hw_now_us();tx.state=OWNER_QUEUED;tx.cca_be=3;accepted_count++;
        }
        else if(!strcmp(input_line,"@PREHOLD")){mock_inline=false;manual_completion=true;mock_preair=true;}
        else if(!strcmp(input_line,"@PREBUSY")){mock_dma=false;mock_ack_timer=false;mock_cca_rx=true;nrf_802154_transmit_failed(tx.raw,NRF_802154_TX_ERROR_BUSY_CHANNEL);}
        else if(!strcmp(input_line,"@INVALID_TX_ACK")){uint8_t a[]={5,2,0,(uint8_t)(tx.raw[3]+1),0,0};mock_dma=false;mock_ack_timer=false;nrf_802154_transmitted_raw(tx.raw,a,0,0);}
        else if(!strcmp(input_line,"@RFSTART")){mock_preair=false;mock_rf_starts++;nrf_802154_tx_started(tx.raw);}
        else if(!strncmp(input_line,"@WINDOW ",8)){sessions[H].recovery.window=true;sessions[H].recovery.phase=R_WAIT_REJOIN;sessions[H].recovery.deadline_us=(uint32_t)strtoul(input_line+8,NULL,10);sessions[H].recovery.poll_due=gate_hw_now_us();}
        else if(!strncmp(input_line,"@RANDOM ",8))mock_backoff_random=(uint32_t)strtoul(input_line+8,NULL,10);
        else if(!strcmp(input_line,"@CCA_PRE")){mock_inline=false;mock_preair=true;next_cca=true;}
        else if(!strcmp(input_line,"@CCA")){mock_inline=false;next_cca=true;}
        else if(!strcmp(input_line,"@NOACK"))mock_inline=false;
        else if(!strcmp(input_line,"@DROP"))mock_drops=1;
        else if(!strcmp(input_line,"@BADACK"))bad_ack=true;
        else if(!strcmp(input_line,"@SLEEPFAIL"))mock_sleep_ok=false;
        else if(!strcmp(input_line,"@RXSTARTFAIL"))mock_receive_ok=false;
        else if(!strcmp(input_line,"@CLOSE"))cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE);
        else if(!strcmp(input_line,"@POWER0"))mock_power=0;
        else command(input_line);
        radio_service();if(drain_enabled)flush_output();if(service_enabled){auto_poll_service();if(drain_enabled)flush_output();tx_service();}
        if(tx.state==2&&!mock_inline&&!manual_completion){mock_dma=false;mock_ack_timer=false;mock_cca_rx=next_cca&&mock_preair;nrf_802154_transmit_failed(tx.raw,next_cca?NRF_802154_TX_ERROR_BUSY_CHANNEL:NRF_802154_TX_ERROR_NO_ACK);if(next_cca){next_cca=false;mock_preair=false;mock_inline=true;}tx_service();}
        if(drain_enabled)flush_output();printf("@END tx=%u state=%s owner=%u dma=%u ack_timer=%u queue=%lu rf=%u attempts=%u\n",mock_transmits,commission_name(sessions[H].phase),tx.state,mock_dma,mock_ack_timer,(unsigned long)(oh-ot),mock_rf_starts,tx.cca_attempts);fflush(stdout);
    }
    return 0;
}
