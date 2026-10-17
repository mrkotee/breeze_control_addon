/* Offline IPC fixture ONLY. Includes actual dispatcher, queue and callbacks.
 * Never compiled into firmware. FakeRadio has no actual device access. */
#ifndef ASSOC_HOST_TEST
#define ASSOC_HOST_TEST
#endif
#define main firmware_entry_not_executed
#include "../src/main.c"
#undef main
#include <stdlib.h>
static bool next_cca;
static uint32_t mock_time=100000,mock_revision=0,mock_drops=0;
static gate_event_t event;static bool has_event,bad_ack;
void gate_hw_init(void){}
uint32_t gate_hw_now_us(void){return mock_time;}
uint32_t gate_hw_revision(void){return mock_revision;}
uint32_t gate_hw_dropped(void){return mock_drops;}
uint32_t gate_hw_crc_errors(void){return 0;}
void gate_hw_session(const commission_t *s){assoc_filter_bind(s);}
bool gate_hw_pop(gate_event_t *out){if(!has_event)return false;*out=event;has_event=false;return true;}
void gate_hw_rx_begin(const uint8_t *p){(void)p;}
void gate_hw_receive(uint8_t *p,int8_t r,uint8_t l){(void)p;(void)r;(void)l;}
void gate_hw_ack_started(void){}
void gate_hw_ack_completed(void){}
void gate_hw_deadline_miss(void){}
void gate_hw_crc_error(void){}
static void flush_output(void){while(ot!=oh){fputs(output[ot%16],stdout);ot++;}fflush(stdout);}
static unsigned digit(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:99;}
#ifdef COMMISSION_UNIT_TEST
int offline_cli_unused(void){
#else
int main(void){
#endif
    memset(&session,0,sizeof(session));gate_hw_session(&session);open=true;
    mock_inline=true;strcpy(boot,"11111111111111111111111111111111");
    char input_line[2048];
    while(fgets(input_line,sizeof(input_line),stdin)){
        input_line[strcspn(input_line,"\r\n")]=0;
        if(!strncmp(input_line,"@RX ",4)){
            const char *hex=input_line+4;size_t n=strlen(hex)/2;if(n>125||strlen(hex)%2)return 2;
            memset(&event,0,sizeof(event));uint8_t raw[128]={0};raw[0]=n+2;
            for(size_t i=0;i<n;i++){unsigned a=digit(hex[2*i]),b=digit(hex[2*i+1]);if(a>15||b>15)return 2;raw[i+1]=event.mac[i]=a*16+b;}
            uint8_t received=126;bool ack=immediate_ack&&assoc_filter_part(raw,&received)==NRF_802154_RX_ERROR_NONE;
            event.length=n;event.revision=++mock_revision;event.session=session.association.session;event.time_us=mock_time;
            event.ack_started=event.ack_completed=ack;event.deadline_miss=bad_ack;has_event=true;receive_service();
        }else if(!strncmp(input_line,"@TIME ",6)){mock_time=(uint32_t)strtoul(input_line+6,NULL,10);assoc_tick(&session.association,mock_time);}
        else if(!strcmp(input_line,"@DRIVER_FAIL"))mock_driver_ok=false;
        else if(!strcmp(input_line,"@CCA")){mock_inline=false;next_cca=true;}
        else if(!strcmp(input_line,"@NOACK"))mock_inline=false;
        else if(!strcmp(input_line,"@DROP"))mock_drops=1;
        else if(!strcmp(input_line,"@BADACK"))bad_ack=true;
        else if(!strcmp(input_line,"@SLEEPFAIL"))mock_sleep_ok=false;
        else if(!strcmp(input_line,"@RXSTARTFAIL"))mock_receive_ok=false;
        else if(!strcmp(input_line,"@CLOSE"))cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE);
        else command(input_line);
        flush_output();tx_service();
        if(tx.state==2&&!mock_inline){nrf_802154_transmit_failed(tx.raw,next_cca?NRF_802154_TX_ERROR_BUSY_CHANNEL:NRF_802154_TX_ERROR_NO_ACK);tx_service();if(next_cca){next_cca=false;mock_inline=true;}}
        flush_output();printf("@END tx=%u state=%s\n",mock_transmits,commission_name(session.phase));fflush(stdout);
    }
    return 0;
}
