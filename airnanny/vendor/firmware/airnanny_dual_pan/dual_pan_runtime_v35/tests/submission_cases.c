#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "submission_trace.h"
typedef unsigned nrf_802154_term_t;
typedef unsigned req_originator_t;
typedef void (*nrf_802154_notification_func_t)(bool);
enum {NRF_802154_TERM_NONE=0,NRF_802154_TERM_802154=1,REQ_ORIG_RSCH=0,REQ_ORIG_HIGHER_LAYER=1};
enum {RADIO_STATE_SLEEP,RADIO_STATE_FALLING_ASLEEP,RADIO_STATE_RX,RADIO_STATE_TX_ACK,RADIO_STATE_CCA_TX,RADIO_STATE_TX,RADIO_STATE_RX_ACK,RADIO_STATE_ED,RADIO_STATE_CCA,RADIO_STATE_CONTINUOUS_CARRIER};
enum {NRF_802154_RX_ERROR_ABORTED,NRF_802154_TX_ERROR_ABORTED,NRF_802154_CCA_ERROR_ABORTED,NRF_802154_ED_ERROR_ABORTED};
volatile submission_trace_t submission_trace;
static bool entry_ok,time_ok,hook_ok,receiving,init_ok;
static unsigned m_state,exits,inits,terminations,notifications;
static const uint8_t *mp_tx_data;
static struct {bool free;uint8_t data[8];} buffer,*mp_current_rx_buffer=&buffer;
static bool nrf_802154_critical_section_enter(void){return entry_ok;}
static bool critical_section_can_be_processed_now(void){return time_ok;}
static void nrf_802154_critical_section_exit(void){exits++;}
static bool nrf_802154_core_hooks_terminate(unsigned t,unsigned o){(void)t;(void)o;return hook_ok;}
static bool psdu_is_being_received(void){return receiving;}
#define TERMINATE(name) static void name(void){terminations++;}
TERMINATE(sleep_terminate) TERMINATE(falling_asleep_terminate) TERMINATE(rx_terminate)
TERMINATE(tx_ack_terminate) TERMINATE(tx_terminate) TERMINATE(rx_ack_terminate)
TERMINATE(ed_terminate) TERMINATE(cca_terminate) TERMINATE(continuous_carrier_terminate)
#define NOTIFY(name) static void name(unsigned e){(void)e;notifications++;}
NOTIFY(nrf_802154_notify_receive_failed) NOTIFY(transmit_failed_notify)
NOTIFY(nrf_802154_notify_energy_detection_failed) NOTIFY(nrf_802154_notify_cca_failed)
static void received_frame_notify(uint8_t *p){(void)p;notifications++;}
static void state_set(unsigned state){m_state=state;}
static bool tx_init(const uint8_t *p,bool cca,bool disable){(void)p;(void)cca;(void)disable;inits++;return init_ok;}
#include "extracted.inc"
static void reset(void){entry_ok=time_ok=hook_ok=init_ok=true;receiving=false;m_state=RADIO_STATE_RX;exits=inits=terminations=notifications=0;mp_tx_data=NULL;submission_trace_reset();}
static const uint8_t frame[]={7,3,8,46};
static void rejected(unsigned reason,unsigned state,unsigned expected_exits){
    assert(!nrf_802154_core_transmit(NRF_802154_TERM_NONE,REQ_ORIG_HIGHER_LAYER,frame,true,false,NULL));
    assert(submission_trace.reason==reason&&submission_trace.state==state);
    assert(inits==0&&mp_tx_data==NULL&&terminations==0&&notifications==0&&exits==expected_exits);
    /* An unrelated subsequent termination must not overwrite the snapshot. */
    unsigned scratch=0;hook_ok=false;
    assert(!current_operation_terminate_traced(0,1,false,&scratch));
    assert(scratch==SUBMIT_HOOK&&submission_trace.reason==reason&&submission_trace.state==state);
}
int main(void){
    unsigned cases=0;
    reset();entry_ok=false;rejected(SUBMIT_CRITICAL,RADIO_STATE_RX,0);cases++;
    reset();time_ok=false;rejected(SUBMIT_TIMESLOT,RADIO_STATE_RX,1);cases++;
    reset();hook_ok=false;rejected(SUBMIT_HOOK,RADIO_STATE_RX,1);cases++;
    reset();receiving=true;rejected(SUBMIT_RX_BUSY,RADIO_STATE_RX,1);cases++;
    unsigned busy[]={RADIO_STATE_TX_ACK,RADIO_STATE_CCA_TX,RADIO_STATE_TX,RADIO_STATE_RX_ACK,RADIO_STATE_ED,RADIO_STATE_CCA};
    for(unsigned i=0;i<6;i++){reset();m_state=busy[i];rejected(SUBMIT_OPERATION_BUSY,busy[i],1);cases++;}
    reset();assert(nrf_802154_core_transmit(0,1,frame,true,false,NULL));assert(inits==1&&mp_tx_data==frame&&exits==1&&m_state==RADIO_STATE_CCA_TX&&submission_trace.reason==0);cases++;
    reset();init_ok=false;assert(nrf_802154_core_transmit(0,1,frame,true,false,NULL));assert(inits==1&&mp_tx_data==frame&&m_state==RADIO_STATE_CCA_TX&&submission_trace.reason==0);cases++;
    reset();assert(nrf_802154_core_transmit(0,1,frame,false,false,NULL));assert(m_state==RADIO_STATE_TX);cases++;
    reset();receiving=true;unsigned reason=0;assert(current_operation_terminate_traced(1,1,true,&reason));assert(terminations==1&&notifications==1&&reason==0);cases++;
    reset();m_state=RADIO_STATE_SLEEP;assert(nrf_802154_core_transmit(0,1,frame,true,false,NULL));assert(terminations==1&&inits==1&&submission_trace.reason==0);cases++;
    assert(cases==15);puts("PASS 15 production submission cases");return 0;
}
