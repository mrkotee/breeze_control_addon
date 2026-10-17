#include "ack_trace.h"
volatile ack_trace_t ack_trace;
/* Offline test of verbatim production PHYEND/ADDRESS handlers and actual
 * ACK timeout/core hooks. Only hardware registers, timer and notifications
 * are mocked. No RF transmit API is linked into this executable. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nrf_802154_core_hooks.h"
#include "nrf_802154_request.h"
#include "timer_scheduler/nrf_802154_timer_sched.h"
#include "nrf_802154_const.h"
#include "mac_features/nrf_802154_ack_timeout.c"

static uint32_t now=100000;
static int adds,removes,errors,receives,successes,radio_state,case_no;
static bool started=true,ar=true,free_buffer=true,egu_worked=true,receive_ok=true;
static uint8_t frame[128],rx[128];
static const uint8_t *mp_tx_data=frame;
static nrf_802154_timer_t *scheduled;
uint32_t nrf_802154_timer_sched_time_get(void){return now;}
void nrf_802154_timer_sched_add(nrf_802154_timer_t *p,bool round_up){assert(round_up);scheduled=p;adds++;}
void nrf_802154_timer_sched_remove(nrf_802154_timer_t *p,bool *running){assert(p==&m_timer);if(running)*running=scheduled!=NULL;scheduled=NULL;removes++;}
void nrf_802154_notify_transmit_failed(const uint8_t *p,nrf_802154_tx_error_t e){assert(p==frame&&e==NRF_802154_TX_ERROR_NO_ACK);errors++;assert(nrf_802154_core_hooks_tx_failed(p,e));}
bool nrf_802154_request_receive(nrf_802154_term_t t,req_originator_t o,nrf_802154_notification_func_t cb,bool abort_notify){assert(t==NRF_802154_TERM_802154&&o==REQ_ORIG_ACK_TIMEOUT&&!abort_notify);receives++;if(receive_ok){assert(nrf_802154_core_hooks_terminate(t,o));cb(true);}return receive_ok;}
static bool transmission_has_started(void){return started;}
static bool ack_is_requested(const uint8_t *p){assert(p==frame);return ar;}
static bool rx_buffer_is_available(void){return free_buffer;}
static uint8_t *rx_buffer_get(void){return rx;}
static void rx_buffer_in_use_set(void *p){(void)p;free_buffer=true;}
static void *nrf_802154_rx_buffer_free_find(void){return rx;}
static void state_set(int s){radio_state=s;}
static bool ppi_egu_worked(void){return egu_worked;}
static void tx_terminate(void){}
static void rx_init(bool b){assert(b);}
static void transmitted_frame_notify(void *p,int r,int l){assert(!p&&!r&&!l);nrf_802154_core_hooks_transmitted(frame);successes++;}
#define RADIO_STATE_RX_ACK 10
#define RADIO_STATE_RX 11
#define SHORTS_RX_ACK 1
#define SHORTS_RX_FREE_BUFFER 2
#define PPI_DISABLED_EGU 1
#define PPI_EGU_RAMP_UP 2
#define PPI_CHGRP0_DIS_TASK 3
#define NRF_RADIO_INT_CCABUSY_MASK 1
#define NRF_RADIO_INT_ADDRESS_MASK 2
#define NRF_RADIO_INT_PHYEND_MASK 4
#define NRF_RADIO_INT_END_MASK 8
#define NRF_RADIO_EVENT_END 1
#define NRF_RADIO_EVENT_ADDRESS 2
#define NRF_RADIO_TASK_RXEN 1
#define NRF_RADIO_TASK_DISABLE 2
#define NRF_RADIO_TASK_START 3
#define NRF_RADIO_STATE_RXIDLE 10
#define EGU_EVENT 1
#define NRF_802154_SWI_EGU_INSTANCE 1
#define nrf_ppi_channel_disable(x) ((void)(x))
#define nrf_ppi_channel_enable(x) ((void)(x))
#define nrf_radio_shorts_set(x) ((void)(x))
#define nrf_radio_packetptr_set(x) ((void)(x))
#define nrf_radio_event_clear(x) ((void)(x))
#define nrf_radio_int_disable(x) ((void)(x))
#define nrf_radio_int_enable(x) ((void)(x))
#define fem_for_tx_reset(x) ((void)(x))
#define fem_for_lna_set() ((void)0)
#define nrf_ppi_channel_and_fork_endpoint_setup(a,b,c,d) ((void)(a),(void)(b),(void)(c),(void)(d))
#define nrf_egu_event_address_get(a,b) 0u
#define nrf_radio_task_address_get(a) 0u
#define nrf_ppi_task_address_get(a) 0u
#define nrf_egu_event_clear(a,b) ((void)(a),(void)(b))
#define nrf_radio_task_trigger(x) ((void)(x))
#define nrf_radio_state_get() NRF_RADIO_STATE_RXIDLE
#define ack_matching_enable() ((void)0)
#include "extracted_ack_core.inc"

static void fire(void){assert(scheduled);nrf_802154_timer_t *p=scheduled;scheduled=NULL;now=p->t0+p->dt;p->callback(p->p_context);}
static void begin(void){assert(nrf_802154_core_hooks_tx_started(frame));assert(adds==0);irq_phyend_state_tx_frame();}
int main(int argc,char **argv){assert(argc==2);case_no=atoi(argv[1]);
 switch(case_no){
 case 0: /* No ACK ADDRESS: old driver fails to arm; new expires once. */
  begin();
#ifdef OLD_ACK_DRIVER
  assert(adds==0&&scheduled==NULL);puts("OLD_NO_ADDRESS_TIMER_NOT_ARMED");return 0;
#else
  assert(adds==1&&scheduled&&radio_state==RADIO_STATE_RX_ACK);assert(m_timer.dt==7000);assert(ack_trace.wait==1&&ack_trace.address==0);fire();assert(ack_trace.timeouts==1);assert(errors==1&&receives==1&&!scheduled);timeout_timer_fired(NULL);assert(errors==1);break;
#endif
 case 1: ar=false;begin();assert(!scheduled&&adds==0&&successes==1);break;
 case 2: started=false;begin();assert(!scheduled&&adds==0&&successes==0);break;
 case 3: assert(nrf_802154_core_hooks_tx_started(frame));assert(!scheduled);break;
 case 4: begin();{uint32_t t0=m_timer.t0;now+=3000;irq_address_state_rx_ack();irq_address_state_rx_ack();assert(adds==1&&m_timer.t0==t0&&m_timer.dt==7000);assert(ack_trace.address==2);fire();assert(errors==1);}break;
 case 5: begin();nrf_802154_core_hooks_transmitted(frame);timeout_timer_fired(NULL);assert(!scheduled&&errors==0&&removes==1);break;
 case 6: begin();assert(nrf_802154_core_hooks_tx_failed(frame,NRF_802154_TX_ERROR_INVALID_ACK));timeout_timer_fired(NULL);assert(!scheduled&&errors==0&&removes==1);break;
 case 7: begin();assert(nrf_802154_core_hooks_terminate(NRF_802154_TERM_802154,REQ_ORIG_HIGHER_LAYER));timeout_timer_fired(NULL);assert(!scheduled&&errors==0);break;
 case 8: begin();receive_ok=false;fire();assert(adds==2&&scheduled&&m_timer.dt==7500&&errors==0);receive_ok=true;fire();assert(errors==1&&receives==2&&!scheduled);break;
 case 9: begin();assert(!nrf_802154_core_hooks_terminate(NRF_802154_TERM_NONE,REQ_ORIG_HIGHER_LAYER));assert(scheduled);fire();assert(errors==1);break;
 case 10: free_buffer=false;egu_worked=false;begin();assert(adds==1&&scheduled);fire();assert(errors==1);break;
 case 11: now=0xfffff000u;begin();assert(m_timer.t0==0xfffff000u);fire();assert(errors==1);break;
 default:assert(0);
 }
 printf("PASS case=%d adds=%d errors=%d receives=%d\n",case_no,adds,errors,receives);return 0;
}
