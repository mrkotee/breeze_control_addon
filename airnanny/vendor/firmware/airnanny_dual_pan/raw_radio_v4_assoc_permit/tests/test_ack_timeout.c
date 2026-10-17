#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#define __DMB() do{}while(0)
#define NRF_802154_ACK_TIMEOUT_DEFAULT_TIMEOUT 7000
#define NRF_802154_ACK_TIMEOUT_ENABLED 1
#define ENABLE_DEBUG_LOG 0
#define NRF_802154_CONFIG_H__
#define NRF_802154_DEBUG_H_
#define nrf_802154_log(...) do{}while(0)
#include "../radio_driver/mac_features/nrf_802154_ack_timeout.c"
static unsigned count,added,removed,failed;static bool req=true;static nrf_802154_timer_t *scheduled;
#define CHECK(x) do{++count;if(!(x)){fprintf(stderr,"FAIL %d\n",__LINE__);exit(1);}}while(0)
uint32_t nrf_802154_timer_sched_time_get(void){return 100;}
void nrf_802154_timer_sched_add(nrf_802154_timer_t *t,bool up){(void)up;added++;scheduled=t;}
void nrf_802154_timer_sched_remove(nrf_802154_timer_t *t,bool *running){(void)t;(void)running;removed++;scheduled=NULL;}
void nrf_802154_notify_transmit_failed(const uint8_t *p,nrf_802154_tx_error_t e){(void)p;CHECK(e==NRF_802154_TX_ERROR_NO_ACK);failed++;}
bool nrf_802154_request_receive(nrf_802154_term_t t,req_originator_t o,void (*f)(bool),bool notify)
{CHECK(t==NRF_802154_TERM_802154);CHECK(o==REQ_ORIG_ACK_TIMEOUT);CHECK(!notify);if(req)f(true);return req;}
int main(void)
{
    uint8_t raw[128]={11};CHECK(nrf_802154_ack_timeout_tx_started_hook(raw));CHECK(added==0);
    nrf_802154_ack_timeout_transmitted_hook(raw);CHECK(added==0); /* AR0 completion */
    CHECK(nrf_802154_ack_timeout_tx_started_hook(raw));nrf_802154_ack_timeout_rx_ack_started_hook();
    CHECK(added==1&&scheduled&&scheduled->t0==100&&scheduled->dt==7000);
    CHECK(!nrf_802154_ack_timeout_abort(NRF_802154_TERM_NONE,REQ_ORIG_HIGHER_LAYER));
    scheduled->callback(NULL);CHECK(failed==1);CHECK(!m_procedure_is_active);
    nrf_802154_ack_timeout_tx_failed_hook(raw,NRF_802154_TX_ERROR_NO_ACK);CHECK(scheduled==NULL);
    nrf_802154_ack_timeout_tx_started_hook(raw);nrf_802154_ack_timeout_rx_ack_started_hook();
    nrf_802154_ack_timeout_transmitted_hook(raw);CHECK(scheduled==NULL);CHECK(!m_procedure_is_active);
    nrf_802154_ack_timeout_tx_started_hook(raw);nrf_802154_ack_timeout_rx_ack_started_hook();
    CHECK(nrf_802154_ack_timeout_abort(NRF_802154_TERM_802154,REQ_ORIG_HIGHER_LAYER));CHECK(scheduled==NULL);
    nrf_802154_ack_timeout_tx_started_hook(raw);nrf_802154_ack_timeout_rx_ack_started_hook();req=false;
    uint32_t dt=scheduled->dt;scheduled->callback(NULL);CHECK(scheduled->dt==dt+500);CHECK(failed==1);
    CHECK(removed>0);printf("PASS actual copied ACK-timeout assertions=%u hardware_events=0\n",count);
}
