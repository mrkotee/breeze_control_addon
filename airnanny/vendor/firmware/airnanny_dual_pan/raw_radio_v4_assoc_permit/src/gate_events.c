#include "gate_events.h"
#include "nrf_802154.h"
#include "nrf_802154_peripherals.h"
#include "nrf.h"
#include <string.h>
_Static_assert(!(NRF_802154_TIMERS_USED_MASK & (1u<<3)),"TIMER3 conflict");
static gate_event_t ring[GATE_RING_SIZE],pending;
static uint32_t head,tail,revision,dropped,crc_errors;
static const assoc_t *session;
void gate_hw_session(const assoc_t *s){session=s;assoc_filter_bind(s);}
void gate_hw_init(void){NRF_TIMER3->MODE=0;NRF_TIMER3->BITMODE=3;NRF_TIMER3->PRESCALER=4;NRF_TIMER3->TASKS_CLEAR=1;NRF_TIMER3->TASKS_START=1;}
uint32_t gate_hw_now_us(void){NRF_TIMER3->TASKS_CAPTURE[0]=1;return NRF_TIMER3->CC[0];}
uint32_t gate_hw_revision(void){return __atomic_load_n(&revision,__ATOMIC_ACQUIRE);}
uint32_t gate_hw_dropped(void){return __atomic_load_n(&dropped,__ATOMIC_ACQUIRE);}
uint32_t gate_hw_crc_errors(void){return __atomic_load_n(&crc_errors,__ATOMIC_ACQUIRE);}
void gate_hw_rx_begin(const uint8_t *raw)
{
    (void)raw;memset(&pending,0,sizeof(pending));
    uint32_t current=__atomic_load_n(&revision,__ATOMIC_RELAXED);
    if(current!=UINT32_MAX){current++;__atomic_store_n(&revision,current,__ATOMIC_RELEASE);}
    else if(dropped!=UINT32_MAX)__atomic_store_n(&dropped,dropped+1,__ATOMIC_RELEASE);
    pending.revision=current;pending.session=session?session->session:0;pending.time_us=gate_hw_now_us();
}
void gate_hw_ack_started(void){pending.ack_started=true;}
void gate_hw_ack_completed(void){pending.ack_completed=true;}
void gate_hw_deadline_miss(void){pending.deadline_miss=true;}
void gate_hw_crc_error(void){if(crc_errors!=UINT32_MAX)__atomic_store_n(&crc_errors,crc_errors+1,__ATOMIC_RELEASE);}
void gate_hw_receive(uint8_t *raw,int8_t r,uint8_t l)
{
    pending.rssi=r;pending.lqi=l;pending.length=raw[0]>=2 && raw[0]<=127?raw[0]-2:0;
    memcpy(pending.mac,raw+1,pending.length);
    uint32_t h=__atomic_load_n(&head,__ATOMIC_RELAXED),t=__atomic_load_n(&tail,__ATOMIC_ACQUIRE);
    if(h-t>=GATE_RING_SIZE){if(dropped!=UINT32_MAX)__atomic_store_n(&dropped,dropped+1,__ATOMIC_RELEASE);}
    else{ring[h%GATE_RING_SIZE]=pending;__atomic_store_n(&head,h+1,__ATOMIC_RELEASE);}
    nrf_802154_buffer_free_raw(raw);
}
bool gate_hw_pop(gate_event_t *o)
{
    uint32_t t=__atomic_load_n(&tail,__ATOMIC_RELAXED);if(t==__atomic_load_n(&head,__ATOMIC_ACQUIRE))return false;
    *o=ring[t%GATE_RING_SIZE];__atomic_store_n(&tail,t+1,__ATOMIC_RELEASE);return true;
}
