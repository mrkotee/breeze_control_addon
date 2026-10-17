#include "gate_events.h"
#include "nrf_802154.h"
#include "nrf_802154_peripherals.h"
#include "nrf.h"
#include <string.h>
_Static_assert(!(NRF_802154_TIMERS_USED_MASK & (1u<<3)),"TIMER3 conflict");
/* PPI 0..3 are captured by this target for the RX and ACK instants; the driver
 * must not be using them. */
_Static_assert(!(NRF_802154_PPI_CHANNELS_USED_MASK & 15u),"PPI0..3 conflict");
static gate_event_t ring[GATE_RING_SIZE],pending;
static gate_stats_t stats;
static uint32_t head,tail,revision,dropped,crc_errors,config_generation;
static uint32_t crc_first_us,crc_last_us;
static bool rx_pending;
static const commission_t *session;
static void inc(uint32_t *p){if(*p!=UINT32_MAX)++*p;}
void gate_hw_session(const commission_t *s){session=s;assoc_filter_bind(s);}
void gate_hw_config_generation(uint32_t generation){config_generation=generation;}
void gate_hw_init(void){
    NRF_TIMER3->MODE=0;NRF_TIMER3->BITMODE=3;NRF_TIMER3->PRESCALER=4;
    NRF_TIMER3->TASKS_CLEAR=1;NRF_TIMER3->TASKS_START=1;
    /* Hardware instants. Software clock reads use CC[4] precisely so that a
     * foreground gate_hw_now_us() cannot overwrite the CRCOK capture in CC[0];
     * that overwrite is the mistake this split exists to prevent. */
    NRF_PPI->CH[0].EEP=(uint32_t)&NRF_RADIO->EVENTS_CRCOK;
    NRF_PPI->CH[0].TEP=(uint32_t)&NRF_TIMER3->TASKS_CAPTURE[0];
    NRF_PPI->CH[1].EEP=(uint32_t)&NRF_RADIO->EVENTS_TXREADY;
    NRF_PPI->CH[1].TEP=(uint32_t)&NRF_TIMER3->TASKS_CAPTURE[1];
    NRF_PPI->CH[2].EEP=(uint32_t)&NRF_RADIO->EVENTS_PHYEND;
    NRF_PPI->CH[2].TEP=(uint32_t)&NRF_TIMER3->TASKS_CAPTURE[2];
    NRF_PPI->CH[3].EEP=(uint32_t)&NRF_RADIO->EVENTS_ADDRESS;
    NRF_PPI->CH[3].TEP=(uint32_t)&NRF_TIMER3->TASKS_CAPTURE[3];
    NRF_PPI->CHENSET=15;
}
uint32_t gate_hw_now_us(void){NRF_TIMER3->TASKS_CAPTURE[4]=1;return NRF_TIMER3->CC[4];}
uint32_t gate_hw_revision(void){return __atomic_load_n(&revision,__ATOMIC_ACQUIRE);}
uint32_t gate_hw_dropped(void){return __atomic_load_n(&dropped,__ATOMIC_ACQUIRE);}
uint32_t gate_hw_crc_errors(void){return __atomic_load_n(&crc_errors,__ATOMIC_ACQUIRE);}
gate_crc_t gate_hw_crc_snapshot(void){
    uint32_t p=__get_PRIMASK();__disable_irq();
    gate_crc_t c={crc_errors,crc_first_us,crc_last_us};
    __DMB();__set_PRIMASK(p);return c;
}
void gate_hw_stats(gate_stats_t *out){
    if(!out)return;
    uint32_t p=__get_PRIMASK();__disable_irq();
    *out=stats;out->rx_drop=dropped;out->crc_error=crc_errors;
    __DMB();__set_PRIMASK(p);
}
bool gate_hw_cutoff_drained(uint32_t deadline){
    uint32_t t=__atomic_load_n(&tail,__ATOMIC_ACQUIRE),h=__atomic_load_n(&head,__ATOMIC_ACQUIRE);
    if(t!=h && ring[t%GATE_RING_SIZE].time_us<deadline)return false;
    return !rx_pending || pending.time_us>=deadline;
}
void gate_hw_rx_begin(const uint8_t *raw)
{
    memset(&pending,0,sizeof(pending));
    uint32_t current=__atomic_load_n(&revision,__ATOMIC_RELAXED);
    if(current!=UINT32_MAX){current++;__atomic_store_n(&revision,current,__ATOMIC_RELEASE);}
    else if(dropped!=UINT32_MAX)__atomic_store_n(&dropped,dropped+1,__ATOMIC_RELEASE);
    pending.revision=current;pending.session=session?session->association.session:0;
    /* The CRCOK capture, not a software read taken after ISR latency. */
    pending.time_us=NRF_TIMER3->CC[0];
    pending.config_generation=config_generation;
    /* Classify the complete frame for the record. The admission predicate also
     * classified, during BCC on a partial header, to decide the ACK; this second
     * pass is what the record and the statistics report. */
    if(raw[0]>=2 && raw[0]<=127)
        pending.match=dual_addr_match(raw+1,(size_t)(raw[0]-2),dual_config_current(),&pending.header);
    else pending.match=MATCH_MALFORMED;
    inc(&stats.rx_total);
    switch(pending.match){
    case MATCH_CTX0:      inc(&stats.ctx0_match);break;
    case MATCH_CTX1:      inc(&stats.ctx1_match);break;
    case MATCH_BROADCAST: inc(&stats.broadcast);break;
    case MATCH_MALFORMED: inc(&stats.malformed_reject);break;
    case MATCH_UNSUPPORTED:inc(&stats.unsupported_reject);break;
    case MATCH_AMBIGUOUS: inc(&stats.ambiguous_reject);break;
    default:
        if(pending.header.reason==REASON_CROSS_PAIR)inc(&stats.cross_pair_reject);
        else inc(&stats.foreign_reject);
        break;
    }
    if(pending.header.ack_requested)inc(&stats.ack_requested);
    rx_pending=true;
}
void gate_hw_ack_started(void){
    pending.ack_started=true;
    pending.ack_start_valid=true;pending.ack_start_us=NRF_TIMER3->CC[1];
    pending.ack_address_valid=true;pending.ack_address_us=NRF_TIMER3->CC[3];
    inc(&stats.ack_started);
}
void gate_hw_ack_completed(void){
    pending.ack_completed=true;
    pending.ack_end_valid=true;pending.ack_end_us=NRF_TIMER3->CC[2];
    inc(&stats.ack_completed);
}
void gate_hw_deadline_miss(void){pending.deadline_miss=true;inc(&stats.ack_deadline_miss);}
void gate_hw_crc_error(void){
    uint32_t now=gate_hw_now_us();if(!crc_errors)crc_first_us=now;crc_last_us=now;
    if(crc_errors!=UINT32_MAX)__atomic_store_n(&crc_errors,crc_errors+1,__ATOMIC_RELEASE);
}
void gate_hw_receive(uint8_t *raw,int8_t r,uint8_t l)
{
    pending.rssi=r;pending.lqi=l;pending.length=raw[0]>=2 && raw[0]<=127?raw[0]-2:0;
    memcpy(pending.mac,raw+1,pending.length);
    uint32_t h=__atomic_load_n(&head,__ATOMIC_RELAXED),t=__atomic_load_n(&tail,__ATOMIC_ACQUIRE);
    if(h-t>=GATE_RING_SIZE){if(dropped!=UINT32_MAX)__atomic_store_n(&dropped,dropped+1,__ATOMIC_RELEASE);}
    else{ring[h%GATE_RING_SIZE]=pending;__atomic_store_n(&head,h+1,__ATOMIC_RELEASE);}
    rx_pending=false;
    nrf_802154_buffer_free_raw(raw);
}
bool gate_hw_pop(gate_event_t *o)
{
    uint32_t t=__atomic_load_n(&tail,__ATOMIC_RELAXED);if(t==__atomic_load_n(&head,__ATOMIC_ACQUIRE))return false;
    *o=ring[t%GATE_RING_SIZE];__atomic_store_n(&tail,t+1,__ATOMIC_RELEASE);return true;
}
