/* Actual ISR ring and CRC diagnostics; fake TIMER3/IRQ/RADIO buffer only. */
#include "../src/gate_events.c"
#include <assert.h>
#include <stdio.h>
fake_timer_t fake_timer;
void assoc_filter_bind(const commission_t *s){(void)s;}
void nrf_802154_buffer_free_raw(uint8_t *p){(void)p;}
int main(void){
 uint8_t raw[]={5,2,0,1,0,0};gate_event_t e;
 fake_timer.CC[0]=99;gate_hw_rx_begin(raw);
 assert(!gate_hw_cutoff_drained(100)); /* CRCOK begun, not yet published. */
 gate_hw_receive(raw,0,0);assert(!gate_hw_cutoff_drained(100));
 assert(gate_hw_pop(&e)&&e.time_us==99&&e.revision==1);assert(gate_hw_cutoff_drained(100));
 fake_timer.CC[0]=100;gate_hw_rx_begin(raw);assert(gate_hw_cutoff_drained(100));
 gate_hw_receive(raw,0,0);assert(gate_hw_cutoff_drained(100));assert(gate_hw_pop(&e));
 for(unsigned i=0;i<32;i++){fake_timer.CC[0]=101+i;gate_hw_rx_begin(raw);gate_hw_receive(raw,0,0);}
 assert(!gate_hw_cutoff_drained(200));
 fake_timer.CC[0]=140;gate_hw_rx_begin(raw);gate_hw_receive(raw,0,0);assert(gate_hw_dropped()==1);
 for(unsigned i=0;i<32;i++)assert(gate_hw_pop(&e));assert(!gate_hw_pop(&e));assert(gate_hw_cutoff_drained(200));
 gate_crc_t c=gate_hw_crc_snapshot();assert(c.count==0&&c.first_us==0&&c.last_us==0);
 fake_timer.CC[0]=150;gate_hw_crc_error();fake_timer.CC[0]=220;gate_hw_crc_error();
 c=gate_hw_crc_snapshot();assert(c.count==2&&c.first_us==150&&c.last_us==220);
 crc_errors=UINT32_MAX;fake_timer.CC[0]=230;gate_hw_crc_error();c=gate_hw_crc_snapshot();assert(c.count==UINT32_MAX&&c.first_us==150&&c.last_us==230);
 puts("ACTUAL_GATE_EVENTS_PASS: pending/cutoff/boundary/full-ring/drop/CRC-snapshot/saturation");return 0;
}
