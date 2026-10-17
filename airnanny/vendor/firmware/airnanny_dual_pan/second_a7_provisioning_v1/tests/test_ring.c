/* Actual merged ring source, hardware clock/buffer release only mocked. */
#include "gate_events.h"
#include "nrf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
mock_timer_t test_timer;
static unsigned released,checks;
void nrf_802154_buffer_free_raw(uint8_t *p){(void)p;released++;}
#define CHECK(x) do{checks++;if(!(x))exit(1);}while(0)
int main(void){
    commission_t s={0};s.association.session=1;gate_hw_session(&s);gate_hw_init();
    uint8_t raw[128]={5,2,0,7};gate_event_t e;
    for(unsigned i=0;i<GATE_RING_SIZE+1;i++){
        test_timer.CC[0]=100+i;gate_hw_rx_begin(raw);gate_hw_ack_started();gate_hw_ack_completed();if(i==2)gate_hw_deadline_miss();gate_hw_receive(raw,-42,200);
    }
    CHECK(released==GATE_RING_SIZE+1);CHECK(gate_hw_dropped()==1);CHECK(gate_hw_revision()==GATE_RING_SIZE+1);
    for(unsigned i=0;i<GATE_RING_SIZE;i++){
        CHECK(gate_hw_pop(&e));CHECK(e.revision==i+1&&e.session==1&&e.time_us==100+i);
        CHECK(e.length==3&&e.rssi==-42&&e.lqi==200&&e.ack_started&&e.ack_completed);
        CHECK(e.deadline_miss==(i==2));CHECK(!memcmp(e.mac,raw+1,3));
    }
    CHECK(!gate_hw_pop(&e));gate_hw_crc_error();CHECK(gate_hw_crc_errors()==1);
    for(unsigned j=0;j<10000;j++){test_timer.CC[0]++;gate_hw_rx_begin(raw);gate_hw_receive(raw,0,0);CHECK(gate_hw_pop(&e));CHECK(e.session==1);}
    CHECK(gate_hw_dropped()==1);printf("V6 RX ring PASS checks=%u releases=%u\n",checks,released);return 0;
}
