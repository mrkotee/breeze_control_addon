#ifndef ASSOC_GATE_EVENTS_H
#define ASSOC_GATE_EVENTS_H
#include "commission.h"
#define GATE_RING_SIZE 8u
typedef struct { uint32_t revision,session,time_us;int8_t rssi;uint8_t lqi,length,mac[125];bool ack_started,ack_completed,deadline_miss; } gate_event_t;
void gate_hw_init(void);
void gate_hw_session(const commission_t *s);
uint32_t gate_hw_now_us(void);
uint32_t gate_hw_revision(void);
uint32_t gate_hw_dropped(void);
uint32_t gate_hw_crc_errors(void);
void gate_hw_rx_begin(const uint8_t *raw);
void gate_hw_ack_started(void);
void gate_hw_ack_completed(void);
void gate_hw_deadline_miss(void);
void gate_hw_receive(uint8_t *raw,int8_t rssi,uint8_t lqi);
bool gate_hw_pop(gate_event_t *out);
void gate_hw_crc_error(void);
void assoc_filter_bind(const commission_t *s);
int assoc_filter_part(const uint8_t *raw,uint8_t *received);
#endif
