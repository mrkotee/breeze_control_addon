#ifndef ACK_TRACE_H
#define ACK_TRACE_H
#include <stdint.h>
/* Observation only: no timing, radio, IRQ mask, ownership or retry API. */
typedef struct {uint32_t dsn,wait,address,end,match,crc,ack_fcf,ack_dsn,timeouts;} ack_trace_t;
extern volatile ack_trace_t ack_trace;
static inline void ack_trace_reset(uint32_t dsn){ack_trace.dsn=dsn;ack_trace.wait=0;ack_trace.address=0;ack_trace.end=0;ack_trace.match=0;ack_trace.crc=0;ack_trace.ack_fcf=0;ack_trace.ack_dsn=0;ack_trace.timeouts=0;}
static inline void ack_trace_wait(uint32_t dsn){ack_trace_reset(dsn);ack_trace.wait=1;}
static inline void ack_trace_address(void){if(ack_trace.address<UINT32_MAX)ack_trace.address++;}
static inline void ack_trace_end(uint32_t match,uint32_t crc,const uint8_t *p){ack_trace.end++;ack_trace.match=match;ack_trace.crc=crc;if(p[0]>=5){ack_trace.ack_fcf=p[1]|((uint32_t)p[2]<<8);ack_trace.ack_dsn=p[3];}}
static inline void ack_trace_timeout(void){if(ack_trace.timeouts<UINT32_MAX)ack_trace.timeouts++;}
#endif
