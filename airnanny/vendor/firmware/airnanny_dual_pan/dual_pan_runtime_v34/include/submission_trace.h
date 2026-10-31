#ifndef SUBMISSION_TRACE_H
#define SUBMISSION_TRACE_H
#include <stdint.h>
/* Observation only. No abort, delay, radio or retry operation. */
enum { SUBMIT_NONE=0, SUBMIT_CRITICAL=1, SUBMIT_TIMESLOT=2,
       SUBMIT_HOOK=3, SUBMIT_RX_BUSY=4, SUBMIT_OPERATION_BUSY=5 };
typedef struct {uint32_t reason,state;} submission_trace_t;
extern volatile submission_trace_t submission_trace;
static inline void submission_trace_reset(void){submission_trace.reason=0;submission_trace.state=0;}
static inline void submission_trace_capture(uint32_t reason,uint32_t state){submission_trace.reason=reason;submission_trace.state=state;}
#endif
