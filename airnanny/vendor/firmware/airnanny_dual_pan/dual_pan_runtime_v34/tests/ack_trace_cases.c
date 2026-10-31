#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "ack_trace.h"
volatile ack_trace_t ack_trace;
int main(int argc,char **argv){assert(argc==2);unsigned n=atoi(argv[1]);uint8_t ack[]={5,18,0,44,0,0};
switch(n){
case 0: ack_trace_wait(27);ack_trace_address();ack_trace_reset(28);assert(ack_trace.dsn==28&&!ack_trace.wait&&!ack_trace.address&&!ack_trace.end&&!ack_trace.timeouts);break;
case 1: ack_trace_wait(44);ack_trace_address();ack_trace_end(1,1,ack);assert(ack_trace.wait==1&&ack_trace.address==1&&ack_trace.end==1&&ack_trace.match==1&&ack_trace.crc==1&&ack_trace.ack_dsn==44&&ack_trace.ack_fcf==18&&!ack_trace.timeouts);break;
case 2: ack_trace_wait(44);ack_trace_timeout();assert(!ack_trace.address&&!ack_trace.end&&ack_trace.timeouts==1);break;
case 3: ack_trace_wait(44);ack_trace_address();ack_trace_address();ack_trace_timeout();assert(ack_trace.address==2&&!ack_trace.end&&ack_trace.timeouts==1);break;
case 4: ack_trace_wait(44);ack[3]=43;ack_trace_end(0,0,ack);assert(!ack_trace.match&&!ack_trace.crc&&ack_trace.ack_dsn==43);break;
case 5: {uint8_t short_frame[]={1};ack_trace_wait(44);ack_trace_end(0,0,short_frame);assert(!ack_trace.ack_fcf&&!ack_trace.ack_dsn&&ack_trace.end==1);}break;
default:return 2;}
printf("TRACE_CASE_%u_PASS\n",n);return 0;}
