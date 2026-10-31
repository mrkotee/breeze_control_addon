#include "radio_wire.h"
/* OFFLINE only. Includes actual V18 dispatcher/fixture, production RX service. */
#define COMMISSION_UNIT_TEST
#include "firmware_cli.c"
int main(void){
 memset(sessions,0,sizeof(sessions));gate_hw_session(&sessions[0]);open=true;mock_inline=true;strcpy(boot,"11111111111111111111111111111111");
 command(RADIO_PREFIX " BIND id=1 boot=11111111111111111111111111111111 session=1 generation=13 epoch=9985b15dcb574c59b87dc2fb379f317f attempt=cbef428849da4e87b48867ac616247d1 guard=22222222222222222222222222222222 short=27733 ctx=1");flush_output();
 mock_time=29303281;mock_revision=55;command(RADIO_PREFIX " ACTIVE_DISCOVERY_BEACON_REQUEST id=2 boot=11111111111111111111111111111111 session=1 generation=13 dsn=55 ctx=1");flush_output();tx_service();flush_output();
 char buf[2048];bool acked=false;
 while(fgets(buf,sizeof(buf),stdin)){
  unsigned long stamp,foreground,rev;char hex[251];
  bool queued=!strncmp(buf,"QUEUE ",6);char *payload=queued?buf+6:buf;
  int parsed=queued?sscanf(payload,"%lu %lu %lu %250s",&stamp,&foreground,&rev,hex):sscanf(payload,"FRAME %lu %lu %lu %250s",&stamp,&foreground,&rev,hex);
  if(parsed==4){
   size_t n=strlen(hex)/2;if(n>125||strlen(hex)%2)return 2;memset(&event,0,sizeof(event));
   for(size_t i=0;i<n;i++){unsigned a=digit(hex[2*i]),b=digit(hex[2*i+1]);if(a>15||b>15)return 2;event.mac[i]=a*16+b;}
   event.match=MATCH_CTX1;event.length=n;event.session=1;event.revision=rev;event.time_us=stamp;mock_revision=rev;has_event=true;mock_time=foreground;
   event.ack_started=event.ack_completed=acked;
   printf("AUDIT CLASSIFY revision=%lu beacon=%u event_time=%lu foreground=%lu\n",rev,management_beacon(&sessions[1],event.mac,n),stamp,foreground);
   if(queued){if(mock_head-mock_tail>=32)return 4;mock_ring[mock_head++%32]=event;has_event=false;}
   else{management_receive_service();flush_output();}
  }else if(sscanf(buf,"TICK %lu",&foreground)==1){mock_time=foreground;management_receive_service();flush_output();}
  else if(sscanf(buf,"PENDING %lu",&foreground)==1){mock_pending_cutoff=foreground!=0;}
  else if(sscanf(buf,"WINDOW %lu",&foreground)==1){sessions[1].recovery.phase=foreground==1?R_WAIT_REJOIN:R_WAIT_TIMEOUT;sessions[1].recovery.window=true;sessions[1].recovery.deadline_us=mock_time+491520u;}
  else if(sscanf(buf,"ACKED %lu",&foreground)==1){acked=foreground!=0;}
  else return 3;
 }
 status(3,1);flush_output();return 0;
}
