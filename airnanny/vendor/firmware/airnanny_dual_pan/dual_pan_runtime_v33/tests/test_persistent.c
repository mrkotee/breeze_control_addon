#define COMMISSION_UNIT_TEST
#include "firmware_cli.c"
static int checks,failures;
static void check(bool pass,const char *name){checks++;if(!pass){failures++;printf("FAIL %s\n",name);}}
static void active(void){
 memset(sessions,0,sizeof(sessions));memset(&tx,0,sizeof(tx));open=true;busy=false;oh=ot=0;
 out_drop=0;mock_drops=0;reboot_required=false;usb_reset_pending=false;mock_system_resets=0;dual_sched_init(1000000u);
 for(unsigned i=0;i<2;i++){
  commission_t *s=&sessions[i];s->phase=G_MANAGEMENT;s->association.session=1;s->generation=40;
  s->keys.pan=i?0x0b7a:0xfa9b;s->keys.short_address=i?0x6c55:0xa326;
  s->recovery.phase=R_ACTIVE;s->recovery.start_us=0;s->recovery.application_ready=true;s->recovery.total_polls=UINT32_MAX;
 }
}
int main(void){
 check(radio_time_reached(20,UINT32_MAX-20),"instant after wrap");
 check(!radio_time_reached(UINT32_MAX-20,20),"future deadline after wrap");
 check(radio_time_reached(0,0),"zero is valid");
 active();management_tick(&sessions[0],4000000000u);check(sessions[0].phase==G_MANAGEMENT,"no 3900s cutoff");
 management_tick(&sessions[0],10);check(sessions[0].recovery.application_ready,"readiness survives wrap");
 sessions[1].recovery.application_ready=false;sessions[1].recovery.start_us=UINT32_MAX-30000000u;
 management_tick(&sessions[1],10000000u);check(!sessions[1].recovery.application_ready,"no early readiness");
 management_tick(&sessions[1],30000000u);check(sessions[1].recovery.application_ready,"60s readiness across wrap");
 management_command_t c={0};uint8_t out[68];size_t n=0;c.kind=M_POLL;c.session=1;c.generation=40;
 sessions[0].recovery.last_idle_poll=UINT32_MAX-1000000u;
 check(management_tx(&sessions[0],&c,1000000u,out,&n)==NULL,"poll after old budget and wrap");
 check(sessions[0].recovery.total_polls==UINT32_MAX,"poll count saturates");
 management_done(&sessions[0],true,false,M_POLL,1000010u);
 check(management_tx(&sessions[0],&c,1000020u,out,&n)!=NULL,"cadence remains bounded");
 active();recovery_transport_t *q=&sessions[0].recovery;q->phase=R_SCANNING;
 management_done(&sessions[0],true,false,M_BEACON,UINT32_MAX-10000u);management_tick(&sessions[0],20);
 check(q->phase==R_SCANNING,"scan not closed early");q->beacon_revision=1;management_tick(&sessions[0],300000);
 check(q->phase==R_DISCOVERED,"scan closes after deadline");
 active();q=&sessions[0].recovery;q->phase=R_SCANNING;management_done(&sessions[0],true,false,M_BEACON,0u-SCAN_US);
 check(q->deadline_us==0&&q->deadline_valid,"zero deadline valid");q->beacon_revision=1;management_tick(&sessions[0],0);
 check(q->phase==R_DISCOVERED,"zero deadline serviced");
 active();q=&sessions[0].recovery;q->window=true;q->phase=R_WAIT_REJOIN;q->poll_due=UINT32_MAX-10;q->deadline_us=100000;q->deadline_valid=true;
 check(management_auto_poll(&sessions[0],20,out),"automatic poll across wrap");check(q->pending&&q->polls==1,"one response poll");
 active();set_ack(true);cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE);
 check(!open&&!immediate_ack&&sessions[0].phase==G_STOPPED&&sessions[1].phase==G_STOPPED,"close stops ACK gates");
 check(usb_reset_allowed(),"idle close can reboot");usb_reset_service();check(mock_system_resets==1&&!usb_reset_pending,"reset once");
 active();tx.state=OWNER_RADIO;cdc_event(NULL,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE);
 check(tx.state==OWNER_ABORTING&&!usb_reset_allowed(),"DMA must clean up first");
 tx.state=OWNER_QUARANTINED;reboot_required=true;usb_reset_service();check(mock_system_resets==0,"quarantine cannot autoresume");
 active();tx.state=OWNER_RADIO;tx.raw[0]=10;tx.ctx=0;mock_time=0;nrf_802154_tx_started(tx.raw);
 check(tx.rf_started&&tx.rf_start_us==0,"RF start at zero valid");nrf_802154_tx_started(tx.raw);
 check(tx.state==OWNER_ABORTING,"duplicate RF start at zero aborts");
 printf("persistent: %d checks, %d failures\n",checks,failures);return failures!=0;
}
