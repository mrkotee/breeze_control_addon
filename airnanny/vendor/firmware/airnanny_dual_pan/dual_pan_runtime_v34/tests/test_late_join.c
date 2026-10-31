#define COMMISSION_UNIT_TEST
#include "firmware_cli.c"
static int checks,failures;
#define CHECK(x) do{checks++;if(!(x)){failures++;printf("FAIL line %d\n",__LINE__);}}while(0)
static management_command_t bind(unsigned ctx,char guard){
 const dual_identity_t *i=dual_identity(ctx);management_command_t c={0};
 c.kind=M_BIND;c.ctx=ctx;c.has_ctx=true;c.session=1;c.generation=40;c.short_address=i->assigned_short;
 strcpy(c.epoch,i->epoch);strcpy(c.attempt,i->attempt);memset(c.guard,guard,32);return c;
}
static void empty_scan(commission_t *s,uint32_t t){
 s->recovery.phase=R_SCANNING;s->recovery.scan_attempts=3;
 s->recovery.deadline_us=t;s->recovery.deadline_valid=true;
 management_tick(s,t);
}
int main(void){
 for(unsigned ctx=0;ctx<2;ctx++){
  commission_t a={0};management_command_t c=bind(ctx,'a');
  CHECK(!management_resume(&a,&c,1000));empty_scan(&a,1000000);
  CHECK(a.phase==G_STOPPED&&a.recovery.restartable);
  CHECK(management_resume(&a,&c,2000000)!=NULL);c=bind(ctx,'b');
  CHECK(!management_resume(&a,&c,2000000));CHECK(a.recovery.phase==R_BOUND&&!a.recovery.restartable);
  CHECK(!a.recovery.scan_attempts&&a.recovery.last_fc==0);
  commission_stop(&a);CHECK(!a.recovery.restartable);
  c=bind(ctx,'c');CHECK(management_resume(&a,&c,3000000)!=NULL);
  memset(&a,0,sizeof(a));c=bind(ctx,'a');CHECK(!management_resume(&a,&c,0));
  a.recovery.last_fc=128;a.recovery.rejoin_once=true;a.recovery.phase=R_WAIT_REJOIN;
  management_done(&a,false,true,M_REJOIN,10);CHECK(a.recovery.restartable);
  c=bind(ctx,'b');CHECK(!management_resume(&a,&c,20));CHECK(a.recovery.last_fc==128&&!a.recovery.rejoin_once);
  empty_scan(&a,1000);CHECK(a.recovery.restartable);c=bind(ctx,'c');CHECK(!management_resume(&a,&c,2000));
  CHECK(a.recovery.last_fc==128);
  a.recovery.phase=R_WAIT_TIMEOUT;a.recovery.pending=true;a.recovery.window=true;
  a.recovery.deadline_valid=true;a.recovery.deadline_us=3000;management_tick(&a,3000);
  CHECK(!a.recovery.restartable);
  memset(&a,0,sizeof(a));c=bind(ctx,'a');CHECK(!management_resume(&a,&c,0));
  a.recovery.phase=R_WAIT_REJOIN;a.recovery.pending=false;a.recovery.window=true;
  a.recovery.deadline_valid=true;a.recovery.deadline_us=4000;management_tick(&a,4000);
  CHECK(a.recovery.restartable);c=bind(ctx,'b');c.generation=39;
  CHECK(management_resume(&a,&c,5000)!=NULL);c=bind(ctx,'b');c.short_address++;
  CHECK(management_resume(&a,&c,5000)!=NULL);c=bind(ctx,'b');c.epoch[0]='z';
  CHECK(management_resume(&a,&c,5000)!=NULL);
  memset(&a,0,sizeof(a));c=bind(ctx,'a');CHECK(!management_resume(&a,&c,0));
  a.recovery.phase=R_WAIT_REJOIN;a.recovery.window=true;a.recovery.poll_due=10000;
  a.recovery.deadline_us=100000;a.recovery.response_revision=1;uint8_t out[10];
  CHECK(!management_auto_poll(&a,10000,out));
 }
 /* Exercise the actual dispatcher: retry changes no published configuration
  * and does not touch the healthy slot or its ACK admission. */
 memset(sessions,0,sizeof(sessions));memset(&tx,0,sizeof(tx));open=true;oh=ot=0;
 out_drop=mock_drops=0;reboot_required=false;last_id=0;has_id=false;dual_sched_init(1000);
 strcpy(boot,"11111111111111111111111111111111");
 management_command_t c=bind(0,'a');CHECK(!management_resume(&sessions[0],&c,1000));
 empty_scan(&sessions[0],1000000);sessions[1].phase=G_MANAGEMENT;
 sessions[1].association.session=1;sessions[1].recovery.phase=R_ACTIVE;sessions[1].generation=55;
 commission_t healthy=sessions[1];uint32_t generation=config_generation;
 char cmd[512];const dual_identity_t *i=dual_identity(0);
 snprintf(cmd,sizeof(cmd),"RADIOV10 BIND id=1 boot=%s ctx=0 session=1 generation=40 epoch=%s attempt=%s guard=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb short=%u",boot,i->epoch,i->attempt,i->assigned_short);
 /* command is the real parser/dispatcher called by firmware_cli. */
 command(cmd);
 CHECK(sessions[0].recovery.phase==R_BOUND);
 CHECK(!memcmp(&healthy,&sessions[1],sizeof(healthy)));
 CHECK(config_generation==generation);
 printf("late_join_v33: %d checks, %d failures\n",checks,failures);return failures!=0;
}
