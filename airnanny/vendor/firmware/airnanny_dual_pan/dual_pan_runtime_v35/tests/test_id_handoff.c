/* The actual dispatcher, not a fake of its reused-id semantics. */
#define COMMISSION_UNIT_TEST
#include "firmware_cli.c"
static int checks,failures;
static void check(bool condition,const char *name){checks++;if(!condition){failures++;printf("FAIL %s\n",name);}}
static void active(void){
 memset(sessions,0,sizeof(sessions));memset(&tx,0,sizeof(tx));
 open=true;oh=ot=0;busy=false;out_drop=0;mock_drops=0;mock_time=70000000;
 has_id=true;last_id=114;strcpy(boot,"11111111111111111111111111111111");
 for(unsigned c=0;c<2;c++){
  sessions[c].phase=G_MANAGEMENT;sessions[c].association.session=1;
  sessions[c].recovery.phase=R_ACTIVE;sessions[c].recovery.start_us=0;
 }
}
int main(void){
 active();command(RADIO_PREFIX " INFO id=1");
 check(strstr(line,"reason=id_reused")!=NULL,"reused INFO id refused");
 check(sessions[0].phase==G_STOPPED&&sessions[1].phase==G_STOPPED,"actual reused-id fail path stops BOTH contexts");
 check(last_id==114,"rejected request does not advance id");
 active();command(RADIO_PREFIX " INFO id=115");
 check(strstr(line," INFO ")!=NULL&&strstr(line," id=115 ")!=NULL,"owned handoff accepted");
 check(sessions[0].phase==G_MANAGEMENT&&sessions[1].phase==G_MANAGEMENT,"handoff preserves BOTH active contexts");
 check(last_id==115,"owned next id advanced once");
 printf("id_handoff: %d checks, %d failures\n",checks,failures);return failures!=0;
}
