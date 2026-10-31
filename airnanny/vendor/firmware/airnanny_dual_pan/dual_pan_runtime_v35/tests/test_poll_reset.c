/* Reproduce the captured V30 sequence on its real dispatcher, then verify V31. */
#define COMMISSION_UNIT_TEST
#ifdef V30_REFERENCE
#include "../../dual_pan_runtime_v30/tests/firmware_cli.c"
#else
#include "firmware_cli.c"
#endif
static int checks,failures;
static void check(bool pass,const char *name){checks++;if(!pass){failures++;printf("FAIL %s\n",name);}}
static void initialize(commission_t *s){memset(s,0,sizeof(*s));s->phase=G_MANAGEMENT;s->association.session=1;s->generation=6;s->recovery.phase=R_REJOINED;s->recovery.poll_misses=1;}
int main(void){
 commission_t s;unsigned kinds[]={M_REJOIN,M_ANNOUNCE,M_TIMEOUT,M_APP};
 for(unsigned i=0;i<4;i++){
  initialize(&s);management_done(&s,true,false,kinds[i],100);
#ifdef V30_REFERENCE
  check(s.recovery.poll_misses==1,"V30 carries miss through successful secured MAC exchange");
#else
  check(s.recovery.poll_misses==0,"V31 successful parent MAC exchange clears old miss");
#endif
  management_done(&s,false,true,M_POLL,200);
  check(s.phase==G_MANAGEMENT,"first new clean miss remains live");
  management_done(&s,false,true,M_POLL,300);
#ifdef V30_REFERENCE
  check(s.phase==G_STOPPED,"V30 stops after only TWO new misses: captured bug reproduced");
#else
  check(s.phase==G_MANAGEMENT&&s.recovery.poll_misses==2,"V31 two new misses stay live");
  management_done(&s,false,true,M_POLL,400);
  check(s.phase==G_STOPPED,"V31 third consecutive miss still stops");
#endif
 }
 initialize(&s);management_done(&s,true,false,M_BEACON,100);
 check(s.recovery.poll_misses==1,"ACK-free beacon cannot clear misses");
 initialize(&s);management_done(&s,false,false,M_TIMEOUT,100);
 check(s.phase==G_STOPPED,"failed secured TX remains terminal");
 initialize(&s);s.recovery.phase=R_WAIT_REJOIN;s.recovery.response_revision=1;s.recovery.response_time=100;
 management_command_t c={0};c.kind=M_SHORT_COMMIT;c.session=1;c.generation=7;c.revision=1;c.short_address=0xa326;
 check(management_control(&s,&c,101)==NULL,"authenticated short commit accepted");
#ifndef V30_REFERENCE
 check(s.recovery.poll_misses==0,"authenticated parent response clears misses");
 s.recovery.poll_misses=2;s.recovery.phase=R_WAIT_TIMEOUT;s.recovery.response_revision=2;s.recovery.response_time=200;
 c.kind=M_ACTIVE;c.generation=7;c.revision=2;
 check(management_control(&s,&c,201)==NULL&&s.recovery.poll_misses==0,"authenticated active commit clears misses");
#endif
 printf("poll_reset%s: %d checks, %d failures\n",
#ifdef V30_REFERENCE
 "_v30_reproduction",
#else
 "_v31",
#endif
 checks,failures);return failures!=0;
}
