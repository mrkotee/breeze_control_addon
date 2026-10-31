#define COMMISSION_UNIT_TEST
#include "firmware_cli.c"
static int checks,failures;
#define CHECK(x) do{checks++;if(!(x)){failures++;printf("FAIL line %d\n",__LINE__);}}while(0)
int main(void){
 commission_t a={0},b={0};a.phase=b.phase=G_MANAGEMENT;
 a.recovery.phase=b.recovery.phase=R_ACTIVE;
 for(unsigned i=0;i<1000;i++){
  management_done(&a,false,true,i%2?M_APP:M_POLL,i*1000);
  CHECK(a.phase==G_MANAGEMENT&&a.recovery.phase==R_ACTIVE);
  CHECK(b.phase==G_MANAGEMENT&&b.recovery.poll_misses==0);
 }
 management_done(&a,true,false,M_POLL,1000001);CHECK(a.recovery.poll_misses==0);
 a.recovery.poll_misses=a.recovery.poll_misses_total=UINT32_MAX;
 management_done(&a,false,true,M_POLL,1000002);CHECK(a.recovery.poll_misses==UINT32_MAX&&a.recovery.poll_misses_total==UINT32_MAX);
 management_done(&a,false,false,M_APP,1000003);CHECK(a.phase==G_STOPPED);
 a.phase=G_MANAGEMENT;a.recovery.phase=R_WAIT_REJOIN;a.recovery.poll_misses=0;
 for(unsigned i=0;i<3;i++)management_done(&a,false,true,M_POLL,1000004+i);
 CHECK(a.phase==G_STOPPED);CHECK(b.phase==G_MANAGEMENT);
 printf("radio_loss_v32: %d checks, %d failures\n",checks,failures);return failures!=0;
}
