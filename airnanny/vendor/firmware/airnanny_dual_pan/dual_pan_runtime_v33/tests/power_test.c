#define COMMISSION_UNIT_TEST
#include "firmware_cli.c"
int main(void){
 mock_power=0;mock_power_reject=true;
 if(radio_power_configure()||mock_power!=0)return 1;
 mock_power_reject=false;
 if(!radio_power_configure()||mock_power!=8)return 2;
 printf("POWER8_CONFIG_READBACK_PASS\n");return 0;
}
