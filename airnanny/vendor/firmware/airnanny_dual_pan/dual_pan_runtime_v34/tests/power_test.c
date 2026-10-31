/* Startup RF configuration, against the actual C in main.c.
 *
 * Through V33 this file asserted +8 dBm, the SoC maximum, because the radio fed
 * the antenna directly. V34's dongle puts an RFX2401C in between, so the number
 * that matters moved: the SoC now drives an amplifier, and the board's figure
 * lives in board_fem.h. The amplifier checks are new, and they are the ones
 * worth having -- a build whose FEM pins are wrong produces no RF at all on
 * this hardware, and nothing else offline would notice.
 */
#define COMMISSION_UNIT_TEST
#include "firmware_cli.c"
int main(void){
 mock_power=0;mock_power_reject=true;
 if(radio_power_configure()||mock_power!=0)return 1;
 mock_power_reject=false;
 if(!radio_power_configure()||mock_power!=BOARD_SOC_TX_POWER_DBM)return 2;

 /* A rejected setter must fail the boot, not be shrugged off: an unconfigured
  * RFX2401C passes nothing, so a dongle that came up anyway would look alive
  * on USB and be invisible on the air. */
 mock_fem_set_reject=true;mock_fem_sets=0;
 if(fem_configure()||mock_fem_sets!=0)return 3;

 mock_fem_set_reject=false;
 if(!fem_configure())return 4;
 if(mock_fem_sets!=1)return 5;
 if(!mock_fem.pa_pin_config.enable||!mock_fem.lna_pin_config.enable)return 6;
 if(mock_fem.pa_pin_config.gpio_pin!=BOARD_FEM_PA_PIN)return 7;
 if(mock_fem.lna_pin_config.gpio_pin!=BOARD_FEM_LNA_PIN)return 8;
 if(!mock_fem.pa_pin_config.active_high||!mock_fem.lna_pin_config.active_high)return 9;
 /* The board brings out TXEN and RXEN only. Enabling PDN would hand the driver
  * a pin wired to nothing and let it power the part down mid-session. */
 if(mock_fem.pdn_pin_config.enable)return 10;
 /* PPI 6..14 belong to the 802.15.4 driver (nrf_802154_peripherals.h). The
  * amplifier must not land on top of the radio's own ramp-up plumbing. */
 if(mock_fem.ppi_ch_id_set<15||mock_fem.ppi_ch_id_clr<15)return 11;
 if(mock_fem.pa_pin_config.gpio_pin==mock_fem.lna_pin_config.gpio_pin)return 12;
 if(mock_fem.pa_pin_config.gpiote_ch_id==mock_fem.lna_pin_config.gpiote_ch_id)return 13;

 printf("FEM_PA%d_LNA%d_TXPOWER%d_CONFIG_READBACK_PASS\n",
        BOARD_FEM_PA_PIN,BOARD_FEM_LNA_PIN,BOARD_SOC_TX_POWER_DBM);
 return 0;
}
