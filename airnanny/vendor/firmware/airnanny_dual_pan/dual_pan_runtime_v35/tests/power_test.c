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

 /* V35: the clear-channel threshold follows the amplifier's receive gain.
  * Asserted as the register value the firmware writes, computed here from dBm
  * the same way the driver does, so a wrong sign or a dropped gain shows up as
  * a number rather than as deferred transmissions on the hardware. */
 mock_cca_sets=0;
 if(!cca_configure())return 14;
 if(mock_cca_sets!=1)return 15;
 if(mock_cca.mode!=NRF_RADIO_CCA_MODE_ED)return 16;
 /* -74 dBm was the pre-amplifier default, 0x14. */
 if(nrf_802154_ccaedthres_from_dbm_calculate(-74)!=0x14)return 17;
 /* Shifted by the LNA's gain and by nothing else. */
 if(BOARD_CCA_ED_THRESHOLD_DBM!=-74+BOARD_FEM_LNA_GAIN_DB)return 18;
 if(mock_cca.ed_threshold!=nrf_802154_ccaedthres_from_dbm_calculate(BOARD_CCA_ED_THRESHOLD_DBM))return 19;
 /* The threshold must rise: a lower one would defer to traffic the old dongle
  * could not hear, which is the fault this change exists to remove. */
 if(mock_cca.ed_threshold<=0x14)return 20;

 printf("FEM_PA%d_LNA%d_TXPOWER%d_CCA%ddBm_0x%02X_CONFIG_READBACK_PASS\n",
        BOARD_FEM_PA_PIN,BOARD_FEM_LNA_PIN,BOARD_SOC_TX_POWER_DBM,
        BOARD_CCA_ED_THRESHOLD_DBM,mock_cca.ed_threshold);
 return 0;
}
