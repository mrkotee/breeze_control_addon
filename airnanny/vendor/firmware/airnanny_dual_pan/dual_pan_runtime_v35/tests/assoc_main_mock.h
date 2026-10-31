#ifndef ASSOC_MAIN_MOCK_H
#define ASSOC_MAIN_MOCK_H
#include "nrf_802154_types.h"
typedef int app_usbd_class_inst_t;
typedef enum {APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE,APP_USBD_CDC_ACM_USER_EVT_TX_DONE,APP_USBD_CDC_ACM_USER_EVT_RX_DONE} app_usbd_cdc_acm_user_event_t;
typedef enum {APP_USBD_EVT_POWER_DETECTED,APP_USBD_EVT_POWER_READY,APP_USBD_EVT_POWER_REMOVED,APP_USBD_EVT_STOPPED} app_usbd_event_type_t;
typedef struct {void (*ev_state_proc)(app_usbd_event_type_t);} app_usbd_config_t;
#define APP_USBD_CDC_ACM_GLOBAL_DEF(name,...) static int name
#define NRF_SUCCESS 0
static unsigned mock_system_resets;
static void NVIC_SystemReset(void){mock_system_resets++;}
#define NRF_ERROR_TIMEOUT 1
#define APP_ERROR_HANDLER(x) do{(void)(x);}while(0)
#define APP_ERROR_CHECK(x) do{(void)(x);}while(0)
typedef struct {unsigned CONFIG,TASKS_START,EVENTS_VALRDY,VALUE,TASKS_STOP;} fake_rng_t;
static fake_rng_t rng_register;
#define NRF_RNG (&rng_register)
static uint32_t __get_PRIMASK(void){return 0;}
static void __disable_irq(void){}
static void __set_PRIMASK(uint32_t v){(void)v;}
static void __DMB(void){}
static bool ack_enabled,mock_sleep_ok=true,mock_receive_ok=true,mock_driver_ok=true,mock_inline;
static uint32_t mock_backoff_random;
static unsigned mock_rf_starts;
static unsigned mock_transmits,mock_sleeps,mock_receives;
static uint8_t mock_sent[128],mock_ieee[8];
static bool mock_core_sleep=true,mock_radio_disabled=true,mock_dma=false,mock_ack_timer=false;
static bool mock_async_sleep=false;
static bool mock_waiting_ack=false,mock_preair=false,mock_cca_rx=false;
static void nrf_802154_auto_ack_set(bool v){ack_enabled=v;}
static bool nrf_802154_sleep(void){mock_sleeps++;if(mock_sleep_ok){mock_ack_timer=false;if(!mock_async_sleep){mock_dma=false;mock_core_sleep=true;mock_radio_disabled=true;}}return mock_sleep_ok;}
static int nrf_802154_state_get(void){return NRF_802154_STATE_SLEEP;}
static void nrf_802154_extended_address_set(const uint8_t *p){for(unsigned i=0;i<8;i++)mock_ieee[i]=p[i];}
static void nrf_802154_pan_id_set(const uint8_t *p){(void)p;}
static void nrf_802154_short_address_set(const uint8_t *p){(void)p;}
static bool nrf_802154_receive(void){mock_receives++;return mock_receive_ok;}
void nrf_802154_transmitted_raw(const uint8_t *p,uint8_t *ack,int8_t r,uint8_t l);
void nrf_802154_tx_started(const uint8_t *p);
static bool nrf_802154_transmit_raw(const uint8_t *p,bool cca){(void)cca;if(!mock_driver_ok)return false;mock_transmits++;mock_core_sleep=false;mock_radio_disabled=false;mock_dma=true;mock_ack_timer=(p[1]&0x20)!=0;for(unsigned i=0;i<=p[0];i++)mock_sent[i]=p[i];mock_cca_rx=false;if(!mock_preair){mock_rf_starts++;nrf_802154_tx_started(p);}if(mock_inline){uint8_t ack[]={5,((p[1]&7)==3)?18:2,0,p[3],0,0};mock_dma=false;mock_ack_timer=false;nrf_802154_transmitted_raw(p,(p[1]&0x20)?ack:NULL,0,0);}return true;}
static void nrf_802154_buffer_free_raw(uint8_t *p){(void)p;}
static void nrf_802154_init(void){}
static void nrf_802154_channel_set(unsigned x){(void)x;}
static void nrf_802154_promiscuous_set(bool x){(void)x;}
static int app_usbd_cdc_acm_read(int *x,uint8_t *p,unsigned n){(void)x;(void)p;(void)n;return 1;}
static int app_usbd_cdc_acm_write(int *x,const char *p,size_t n){(void)x;(void)p;(void)n;return 0;}
static bool nrf_drv_usbd_is_enabled(void){return true;}
static void app_usbd_enable(void){}
static void app_usbd_start(void){}
static void app_usbd_stop(void){}
static void app_usbd_disable(void){}
static int nrf_drv_clock_init(void){return 0;}
static void app_usbd_serial_num_generate(void){}
static int app_usbd_init(const app_usbd_config_t *p){(void)p;return 0;}
static int app_usbd_class_append(const void *p){(void)p;return 0;}
static void *app_usbd_cdc_acm_class_inst_get(int *p){return p;}
static int app_usbd_power_events_enable(void){return 0;}
static void app_usbd_event_queue_process(void){}
#endif

static int8_t mock_power;static bool mock_power_reject;
#define NRF_ERROR_INTERNAL 3
static void nrf_802154_tx_power_set(int8_t p){if(!mock_power_reject)mock_power=p;}
static int8_t nrf_802154_tx_power_get(void){return mock_power;}

/* V34 front-end stubs. The native tests cannot drive a GPIO, so what they can
 * check is the one thing a wrong build would get wrong silently: that main.c
 * hands the driver the pins this board actually has, before it starts
 * receiving. mock_fem_set_reject makes the setter fail so the boot path's
 * refusal is exercised too -- on the real dongle a FEM that is not configured
 * means no RF at all, so booting on anyway would be worse than not booting. */
#define NRF_SUCCESS 0
#define NRF_ERROR_NOT_SUPPORTED 6
#define NRF_FEM_PDN_SETTLE_US 18
#define NRF_FEM_TRX_HOLD_US 5
typedef struct{bool enable;bool active_high;uint8_t gpio_pin;uint8_t gpiote_ch_id;}
    nrf_fem_gpiote_pin_config_t;
typedef struct{
    struct{uint32_t pa_time_gap_us;uint32_t lna_time_gap_us;uint32_t pdn_settle_us;
           uint32_t trx_hold_us;int8_t pa_gain_db;int8_t lna_gain_db;} fem_config;
    nrf_fem_gpiote_pin_config_t pa_pin_config,lna_pin_config,pdn_pin_config;
    uint8_t ppi_ch_id_set,ppi_ch_id_clr,ppi_ch_id_pdn;} nrf_fem_interface_config_t;
/* V35 clear-channel threshold. nrf_802154_cca_cfg_t comes from the real
 * nrf_802154_types.h, which the mock already includes, so only the mode
 * constant and the two accessors are stubbed. The conversion mirrors the real
 * nrf_802154_ccaedthres_from_dbm_calculate(), `dbm - ED_MIN_DBM` with
 * ED_MIN_DBM -94, so the test asserts the register value the firmware would
 * actually write rather than restating its own arithmetic. */
#define NRF_RADIO_CCA_MODE_ED 0
#define MOCK_ED_MIN_DBM (-94)
static nrf_802154_cca_cfg_t mock_cca;static unsigned mock_cca_sets;
static uint8_t nrf_802154_ccaedthres_from_dbm_calculate(int8_t dbm)
{return (uint8_t)(dbm - MOCK_ED_MIN_DBM);}
static void nrf_802154_cca_cfg_set(const nrf_802154_cca_cfg_t *c){mock_cca=*c;mock_cca_sets++;}
static void nrf_802154_cca_cfg_get(nrf_802154_cca_cfg_t *c){*c=mock_cca;}

static nrf_fem_interface_config_t mock_fem;static bool mock_fem_set_reject;
static unsigned mock_fem_sets;
static int32_t nrf_fem_interface_configuration_set(const nrf_fem_interface_config_t *c)
{if(mock_fem_set_reject)return NRF_ERROR_NOT_SUPPORTED;mock_fem=*c;mock_fem_sets++;return NRF_SUCCESS;}
static int32_t nrf_fem_interface_configuration_get(nrf_fem_interface_config_t *c)
{*c=mock_fem;return NRF_SUCCESS;}

static uint32_t mock_rx_busy_until;
static bool nrf_802154_core_tx_admission_busy(void){return gate_hw_now_us()<mock_rx_busy_until;}
