#ifndef ASSOC_MAIN_MOCK_H
#define ASSOC_MAIN_MOCK_H
#include "nrf_802154_types.h"
typedef int app_usbd_class_inst_t;
typedef enum {APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN,APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE,APP_USBD_CDC_ACM_USER_EVT_TX_DONE,APP_USBD_CDC_ACM_USER_EVT_RX_DONE} app_usbd_cdc_acm_user_event_t;
typedef enum {APP_USBD_EVT_POWER_DETECTED,APP_USBD_EVT_POWER_READY,APP_USBD_EVT_POWER_REMOVED,APP_USBD_EVT_STOPPED} app_usbd_event_type_t;
typedef struct {void (*ev_state_proc)(app_usbd_event_type_t);} app_usbd_config_t;
#define APP_USBD_CDC_ACM_GLOBAL_DEF(name,...) static int name
#define NRF_SUCCESS 0
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
static unsigned mock_transmits;
static uint8_t mock_sent[128],mock_ieee[8];
static void nrf_802154_auto_ack_set(bool v){ack_enabled=v;}
static bool nrf_802154_sleep(void){return mock_sleep_ok;}
static int nrf_802154_state_get(void){return NRF_802154_STATE_SLEEP;}
static void nrf_802154_extended_address_set(const uint8_t *p){for(unsigned i=0;i<8;i++)mock_ieee[i]=p[i];}
static void nrf_802154_pan_id_set(const uint8_t *p){(void)p;}
static void nrf_802154_short_address_set(const uint8_t *p){(void)p;}
static bool nrf_802154_receive(void){return mock_receive_ok;}
void nrf_802154_transmitted_raw(const uint8_t *p,uint8_t *ack,int8_t r,uint8_t l);
static bool nrf_802154_transmit_raw(const uint8_t *p,bool cca){(void)cca;if(!mock_driver_ok)return false;mock_transmits++;for(unsigned i=0;i<=p[0];i++)mock_sent[i]=p[i];if(mock_inline)nrf_802154_transmitted_raw(p,NULL,0,0);return true;}
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
