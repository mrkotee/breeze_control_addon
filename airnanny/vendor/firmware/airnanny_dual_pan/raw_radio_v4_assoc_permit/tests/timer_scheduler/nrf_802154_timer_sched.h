#include <stdint.h>
#include <stdbool.h>
typedef struct {uint32_t t0,dt;void (*callback)(void *);void *p_context;} nrf_802154_timer_t;
void nrf_802154_timer_sched_add(nrf_802154_timer_t *,bool);
void nrf_802154_timer_sched_remove(nrf_802154_timer_t *,bool *);
uint32_t nrf_802154_timer_sched_time_get(void);
