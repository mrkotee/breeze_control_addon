#include <stdint.h>
typedef struct {uint32_t MODE,BITMODE,PRESCALER,TASKS_CLEAR,TASKS_START,TASKS_CAPTURE[1],CC[1];} fake_timer_t;
extern fake_timer_t fake_timer;
#define NRF_TIMER3 (&fake_timer)
static inline uint32_t __get_PRIMASK(void){return 0;}
static inline void __disable_irq(void){}
static inline void __set_PRIMASK(uint32_t p){(void)p;}
#define __DMB() ((void)0)
