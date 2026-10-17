#include <stdint.h>
typedef struct {uint32_t MODE,BITMODE,PRESCALER,TASKS_CLEAR,TASKS_START,TASKS_CAPTURE[1],CC[1];} mock_timer_t;
extern mock_timer_t test_timer;
#define NRF_TIMER3 (&test_timer)
