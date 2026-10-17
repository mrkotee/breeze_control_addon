#ifndef RADIO_TIME_H
#define RADIO_TIME_H
#include <stdint.h>
#include <stdbool.h>
/* Every live deadline/window is shorter than 2^31 us. Compare instants only
 * inside that horizon; duration differences use unsigned subtraction. */
static inline bool radio_time_reached(uint32_t now,uint32_t instant)
{return (int32_t)(now-instant)>=0;}
#endif
