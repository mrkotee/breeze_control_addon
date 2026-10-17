#include "gate_events.h"
#include "nrf_802154_types.h"
static const assoc_t *bound;
void assoc_filter_bind(const assoc_t *s){bound=s;}
int assoc_filter_part(const uint8_t *raw,uint8_t *received)
{
    if(!raw || !received || *received<3)return NRF_802154_RX_ERROR_INVALID_FRAME;
    if(raw[0]<5 || raw[0]>127)return NRF_802154_RX_ERROR_INVALID_LENGTH;
    if(raw[0]!=27)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(!bound || (bound->state!=A_REQUEST_SENT && bound->state!=A_WAIT_RESPONSE))return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(raw[1]!=0x63 || raw[2]!=0xcc)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    /* Full captured response inspected before CRCOK; PHR includes FCS. No other AR1 frame ACKed. */
    if(*received<26){*received=26;return NRF_802154_RX_ERROR_NONE;}
    assoc_result_t r;
    return assoc_response_parse(raw+1,25,&bound->target,1,0,&r)?NRF_802154_RX_ERROR_NONE:NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
}
