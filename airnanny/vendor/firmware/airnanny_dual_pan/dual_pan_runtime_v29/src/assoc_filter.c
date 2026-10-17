/* Immediate ACK clear-envelope admission only; host authenticates MIC/replay. */
#include "gate_events.h"
#include "nrf_802154_types.h"
#include <string.h>
static const commission_t *bound;
void assoc_filter_bind(const commission_t *s){bound=s;}
static uint16_t le16(const uint8_t *p){return p[0]|(uint16_t)p[1]<<8;}
int assoc_filter_part(const uint8_t *raw,uint8_t *received){
    if(!raw||!received||*received<3)return NRF_802154_RX_ERROR_INVALID_FRAME;
    if(!bound||bound->phase!=G_MANAGEMENT||bound->recovery.phase==R_SCANNING||raw[0]<40||raw[0]>127||raw[1]!=0x61||raw[2]!=0x88)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(*received<18){*received=18;return NRF_802154_RX_ERROR_NONE;}
    const uint8_t *m=raw+1;uint16_t f=le16(m+9);size_t h=8;
    /* Supported A7 secured DATA, or CMD response with both extended addresses. */
    if(f==0x1a09)h=24;else if(f==0x1209)h=16;else if(f!=0x0248&&f!=0x0208)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    size_t need=9+h+14;
    if(raw[0]<need+4+2)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(*received<need+1){*received=need+1;return NRF_802154_RX_ERROR_NONE;}
    const key_gate_t *k=&bound->keys;
    if(le16(m+3)!=k->pan||le16(m+5)!=k->short_address||le16(m+7)!=0||le16(m+11)!=k->short_address||le16(m+13)!=0)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(h==24&&(memcmp(m+17,k->raw,8)||memcmp(m+25,k->tc,8)))return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(h==16&&memcmp(m+17,k->tc,8))return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    const uint8_t *aux=m+9+h;
    if(aux[0]!=0x28||memcmp(aux+5,k->tc,8)||aux[13]!=k->keyseq)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    return NRF_802154_RX_ERROR_NONE;
}
