#include "gate_events.h"
#include "nrf_802154_types.h"
static const assoc_t *a_bound;
void v4_bind(const assoc_t *s){a_bound=s;}
int v4_filter(const uint8_t *raw,uint8_t *received)
{
    if(!raw || !received || *received<3)return NRF_802154_RX_ERROR_INVALID_FRAME;
    if(raw[0]<5 || raw[0]>127)return NRF_802154_RX_ERROR_INVALID_LENGTH;
    if(raw[0]!=27)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(!a_bound || (a_bound->state!=A_REQUEST_SENT && a_bound->state!=A_WAIT_RESPONSE))return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(raw[1]!=0x63 || raw[2]!=0xcc)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    /* Full captured response inspected before CRCOK; PHR includes FCS. No other AR1 frame ACKed. */
    if(*received<26){*received=26;return NRF_802154_RX_ERROR_NONE;}
    assoc_result_t r;
    return assoc_response_parse(raw+1,25,&a_bound->target,1,0,&r)?NRF_802154_RX_ERROR_NONE:NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
}

/* Immediate ACK envelope gate; MIC authentication is exclusively on host. */
#include "gate_events.h"
#include "nrf_802154_types.h"
#include <string.h>
static const key_gate_t *k_bound;
void v5_bind(const key_gate_t *s){k_bound=s;}
static uint16_t le(const uint8_t *p){return p[0]|(uint16_t)p[1]<<8;}
int v5_filter(const uint8_t *raw,uint8_t *received)
{
    if(!raw||!received||*received<3)return NRF_802154_RX_ERROR_INVALID_FRAME;
    if(raw[0]<5||raw[0]>127)return NRF_802154_RX_ERROR_INVALID_LENGTH;
    if(!k_bound||(k_bound->state!=K_UNKEYED&&k_bound->state!=K_INSTALLED&&k_bound->state!=K_QUEUED&&k_bound->state!=K_MANAGEMENT))return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(raw[1]!=0x61||raw[2]!=0x88)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    /* Only A7 unicast short-source TransportKey / secured management envelopes.
       Need complete clear header before allowing ACK. No other PAN/IEEE ACKed. */
    bool tk=raw[0]==73; /* MAC9 + NWK8 + APS54 + FCS2 */
    size_t need=tk?33:40;
    if(raw[0]<need+1)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(*received<need){*received=need;return NRF_802154_RX_ERROR_NONE;}
    const uint8_t *m=raw+1;
    if(le(m+3)!=k_bound->pan||le(m+5)!=k_bound->short_address||le(m+7)!=0||le(m+11)!=k_bound->short_address||le(m+13)!=0)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if(tk && le(m+9)==0x0048 && m[17]==0x21 && m[19]==0x30 && !memcmp(m+24,k_bound->tc,8))return NRF_802154_RX_ERROR_NONE;
    /* Fixed NWK header subset (no extended NWK address fields). */
    if(le(m+9)==0x0248 && m[17]==0x28 && !memcmp(m+22,k_bound->tc,8) && m[30]==k_bound->keyseq && k_bound->state!=K_UNKEYED)return NRF_802154_RX_ERROR_NONE;
    return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
}

static const commission_t *both;
void assoc_filter_bind(const commission_t *s){both=s;v4_bind(&s->association);v5_bind(&s->keys);}
int assoc_filter_part(const uint8_t *raw,uint8_t *received){
    if(!both||both->phase==G_STOPPED)return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    return both->keys.session?v5_filter(raw,received):v4_filter(raw,received);
}
