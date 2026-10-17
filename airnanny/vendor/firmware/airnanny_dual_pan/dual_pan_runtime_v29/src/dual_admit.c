/* V26 immediate-ACK admission: classify the context first, then apply the V25
 * deep predicate of that one context.
 *
 * Provenance: the field checks below are ctx1_rx_admission_v25/src/assoc_filter.c
 * verbatim in substance, with the single global `bound->keys` replaced by the
 * binding of the context that classification selected, and the single
 * session-wide phase gate replaced by the per-context ACK gate. No check was
 * removed or relaxed.
 *
 * Host still authenticates MIC and replay. Admission only decides whether this
 * frame may be answered with a legacy MAC ACK.
 */
#include "dual_context.h"
#include "nrf_802154_types.h"
#include <string.h>

dual_stats_t *dual_stats_mutable(void);

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

/* Deep predicate of one bound context. `raw` is PHR + PSDU; at least
 * `need + 1` bytes are present. */
static int deep_admit(const uint8_t *raw, uint8_t *received, const dual_binding_t *k)
{
    if (raw[0] < 40 || raw[0] > 127 || raw[1] != 0x61 || raw[2] != 0x88)
        return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if (*received < 18) { *received = 18; return NRF_802154_RX_ERROR_NONE; }

    const uint8_t *m = raw + 1;
    uint16_t f = le16(m + 9);
    size_t h = 8;
    /* Supported A7 secured DATA, or CMD response with both extended addresses. */
    if (f == 0x1a09) h = 24;
    else if (f == 0x1209) h = 16;
    else if (f != 0x0248 && f != 0x0208) return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;

    size_t need = 9 + h + 14;
    if (raw[0] < need + 4 + 2) return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if (*received < need + 1) { *received = (uint8_t)(need + 1); return NRF_802154_RX_ERROR_NONE; }

    if (le16(m + 3) != k->pan || le16(m + 5) != k->short_address || le16(m + 7) != 0 ||
        le16(m + 11) != k->short_address || le16(m + 13) != 0)
        return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if (h == 24 && (memcmp(m + 17, k->raw, 8) || memcmp(m + 25, k->tc, 8)))
        return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    if (h == 16 && memcmp(m + 17, k->tc, 8))
        return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;

    const uint8_t *aux = m + 9 + h;
    if (aux[0] != 0x28 || memcmp(aux + 5, k->tc, 8) || aux[13] != k->keyseq)
        return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    return NRF_802154_RX_ERROR_NONE;
}

int dual_admit_part(const uint8_t *raw, uint8_t *received)
{
    if (!raw || !received || *received < 3) return NRF_802154_RX_ERROR_INVALID_FRAME;
    if (raw[0] < 5 || raw[0] > 127) return NRF_802154_RX_ERROR_INVALID_LENGTH;

    uint8_t needed = 0;
    dual_stats_t *s = dual_stats_mutable();
    dual_match_t m = dual_header_size(raw + 1, (size_t)(*received - 1), &needed);
    if (m != MATCH_NONE || (unsigned)needed + 2 > raw[0]) {
        if (m == MATCH_UNSUPPORTED) s->unsupported_reject++; else s->malformed_reject++;
        return NRF_802154_RX_ERROR_INVALID_FRAME;
    }

    /* One BCC round for everything we can already tell apart. A frame that could
     * still be a target frame jumps straight to the 18 bytes the deep predicate
     * needs, so an admitted frame costs the same two rounds it cost in V25. */
    uint8_t want = (uint8_t)(needed + 1);
    if (raw[0] >= 40 && raw[1] == 0x61 && raw[2] == 0x88 && want < 18) want = 18;
    if (*received < want) { *received = want; return NRF_802154_RX_ERROR_NONE; }

    dual_header_t header;
    m = dual_addr_match(raw + 1, (size_t)(*received - 1), dual_config_current(), &header);
    s->rx_total++;

    switch (m) {
    case MATCH_CTX0: s->ctx0_match++; break;
    case MATCH_CTX1: s->ctx1_match++; break;
    case MATCH_BROADCAST:
        /* Broadcast deliberately stays unfiltered and observable in promiscuous
         * RX. The core ACK condition cannot ACK a broadcast with a bogus AR=1. */
        s->broadcast++;
        return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    case MATCH_AMBIGUOUS:
        s->ambiguous_reject++;
        return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    case MATCH_MALFORMED:
        s->malformed_reject++;
        return NRF_802154_RX_ERROR_INVALID_FRAME;
    case MATCH_UNSUPPORTED:
        s->unsupported_reject++;
        return NRF_802154_RX_ERROR_INVALID_FRAME;
    case MATCH_NONE:
    default:
        if (header.reason == REASON_CROSS_PAIR) s->cross_pair_reject++;
        else s->foreign_reject++;
        return NRF_802154_RX_ERROR_INVALID_DEST_ADDR;
    }

    unsigned ctx = (m == MATCH_CTX0) ? 0u : 1u;
    const dual_binding_t *k = dual_binding_get(ctx);
    if (!k || !k->bound) { s->ack_suppressed_disabled++; return NRF_802154_RX_ERROR_INVALID_DEST_ADDR; }
    if (k->scanning)     { s->ack_suppressed_scanning++; return NRF_802154_RX_ERROR_INVALID_DEST_ADDR; }
    if (!dual_ctx_ack_allowed(ctx)) { s->ack_suppressed_disabled++; return NRF_802154_RX_ERROR_INVALID_DEST_ADDR; }

    int result = deep_admit(raw, received, k);
    if (result != NRF_802154_RX_ERROR_NONE) s->deep_reject++;
    return result;
}
