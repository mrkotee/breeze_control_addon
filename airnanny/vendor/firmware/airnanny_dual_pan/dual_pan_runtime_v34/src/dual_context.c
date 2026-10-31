/* Classification and per-context bindings. Behaviour of dual_config_valid,
 * dual_header_size, dual_addr_match and dual_ack_eligible is carried over from
 * dual_pan_mac_gate/src/dual_filter.c without relaxation. */
#include "dual_context.h"
#include "dual_identity.h"
#include <string.h>

static dual_config_t current = { .channel = 21 };
static dual_binding_t bindings[DUAL_CONTEXTS];
static dual_stats_t stats;

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

bool dual_config_valid(const dual_config_t *c)
{
    if (!c || c->channel != 21) return false;
    for (unsigned i = 0; i < DUAL_CONTEXTS; i++) {
        if (!c->ctx[i].enabled) continue;
        if (c->ctx[i].pan_id == 0xffff || c->ctx[i].local_short >= 0xfffe) return false;
        /* Pinned identity: this image addresses two networks and no others.
         * The host chooses whether a context is on and which short it currently
         * holds, never which network it is. */
        if (!dual_identity_pan_matches(i, c->ctx[i].pan_id)) return false;
        if (!dual_identity_short_plausible(i, c->ctx[i].local_short)) return false;
        if (c->ctx[i].ieee_valid && !dual_identity_raw_matches(i, c->ctx[i].local_ieee))
            return false;
    }
    /* Two enabled entries must differ as a pair, otherwise classification is
     * ambiguous and no context could own an ACK. */
    return !(c->ctx[0].enabled && c->ctx[1].enabled &&
             c->ctx[0].pan_id == c->ctx[1].pan_id &&
             c->ctx[0].local_short == c->ctx[1].local_short);
}

dual_match_t dual_header_size(const uint8_t *p, size_t len, uint8_t *size)
{
    if (!p || !size || len < 2) return MATCH_MALFORMED;
    uint16_t f = le16(p); unsigned d = (f >> 10) & 3, s = (f >> 14) & 3;
    bool compress = (f & 0x40) != 0;
    if (d == 1 || s == 1 || (compress && (d == 0 || s == 0))) return MATCH_MALFORMED;
    /* Deliberately scoped to legacy unencrypted DATA; extended explicitly rejected. */
    if ((f & 7) != 1 || ((f >> 12) & 3) != 0 || (f & 0x0388) != 0 || d == 3 || s == 3)
        return MATCH_UNSUPPORTED;
    *size = (uint8_t)(3 + (d == 2 ? 4 : 0) + (s == 2 ? (compress ? 2 : 4) : 0));
    return MATCH_NONE;
}

dual_match_t dual_addr_match(const uint8_t *p, size_t len, const dual_config_t *c, dual_header_t *h)
{
    if (!h) return MATCH_MALFORMED;
    memset(h, 0, sizeof(*h));
    uint8_t needed = 0; dual_match_t result = dual_header_size(p, len, &needed);
    if (result != MATCH_NONE) return result;
    if (len < needed) return MATCH_MALFORMED;
    h->fcf = le16(p); h->dsn = p[2]; h->header_len = needed;
    h->ack_requested = (h->fcf & 0x20) != 0;
    unsigned d = (h->fcf >> 10) & 3, s = (h->fcf >> 14) & 3;
    h->destination_present = d != 0;
    if (!d) return MATCH_NONE;
    h->pan = le16(p + 3); h->dst = le16(p + 5);
    if (s) h->src = le16(p + ((h->fcf & 0x40) ? 7 : 9));
    if (h->pan == 0xffff || h->dst == 0xffff) return MATCH_BROADCAST;
    if (!dual_config_valid(c)) return MATCH_AMBIGUOUS;
    if (!c->enabled) return MATCH_NONE;
    bool a = c->ctx[0].enabled && c->ctx[0].pan_id == h->pan && c->ctx[0].local_short == h->dst;
    bool b = c->ctx[1].enabled && c->ctx[1].pan_id == h->pan && c->ctx[1].local_short == h->dst;
    if (a && b) return MATCH_AMBIGUOUS;
    if (a) return MATCH_CTX0;
    if (b) return MATCH_CTX1;
    bool cross = c->ctx[0].enabled && c->ctx[1].enabled &&
        ((h->pan == c->ctx[0].pan_id && h->dst == c->ctx[1].local_short) ||
         (h->pan == c->ctx[1].pan_id && h->dst == c->ctx[0].local_short));
    h->reason = cross ? REASON_CROSS_PAIR : REASON_FOREIGN;
    return MATCH_NONE;
}

bool dual_ack_eligible(dual_match_t m, const dual_header_t *h, bool crc, bool auto_ack)
{ return h && (m == MATCH_CTX0 || m == MATCH_CTX1) && h->ack_requested && crc && auto_ack; }

const dual_config_t *dual_config_current(void) { return &current; }

bool dual_config_commit_locked(const dual_config_t *c)
{
    if (!dual_config_valid(c)) return false;
    /* Monotonic only; a repeat or a rollback is refused so that every RX record
     * can name the generation that classified it. */
    if (c->generation <= current.generation && current.generation != 0) return false;
    current = *c;
    /* A context that is reconfigured loses its previous deep binding and its
     * ACK permission; nothing may survive a tuple change implicitly. */
    for (unsigned i = 0; i < DUAL_CONTEXTS; i++)
        if (!current.ctx[i].enabled) memset(&bindings[i], 0, sizeof(bindings[i]));
    return true;
}

bool dual_binding_set(unsigned ctx, const dual_binding_t *b)
{
    if (ctx >= DUAL_CONTEXTS || !b || !current.ctx[ctx].enabled) return false;
    /* The binding must describe the same identity the configuration published. */
    if (b->pan != current.ctx[ctx].pan_id || b->short_address != current.ctx[ctx].local_short)
        return false;
    if (b->short_address >= 0xfff8) return false;
    /* RAW identity and trust-centre identity are distinct by construction. */
    if (!memcmp(b->raw, b->tc, 8)) return false;
    bool raw_nonzero = false, tc_nonzero = false;
    for (unsigned i = 0; i < 8; i++) { raw_nonzero |= b->raw[i] != 0; tc_nonzero |= b->tc[i] != 0; }
    if (!raw_nonzero || !tc_nonzero) return false;
    /* Pinned identity again, because a binding is what the admission predicate
     * actually compares frames against. A syntactically valid binding naming
     * another network, or this context's PAN with the other context's RAW or
     * trust-centre address, is refused here rather than on air. */
    if (!dual_identity_pan_matches(ctx, b->pan)) return false;
    if (!dual_identity_raw_matches(ctx, b->raw)) return false;
    if (!dual_identity_tc_matches(ctx, b->tc)) return false;
    if (b->keyseq != dual_identity(ctx)->keyseq) return false;
    dual_binding_t copy = *b;
    copy.bound = true;
    /* ACK is never granted by BIND; it needs its own explicit command. */
    copy.ack_enabled = false;
    copy.scanning = false;
    bindings[ctx] = copy;
    return true;
}

const dual_binding_t *dual_binding_get(unsigned ctx)
{ return ctx < DUAL_CONTEXTS ? &bindings[ctx] : NULL; }

bool dual_binding_ack(unsigned ctx, bool enabled)
{
    if (ctx >= DUAL_CONTEXTS || !bindings[ctx].bound || !current.ctx[ctx].enabled) return false;
    bindings[ctx].ack_enabled = enabled;
    return true;
}

bool dual_binding_scanning(unsigned ctx, bool scanning)
{
    if (ctx >= DUAL_CONTEXTS || !bindings[ctx].bound) return false;
    bindings[ctx].scanning = scanning;
    return true;
}

bool dual_ctx_ack_allowed(unsigned ctx)
{
    if (ctx >= DUAL_CONTEXTS) return false;
    const dual_binding_t *b = &bindings[ctx];
    return current.enabled && current.ctx[ctx].enabled &&
           b->bound && b->ack_enabled && !b->scanning;
}

const char *dual_match_name(dual_match_t m)
{
    switch (m) {
    case MATCH_CTX0: return "ctx0";
    case MATCH_CTX1: return "ctx1";
    case MATCH_BROADCAST: return "broadcast";
    case MATCH_MALFORMED: return "malformed";
    case MATCH_UNSUPPORTED: return "unsupported";
    case MATCH_AMBIGUOUS: return "ambiguous";
    default: return "none";
    }
}

const char *dual_reason_name(dual_reason_t r)
{
    switch (r) {
    case REASON_FOREIGN: return "foreign";
    case REASON_CROSS_PAIR: return "cross_pair";
    default: return "none";
    }
}

void dual_stats_reset(void) { memset(&stats, 0, sizeof(stats)); }
void dual_stats_get(dual_stats_t *out) { if (out) *out = stats; }

/* Internal, used by the admission shim in dual_admit.c. */
dual_stats_t *dual_stats_mutable(void) { return &stats; }
