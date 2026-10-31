#include "dual_records.h"
#include <stdio.h>
#include <string.h>

#define MAX_FIELDS 32u

typedef struct { const char *key; size_t key_len; const char *value; size_t value_len; } field_t;

static bool eq(const field_t *f, const char *name)
{ size_t n = strlen(name); return f->key_len == n && !memcmp(f->key, name, n); }

static bool parse_u32(const field_t *f, uint32_t *out, uint32_t limit)
{
    if (!f->value_len || f->value_len > 10) return false;
    uint32_t v = 0;
    for (size_t i = 0; i < f->value_len; i++) {
        char c = f->value[i];
        if (c < '0' || c > '9') return false;
        v = v * 10u + (uint32_t)(c - '0');
    }
    if (v > limit) return false;
    *out = v;
    return true;
}

static bool hex_nibble(char c, uint8_t *out)
{
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(c - 'a' + 10); return true; }
    /* Lowercase only on input, so one byte sequence has one spelling. */
    return false;
}

static bool parse_hex_bytes(const field_t *f, uint8_t *out, size_t expect)
{
    if (f->value_len != expect * 2u) return false;
    for (size_t i = 0; i < expect; i++) {
        uint8_t hi, lo;
        if (!hex_nibble(f->value[i * 2], &hi) || !hex_nibble(f->value[i * 2 + 1], &lo)) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool parse_hex16(const field_t *f, uint16_t *out)
{
    uint8_t b[2];
    if (!parse_hex_bytes(f, b, 2)) return false;
    *out = (uint16_t)((b[0] << 8) | b[1]);   /* wire-independent: text is big endian */
    return true;
}

static bool parse_hex_var(const field_t *f, uint8_t *out, size_t cap, uint8_t *len)
{
    if (!f->value_len || (f->value_len & 1u) || f->value_len / 2u > cap) return false;
    if (!parse_hex_bytes(f, out, f->value_len / 2u)) return false;
    *len = (uint8_t)(f->value_len / 2u);
    return true;
}

static bool parse_bool(const field_t *f, bool *out)
{
    if (f->value_len != 1) return false;
    if (f->value[0] == '0') { *out = false; return true; }
    if (f->value[0] == '1') { *out = true; return true; }
    return false;
}

static bool parse_token(const field_t *f, char *out, size_t cap)
{
    if (!f->value_len || f->value_len >= cap) return false;
    for (size_t i = 0; i < f->value_len; i++) {
        char c = f->value[i];
        bool allowed = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        if (!allowed) return false;
    }
    memcpy(out, f->value, f->value_len);
    out[f->value_len] = '\0';
    return true;
}

const char *dual_cmd_parse(const char *line, dual_cmd_t *out)
{
    if (!line || !out) return "null_input";
    memset(out, 0, sizeof(*out));
    out->channel = 21;

    size_t len = strlen(line);
    if (!len || len >= RADIO_LINE_MAX) return "line_length";
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)line[i];
        if (c < 0x20 || c > 0x7e) return "non_ascii";
    }

    const char *p = line;
    size_t prefix = strlen(RADIOV10_PREFIX);
    if (strncmp(p, RADIOV10_PREFIX, prefix) || p[prefix] != ' ') return "prefix";
    p += prefix + 1;

    const char *kind_start = p;
    while (*p && *p != ' ') p++;
    size_t kind_len = (size_t)(p - kind_start);
    static const struct { const char *name; dual_cmd_kind_t kind; } kinds[] = {
        { "INFO", CMD_INFO }, { "CONFIG", CMD_CONFIG }, { "BIND", CMD_BIND },
        { "ACK", CMD_ACK }, { "SCAN", CMD_SCAN }, { "TX", CMD_TX },
        { "STATS", CMD_STATS }, { "STATUS", CMD_STATUS }, { "END", CMD_END },
    };
    bool found = false;
    for (unsigned i = 0; i < sizeof kinds / sizeof *kinds; i++)
        if (kind_len == strlen(kinds[i].name) && !memcmp(kind_start, kinds[i].name, kind_len)) {
            out->kind = kinds[i].kind; found = true; break;
        }
    if (!found) return "unknown_command";

    field_t fields[MAX_FIELDS];
    unsigned count = 0;
    while (*p == ' ') {
        p++;
        if (!*p) return "trailing_space";
        const char *key = p;
        while (*p && *p != '=' && *p != ' ') p++;
        if (*p != '=') return "field_syntax";
        size_t key_len = (size_t)(p - key);
        if (!key_len) return "field_syntax";
        p++;
        const char *value = p;
        while (*p && *p != ' ') p++;
        size_t value_len = (size_t)(p - value);
        if (!value_len) return "empty_value";
        if (count >= MAX_FIELDS) return "too_many_fields";
        /* A repeated key is a refusal: last-one-wins would let a second ctx
         * silently override the first. */
        for (unsigned i = 0; i < count; i++)
            if (fields[i].key_len == key_len && !memcmp(fields[i].key, key, key_len))
                return "duplicate_field";
        fields[count].key = key; fields[count].key_len = key_len;
        fields[count].value = value; fields[count].value_len = value_len;
        count++;
    }
    if (*p) return "field_syntax";

    bool seen_id = false;
    uint32_t scratch;

    for (unsigned i = 0; i < count; i++) {
        field_t *f = &fields[i];
        if (eq(f, "id")) {
            if (!parse_u32(f, &out->id, 0xffffffffu)) return "id_invalid";
            seen_id = true;
        } else if (eq(f, "ctx")) {
            if (!parse_u32(f, &scratch, DUAL_CONTEXTS - 1u)) return "ctx_invalid";
            out->ctx = (unsigned)scratch; out->has_ctx = true;
        } else if (eq(f, "channel")) {
            if (!parse_u32(f, &scratch, 26u) || scratch != 21u) return "channel_invalid";
            out->channel = (uint8_t)scratch;
        } else if (eq(f, "generation")) {
            if (!parse_u32(f, &out->generation, 0xffffffffu) || !out->generation) return "generation_invalid";
            out->bind_generation = out->generation;
        } else if (eq(f, "enabled")) {
            if (!parse_bool(f, &out->enabled)) return "enabled_invalid";
        } else if (eq(f, "cca")) {
            if (!parse_bool(f, &out->cca)) return "cca_invalid";
        } else if (eq(f, "mac")) {
            if (!parse_hex_var(f, out->mac, DUAL_TX_MAC_MAX, &out->mac_len)) return "mac_invalid";
        } else if (eq(f, "class")) {
            if (f->value_len == 4 && !memcmp(f->value, "POLL", 4)) out->klass = TX_CLASS_POLL;
            else if (f->value_len == 10 && !memcmp(f->value, "MANAGEMENT", 10)) out->klass = TX_CLASS_MANAGEMENT;
            else if (f->value_len == 11 && !memcmp(f->value, "APPLICATION", 11)) out->klass = TX_CLASS_APPLICATION;
            else return "class_invalid";
        } else if (eq(f, "raw_ieee")) {
            if (!parse_hex_bytes(f, out->raw, 8)) return "raw_ieee_invalid";
        } else if (eq(f, "tc_ieee")) {
            if (!parse_hex_bytes(f, out->tc, 8)) return "tc_ieee_invalid";
        } else if (eq(f, "extpan")) {
            if (!parse_hex_bytes(f, out->extpan, 8)) return "extpan_invalid";
        } else if (eq(f, "pan")) {
            if (!parse_hex16(f, &out->bind_pan)) return "pan_invalid";
        } else if (eq(f, "short")) {
            if (!parse_hex16(f, &out->bind_short)) return "short_invalid";
        } else if (eq(f, "coordinator_short")) {
            if (!parse_hex16(f, &out->coordinator_short)) return "coordinator_short_invalid";
        } else if (eq(f, "keyseq")) {
            if (!parse_u32(f, &scratch, 255u)) return "keyseq_invalid";
            out->keyseq = (uint8_t)scratch;
        } else if (eq(f, "max_polls")) {
            if (!parse_u32(f, &out->max_polls, 0xffffu)) return "max_polls_invalid";
        } else if (eq(f, "poll_interval_ms")) {
            if (!parse_u32(f, &out->poll_interval_ms, 0xffffu)) return "poll_interval_invalid";
        } else if (eq(f, "timeout_ms")) {
            if (!parse_u32(f, &out->timeout_ms, 0xffffu)) return "timeout_invalid";
        } else if (eq(f, "attempt")) {
            if (!parse_token(f, out->attempt, sizeof out->attempt)) return "attempt_invalid";
        } else {
            /* ctxN_* configuration fields. */
            bool handled = false;
            for (unsigned c = 0; c < DUAL_CONTEXTS && !handled; c++) {
                char base[8];
                snprintf(base, sizeof base, "ctx%u_", c);
                size_t bl = strlen(base);
                if (f->key_len <= bl || memcmp(f->key, base, bl)) continue;
                field_t tail = { f->key + bl, f->key_len - bl, f->value, f->value_len };
                if (eq(&tail, "enabled")) {
                    if (!parse_bool(&tail, &out->ctx_enabled[c])) return "ctx_enabled_invalid";
                } else if (eq(&tail, "pan")) {
                    if (!parse_hex16(&tail, &out->pan[c])) return "ctx_pan_invalid";
                } else if (eq(&tail, "short")) {
                    if (!parse_hex16(&tail, &out->shortaddr[c])) return "ctx_short_invalid";
                } else if (eq(&tail, "ieee")) {
                    if (!parse_hex_bytes(&tail, out->ieee[c], 8)) return "ctx_ieee_invalid";
                } else {
                    return "unknown_field";
                }
                handled = true;
            }
            if (!handled) return "unknown_field";
        }
    }

    if (!seen_id) return "id_missing";

    switch (out->kind) {
    case CMD_CONFIG:
        if (!out->generation) return "generation_missing";
        for (unsigned c = 0; c < DUAL_CONTEXTS; c++) {
            if (!out->ctx_enabled[c]) continue;
            if (out->pan[c] == 0xffff || out->pan[c] == 0) return "ctx_pan_invalid";
            if (out->shortaddr[c] >= 0xfffe) return "ctx_short_invalid";
        }
        if (!out->ctx_enabled[0] && !out->ctx_enabled[1]) return "no_context_enabled";
        if (out->ctx_enabled[0] && out->ctx_enabled[1] &&
            out->pan[0] == out->pan[1] && out->shortaddr[0] == out->shortaddr[1])
            return "identical_tuple";
        break;
    case CMD_BIND:
        if (!out->has_ctx) return "ctx_missing";
        if (!out->bind_generation) return "generation_missing";
        if (!out->attempt[0]) return "attempt_missing";
        if (out->bind_short >= 0xfff8) return "short_invalid";
        if (!memcmp(out->raw, out->tc, 8)) return "identity_collision";
        if (memcmp(out->tc, out->extpan, 8)) return "extpan_mismatch";
        if (out->coordinator_short) return "coordinator_short_invalid";
        if (!out->max_polls || out->max_polls > 8) return "poll_policy";
        if (out->poll_interval_ms < 100 || out->poll_interval_ms > 5000) return "poll_policy";
        if (out->timeout_ms < 1000 || out->timeout_ms > 45000) return "poll_policy";
        if (out->poll_interval_ms > out->timeout_ms) return "poll_policy";
        break;
    case CMD_ACK:
    case CMD_SCAN:
        if (!out->has_ctx) return "ctx_missing";
        break;
    case CMD_TX:
        if (!out->has_ctx) return "ctx_missing";
        if (out->mac_len < 9) return "mac_invalid";
        break;
    case CMD_INFO:
    case CMD_STATS:
    case CMD_STATUS:
    case CMD_END:
        if (out->has_ctx) return "ctx_not_allowed";
        break;
    }
    return NULL;
}

const char *dual_tx_result_name(dual_tx_result_t r)
{
    switch (r) {
    case TX_RESULT_OK: return "ok";
    case TX_RESULT_NO_ACK: return "no_ack";
    case TX_RESULT_INVALID_ACK: return "invalid_ack";
    case TX_RESULT_CCA_FAIL: return "cca_fail";
    case TX_RESULT_ABORTED: return "aborted";
    default: return "error";
    }
}

/* Writes whole lines or nothing: a record is never emitted truncated. */
static bool commit(char *out, size_t capacity, const char *scratch, int written)
{
    if (written < 0 || (size_t)written >= capacity) return false;
    memcpy(out, scratch, (size_t)written + 1u);
    return true;
}

static bool hex_append(char *dst, size_t cap, const uint8_t *src, uint8_t len)
{
    if ((size_t)len * 2u + 1u > cap) return false;
    static const char digits[] = "0123456789abcdef";
    for (uint8_t i = 0; i < len; i++) {
        dst[i * 2] = digits[src[i] >> 4];
        dst[i * 2 + 1] = digits[src[i] & 0x0f];
    }
    dst[len * 2] = '\0';
    return true;
}

bool dual_format_rx(char *out, size_t capacity, const char *boot, const dual_rx_record_t *r)
{
    if (!out || !boot || !r) return false;
    char mac[DUAL_TX_MAC_MAX * 2u + 1u];
    if (!hex_append(mac, sizeof mac, r->mac, r->mac_len)) return false;
    char line[RADIO_LINE_MAX];
    char ctx[8];
    if (r->has_ctx) snprintf(ctx, sizeof ctx, "%u", r->ctx);
    else snprintf(ctx, sizeof ctx, "none");
    int n = snprintf(line, sizeof line,
        RADIOV10_PREFIX " RX boot=%s rx_id=%lu ctx=%s config_generation=%lu match=%s reason=%s"
        " channel=21 rx_end_us=%lu rx_end_valid=%u ack_address_us=%lu ack_address_valid=%u"
        " ack_start_us=%lu ack_start_valid=%u ack_end_us=%lu ack_end_valid=%u"
        " ack_started=%u ack_completed=%u deadline_miss=%u rssi=%d lqi=%u fcs_ok=%u mac=%s\n",
        boot, (unsigned long)r->rx_id, ctx, (unsigned long)r->config_generation,
        dual_match_name(r->match), dual_reason_name(r->reason),
        (unsigned long)r->rx_end_us, r->rx_end_valid, (unsigned long)r->ack_address_us,
        r->ack_address_valid, (unsigned long)r->ack_start_us, r->ack_start_valid,
        (unsigned long)r->ack_end_us, r->ack_end_valid,
        r->ack_started, r->ack_completed, r->deadline_miss, r->rssi, r->lqi, r->fcs_ok, mac);
    return commit(out, capacity, line, n);
}

bool dual_format_txaccept(char *out, size_t capacity, const char *boot,
                          const dual_tx_frame_t *f, uint32_t queue_depth)
{
    if (!out || !boot || !f) return false;
    char mac[DUAL_TX_MAC_MAX * 2u + 1u];
    if (!hex_append(mac, sizeof mac, f->mac, f->len)) return false;
    static const char *classes[] = { "POLL", "MANAGEMENT", "APPLICATION" };
    char line[RADIO_LINE_MAX];
    int n = snprintf(line, sizeof line,
        RADIOV10_PREFIX " TXACCEPT boot=%s id=%lu ctx=%u class=%s queue_depth=%lu mac=%s retry=0\n",
        boot, (unsigned long)f->host_id, f->ctx, classes[f->klass],
        (unsigned long)queue_depth, mac);
    return commit(out, capacity, line, n);
}

bool dual_format_txdone(char *out, size_t capacity, const char *boot, uint32_t host_id,
                        unsigned ctx, dual_tx_result_t result, bool ack_requested,
                        uint32_t rf_start_us, uint32_t callback_us)
{
    if (!out || !boot || ctx >= DUAL_CONTEXTS) return false;
    char line[RADIO_LINE_MAX];
    int n = snprintf(line, sizeof line,
        RADIOV10_PREFIX " TXDONE boot=%s id=%lu ctx=%u result=%s ack_requested=%u"
        " rf_start_us=%lu callback_us=%lu\n",
        boot, (unsigned long)host_id, ctx, dual_tx_result_name(result), ack_requested ? 1u : 0u,
        (unsigned long)rf_start_us, (unsigned long)callback_us);
    return commit(out, capacity, line, n);
}

bool dual_format_stats(char *out, size_t capacity, const char *boot, uint32_t host_id,
                       uint32_t config_generation, const dual_stats_t *rx,
                       const dual_sched_stats_t *tx, uint32_t starved_polls,
                       uint32_t routing_faults)
{
    if (!out || !boot || !rx || !tx) return false;
    char line[RADIO_LINE_MAX];
    int n = snprintf(line, sizeof line,
        RADIOV10_PREFIX " STATS boot=%s id=%lu config_generation=%lu rx_total=%lu ctx0_rx=%lu ctx1_rx=%lu"
        " foreign_reject=%lu cross_pair_reject=%lu malformed_reject=%lu unsupported=%lu"
        " broadcast=%lu ambiguous=%lu ack_suppressed_scanning=%lu ack_suppressed_disabled=%lu"
        " deep_reject=%lu ctx0_tx_queue=%lu ctx1_tx_queue=%lu ctx0_tx_accepted=%lu"
        " ctx1_tx_accepted=%lu ctx0_tx_terminal=%lu ctx1_tx_terminal=%lu ctx0_tx_failed=%lu"
        " ctx1_tx_failed=%lu ctx0_timed_out=%lu ctx1_timed_out=%lu ctx0_queue_full=%lu"
        " ctx1_queue_full=%lu ctx0_tuple_reject=%lu ctx1_tuple_reject=%lu"
        " rx_priority_deferrals=%lu ack_priority_deferrals=%lu routing_error=%lu"
        " scheduler_starvation=%lu starved_polls=%lu routing_faults=%lu\n",
        boot, (unsigned long)host_id, (unsigned long)config_generation,
        (unsigned long)rx->rx_total, (unsigned long)rx->ctx0_match, (unsigned long)rx->ctx1_match,
        (unsigned long)rx->foreign_reject, (unsigned long)rx->cross_pair_reject,
        (unsigned long)rx->malformed_reject, (unsigned long)rx->unsupported_reject,
        (unsigned long)rx->broadcast, (unsigned long)rx->ambiguous_reject,
        (unsigned long)rx->ack_suppressed_scanning, (unsigned long)rx->ack_suppressed_disabled,
        (unsigned long)rx->deep_reject,
        (unsigned long)tx->queue_depth[0], (unsigned long)tx->queue_depth[1],
        (unsigned long)tx->accepted[0], (unsigned long)tx->accepted[1],
        (unsigned long)tx->terminal[0], (unsigned long)tx->terminal[1],
        (unsigned long)tx->failed[0], (unsigned long)tx->failed[1],
        (unsigned long)tx->timed_out[0], (unsigned long)tx->timed_out[1],
        (unsigned long)tx->refused_queue_full[0], (unsigned long)tx->refused_queue_full[1],
        (unsigned long)tx->refused_tuple[0], (unsigned long)tx->refused_tuple[1],
        (unsigned long)tx->rx_priority_deferrals, (unsigned long)tx->ack_priority_deferrals,
        (unsigned long)tx->routing_error, (unsigned long)tx->starvation,
        (unsigned long)starved_polls, (unsigned long)routing_faults);
    return commit(out, capacity, line, n);
}

bool dual_format_error(char *out, size_t capacity, const char *boot, bool has_id, uint32_t id,
                       bool has_ctx, unsigned ctx, const char *reason)
{
    if (!out || !boot || !reason) return false;
    char line[RADIO_LINE_MAX];
    char id_part[32] = "";
    char ctx_part[16] = "";
    if (has_id) snprintf(id_part, sizeof id_part, " id=%lu", (unsigned long)id);
    if (has_ctx && ctx < DUAL_CONTEXTS) snprintf(ctx_part, sizeof ctx_part, " ctx=%u", ctx);
    int n = snprintf(line, sizeof line, RADIOV10_PREFIX " ERROR boot=%s%s%s reason=%s\n",
                     boot, id_part, ctx_part, reason);
    return commit(out, capacity, line, n);
}
