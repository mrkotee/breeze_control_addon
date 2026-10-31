/* V26 two-context classification and per-context admission bindings.
 *
 * Provenance: the configuration/classification half is the offline-tested
 * dual_pan_mac_gate/include/dual_filter.h contract, unchanged in behaviour.
 * The binding half carries the fields that the V25 deep admission predicate
 * (ctx1_rx_admission_v25/src/assoc_filter.c) checks, so that predicate can run
 * against one selected context instead of a single global binding.
 *
 * No cryptography here. Keys never enter this layer; only the clear-header
 * values needed to classify and to admit a frame for immediate ACK.
 */
#ifndef DUAL_CONTEXT_H
#define DUAL_CONTEXT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dual_identity.h"

/* MATCH_NONE is deliberately the zero value: a zeroed or partially initialised
 * record must mean "belongs to no context", never "belongs to ctx0". With
 * MATCH_CTX0 at zero, any record that was memset and not classified would have
 * claimed membership of the first context. */
typedef enum { MATCH_NONE = 0, MATCH_CTX0, MATCH_CTX1, MATCH_BROADCAST,
               MATCH_MALFORMED, MATCH_UNSUPPORTED, MATCH_AMBIGUOUS } dual_match_t;
typedef enum { REASON_NONE, REASON_FOREIGN, REASON_CROSS_PAIR } dual_reason_t;

/* One configured local identity. Paired tuple: pan_id and local_short belong
 * together and are never matched across entries. */
typedef struct { bool enabled; uint16_t pan_id, local_short; bool ieee_valid;
                 uint8_t local_ieee[8]; } dual_context_t;

typedef struct { bool enabled; uint8_t channel; uint32_t generation;
                 dual_context_t ctx[DUAL_CONTEXTS]; } dual_config_t;

typedef struct { uint16_t fcf, pan, dst, src; uint8_t dsn, header_len;
                 bool ack_requested, destination_present;
                 dual_reason_t reason; } dual_header_t;

/* Deep admission binding of one context, established by the host BIND command.
 * `scanning` and `ack_enabled` are per context on purpose: V25 gated ACK with a
 * single session-wide condition, which would silence both contexts whenever
 * either one scanned. */
typedef struct {
    bool bound, ack_enabled, scanning;
    uint16_t pan, short_address;
    uint8_t raw[8], tc[8];
    uint8_t keyseq;
} dual_binding_t;

typedef struct {
    uint32_t rx_total, ctx0_match, ctx1_match, foreign_reject, cross_pair_reject,
             malformed_reject, unsupported_reject, broadcast, ambiguous_reject,
             ack_suppressed_scanning, ack_suppressed_disabled, deep_reject;
} dual_stats_t;

bool dual_config_valid(const dual_config_t *config);
/* MHR, excluding PHR/FCS; partial inputs are always bounded by len. */
dual_match_t dual_header_size(const uint8_t *mhr, size_t len, uint8_t *size);
dual_match_t dual_addr_match(const uint8_t *mhr, size_t len,
                             const dual_config_t *config, dual_header_t *header);
bool dual_ack_eligible(dual_match_t match, const dual_header_t *header,
                       bool crc_valid, bool auto_ack);

/* Singleton runtime configuration: starts disabled and holds no tuple. */
const dual_config_t *dual_config_current(void);
/* Caller must stop RX and mask RADIO IRQ; no partial configuration is published. */
bool dual_config_commit_locked(const dual_config_t *config);

bool dual_binding_set(unsigned ctx, const dual_binding_t *binding);
const dual_binding_t *dual_binding_get(unsigned ctx);
bool dual_binding_ack(unsigned ctx, bool enabled);
bool dual_binding_scanning(unsigned ctx, bool scanning);
/* True only when that one context may currently answer with an immediate ACK. */
bool dual_ctx_ack_allowed(unsigned ctx);

const char *dual_match_name(dual_match_t match);
const char *dual_reason_name(dual_reason_t reason);

void dual_stats_reset(void);
void dual_stats_get(dual_stats_t *out);

/* Actual Nordic integration shim: PHR + bytes already received; BCC output.
 * Classifies first, then applies the V25 deep predicate of the matched context. */
int dual_admit_part(const uint8_t *raw, uint8_t *received);

#endif
