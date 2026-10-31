/* The two identities this image is allowed to address, pinned at compile time.
 *
 * Why this exists. Every predecessor pinned its single context in file-scope
 * constants on purpose: ctx1_rx_admission_v25/src/rejoin_transport.c carries
 * ctx1's RAW and trust-centre addresses, its short 0x6c55, its epoch id and its
 * attempt id as literals, and the V7 and V22 sources before it pinned ctx0 the
 * same way and explicitly refused ctx1. The effect is a safety property, not an
 * accident: the image physically cannot address a network it was not built for.
 *
 * A dual-PAN runtime has to address two networks, so the analogue of that
 * property is a two-entry table of compile-time constants, not a table the host
 * may fill with arbitrary values. The host still chooses whether a context is
 * enabled, when it is bound and when it may ACK, and it still supplies the
 * current short, which the coordinator assigns and can change. Every such value
 * is validated against this table and anything else is refused.
 *
 * Values here are public: PAN ids, assigned shorts, IEEE addresses, key epoch
 * ids and attempt ids all already appear in committed sources and published
 * result documents. No key material is here, and none ever belongs here.
 *
 * IEEE addresses are stored in wire order, least significant byte first, the
 * same convention the predecessor used.
 */
#ifndef DUAL_IDENTITY_H
#define DUAL_IDENTITY_H
#include <stdbool.h>
#include <stdint.h>

#define DUAL_CONTEXTS 2u
#define DUAL_EPOCH_CHARS 33u

typedef struct {
    uint16_t pan;
    uint16_t assigned_short;     /* last coordinator-assigned short, for reference */
    uint8_t raw_ieee[8];         /* wire order */
    uint8_t tc_ieee[8];          /* wire order; also the extended PAN id */
    uint8_t keyseq;
    const char *epoch;
    const char *attempt;
} dual_identity_t;

/* The historical sanity floor the predecessor used. Real rollback protection is
 * the host's durable store, which holds the live generation and outgoing
 * counter high-water; the store's generation advances every session, so pinning
 * it into the image would demand a rebuild after every run. */
#define DUAL_GENERATION_FLOOR 6u

/* ctx0, the living-room A7. Issue #3, store generation 19, next_fc 1280. */
#define DUAL_CTX0_PAN   0xFA9Bu
#define DUAL_CTX0_SHORT 0xA326u

/* ctx1, the bedroom A7. Issue #4, store generation 16, next_fc 1088. */
#define DUAL_CTX1_PAN   0x0B7Au
#define DUAL_CTX1_SHORT 0x6C55u

const dual_identity_t *dual_identity(unsigned ctx);
/* True when this PAN belongs to this context and to no other. */
bool dual_identity_pan_matches(unsigned ctx, uint16_t pan);
/* A coordinator may reassign a short, so a short is accepted when it is a
 * plausible assigned short rather than only the recorded one. */
bool dual_identity_short_plausible(unsigned ctx, uint16_t short_address);
bool dual_identity_raw_matches(unsigned ctx, const uint8_t *raw_wire);
bool dual_identity_tc_matches(unsigned ctx, const uint8_t *tc_wire);
bool dual_identity_epoch_matches(unsigned ctx, const char *epoch);
bool dual_identity_attempt_matches(unsigned ctx, const char *attempt);
/* Resolves a PAN to its context index, or DUAL_CONTEXTS when it is foreign. */
unsigned dual_identity_context_of_pan(uint16_t pan);

#endif
