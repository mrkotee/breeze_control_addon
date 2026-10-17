/* Offline native tests for the V26 two-context admission layer.
 * No COM, no RF, no cryptography, no keys. Synthetic headers only; the two
 * historical tuples appear here as test data, never as a default configuration.
 */
#include "dual_context.h"
#include "dual_identity.h"
#include "nrf_802154_types.h"
#include <stdio.h>
#include <string.h>

static int failures, checks;
static void ok(int cond, const char *what)
{
    checks++;
    if (!cond) { failures++; printf("FAIL %s\n", what); }
}

/* Historical observed tuples, used as test vectors only. */
#define PAN0 0xFA9Bu
#define SHORT0 0xA326u
#define PAN1 0x0B7Au
#define SHORT1 0x6C55u
/* Wire order, least significant byte first, as the predicate compares them. */
static const uint8_t RAW0[8] = { 0x69,0x20,0x58,0x4d,0x5f,0x27,0xb0,0xe2 }; /* e2b0275f4d582069 */
static const uint8_t TC0[8]  = { 0xe5,0x48,0xa1,0x36,0x00,0x4b,0x12,0x00 }; /* 00124b0036a148e5 */
static const uint8_t RAW1[8] = { 0x37,0x14,0xa4,0x75,0xbb,0x56,0x7a,0x02 }; /* 027a56bb75a41437 */
static const uint8_t TC1[8]  = { 0x5f,0x87,0xa1,0x36,0x00,0x4b,0x12,0x00 }; /* 00124b0036a1875f */

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v & 0xff); p[1] = (uint8_t)(v >> 8); }

/* Builds PHR + MAC bytes of an A7-shaped secured DATA frame.
 * nwk_fcf selects the 8/16/24 byte NWK header variants the predicate accepts. */
static uint8_t build(uint8_t *raw, uint16_t mac_fcf, uint16_t pan, uint16_t dst, uint16_t src,
                     uint16_t nwk_fcf, uint16_t nwk_dst, uint16_t nwk_src,
                     const uint8_t *ext_a, const uint8_t *ext_b,
                     uint8_t aux_control, const uint8_t *aux_source, uint8_t keyseq)
{
    size_t h = (nwk_fcf == 0x1a09) ? 24 : (nwk_fcf == 0x1209) ? 16 : 8;
    size_t need = 9 + h + 14;
    size_t mac_len = need + 4;              /* header fields plus a MIC */
    uint8_t psdu = (uint8_t)(mac_len + 2);  /* plus hardware FCS */
    if (psdu < 40) { mac_len += (size_t)(40 - psdu); psdu = 40; }
    memset(raw, 0, 160);
    raw[0] = psdu;
    uint8_t *m = raw + 1;
    put16(m, mac_fcf);
    m[2] = 0x3d;
    put16(m + 3, pan);
    put16(m + 5, dst);
    put16(m + 7, src);
    put16(m + 9, nwk_fcf);
    put16(m + 11, nwk_dst);
    put16(m + 13, nwk_src);
    m[15] = 60; m[16] = 0;
    if (h == 24) { memcpy(m + 17, ext_a, 8); memcpy(m + 25, ext_b, 8); }
    else if (h == 16) { memcpy(m + 17, ext_b, 8); }
    uint8_t *aux = m + 9 + h;
    aux[0] = aux_control;
    put16(aux + 1, 0x1234); put16(aux + 3, 0x0056);
    memcpy(aux + 5, aux_source, 8);
    aux[13] = keyseq;
    return (uint8_t)(psdu + 1); /* bytes available including PHR */
}

static uint8_t target0(uint8_t *raw)
{ return build(raw, 0x8861, PAN0, SHORT0, 0, 0x0208, SHORT0, 0, RAW0, TC0, 0x28, TC0, 0); }
static uint8_t target1(uint8_t *raw)
{ return build(raw, 0x8861, PAN1, SHORT1, 0, 0x0208, SHORT1, 0, RAW1, TC1, 0x28, TC1, 0); }

static dual_config_t both_enabled(uint32_t generation)
{
    dual_config_t c; memset(&c, 0, sizeof(c));
    c.enabled = true; c.channel = 21; c.generation = generation;
    c.ctx[0].enabled = true; c.ctx[0].pan_id = PAN0; c.ctx[0].local_short = SHORT0;
    c.ctx[0].ieee_valid = true; memcpy(c.ctx[0].local_ieee, RAW0, 8);
    c.ctx[1].enabled = true; c.ctx[1].pan_id = PAN1; c.ctx[1].local_short = SHORT1;
    c.ctx[1].ieee_valid = true; memcpy(c.ctx[1].local_ieee, RAW1, 8);
    return c;
}

static dual_binding_t binding(uint16_t pan, uint16_t sh, const uint8_t *raw, const uint8_t *tc, uint8_t keyseq)
{
    dual_binding_t b; memset(&b, 0, sizeof(b));
    b.pan = pan; b.short_address = sh; b.keyseq = keyseq;
    memcpy(b.raw, raw, 8); memcpy(b.tc, tc, 8);
    return b;
}

/* Fresh configuration generation per scenario; commit is monotonic by design. */
static uint32_t g = 1;
static void arm_both(bool ack0, bool ack1)
{
    dual_config_t c = both_enabled(++g);
    ok(dual_config_commit_locked(&c), "commit both contexts");
    dual_binding_t b0 = binding(PAN0, SHORT0, RAW0, TC0, 0);
    dual_binding_t b1 = binding(PAN1, SHORT1, RAW1, TC1, 0);
    ok(dual_binding_set(0, &b0), "bind ctx0");
    ok(dual_binding_set(1, &b1), "bind ctx1");
    ok(dual_binding_ack(0, ack0), "ack ctx0");
    ok(dual_binding_ack(1, ack1), "ack ctx1");
    dual_stats_reset();
}

/* Drives BCC staging the way the core does: each round passes the bytes that
 * are actually available, and the loop ends when the callee stops asking for
 * more. `rounds` receives the number of calls when the caller cares. */
static int admit_rounds(const uint8_t *frame, uint8_t available, int *rounds)
{
    uint8_t raw[160]; memcpy(raw, frame, 160);
    uint8_t received = 3 < available ? 3 : available;
    int calls = 0, r;
    for (;;) {
        uint8_t asked = received;
        r = dual_admit_part(raw, &received);
        calls++;
        if (r != NRF_802154_RX_ERROR_NONE) break;
        if (received <= asked) break;            /* admitted, nothing more wanted */
        if (received > available) { r = NRF_802154_RX_ERROR_INVALID_FRAME; break; }
        if (calls >= 6) break;                   /* staging must terminate */
    }
    if (rounds) *rounds = calls;
    return r;
}

static int admit(const uint8_t *frame, uint8_t available)
{ return admit_rounds(frame, available, NULL); }

static void test_config_validation(void)
{
    dual_config_t c = both_enabled(100);
    ok(dual_config_valid(&c), "valid dual configuration");
    c.channel = 15; ok(!dual_config_valid(&c), "channel other than 21 rejected");
    c = both_enabled(100); c.ctx[0].pan_id = 0xffff;
    ok(!dual_config_valid(&c), "broadcast PAN rejected");
    c = both_enabled(100); c.ctx[1].local_short = 0xfffe;
    ok(!dual_config_valid(&c), "reserved short rejected");
    c = both_enabled(100); c.ctx[1].pan_id = PAN0; c.ctx[1].local_short = SHORT0;
    ok(!dual_config_valid(&c), "identical paired tuple rejected");
    /* Same short under different PAN is legitimate: coordinators assign freely. */
    c = both_enabled(100); c.ctx[1].local_short = SHORT0;
    ok(dual_config_valid(&c), "same short under different PAN accepted");
}

static void test_commit_monotonic(void)
{
    dual_config_t c = both_enabled(++g);
    ok(dual_config_commit_locked(&c), "commit accepted");
    dual_config_t same = both_enabled(c.generation);
    ok(!dual_config_commit_locked(&same), "repeated generation rejected");
    dual_config_t older = both_enabled(c.generation - 1);
    ok(!dual_config_commit_locked(&older), "generation rollback rejected");
    ok(dual_config_current()->generation == c.generation, "generation unchanged after refusal");
}

static void test_classification(void)
{
    dual_config_t c = both_enabled(++g);
    ok(dual_config_commit_locked(&c), "commit for classification");
    uint8_t raw[160]; dual_header_t h;

    target0(raw);
    ok(dual_addr_match(raw + 1, 60, dual_config_current(), &h) == MATCH_CTX0, "ctx0 classified");
    target1(raw);
    ok(dual_addr_match(raw + 1, 60, dual_config_current(), &h) == MATCH_CTX1, "ctx1 classified");

    /* Cross pair must never be accepted by either context. */
    build(raw, 0x8861, PAN0, SHORT1, 0, 0x0208, SHORT1, 0, RAW1, TC1, 0x28, TC1, 0);
    ok(dual_addr_match(raw + 1, 60, dual_config_current(), &h) == MATCH_NONE, "cross pair not matched");
    ok(h.reason == REASON_CROSS_PAIR, "cross pair reason reported");

    build(raw, 0x8861, 0x1234, 0x5678, 0, 0x0208, 0x5678, 0, RAW0, TC0, 0x28, TC0, 0);
    ok(dual_addr_match(raw + 1, 60, dual_config_current(), &h) == MATCH_NONE, "foreign not matched");
    ok(h.reason == REASON_FOREIGN, "foreign reason reported");

    build(raw, 0x8861, 0xffff, SHORT0, 0, 0x0208, SHORT0, 0, RAW0, TC0, 0x28, TC0, 0);
    ok(dual_addr_match(raw + 1, 60, dual_config_current(), &h) == MATCH_BROADCAST, "broadcast PAN detected");
    build(raw, 0x8861, PAN0, 0xffff, 0, 0x0208, 0xffff, 0, RAW0, TC0, 0x28, TC0, 0);
    ok(dual_addr_match(raw + 1, 60, dual_config_current(), &h) == MATCH_BROADCAST, "broadcast short detected");

    ok(!dual_ack_eligible(MATCH_BROADCAST, &h, true, true), "broadcast never ACK eligible");
    ok(!dual_ack_eligible(MATCH_CTX0, &h, false, true), "CRC failure never ACK eligible");
}

static void test_per_context_ack_gate(void)
{
    uint8_t raw0[160], raw1[160];
    uint8_t a0 = target0(raw0), a1 = target1(raw1);

    arm_both(true, true);
    ok(admit(raw0, a0) == NRF_802154_RX_ERROR_NONE, "ctx0 admitted when both enabled");
    ok(admit(raw1, a1) == NRF_802154_RX_ERROR_NONE, "ctx1 admitted when both enabled");

    /* The requirement neither the issue nor earlier documents stated: one
     * context scanning must not silence the other. */
    arm_both(true, true);
    ok(dual_binding_scanning(1, true), "ctx1 enters scanning");
    ok(admit(raw0, a0) == NRF_802154_RX_ERROR_NONE, "ctx0 still admitted while ctx1 scans");
    ok(admit(raw1, a1) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "ctx1 suppressed while scanning");
    ok(!dual_ctx_ack_allowed(1), "ctx1 ACK not allowed while scanning");
    ok(dual_ctx_ack_allowed(0), "ctx0 ACK still allowed");
    dual_stats_t s; dual_stats_get(&s);
    ok(s.ack_suppressed_scanning == 1, "scanning suppression counted once");

    arm_both(true, false);
    ok(admit(raw1, a1) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "ctx1 suppressed when ACK disabled");
    ok(admit(raw0, a0) == NRF_802154_RX_ERROR_NONE, "ctx0 unaffected by ctx1 ACK state");

    /* ACK must start disabled: BIND alone never grants it. */
    dual_config_t c = both_enabled(++g);
    ok(dual_config_commit_locked(&c), "commit for bind-only scenario");
    dual_binding_t b0 = binding(PAN0, SHORT0, RAW0, TC0, 0);
    ok(dual_binding_set(0, &b0), "bind ctx0 only");
    ok(!dual_ctx_ack_allowed(0), "BIND does not grant ACK");
    dual_stats_reset();
    ok(admit(raw0, a0) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "unbound ACK suppressed");

    /* A context with no binding at all cannot ACK even if classified. */
    dual_stats_reset();
    ok(admit(raw1, a1) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "unbound ctx1 suppressed");
    dual_stats_get(&s);
    ok(s.ack_suppressed_disabled >= 1, "disabled suppression counted");
}

static void test_deep_predicate(void)
{
    uint8_t raw[160];
    arm_both(true, true);

    uint8_t a = target0(raw);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_NONE, "well formed ctx0 frame admitted");

    /* Extended-address CMD variants. */
    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x1a09, SHORT0, 0, RAW0, TC0, 0x28, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_NONE, "0x1a09 with both extended addresses admitted");
    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x1a09, SHORT0, 0, RAW1, TC0, 0x28, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "wrong extended RAW identity rejected");
    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x1a09, SHORT0, 0, RAW0, TC1, 0x28, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "wrong extended TC identity rejected");
    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x1209, SHORT0, 0, RAW0, TC0, 0x28, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_NONE, "0x1209 with TC extended address admitted");

    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x0999, SHORT0, 0, RAW0, TC0, 0x28, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "unsupported NWK FCF rejected");
    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x0208, 0x1111, 0, RAW0, TC0, 0x28, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "NWK destination mismatch rejected");
    a = build(raw, 0x8861, PAN0, SHORT0, 0x4444, 0x0208, SHORT0, 0, RAW0, TC0, 0x28, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "non coordinator MAC source rejected");
    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x0208, SHORT0, 0x4444, RAW0, TC0, 0x28, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "non coordinator NWK source rejected");

    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x0208, SHORT0, 0, RAW0, TC0, 0x08, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "aux security control mismatch rejected");
    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x0208, SHORT0, 0, RAW0, TC0, 0x28, TC1, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "aux security source mismatch rejected");
    a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x0208, SHORT0, 0, RAW0, TC0, 0x28, TC0, 3);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "key sequence mismatch rejected");

    /* MAC FCF outside the supported A7 shape. */
    a = build(raw, 0x8821, PAN0, SHORT0, 0, 0x0208, SHORT0, 0, RAW0, TC0, 0x28, TC0, 0);
    ok(admit(raw, a) != NRF_802154_RX_ERROR_NONE, "unexpected MAC FCF not admitted");
}

static void test_cross_context_isolation(void)
{
    uint8_t raw[160];
    /* ctx0 tuple carrying ctx1 security identity: classification selects ctx0,
     * whose binding then refuses the foreign trust-centre source. */
    arm_both(true, true);
    uint8_t a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x0208, SHORT0, 0, RAW0, TC0, 0x28, TC1, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "ctx0 frame with ctx1 security source rejected");

    /* ctx1 short under ctx0 PAN: refused before any binding is consulted. */
    a = build(raw, 0x8861, PAN0, SHORT1, 0, 0x0208, SHORT1, 0, RAW1, TC1, 0x28, TC1, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "ctx1 short under ctx0 PAN rejected");
    dual_stats_t s; dual_stats_get(&s);
    ok(s.cross_pair_reject >= 1, "cross pair counted separately from foreign");

    /* A binding may not describe an identity the configuration never published. */
    dual_config_t c = both_enabled(++g);
    ok(dual_config_commit_locked(&c), "commit for binding validation");
    dual_binding_t wrong = binding(PAN1, SHORT1, RAW1, TC1, 0);
    ok(!dual_binding_set(0, &wrong), "binding of other context refused on ctx0");
    dual_binding_t same = binding(PAN0, SHORT0, RAW0, RAW0, 0);
    ok(!dual_binding_set(0, &same), "identical RAW and TC identity refused");
    dual_binding_t zero = binding(PAN0, SHORT0, RAW0, (const uint8_t *)"\0\0\0\0\0\0\0\0", 0);
    ok(!dual_binding_set(0, &zero), "zero trust centre identity refused");
    ok(!dual_binding_set(DUAL_CONTEXTS, &wrong), "out of range context refused");
    ok(dual_binding_get(DUAL_CONTEXTS) == NULL, "out of range context has no binding");
}

static void test_bcc_staging(void)
{
    uint8_t raw[160]; uint8_t received;
    arm_both(true, true);
    uint8_t a = target0(raw);

    received = 2;
    ok(dual_admit_part(raw, &received) == NRF_802154_RX_ERROR_INVALID_FRAME, "fewer than three bytes rejected");

    uint8_t bad[160]; memset(bad, 0, sizeof(bad));
    bad[0] = 3; bad[1] = 0x61; bad[2] = 0x88;
    received = 3;
    ok(dual_admit_part(bad, &received) == NRF_802154_RX_ERROR_INVALID_LENGTH, "impossible PHR length rejected");

    /* A candidate target frame jumps straight to the 18 bytes the deep stage
     * needs, so admission costs the same three calls it cost in V25:
     * ask 18, ask need+1, admit. */
    int rounds = 0;
    ok(admit_rounds(raw, a, &rounds) == NRF_802154_RX_ERROR_NONE, "staged admission succeeds");
    ok(rounds == 3, "admission completes in the V25 round budget");
    received = a;
    ok(dual_admit_part(raw, &received) == NRF_802154_RX_ERROR_NONE, "complete frame admitted");

    /* A short foreign frame must not be dragged to 18 bytes. */
    uint8_t small[160]; memset(small, 0, sizeof(small));
    small[0] = 12; small[1] = 0x61; small[2] = 0x88;
    small[3] = 0x11; small[4] = 0x22; small[5] = 0x33; small[6] = 0x44; small[7] = 0x55;
    received = 3;
    int small_result = dual_admit_part(small, &received);
    ok(small_result == NRF_802154_RX_ERROR_NONE && received == 10,
       "short frame requests only its MHR");
}

static void test_disabled_configuration(void)
{
    uint8_t raw[160]; uint8_t a = target0(raw);
    dual_config_t c = both_enabled(++g);
    c.enabled = false;
    ok(dual_config_commit_locked(&c), "disabled configuration committed");
    dual_stats_reset();
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR, "nothing admitted while configuration disabled");

    /* Disabling one entry clears its binding rather than leaving it live. */
    dual_config_t one = both_enabled(++g);
    one.ctx[1].enabled = false;
    ok(dual_config_commit_locked(&one), "single context configuration committed");
    ok(dual_binding_get(1) != NULL && !dual_binding_get(1)->bound, "disabled context binding cleared");
}

/* The image addresses two pinned networks and no others. Every case below is
 * syntactically valid and must still be refused. */
static void test_pinned_identity(void)
{
    ok(dual_identity(0) != NULL && dual_identity(1) != NULL, "both identities present");
    ok(dual_identity(DUAL_CONTEXTS) == NULL, "no third identity");
    ok(dual_identity_context_of_pan(PAN0) == 0, "ctx0 PAN resolves to ctx0");
    ok(dual_identity_context_of_pan(PAN1) == 1, "ctx1 PAN resolves to ctx1");
    ok(dual_identity_context_of_pan(0x1234) == DUAL_CONTEXTS, "foreign PAN resolves to nothing");
    ok(!dual_identity_pan_matches(0, PAN1), "ctx0 refuses ctx1 PAN");
    ok(!dual_identity_pan_matches(1, PAN0), "ctx1 refuses ctx0 PAN");

    dual_config_t c = both_enabled(++g);
    c.ctx[0].pan_id = PAN1;
    ok(!dual_config_valid(&c), "ctx0 configured with ctx1 PAN refused");
    c = both_enabled(++g); c.ctx[0].pan_id = 0x1234;
    ok(!dual_config_valid(&c), "ctx0 configured with a foreign PAN refused");
    c = both_enabled(++g); memcpy(c.ctx[0].local_ieee, RAW1, 8);
    ok(!dual_config_valid(&c), "ctx0 configured with ctx1 RAW identity refused");
    c = both_enabled(++g); c.ctx[1].local_short = 0x0000;
    ok(!dual_config_valid(&c), "coordinator short as our own short refused");

    /* A coordinator may reassign our short, so another plausible short is fine. */
    c = both_enabled(++g); c.ctx[1].local_short = 0x1234;
    ok(dual_config_valid(&c), "a reassigned plausible short accepted");
    ok(dual_config_commit_locked(&c), "reassigned short committed");
    dual_binding_t moved = binding(PAN1, 0x1234, RAW1, TC1, 0);
    ok(dual_binding_set(1, &moved), "binding follows the reassigned short");

    /* Bindings are what frames are actually compared against. */
    c = both_enabled(++g);
    ok(dual_config_commit_locked(&c), "commit for binding pin checks");
    dual_binding_t foreign_raw = binding(PAN0, SHORT0, RAW1, TC0, 0);
    ok(!dual_binding_set(0, &foreign_raw), "ctx0 binding with ctx1 RAW refused");
    dual_binding_t foreign_tc = binding(PAN0, SHORT0, RAW0, TC1, 0);
    ok(!dual_binding_set(0, &foreign_tc), "ctx0 binding with ctx1 trust centre refused");
    dual_binding_t wrong_keyseq = binding(PAN0, SHORT0, RAW0, TC0, 7);
    ok(!dual_binding_set(0, &wrong_keyseq), "binding with an unexpected key sequence refused");
    dual_binding_t good = binding(PAN0, SHORT0, RAW0, TC0, 0);
    ok(dual_binding_set(0, &good), "correct ctx0 binding accepted");

    /* And the admission path still refuses a frame carrying the other network's
     * identity even when its PAN and short are ours. */
    ok(dual_binding_ack(0, true), "ctx0 ACK enabled");
    uint8_t raw[160];
    uint8_t a = build(raw, 0x8861, PAN0, SHORT0, 0, 0x1a09, SHORT0, 0, RAW1, TC0, 0x28, TC0, 0);
    ok(admit(raw, a) == NRF_802154_RX_ERROR_INVALID_DEST_ADDR,
       "ctx0 frame carrying ctx1 RAW identity refused on air");
}

int main(void)
{
    test_pinned_identity();
    test_config_validation();
    test_commit_monotonic();
    test_classification();
    test_per_context_ack_gate();
    test_deep_predicate();
    test_cross_context_isolation();
    test_bcc_staging();
    test_disabled_configuration();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
