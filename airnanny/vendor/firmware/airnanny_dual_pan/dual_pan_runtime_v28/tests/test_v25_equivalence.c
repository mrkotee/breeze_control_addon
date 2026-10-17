/* Equivalence of V26 admission with the frozen V25 predicate.
 *
 * Claim under test: for a single configured context, the V26 layer admits a
 * frame for immediate ACK exactly when ctx1_rx_admission_v25/src/assoc_filter.c
 * admitted it. The original file is compiled into this binary unmodified and
 * bound to the same identity, then both are driven over the same corpus.
 *
 * The compared invariant is admitted-or-not, because that is what decides
 * whether an ACK is sent. Error codes for refused frames are deliberately not
 * compared: V26 classifies generically before the deep stage and therefore
 * reports INVALID_FRAME where V25 reported INVALID_DEST_ADDR for some malformed
 * input. Nothing that V25 admitted may become refused, and nothing V25 refused
 * may become admitted.
 *
 * No COM, no RF, no cryptography, no keys.
 */
#include "dual_context.h"
#include "commission.h"
#include "nrf_802154_types.h"
#include <stdio.h>
#include <string.h>

/* Provided by the unmodified V25 source compiled alongside. */
void assoc_filter_bind(const commission_t *s);
int assoc_filter_part(const uint8_t *raw, uint8_t *received);

#define PAN_T 0x0B7Au
#define SHORT_T 0x6C55u
#define PAN_O 0xFA9Bu
#define SHORT_O 0xA326u
/* Wire order, matching ctx1_rx_admission_v25/src/rejoin_transport.c. */
static const uint8_t RAW_T[8] = { 0x37,0x14,0xa4,0x75,0xbb,0x56,0x7a,0x02 };
static const uint8_t TC_T[8]  = { 0x5f,0x87,0xa1,0x36,0x00,0x4b,0x12,0x00 };
static const uint8_t RAW_O[8] = { 0x69,0x20,0x58,0x4d,0x5f,0x27,0xb0,0xe2 };
static const uint8_t TC_O[8]  = { 0xe5,0x48,0xa1,0x36,0x00,0x4b,0x12,0x00 };

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v & 0xff); p[1] = (uint8_t)(v >> 8); }

static uint8_t build(uint8_t *raw, uint16_t mac_fcf, uint16_t pan, uint16_t dst, uint16_t src,
                     uint16_t nwk_fcf, const uint8_t *ext_a, const uint8_t *ext_b,
                     uint8_t aux_control, const uint8_t *aux_source, uint8_t keyseq, bool shrink)
{
    size_t h = (nwk_fcf == 0x1a09) ? 24 : (nwk_fcf == 0x1209) ? 16 : 8;
    size_t need = 9 + h + 14;
    size_t mac_len = need + 4;
    uint8_t psdu = (uint8_t)(mac_len + 2);
    if (psdu < 40) { mac_len += (size_t)(40 - psdu); psdu = 40; }
    memset(raw, 0, 160);
    raw[0] = shrink ? 39 : psdu;
    uint8_t *m = raw + 1;
    put16(m, mac_fcf);
    m[2] = 0x3d;
    put16(m + 3, pan);
    put16(m + 5, dst);
    put16(m + 7, src);
    put16(m + 9, nwk_fcf);
    put16(m + 11, dst);       /* NWK destination mirrors the MAC destination */
    put16(m + 13, src);       /* NWK source mirrors the MAC source */
    m[15] = 60; m[16] = 0;
    if (h == 24) { memcpy(m + 17, ext_a, 8); memcpy(m + 25, ext_b, 8); }
    else if (h == 16) { memcpy(m + 17, ext_b, 8); }
    uint8_t *aux = m + 9 + h;
    aux[0] = aux_control;
    put16(aux + 1, 0x1234); put16(aux + 3, 0x0056);
    memcpy(aux + 5, aux_source, 8);
    aux[13] = keyseq;
    return (uint8_t)((shrink ? 39 : psdu) + 1);
}

/* Drives one predicate over the BCC staging and reports whether it admitted. */
static bool admitted(int (*fn)(const uint8_t *, uint8_t *), const uint8_t *frame, uint8_t available)
{
    uint8_t raw[160]; memcpy(raw, frame, 160);
    uint8_t received = 3 < available ? 3 : available;
    for (int calls = 0; calls < 8; calls++) {
        uint8_t asked = received;
        int r = fn(raw, &received);
        if (r != NRF_802154_RX_ERROR_NONE) return false;
        if (received <= asked) return true;           /* admitted */
        if (received > available) return false;        /* cannot be satisfied */
    }
    return false;
}

static commission_t legacy;

static void arm_legacy(void)
{
    memset(&legacy, 0, sizeof(legacy));
    legacy.phase = G_MANAGEMENT;
    legacy.recovery.phase = R_ACTIVE;
    legacy.keys.state = K_MANAGEMENT;
    legacy.keys.ctx = 1;
    legacy.keys.pan = PAN_T;
    legacy.keys.short_address = SHORT_T;
    legacy.keys.keyseq = 0;
    memcpy(legacy.keys.raw, RAW_T, 8);
    memcpy(legacy.keys.tc, TC_T, 8);
    assoc_filter_bind(&legacy);
}

static void arm_v26(void)
{
    dual_config_t c; memset(&c, 0, sizeof(c));
    c.enabled = true; c.channel = 21; c.generation = 1;
    /* Only one context enabled, so the comparison is apples to apples. */
    c.ctx[1].enabled = true; c.ctx[1].pan_id = PAN_T; c.ctx[1].local_short = SHORT_T;
    c.ctx[1].ieee_valid = true; memcpy(c.ctx[1].local_ieee, RAW_T, 8);
    if (!dual_config_commit_locked(&c)) { printf("FAIL commit\n"); return; }
    dual_binding_t b; memset(&b, 0, sizeof(b));
    b.pan = PAN_T; b.short_address = SHORT_T; b.keyseq = 0;
    memcpy(b.raw, RAW_T, 8); memcpy(b.tc, TC_T, 8);
    if (!dual_binding_set(1, &b)) { printf("FAIL bind\n"); return; }
    if (!dual_binding_ack(1, true)) { printf("FAIL ack\n"); return; }
}

int main(void)
{
    static const uint16_t mac_fcfs[] = { 0x8861, 0x8841, 0x8821, 0x9861 };
    static const uint16_t pans[] = { PAN_T, PAN_O, 0x1234, 0xffff };
    static const uint16_t dsts[] = { SHORT_T, SHORT_O, 0x5678, 0xffff };
    static const uint16_t srcs[] = { 0x0000, 0x4444 };
    static const uint16_t nwks[] = { 0x0208, 0x0248, 0x1209, 0x1a09, 0x0999 };
    const uint8_t *exts_a[] = { RAW_T, RAW_O };
    const uint8_t *exts_b[] = { TC_T, TC_O };
    static const uint8_t controls[] = { 0x28, 0x08 };
    const uint8_t *sources[] = { TC_T, TC_O };
    static const uint8_t keyseqs[] = { 0, 3 };
    static const bool shrinks[] = { false, true };

    arm_legacy();
    arm_v26();

    unsigned long total = 0, both_admit = 0, both_refuse = 0;
    unsigned long only_v25 = 0, only_v26 = 0;
    uint8_t raw[160];

    for (unsigned a = 0; a < sizeof mac_fcfs / sizeof *mac_fcfs; a++)
    for (unsigned b = 0; b < sizeof pans / sizeof *pans; b++)
    for (unsigned c = 0; c < sizeof dsts / sizeof *dsts; c++)
    for (unsigned d = 0; d < sizeof srcs / sizeof *srcs; d++)
    for (unsigned e = 0; e < sizeof nwks / sizeof *nwks; e++)
    for (unsigned f = 0; f < 2; f++)
    for (unsigned g = 0; g < 2; g++)
    for (unsigned h = 0; h < sizeof controls / sizeof *controls; h++)
    for (unsigned i = 0; i < 2; i++)
    for (unsigned j = 0; j < sizeof keyseqs / sizeof *keyseqs; j++)
    for (unsigned k = 0; k < 2; k++) {
        uint8_t available = build(raw, mac_fcfs[a], pans[b], dsts[c], srcs[d], nwks[e],
                                  exts_a[f], exts_b[g], controls[h], sources[i],
                                  keyseqs[j], shrinks[k]);
        bool old_ok = admitted(assoc_filter_part, raw, available);
        bool new_ok = admitted(dual_admit_part, raw, available);
        total++;
        if (old_ok && new_ok) both_admit++;
        else if (!old_ok && !new_ok) both_refuse++;
        else if (old_ok) {
            only_v25++;
            if (only_v25 <= 3)
                printf("REGRESSION V25 admitted, V26 refused: mac=%04x pan=%04x dst=%04x src=%04x nwk=%04x ctl=%02x ks=%u shrink=%d\n",
                       mac_fcfs[a], pans[b], dsts[c], srcs[d], nwks[e], controls[h], keyseqs[j], (int)shrinks[k]);
        } else {
            only_v26++;
            if (only_v26 <= 3)
                printf("WIDENING V26 admitted, V25 refused: mac=%04x pan=%04x dst=%04x src=%04x nwk=%04x ctl=%02x ks=%u shrink=%d\n",
                       mac_fcfs[a], pans[b], dsts[c], srcs[d], nwks[e], controls[h], keyseqs[j], (int)shrinks[k]);
        }
    }

    printf("corpus=%lu both_admit=%lu both_refuse=%lu v25_only=%lu v26_only=%lu\n",
           total, both_admit, both_refuse, only_v25, only_v26);
    /* A corpus that admits nothing would prove nothing. */
    if (!both_admit) { printf("FAIL corpus admitted no frame at all\n"); return 1; }
    if (only_v25 || only_v26) { printf("FAIL admission sets differ\n"); return 1; }
    printf("equivalence holds\n");
    return 0;
}
