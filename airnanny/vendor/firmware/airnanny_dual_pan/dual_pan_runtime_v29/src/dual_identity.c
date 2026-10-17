#include "dual_identity.h"
#include <string.h>

/* ctx0 provenance: ISSUE_3_RESULT.md and the ctx0 security store.
 * ctx1 provenance: SECOND_A7_PROVISIONING_RESULT.md, the ctx1 security store,
 * and the literals already present in ctx1_rx_admission_v25/src/rejoin_transport.c. */
static const dual_identity_t identities[DUAL_CONTEXTS] = {
    {   /* ctx0, living room */
        .pan = DUAL_CTX0_PAN,
        .assigned_short = DUAL_CTX0_SHORT,
        .raw_ieee = { 0x69,0x20,0x58,0x4d,0x5f,0x27,0xb0,0xe2 }, /* e2b0275f4d582069 */
        .tc_ieee  = { 0xe5,0x48,0xa1,0x36,0x00,0x4b,0x12,0x00 }, /* 00124b0036a148e5 */
        .keyseq = 0,
        .epoch = "1ea30211ee014345a8288337a173a833",
        .attempt = "5b09cb6bc02746298fbffcfb780844a5",
    },
    {   /* ctx1, bedroom */
        .pan = DUAL_CTX1_PAN,
        .assigned_short = DUAL_CTX1_SHORT,
        .raw_ieee = { 0x37,0x14,0xa4,0x75,0xbb,0x56,0x7a,0x02 }, /* 027a56bb75a41437 */
        .tc_ieee  = { 0x5f,0x87,0xa1,0x36,0x00,0x4b,0x12,0x00 }, /* 00124b0036a1875f */
        .keyseq = 0,
        .epoch = "9985b15dcb574c59b87dc2fb379f317f",
        .attempt = "cbef428849da4e87b48867ac616247d1",
    },
};

const dual_identity_t *dual_identity(unsigned ctx)
{ return ctx < DUAL_CONTEXTS ? &identities[ctx] : NULL; }

bool dual_identity_pan_matches(unsigned ctx, uint16_t pan)
{
    if (ctx >= DUAL_CONTEXTS) return false;
    if (identities[ctx].pan != pan) return false;
    /* The two pinned PANs differ, so a match here is exclusive by construction;
     * this assertion keeps that true if the table is ever edited. */
    for (unsigned i = 0; i < DUAL_CONTEXTS; i++)
        if (i != ctx && identities[i].pan == pan) return false;
    return true;
}

bool dual_identity_short_plausible(unsigned ctx, uint16_t short_address)
{
    if (ctx >= DUAL_CONTEXTS) return false;
    /* 0x0000 is the coordinator and 0xfff8 upward is reserved; anything else is
     * a short a coordinator could legitimately have assigned to us. The
     * recorded short is not required, because a rejoin can change it. */
    return short_address != 0x0000u && short_address < 0xfff8u;
}

bool dual_identity_raw_matches(unsigned ctx, const uint8_t *raw_wire)
{
    if (ctx >= DUAL_CONTEXTS || !raw_wire) return false;
    return !memcmp(identities[ctx].raw_ieee, raw_wire, 8);
}

bool dual_identity_tc_matches(unsigned ctx, const uint8_t *tc_wire)
{
    if (ctx >= DUAL_CONTEXTS || !tc_wire) return false;
    return !memcmp(identities[ctx].tc_ieee, tc_wire, 8);
}

bool dual_identity_epoch_matches(unsigned ctx, const char *epoch)
{
    if (ctx >= DUAL_CONTEXTS || !epoch) return false;
    return !strcmp(identities[ctx].epoch, epoch);
}

bool dual_identity_attempt_matches(unsigned ctx, const char *attempt)
{
    if (ctx >= DUAL_CONTEXTS || !attempt) return false;
    return !strcmp(identities[ctx].attempt, attempt);
}

unsigned dual_identity_context_of_pan(uint16_t pan)
{
    for (unsigned i = 0; i < DUAL_CONTEXTS; i++)
        if (identities[i].pan == pan) return i;
    return DUAL_CONTEXTS;
}
