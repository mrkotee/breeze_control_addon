/* Frame equivalence of the context-parameterised transport with frozen V25.
 *
 * The V25 rejoin_transport.c is compiled into this binary with its external
 * names prefixed (see the build line in the README), so both implementations
 * coexist. Driven over the same command sequences with ctx1 selected, the
 * parameterised code must emit byte-identical frames and reach identical
 * state, because ctx1 is exactly the network V25 was pinned to.
 *
 * This is the evidence that replacing the pinned literals with per-session
 * values changed no behaviour for the context that already has hardware proof.
 *
 * No COM, no RF, no cryptography, no keys.
 */
#include "radio_wire.h"
#include "management.h"
#include "dual_identity.h"
#include <stdio.h>
#include <string.h>

/* The frozen V25 implementation, same signatures, prefixed names. */
const char *v25_management_parse(const char *, management_command_t *);
const char *v25_management_resume(commission_t *, const management_command_t *, uint32_t);
const char *v25_management_tx(commission_t *, const management_command_t *, uint32_t, uint8_t *, size_t *);
const char *v25_management_control(commission_t *, const management_command_t *, uint32_t);
void v25_management_done(commission_t *, bool, unsigned, uint32_t);
bool v25_management_auto_poll(commission_t *, uint32_t, uint8_t[10]);
bool v25_management_beacon(const uint8_t *, size_t);
void v25_management_observe(commission_t *, const uint8_t *, size_t, uint32_t, uint32_t, bool);
void v25_management_tick(commission_t *, uint32_t);

static int failures, checks;
static void ok(int cond, const char *what)
{
    checks++;
    if (!cond) { failures++; printf("FAIL %s\n", what); }
}

#define BOOT "11111111111111111111111111111111"
#define GUARD "22222222222222222222222222222222"
#define EPOCH1 "9985b15dcb574c59b87dc2fb379f317f"
#define ATTEMPT1 "cbef428849da4e87b48867ac616247d1"

/* V25 required generation >= 6 and short 0x6c55; use values it accepts so the
 * two implementations are compared where both are defined. */
#define GEN 16u
#define SHORT1 27733u   /* 0x6c55 */

static commission_t a, b;   /* a: parameterised, b: frozen V25 */

static void reset(void)
{
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
}

static bool same_frame(const uint8_t *x, size_t nx, const uint8_t *y, size_t ny, const char *what)
{
    checks++;
    if (nx != ny || memcmp(x, y, nx)) {
        failures++;
        printf("FAIL %s: lengths %zu/%zu\n", what, nx, ny);
        printf("  new:"); for (size_t i = 0; i < nx; i++) printf(" %02x", x[i]); printf("\n");
        printf("  v25:"); for (size_t i = 0; i < ny; i++) printf(" %02x", y[i]); printf("\n");
        return false;
    }
    return true;
}

static void parse_both(const char *line, management_command_t *ca, management_command_t *cb,
                       const char *what)
{
    /* Two differences are by construction, and only two: V26 speaks RADIOV10
     * and requires ctx on every per-context verb, V25 speaks RADIOV9 and has no
     * ctx at all. Each parser is handed the line its own contract defines, so
     * what the comparison measures afterwards is the parse *result* -- the
     * frame built, the state reached -- and not the spelling of the envelope.
     * Anything else in the line is identical between the two. */
    const char *ra = management_parse(line, ca);

    char lineage[512];
    size_t at = 0;
    const char *body = line + strlen(RADIO_PREFIX);   /* line starts with the V10 prefix */
    at += (size_t)snprintf(lineage + at, sizeof lineage - at, "%s", RADIO_PREFIX_LINEAGE);
    const char *ctx = strstr(body, " ctx=");
    if (ctx) {
        size_t head = (size_t)(ctx - body);
        memcpy(lineage + at, body, head);
        at += head;
        const char *rest = ctx + 1;
        while (*rest && *rest != ' ') rest++;
        snprintf(lineage + at, sizeof lineage - at, "%s", rest);
    } else {
        snprintf(lineage + at, sizeof lineage - at, "%s", body);
    }
    const char *rb = v25_management_parse(lineage, cb);
    checks++;
    if (ra || rb) { failures++; printf("FAIL parse %s: new=%s v25=%s\n", what, ra ? ra : "ok", rb ? rb : "ok"); }
}

static void resume_both(void)
{
    management_command_t ca, cb;
    parse_both(RADIO_PREFIX " BIND id=1 boot=" BOOT " session=1 generation=16 epoch=" EPOCH1
               " attempt=" ATTEMPT1 " guard=" GUARD " short=27733 ctx=1", &ca, &cb, "BIND");
    const char *ra = management_resume(&a, &ca, 1000);
    const char *rb = v25_management_resume(&b, &cb, 1000);
    ok(!ra && !rb, "both resumed");
    ok(a.keys.pan == b.keys.pan, "same PAN after resume");
    ok(a.keys.short_address == b.keys.short_address, "same short after resume");
    ok(!memcmp(a.keys.raw, b.keys.raw, 8), "same RAW identity after resume");
    ok(!memcmp(a.keys.tc, b.keys.tc, 8), "same trust centre identity after resume");
    ok(a.keys.keyseq == b.keys.keyseq, "same key sequence after resume");
    ok(a.keys.ctx == b.keys.ctx, "same context index after resume");
    ok(a.generation == b.generation && a.phase == b.phase, "same phase and generation");
    ok(a.recovery.phase == b.recovery.phase, "same recovery phase");
}

/* Beacon acceptance must agree over a corpus of candidate beacons. */
static void beacon_corpus(void)
{
    static const uint8_t tc1[8] = { 0x5f,0x87,0xa1,0x36,0x00,0x4b,0x12,0x00 };
    unsigned agree = 0, accepted = 0;
    for (unsigned variant = 0; variant < 512; variant++) {
        uint8_t m[40]; memset(m, 0, sizeof m);
        m[0] = 0x00; m[1] = 0x80;                 /* beacon FCF 0x8000 */
        m[2] = (uint8_t)variant;
        m[3] = 0x7a; m[4] = 0x0b;                 /* ctx1 PAN */
        m[5] = 0; m[6] = 0;
        m[7] = 0xff; m[8] = 0x4f;                 /* superframe */
        m[9] = 0; m[10] = 0;
        size_t i = 11;
        m[i] = 0; m[i+1] = 0x22; m[i+2] = 0x80;
        memcpy(m + i + 3, tc1, 8);
        m[i+11] = 255; m[i+12] = 255; m[i+13] = 255;
        size_t n = i + 15;
        /* Perturb one field per variant so both accept and reject paths run. */
        if (variant & 1) m[3] = 0x9b;             /* foreign PAN */
        if (variant & 2) m[i+3] ^= 0xff;          /* wrong trust centre */
        if (variant & 4) m[1] = 0x81;             /* wrong FCF */
        if (variant & 8) m[7] = 0x00;             /* wrong superframe */
        if (variant & 16) m[i+1] = 0x23;          /* wrong payload tag */
        if (variant & 32) n -= 1;                 /* wrong length */
        if (variant & 64) m[9] = 0x01;            /* reserved bits set */
        if (variant & 128) m[i+2] = 0x00;         /* association bit clear */
        bool ga = management_beacon(&a, m, n);
        bool gb = v25_management_beacon(m, n);
        if (ga == gb) agree++;
        if (ga) accepted++;
    }
    ok(agree == 512, "beacon verdicts agree over the corpus");
    ok(accepted > 0, "the beacon corpus contains accepted cases");
}

/* Automatic poll frames are where the PAN used to be literal bytes. */
static void auto_poll_frames(void)
{
    a.recovery.window = b.recovery.window = true;
    a.recovery.poll_due = b.recovery.poll_due = 2000;
    a.recovery.deadline_us = b.recovery.deadline_us = 500000;
    a.recovery.poll_dsn = b.recovery.poll_dsn = 7;
    for (unsigned round = 0; round < 5; round++) {
        uint8_t fa[10], fb[10];
        bool ga = management_auto_poll(&a, 2000 + round * 100000u, fa);
        bool gb = v25_management_auto_poll(&b, 2000 + round * 100000u, fb);
        ok(ga == gb, "auto poll availability agrees");
        if (ga && gb) same_frame(fa, 10, fb, 10, "auto poll frame");
        a.recovery.pending = b.recovery.pending = false;
    }
    ok(a.recovery.poll_dsn == b.recovery.poll_dsn, "same poll DSN after the round");
    ok(a.recovery.total_polls == b.recovery.total_polls, "same poll counters");
}

/* The idle MANAGEMENT_POLL command frame, likewise. */
static void idle_poll_frames(void)
{
    a.recovery.phase = b.recovery.phase = R_ACTIVE;
    a.recovery.window = b.recovery.window = false;
    a.recovery.pending = b.recovery.pending = false;
    a.recovery.last_idle_poll = b.recovery.last_idle_poll = 0;
    a.recovery.start_us = b.recovery.start_us = 0;
    for (unsigned round = 0; round < 4; round++) {
        char line[256];
        snprintf(line, sizeof line, RADIO_PREFIX " MANAGEMENT_POLL id=%u boot=" BOOT
                 " session=1 generation=16 dsn=%u ctx=1", 10 + round, 100 + round);
        management_command_t ca, cb;
        parse_both(line, &ca, &cb, "MANAGEMENT_POLL");
        uint8_t fa[32], fb[32]; size_t na = 0, nb = 0;
        uint32_t now = 2000000u + round * 2000000u;
        const char *ra = management_tx(&a, &ca, now, fa, &na);
        const char *rb = v25_management_tx(&b, &cb, now, fb, &nb);
        ok((ra == NULL) == (rb == NULL), "idle poll acceptance agrees");
        if (!ra && !rb) same_frame(fa, na, fb, nb, "idle poll frame");
        a.recovery.pending = b.recovery.pending = false;
    }
}

/* Response observation gates on PAN and both identities. */
static void observe_response(void)
{
    static const uint8_t raw1[8] = { 0x37,0x14,0xa4,0x75,0xbb,0x56,0x7a,0x02 };
    static const uint8_t tc1[8]  = { 0x5f,0x87,0xa1,0x36,0x00,0x4b,0x12,0x00 };
    for (unsigned variant = 0; variant < 64; variant++) {
        a.recovery.phase = b.recovery.phase = R_WAIT_REJOIN;
        a.recovery.response_revision = b.recovery.response_revision = 0;
        a.recovery.tx_end_us = b.recovery.tx_end_us = 1000;
        a.recovery.deadline_us = b.recovery.deadline_us = 500000;
        uint8_t m[55]; memset(m, 0, sizeof m);
        m[0] = 0x61; m[1] = 0x88; m[2] = 0x40;
        m[3] = 0x7a; m[4] = 0x0b;
        m[5] = (uint8_t)SHORT1; m[6] = (uint8_t)(SHORT1 >> 8);
        m[7] = 0; m[8] = 0;
        m[9] = 0x09; m[10] = 0x1a;
        m[11] = (uint8_t)SHORT1; m[12] = (uint8_t)(SHORT1 >> 8);
        m[13] = 0; m[14] = 0;
        memcpy(m + 17, raw1, 8);
        memcpy(m + 25, tc1, 8);
        m[33] = 0x28;
        memcpy(m + 38, tc1, 8);
        m[46] = 0;
        if (variant & 1) m[3] = 0x9b;
        if (variant & 2) m[17] ^= 0xff;
        if (variant & 4) m[25] ^= 0xff;
        if (variant & 8) m[33] = 0x08;
        if (variant & 16) m[38] ^= 0xff;
        if (variant & 32) m[46] = 3;
        management_observe(&a, m, 55, 10, 2000, true);
        v25_management_observe(&b, m, 55, 10, 2000, true);
        checks++;
        if (a.recovery.response_revision != b.recovery.response_revision) {
            failures++;
            printf("FAIL observe variant %u: new=%lu v25=%lu\n", variant,
                   (unsigned long)a.recovery.response_revision,
                   (unsigned long)b.recovery.response_revision);
        }
    }
}

/* The widened budgets are the one intended difference. */
static void budgets_widened(void)
{
    ok(SESSION_LIMIT_US > 360000000u, "session limit raised above the V25 bound");
    ok(DUAL_GENERATION_FLOOR == 6u, "the V25 generation floor is preserved exactly");
    ok(SESSION_LIMIT_US >= 3600000000u, "session limit covers a 60 minute soak");
    ok(MAX_TOTAL_POLLS_PER_CONTEXT >= 3600u, "poll budget covers an hour at one poll per second");
    /* And they remain inside the 32 bit microsecond domain the timer uses. */
    ok(SESSION_LIMIT_US < 4294967295u, "session limit fits the 32 bit microsecond clock");
}

/* A context the image does not know must be refused at resume. */
static void foreign_context_refused(void)
{
    reset();
    management_command_t c; memset(&c, 0, sizeof c);
    const char *r = management_parse(RADIO_PREFIX " BIND id=1 boot=" BOOT " session=1 generation=16"
                                     " epoch=" EPOCH1 " attempt=" ATTEMPT1 " guard=" GUARD
                                     " short=27733 ctx=2", &c);
    ok(r && !strcmp(r, "ctx"), "a third context is refused by the parser");

    /* ctx0's slot with ctx1's epoch is a transplant and must not resume. */
    management_command_t c0; memset(&c0, 0, sizeof c0);
    r = management_parse(RADIO_PREFIX " BIND id=1 boot=" BOOT " session=1 generation=19"
                         " epoch=" EPOCH1 " attempt=" ATTEMPT1 " guard=" GUARD
                         " short=41766 ctx=0", &c0);
    ok(!r, "the transplanted line parses");
    commission_t s; memset(&s, 0, sizeof s);
    r = management_resume(&s, &c0, 1000);
    ok(r && !strcmp(r, "current_context_only"), "ctx1 epoch on ctx0 refused at resume");
    ok(s.phase == G_IDLE, "a refused resume leaves the session untouched");
}

/* ctx0 resumes with its own pinned identity, which V25 could not do at all. */
static void ctx0_resumes(void)
{
    commission_t s; memset(&s, 0, sizeof s);
    management_command_t c; memset(&c, 0, sizeof c);
    const char *r = management_parse(RADIO_PREFIX " BIND id=1 boot=" BOOT " session=1 generation=19"
                                     " epoch=1ea30211ee014345a8288337a173a833"
                                     " attempt=5b09cb6bc02746298fbffcfb780844a5"
                                     " guard=" GUARD " short=41766 ctx=0", &c);
    ok(!r, "ctx0 BIND parses");
    r = management_resume(&s, &c, 1000);
    ok(!r, "ctx0 resumes");
    ok(s.keys.pan == DUAL_CTX0_PAN, "ctx0 bound to its own PAN");
    ok(s.keys.ctx == 0, "ctx0 context index recorded");
    const dual_identity_t *id = dual_identity(0);
    ok(!memcmp(s.keys.raw, id->raw_ieee, 8), "ctx0 RAW identity from the pinned table");
    ok(!memcmp(s.keys.tc, id->tc_ieee, 8), "ctx0 trust centre identity from the pinned table");

    /* And its poll frame carries its own PAN, not ctx1's. */
    s.recovery.window = true; s.recovery.poll_due = 0;
    s.recovery.deadline_us = 500000; s.recovery.poll_dsn = 1;
    uint8_t f[10];
    ok(management_auto_poll(&s, 1000, f), "ctx0 auto poll built");
    ok(f[3] == (uint8_t)DUAL_CTX0_PAN && f[4] == (uint8_t)(DUAL_CTX0_PAN >> 8),
       "ctx0 poll frame carries ctx0 PAN");
}

/* The ctx scope rules of the RADIOV10 envelope. V25 had one context and so no
 * scope to get wrong; with two, an unscoped action is a frame sent into some
 * network chosen by the firmware rather than by the host, which is exactly the
 * failure issue #5 forbids. These are the negative cases. */
static void ctx_scope_rules(void)
{
    management_command_t c;
    struct { const char *line; const char *want; const char *what; } cases[] = {
      /* Every per-context verb must be scoped, including the ones whose field
       * set V25 accepted bare. */
      { RADIO_PREFIX " BIND id=1 boot=" BOOT " session=1 generation=16 epoch=" EPOCH1
        " attempt=" ATTEMPT1 " guard=" GUARD " short=27733", "ctx_required",
        "BIND without ctx" },
      { RADIO_PREFIX " MANAGEMENT_POLL id=1 boot=" BOOT " session=1 generation=16 dsn=7",
        "ctx_required", "MANAGEMENT_POLL without ctx" },
      { RADIO_PREFIX " ACTIVE_DISCOVERY_BEACON_REQUEST id=1 boot=" BOOT
        " session=1 generation=16 dsn=7", "ctx_required", "beacon request without ctx" },
      { RADIO_PREFIX " PARENT_LINK_ACTIVE id=1 boot=" BOOT " session=1 generation=16"
        " revision=5", "ctx_required", "PARENT_LINK_ACTIVE without ctx" },
      /* The two global verbs refuse a scope they do not have, rather than
       * ignoring it: an ignored ctx reads to the host as an accepted one. */
      { RADIO_PREFIX " INFO id=1 ctx=0", "ctx_not_scoped", "INFO with ctx" },
      { RADIO_PREFIX " END id=1 boot=" BOOT " session=1 ctx=1", "ctx_not_scoped",
        "END with ctx" },
      /* Out of range is refused at the field, before any scope question. */
      { RADIO_PREFIX " MANAGEMENT_POLL id=1 boot=" BOOT " session=1 generation=16"
        " dsn=7 ctx=2", "ctx", "ctx out of range" },
      /* And the lineage prefix is no longer accepted on this link. */
      { RADIO_PREFIX_LINEAGE " INFO id=1", "prefix", "the RADIOV9 prefix" },
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        memset(&c, 0, sizeof c);
        const char *r = management_parse(cases[i].line, &c);
        ok(r && !strcmp(r, cases[i].want), cases[i].what);
    }

    /* STATUS is the one exception, and it is a report rather than an action: it
     * may name a context or leave the firmware to describe the single bound
     * one. Both spellings parse, and has_ctx records which was used. */
    memset(&c, 0, sizeof c);
    ok(management_parse(RADIO_PREFIX " STATUS id=1 boot=" BOOT " session=1", &c) == NULL
       && !c.has_ctx, "STATUS without ctx parses and is marked unscoped");
    memset(&c, 0, sizeof c);
    ok(management_parse(RADIO_PREFIX " STATUS id=1 boot=" BOOT " session=1 ctx=1", &c) == NULL
       && c.has_ctx && c.ctx == 1, "STATUS with ctx parses and records it");
}

int main(void)
{
    reset();
    ctx_scope_rules();
    resume_both();
    beacon_corpus();
    auto_poll_frames();
    idle_poll_frames();
    observe_response();
    budgets_widened();
    foreign_context_refused();
    ctx0_resumes();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
