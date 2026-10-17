/* V27's one behavioural change, and nothing else: a clean miss on a MAC poll
 * no longer ends the context; MAX_CONSECUTIVE_POLL_MISSES in a row still do.
 *
 * Why: V26 ended a context on the first failed TX of any kind
 * (management_done: if(!ok) commission_stop). Gate C attempts 2 and 3 and
 * Gate D attempt 1 each lost a context to one poll that got no ACK, or an ACK
 * with a bad CRC, on a clear channel. A data request carries no frame counter
 * and no security state, so the next poll asking again spends nothing and
 * risks nothing; a secured frame's first failure is still terminal.
 *
 * The frozen V25 transport is linked beside it, so the divergence is pinned
 * as intended rather than discovered: V25 stops on the first miss, V27 on the
 * third. No COM, no RF, no flash. */
#include "radio_wire.h"
#include "management.h"
#include <stdio.h>
#include <string.h>

void v25_management_done(commission_t *, bool, unsigned, uint32_t);

static int failures, checks;
static void ok(int cond, const char *what)
{
    checks++;
    if (!cond) { failures++; printf("FAIL %s\n", what); }
}

static commission_t live(void)
{
    commission_t s; memset(&s, 0, sizeof s);
    s.phase = G_MANAGEMENT;
    s.recovery.phase = R_ACTIVE;
    s.recovery.pending = true;
    return s;
}

static int stopped(const commission_t *s)
{
    return s->phase == G_STOPPED && s->recovery.phase == R_STOPPED;
}

int main(void)
{
    uint32_t now = 1000000u;

    /* Two clean poll misses are survived; the third in a row ends it. */
    commission_t s = live();
    for (unsigned i = 1; i < MAX_CONSECUTIVE_POLL_MISSES; i++) {
        management_done(&s, false, true, M_POLL, now += 60000000u);
        ok(!stopped(&s), "a clean poll miss below the limit keeps the context");
        ok(!s.recovery.pending, "the miss still releases the pending slot");
    }
    ok(s.recovery.poll_misses == MAX_CONSECUTIVE_POLL_MISSES - 1, "misses are counted");
    management_done(&s, false, true, M_POLL, now += 60000000u);
    ok(stopped(&s), "the limit-th consecutive miss ends the context");

    /* A good poll resets the run, so isolated misses over an hour never add up. */
    s = live();
    for (unsigned i = 0; i < 20; i++) {
        management_done(&s, false, true, M_POLL, now += 60000000u);
        management_done(&s, true, false, M_POLL, now += 60000000u);
    }
    ok(!stopped(&s), "isolated misses separated by good polls never end it");
    ok(s.recovery.poll_misses == 0, "a good poll resets the consecutive count");
    ok(s.recovery.poll_misses_total == 20, "the total is kept for the record");

    /* Only a CLEAN miss on a POLL is tolerated. */
    s = live();
    management_done(&s, false, false, M_POLL, now);
    ok(stopped(&s), "an unclean poll failure (aborted, ambiguous) still ends it");

    const unsigned secured[] = {M_REJOIN, M_ANNOUNCE, M_TIMEOUT, M_APP, M_BEACON};
    for (unsigned i = 0; i < sizeof secured / sizeof secured[0]; i++) {
        s = live();
        management_done(&s, false, true, secured[i], now);
        ok(stopped(&s), "any non-poll failure ends the context on the first, as in V26");
    }

    /* The window bookkeeping of a successful secured frame is untouched. */
    s = live();
    s.recovery.phase = R_PREPARED;
    management_done(&s, true, false, M_REJOIN, now);
    ok(s.recovery.window && s.recovery.deadline_us == now + RESPONSE_US,
       "a successful REJOIN still opens its response window");

    /* The divergence from V25, pinned: V25 stops on the first clean miss. */
    commission_t v = live();
    v25_management_done(&v, false, M_POLL, now);
    ok(stopped(&v), "V25 ends the context on the first missed poll (the behaviour V27 changes)");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
