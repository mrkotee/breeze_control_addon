/* Offline native tests for the V26 one-radio TX scheduler.
 * No COM, no RF, no cryptography, no keys. Synthetic MAC headers only.
 */
#include "dual_sched.h"
#include <stdio.h>
#include <string.h>

static int failures, checks;
static void ok(int cond, const char *what)
{
    checks++;
    if (!cond) { failures++; printf("FAIL %s\n", what); }
}

#define PAN0 0xFA9Bu
#define SHORT0 0xA326u
#define PAN1 0x0B7Au
#define SHORT1 0x6C55u
static const uint8_t RAW0[8] = { 0x69,0x20,0x58,0x4d,0x5f,0x27,0xb0,0xe2 };
static const uint8_t TC0[8]  = { 0xe5,0x48,0xa1,0x36,0x00,0x4b,0x12,0x00 };
static const uint8_t RAW1[8] = { 0x37,0x14,0xa4,0x75,0xbb,0x56,0x7a,0x02 };
static const uint8_t TC1[8]  = { 0x5f,0x87,0xa1,0x36,0x00,0x4b,0x12,0x00 };

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v & 0xff); p[1] = (uint8_t)(v >> 8); }

/* Outgoing shape observed in the captures: PAN, destination coordinator 0000,
 * source our assigned short. */
static uint8_t outgoing[DUAL_TX_MAC_MAX];
static const uint8_t *frame(uint16_t pan, uint16_t src_short, uint8_t len)
{
    memset(outgoing, 0, sizeof(outgoing));
    put16(outgoing, 0x8861);
    outgoing[2] = 0x11;
    put16(outgoing + 3, pan);
    put16(outgoing + 5, 0x0000);
    put16(outgoing + 7, src_short);
    for (uint8_t i = 9; i < len; i++) outgoing[i] = (uint8_t)(0xa0 + i);
    return outgoing;
}

static uint32_t generation = 1;
static void arm(bool ctx0, bool ctx1)
{
    dual_config_t c; memset(&c, 0, sizeof(c));
    c.enabled = true; c.channel = 21; c.generation = ++generation;
    if (ctx0) { c.ctx[0].enabled = true; c.ctx[0].pan_id = PAN0; c.ctx[0].local_short = SHORT0; }
    if (ctx1) { c.ctx[1].enabled = true; c.ctx[1].pan_id = PAN1; c.ctx[1].local_short = SHORT1; }
    ok(dual_config_commit_locked(&c), "configuration committed");
    if (ctx0) {
        dual_binding_t b; memset(&b, 0, sizeof(b));
        b.pan = PAN0; b.short_address = SHORT0; memcpy(b.raw, RAW0, 8); memcpy(b.tc, TC0, 8);
        ok(dual_binding_set(0, &b), "ctx0 bound");
    }
    if (ctx1) {
        dual_binding_t b; memset(&b, 0, sizeof(b));
        b.pan = PAN1; b.short_address = SHORT1; memcpy(b.raw, RAW1, 8); memcpy(b.tc, TC1, 8);
        ok(dual_binding_set(1, &b), "ctx1 bound");
    }
    dual_sched_init(100000);
}

static void test_submission_validation(void)
{
    arm(true, true);
    ok(dual_sched_submit(0, 1, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED,
       "well formed ctx0 frame accepted");
    ok(dual_sched_submit(1, 2, TX_CLASS_POLL, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_ACCEPTED,
       "well formed ctx1 frame accepted");

    /* Cross-context tuples must never reach the radio. */
    ok(dual_sched_submit(0, 3, TX_CLASS_POLL, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_TUPLE_MISMATCH,
       "ctx1 tuple refused on ctx0");
    ok(dual_sched_submit(1, 4, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_TUPLE_MISMATCH,
       "ctx0 tuple refused on ctx1");
    ok(dual_sched_submit(0, 5, TX_CLASS_POLL, true, frame(PAN0, SHORT1, 20), 20, 0) == TX_SUBMIT_TUPLE_MISMATCH,
       "foreign source short refused under own PAN");
    ok(dual_sched_submit(0, 6, TX_CLASS_POLL, true, frame(PAN1, SHORT0, 20), 20, 0) == TX_SUBMIT_TUPLE_MISMATCH,
       "own short under foreign PAN refused");

    ok(dual_sched_submit(2, 7, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_BAD_CONTEXT,
       "out of range context refused");
    ok(dual_sched_submit(0, 8, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 8, 0) == TX_SUBMIT_BAD_LENGTH,
       "too short frame refused");
    ok(dual_sched_submit(0, 1, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_DUPLICATE_ID,
       "duplicate host id refused");

    dual_sched_stats_t s; dual_sched_stats(&s);
    ok(s.refused_tuple[0] == 3 && s.refused_tuple[1] == 1, "tuple refusals counted per context");
    ok(s.refused_duplicate == 1 && s.refused_length == 1 && s.refused_context == 1, "other refusals counted");
}

/* The active discovery beacon request: the one frame a context sends before it
 * can name itself. It has no source address and a broadcast destination, so it
 * carries no tuple to check. Wiring the scheduler onto the real TX path found
 * this: the length floor of nine bytes refused it, and a context could never
 * have scanned. */
static uint8_t beacon[8];
static const uint8_t *beacon_request(uint8_t dsn)
{
    const uint8_t t[8] = { 0x03, 0x08, dsn, 0xff, 0xff, 0xff, 0xff, 0x07 };
    memcpy(beacon, t, 8);
    return beacon;
}

static void test_beacon_request_has_no_tuple(void)
{
    arm(true, true);
    ok(dual_sched_submit(0, 40, TX_CLASS_MANAGEMENT, false, beacon_request(55), 8, 0)
       == TX_SUBMIT_ACCEPTED, "ctx0 beacon request accepted despite carrying no tuple");
    ok(dual_sched_submit(1, 41, TX_CLASS_MANAGEMENT, false, beacon_request(56), 8, 0)
       == TX_SUBMIT_ACCEPTED, "ctx1 beacon request accepted");

    /* Accepting it must not open a hole: only the exact reviewed template
     * passes, and every other eight-byte frame is still refused. A sequence
     * number is the only byte allowed to vary. */
    uint8_t m[8];
    for (unsigned i = 0; i < 8; i++) {
        if (i == 2) continue;                 /* the sequence number */
        memcpy(m, beacon_request(57), 8);
        m[i] = (uint8_t)(m[i] ^ 0xff);
        ok(dual_sched_submit(0, 100 + i, TX_CLASS_MANAGEMENT, false, m, 8, 0)
           == TX_SUBMIT_BAD_LENGTH, "a mutated eight byte frame is still refused");
    }
    /* And the template at the wrong length is not the template. */
    ok(dual_sched_submit(0, 60, TX_CLASS_MANAGEMENT, false, beacon_request(58), 7, 0)
       == TX_SUBMIT_BAD_LENGTH, "a truncated beacon request is refused");

    /* Its completion still routes to the context that submitted it, which is
     * the property the tuple check was there to protect. */
    const dual_tx_frame_t *f = NULL;
    ok(dual_sched_dispatch(1000, false, false, 50000, &f) && f, "a beacon request dispatches");
    ok(f && f->ctx == 0 && f->host_id == 40, "the first beacon request belongs to ctx0");
    ok(dual_sched_complete(40, TX_RESULT_OK, 2000), "and completes against its own context");
    ok(dual_sched_dispatch(3000, false, false, 50000, &f) && f && f->ctx == 1,
       "then ctx1's beacon request takes the radio");
    ok(dual_sched_complete(41, TX_RESULT_OK, 4000), "and completes too");
}

static void test_unbound_context(void)
{
    arm(true, false);
    ok(dual_sched_submit(1, 10, TX_CLASS_POLL, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_BAD_CONTEXT,
       "disabled context refuses submission");
    ok(dual_sched_submit(0, 11, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED,
       "enabled context still accepts");
}

static void test_rx_and_ack_priority(void)
{
    arm(true, true);
    ok(dual_sched_submit(0, 20, TX_CLASS_APPLICATION, true, frame(PAN0, SHORT0, 30), 30, 0) == TX_SUBMIT_ACCEPTED,
       "application frame queued");
    const dual_tx_frame_t *f = NULL;

    ok(!dual_sched_dispatch(1000, false, true, 2000, &f), "ACK in progress blocks dispatch");
    ok(f == NULL, "nothing dispatched while ACK busy");
    ok(!dual_sched_dispatch(1000, true, false, 2000, &f), "RX in progress blocks dispatch");
    ok(!dual_sched_busy(), "radio still free while deferred");
    ok(dual_sched_dispatch(1000, false, false, 2000, &f), "dispatch proceeds once radio is quiet");
    ok(f != NULL && f->host_id == 20, "the queued frame was dispatched");

    dual_sched_stats_t s; dual_sched_stats(&s);
    ok(s.ack_priority_deferrals == 1 && s.rx_priority_deferrals == 1, "priority deferrals counted separately");
}

static void test_serialisation_and_fairness(void)
{
    arm(true, true);
    ok(dual_sched_submit(0, 30, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx0 queued");
    ok(dual_sched_submit(1, 31, TX_CLASS_POLL, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx1 queued");

    const dual_tx_frame_t *f = NULL;
    ok(dual_sched_dispatch(10, false, false, 1000, &f), "first dispatch");
    unsigned first = f->ctx;
    ok(dual_sched_busy(), "radio owned while in flight");
    ok(dual_sched_owner() == first, "owner names the dispatching context");
    /* One radio means the second context waits, it does not run in parallel. */
    ok(!dual_sched_dispatch(20, false, false, 1000, &f), "no second frame while one is in flight");

    ok(dual_sched_complete(first == 0 ? 30u : 31u, TX_RESULT_OK, 30), "first completes");
    ok(!dual_sched_busy(), "radio free after completion");
    ok(dual_sched_owner() == DUAL_CONTEXTS, "no owner when free");
    ok(dual_sched_dispatch(40, false, false, 1000, &f), "second dispatch");
    ok(f->ctx != first, "round robin served the other context next");

    /* Alternation continues when both contexts keep work pending. */
    ok(dual_sched_complete(f->host_id, TX_RESULT_OK, 50), "second completes");
    uint32_t id = 100;
    unsigned seen[DUAL_CONTEXTS] = { 0, 0 };
    for (unsigned round = 0; round < 6; round++) {
        ok(dual_sched_submit(0, id++, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx0 refill");
        ok(dual_sched_submit(1, id++, TX_CLASS_POLL, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx1 refill");
        ok(dual_sched_dispatch(60 + round * 10, false, false, 100000, &f), "round dispatch");
        seen[f->ctx]++;
        ok(dual_sched_complete(f->host_id, TX_RESULT_OK, 65 + round * 10), "round completes");
    }
    ok(seen[0] == 3 && seen[1] == 3, "both contexts served equally under sustained load");
}

static void test_fifo_within_context(void)
{
    arm(true, false);
    ok(dual_sched_submit(0, 40, TX_CLASS_APPLICATION, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "app queued first");
    ok(dual_sched_submit(0, 41, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "poll queued second");
    const dual_tx_frame_t *f = NULL;
    ok(dual_sched_dispatch(10, false, false, 1000, &f), "dispatch");
    /* A later poll must not overtake an already submitted application frame;
     * application frames are one shot and are never retried. */
    ok(f->host_id == 40, "FIFO order preserved within a context");
}

static void test_queue_bounds(void)
{
    arm(true, true);
    uint32_t id = 50;
    for (unsigned i = 0; i < DUAL_TX_QUEUE_DEPTH; i++)
        ok(dual_sched_submit(0, id++, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED,
           "queue fills to depth");
    ok(dual_sched_submit(0, id++, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_QUEUE_FULL,
       "overflow refused explicitly");
    /* The other context keeps its own capacity. */
    ok(dual_sched_submit(1, id++, TX_CLASS_POLL, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_ACCEPTED,
       "other context unaffected by a full queue");
    dual_sched_stats_t s; dual_sched_stats(&s);
    ok(s.refused_queue_full[0] == 1 && s.refused_queue_full[1] == 0, "overflow counted on the right context");
    ok(s.queue_high_water[0] == DUAL_TX_QUEUE_DEPTH, "queue high water recorded");
}

static void test_completion_routing(void)
{
    arm(true, true);
    ok(dual_sched_submit(1, 60, TX_CLASS_MANAGEMENT, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx1 queued");
    const dual_tx_frame_t *f = NULL;
    ok(dual_sched_dispatch(10, false, false, 1000, &f), "dispatch ctx1");
    ok(f->ctx == 1, "ctx1 in flight");

    /* A completion naming an unknown transaction is a routing error and
     * completes nothing. */
    ok(!dual_sched_complete(999, TX_RESULT_OK, 20), "unknown host id refused");
    ok(dual_sched_busy(), "frame still in flight after a routing error");
    dual_sched_stats_t s; dual_sched_stats(&s);
    ok(s.routing_error == 1, "routing error counted");
    ok(s.terminal[0] == 0 && s.terminal[1] == 0, "no context credited by a routing error");

    ok(dual_sched_complete(60, TX_RESULT_OK, 30), "correct host id completes");
    dual_sched_stats(&s);
    ok(s.terminal[1] == 1 && s.terminal[0] == 0, "completion credited only to the originating context");
}

static void test_failure_isolation(void)
{
    arm(true, true);
    ok(dual_sched_submit(0, 70, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx0 queued");
    ok(dual_sched_submit(1, 71, TX_CLASS_POLL, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx1 queued");
    const dual_tx_frame_t *f = NULL;
    ok(dual_sched_dispatch(10, false, false, 1000, &f), "dispatch");
    unsigned failing = f->ctx;
    ok(dual_sched_complete(f->host_id, TX_RESULT_NO_ACK, 20), "failure accepted as terminal");
    ok(!dual_sched_busy(), "radio freed after failure");

    dual_sched_stats_t s; dual_sched_stats(&s);
    ok(s.failed[failing] == 1, "failure counted on its own context");
    ok(s.failed[failing ^ 1u] == 0, "other context not marked failed");

    /* The surviving context still transmits. */
    ok(dual_sched_dispatch(30, false, false, 1000, &f), "other context still dispatches");
    ok(f->ctx != failing, "the healthy context is the one served");
    ok(dual_sched_complete(f->host_id, TX_RESULT_OK, 40), "healthy context completes normally");
}

static void test_timeout(void)
{
    arm(true, true);
    ok(dual_sched_submit(0, 80, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx0 queued");
    ok(dual_sched_submit(1, 81, TX_CLASS_POLL, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx1 queued");
    const dual_tx_frame_t *f = NULL;
    ok(dual_sched_dispatch(1000, false, false, 5000, &f), "dispatch with deadline");
    unsigned stuck = f->ctx;

    ok(!dual_sched_poll(4999), "no action before the deadline");
    ok(dual_sched_busy(), "still in flight before the deadline");
    ok(dual_sched_poll(5000), "timeout acted at the deadline");
    ok(!dual_sched_busy(), "radio freed by timeout");

    dual_sched_stats_t s; dual_sched_stats(&s);
    ok(s.timed_out[stuck] == 1 && s.timed_out[stuck ^ 1u] == 0, "timeout counted on its own context");
    ok(s.terminal[stuck] == 1, "timeout is terminal");

    /* Nothing is retried: the timed out frame does not come back. */
    ok(dual_sched_dispatch(6000, false, false, 10000, &f), "next frame dispatches");
    ok(f->ctx != stuck, "the timed out frame was not retried");
    ok(dual_sched_complete(f->host_id, TX_RESULT_OK, 7000), "surviving frame completes");
    ok(!dual_sched_poll(20000), "an idle radio cannot time out");
    dual_sched_stats(&s);
    ok(s.timed_out[stuck] == 1, "the timeout was not counted twice");
    ok(!dual_sched_dispatch(21000, false, false, 25000, &f), "both queues are empty, nothing requeued");
}

static void test_starvation_counter(void)
{
    arm(true, true);
    ok(dual_sched_submit(0, 90, TX_CLASS_POLL, true, frame(PAN0, SHORT0, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx0 queued early");
    ok(dual_sched_submit(1, 91, TX_CLASS_POLL, true, frame(PAN1, SHORT1, 20), 20, 0) == TX_SUBMIT_ACCEPTED, "ctx1 queued early");
    const dual_tx_frame_t *f = NULL;
    /* Dispatch far past the bound: the context left waiting is flagged. */
    ok(dual_sched_dispatch(500000, false, false, 600000, &f), "late dispatch");
    dual_sched_stats_t s; dual_sched_stats(&s);
    ok(s.starvation == 1, "waiting context flagged once");
    /* The counter is diagnostic only and must not reorder anything. */
    ok(dual_sched_complete(f->host_id, TX_RESULT_OK, 500010), "dispatch unaffected by the counter");
}

int main(void)
{
    test_submission_validation();
    test_unbound_context();
    test_beacon_request_has_no_tuple();
    test_rx_and_ack_priority();
    test_serialisation_and_fairness();
    test_fifo_within_context();
    test_queue_bounds();
    test_completion_routing();
    test_failure_isolation();
    test_timeout();
    test_starvation_counter();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
