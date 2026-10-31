#include "dual_sched.h"
#include <string.h>

typedef struct {
    dual_tx_frame_t slots[DUAL_TX_QUEUE_DEPTH];
    uint32_t enqueued_us[DUAL_TX_QUEUE_DEPTH];
    unsigned head, count;
} dual_queue_t;

static dual_queue_t queues[DUAL_CONTEXTS];
static dual_sched_stats_t stats;
static dual_tx_frame_t in_flight;
static bool owned;
static uint32_t in_flight_deadline;
static unsigned last_served;
static uint32_t starvation_bound;

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

/* The one frame a context sends before it can name itself: an active discovery
 * beacon request. FCF 0x0803 is a MAC command with no source address and a
 * broadcast destination PAN and short, so it carries no tuple, and the
 * ownership check below cannot be applied to it without refusing a legitimate
 * frame -- which is exactly what it did when this check was first written.
 *
 * What replaces the tuple check here is stronger rather than weaker: the frame
 * must be byte-for-byte the reviewed eight-byte template, variable only in its
 * sequence number. Its completion is still routed to the context that
 * submitted it, because routing is by host id and never by anything read out
 * of the frame. */
static bool is_beacon_request(const uint8_t *mac, uint8_t len)
{
    return len == 8 && mac[0] == 0x03 && mac[1] == 0x08 &&
           mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff && mac[6] == 0xff &&
           mac[7] == 0x07;
}

void dual_sched_init(uint32_t starvation_bound_us)
{
    memset(queues, 0, sizeof(queues));
    memset(&stats, 0, sizeof(stats));
    memset(&in_flight, 0, sizeof(in_flight));
    owned = false;
    in_flight_deadline = 0;
    last_served = DUAL_CONTEXTS - 1;
    starvation_bound = starvation_bound_us;
}

static bool id_known(uint32_t host_id)
{
    if (owned && in_flight.host_id == host_id) return true;
    for (unsigned c = 0; c < DUAL_CONTEXTS; c++)
        for (unsigned i = 0; i < queues[c].count; i++) {
            unsigned slot = (queues[c].head + i) % DUAL_TX_QUEUE_DEPTH;
            if (queues[c].slots[slot].host_id == host_id) return true;
        }
    return false;
}

static void note_depth(unsigned ctx)
{
    stats.queue_depth[ctx] = queues[ctx].count;
    if (queues[ctx].count > stats.queue_high_water[ctx])
        stats.queue_high_water[ctx] = queues[ctx].count;
}

dual_tx_submit_t dual_sched_submit(unsigned ctx, uint32_t host_id, dual_tx_class_t klass,
                                   bool cca, const uint8_t *mac, uint8_t len, uint32_t now_us)
{
    if (ctx >= DUAL_CONTEXTS || !mac) { stats.refused_context++; return TX_SUBMIT_BAD_CONTEXT; }
    const dual_binding_t *b = dual_binding_get(ctx);
    const dual_config_t *cfg = dual_config_current();
    if (!b || !b->bound || !cfg->enabled || !cfg->ctx[ctx].enabled) {
        stats.refused_context++;
        return TX_SUBMIT_BAD_CONTEXT;
    }
    if (len > DUAL_TX_MAC_MAX) { stats.refused_length++; return TX_SUBMIT_BAD_LENGTH; }

    if (is_beacon_request(mac, len)) {
        /* Nothing further to check: the shape test above is exhaustive apart
         * from the sequence number. No tuple check is possible or needed. */
    } else {
        /* Nine MAC header bytes are the minimum that can carry PAN and both
         * short addresses, which is what ownership is checked against. */
        if (len < 9) { stats.refused_length++; return TX_SUBMIT_BAD_LENGTH; }

        /* Ownership check: the frame must name this context's PAN and carry
         * this context's short as its MAC source. This is where a
         * cross-context tuple is stopped, before the radio is ever asked for
         * anything. */
        if (le16(mac + 3) != cfg->ctx[ctx].pan_id ||
            le16(mac + 7) != cfg->ctx[ctx].local_short) {
            stats.refused_tuple[ctx]++;
            return TX_SUBMIT_TUPLE_MISMATCH;
        }
    }

    if (id_known(host_id)) { stats.refused_duplicate++; return TX_SUBMIT_DUPLICATE_ID; }
    if (queues[ctx].count >= DUAL_TX_QUEUE_DEPTH) {
        stats.refused_queue_full[ctx]++;
        return TX_SUBMIT_QUEUE_FULL;
    }

    unsigned slot = (queues[ctx].head + queues[ctx].count) % DUAL_TX_QUEUE_DEPTH;
    dual_tx_frame_t *f = &queues[ctx].slots[slot];
    memset(f, 0, sizeof(*f));
    f->ctx = ctx; f->host_id = host_id; f->klass = klass; f->cca = cca; f->len = len;
    memcpy(f->mac, mac, len);
    queues[ctx].enqueued_us[slot] = now_us;
    queues[ctx].count++;
    stats.accepted[ctx]++;
    note_depth(ctx);
    return TX_SUBMIT_ACCEPTED;
}

static void count_starvation(uint32_t now_us, unsigned chosen)
{
    if (!starvation_bound) return;
    for (unsigned c = 0; c < DUAL_CONTEXTS; c++) {
        if (c == chosen || !queues[c].count) continue;
        uint32_t waited = now_us - queues[c].enqueued_us[queues[c].head];
        if (waited > starvation_bound) stats.starvation++;
    }
}

bool dual_sched_dispatch(uint32_t now_us, bool rx_busy, bool ack_busy,
                         uint32_t deadline_us, const dual_tx_frame_t **out)
{
    if (out) *out = NULL;
    if (owned) return false;
    /* Reception and an immediate ACK in progress always win. The ACK deadline
     * is the one obligation this firmware cannot miss. */
    if (ack_busy) { stats.ack_priority_deferrals++; return false; }
    if (rx_busy)  { stats.rx_priority_deferrals++;  return false; }

    /* Round robin across contexts that have work; FIFO within a context, so a
     * submitted application frame is never reordered behind later polls. */
    for (unsigned step = 1; step <= DUAL_CONTEXTS; step++) {
        unsigned c = (last_served + step) % DUAL_CONTEXTS;
        if (!queues[c].count) continue;
        unsigned slot = queues[c].head;
        in_flight = queues[c].slots[slot];
        queues[c].head = (queues[c].head + 1) % DUAL_TX_QUEUE_DEPTH;
        queues[c].count--;
        note_depth(c);
        owned = true;
        in_flight_deadline = deadline_us;
        last_served = c;
        stats.dispatched[c]++;
        count_starvation(now_us, c);
        if (out) *out = &in_flight;
        return true;
    }
    return false;
}

bool dual_sched_busy(void) { return owned; }
unsigned dual_sched_owner(void) { return owned ? in_flight.ctx : DUAL_CONTEXTS; }

bool dual_sched_complete(uint32_t host_id, dual_tx_result_t result, uint32_t now_us)
{
    (void)now_us;
    if (!owned || in_flight.host_id != host_id) {
        /* A completion that names no in-flight frame is never attributed to a
         * context by guesswork. */
        stats.routing_error++;
        return false;
    }
    unsigned ctx = in_flight.ctx;
    stats.terminal[ctx]++;
    if (result != TX_RESULT_OK) stats.failed[ctx]++;
    owned = false;
    in_flight_deadline = 0;
    memset(&in_flight, 0, sizeof(in_flight));
    return true;
}

bool dual_sched_poll(uint32_t now_us)
{
    if (!owned || !in_flight_deadline) return false;
    if ((int32_t)(now_us - in_flight_deadline) < 0) return false;
    unsigned ctx = in_flight.ctx;
    stats.terminal[ctx]++;
    stats.failed[ctx]++;
    stats.timed_out[ctx]++;
    owned = false;
    in_flight_deadline = 0;
    memset(&in_flight, 0, sizeof(in_flight));
    return true;
}

void dual_sched_stats(dual_sched_stats_t *out) { if (out) *out = stats; }
