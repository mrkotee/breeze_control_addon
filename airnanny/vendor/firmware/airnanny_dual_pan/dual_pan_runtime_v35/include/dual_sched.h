/* V26 one-radio TX scheduler.
 *
 * The dongle has one radio on one channel, so transmissions of the two
 * contexts are serialised. This module owns that decision and nothing else: it
 * holds no radio calls, no cryptography and no timers of its own. The caller
 * passes the current time and whether RX or an immediate ACK is in progress,
 * and the module answers which frame, if any, may go on air next.
 *
 * Invariants:
 *   - exactly one in-flight frame at a time, with a named owning context;
 *   - RX and immediate ACK always win over any application transmission;
 *   - queues are bounded and per context; overflow is an explicit refusal;
 *   - a completion is routed only to the context that submitted it;
 *   - a frame whose MAC PAN or source short does not belong to its context is
 *     refused at submission, so no cross-context tuple can reach the radio;
 *   - a failure or timeout in one context frees the radio and leaves the other
 *     context's queue and counters untouched;
 *   - nothing is ever retried here. A failed or unknown transmission is
 *     terminal, as it is in V25.
 */
#ifndef DUAL_SCHED_H
#define DUAL_SCHED_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dual_context.h"

#define DUAL_TX_QUEUE_DEPTH 4u
#define DUAL_TX_MAC_MAX 125u

typedef enum { TX_CLASS_POLL, TX_CLASS_MANAGEMENT, TX_CLASS_APPLICATION } dual_tx_class_t;

typedef enum {
    TX_SUBMIT_ACCEPTED,
    TX_SUBMIT_BAD_CONTEXT,      /* index out of range, disabled or unbound */
    TX_SUBMIT_QUEUE_FULL,
    TX_SUBMIT_DUPLICATE_ID,     /* a host id already queued or in flight */
    TX_SUBMIT_BAD_LENGTH,
    TX_SUBMIT_TUPLE_MISMATCH    /* MAC PAN or source short is not this context's */
} dual_tx_submit_t;

typedef enum {
    TX_RESULT_OK, TX_RESULT_NO_ACK, TX_RESULT_INVALID_ACK,
    TX_RESULT_CCA_FAIL, TX_RESULT_ABORTED, TX_RESULT_ERROR
} dual_tx_result_t;

typedef struct {
    unsigned ctx;
    uint32_t host_id;
    dual_tx_class_t klass;
    bool cca;
    uint8_t len;
    uint8_t mac[DUAL_TX_MAC_MAX];
} dual_tx_frame_t;

typedef struct {
    uint32_t accepted[DUAL_CONTEXTS], terminal[DUAL_CONTEXTS];
    uint32_t refused_queue_full[DUAL_CONTEXTS], refused_tuple[DUAL_CONTEXTS];
    uint32_t refused_duplicate, refused_context, refused_length;
    uint32_t dispatched[DUAL_CONTEXTS], failed[DUAL_CONTEXTS], timed_out[DUAL_CONTEXTS];
    uint32_t rx_priority_deferrals, ack_priority_deferrals;
    uint32_t routing_error, starvation;
    uint32_t queue_depth[DUAL_CONTEXTS], queue_high_water[DUAL_CONTEXTS];
} dual_sched_stats_t;

/* `starvation_bound_us` only drives a diagnostic counter; it never reorders
 * work. Pass 0 to disable the counter. */
void dual_sched_init(uint32_t starvation_bound_us);

dual_tx_submit_t dual_sched_submit(unsigned ctx, uint32_t host_id, dual_tx_class_t klass,
                                   bool cca, const uint8_t *mac, uint8_t len, uint32_t now_us);

/* Picks the next frame when the radio is free and neither RX nor ACK is busy.
 * On true, *out points at the in-flight frame, owned until completion or
 * timeout. `deadline_us` is remembered for dual_sched_poll. */
bool dual_sched_dispatch(uint32_t now_us, bool rx_busy, bool ack_busy,
                         uint32_t deadline_us, const dual_tx_frame_t **out);

bool dual_sched_busy(void);
/* Index of the context that owns the radio, or DUAL_CONTEXTS when free. */
unsigned dual_sched_owner(void);

/* Routes a terminal radio result. A host id that does not match the in-flight
 * frame is a routing error and never completes anything. */
bool dual_sched_complete(uint32_t host_id, dual_tx_result_t result, uint32_t now_us);

/* Fails the in-flight frame when its deadline passed. Returns true when it
 * acted; the other context is not touched. */
bool dual_sched_poll(uint32_t now_us);

void dual_sched_stats(dual_sched_stats_t *out);

#endif
