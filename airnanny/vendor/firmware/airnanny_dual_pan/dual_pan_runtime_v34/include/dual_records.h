/* RADIOV10 transport records: host command parsing and firmware record
 * formatting. Contract: ../DUAL_PAN_RADIO_PROTOCOL.md
 *
 * Parsing is the boundary where a wrong context would become a cross-context
 * action, so every command carries an explicit ctx and nothing is defaulted:
 * a missing, duplicated or out-of-range field is a refusal, never an
 * assumption. Unknown keys are refused rather than ignored, so a typo in a
 * host command cannot silently change the meaning of a line.
 *
 * Formatting never runs in the RADIO interrupt. It writes whole lines or
 * nothing; a truncated record is never emitted.
 */
#ifndef DUAL_RECORDS_H
#define DUAL_RECORDS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dual_context.h"
#include "dual_sched.h"
#include "radio_wire.h"

#define RADIO_LINE_MAX 768u
/* Retained as the name the V10 formatters already use; it now resolves to the
 * single definition in radio_wire.h rather than its own literal. */
#define RADIOV10_PREFIX RADIO_PREFIX

typedef enum {
    CMD_INFO, CMD_CONFIG, CMD_BIND, CMD_ACK, CMD_SCAN, CMD_TX, CMD_STATS, CMD_STATUS, CMD_END
} dual_cmd_kind_t;

typedef struct {
    dual_cmd_kind_t kind;
    uint32_t id;                 /* host transaction id, mandatory on every command */
    bool has_ctx;
    unsigned ctx;

    /* CONFIG */
    uint32_t generation;
    bool ctx_enabled[DUAL_CONTEXTS];
    uint16_t pan[DUAL_CONTEXTS], shortaddr[DUAL_CONTEXTS];
    uint8_t ieee[DUAL_CONTEXTS][8];
    uint8_t channel;

    /* BIND */
    uint8_t raw[8], tc[8], extpan[8];
    uint16_t bind_pan, bind_short, coordinator_short;
    uint8_t keyseq;
    uint32_t bind_generation, max_polls, poll_interval_ms, timeout_ms;
    char attempt[33];

    /* ACK / SCAN */
    bool enabled;

    /* TX */
    dual_tx_class_t klass;
    bool cca;
    uint8_t mac[DUAL_TX_MAC_MAX];
    uint8_t mac_len;
} dual_cmd_t;

/* Returns NULL on success, or a stable lowercase reason token on refusal.
 * The reason is what the ERROR record reports; it never echoes host input. */
const char *dual_cmd_parse(const char *line, dual_cmd_t *out);

/* One RX observation as the gate hardware captured it. */
typedef struct {
    uint32_t rx_id, config_generation;
    dual_match_t match;
    dual_reason_t reason;
    bool has_ctx;
    unsigned ctx;
    bool rx_end_valid, ack_address_valid, ack_start_valid, ack_end_valid;
    uint32_t rx_end_us, ack_address_us, ack_start_us, ack_end_us;
    bool ack_started, ack_completed, deadline_miss, fcs_ok;
    int8_t rssi;
    uint8_t lqi, mac_len;
    uint8_t mac[DUAL_TX_MAC_MAX];
} dual_rx_record_t;

/* All formatters return false without writing when the buffer is too small. */
bool dual_format_rx(char *out, size_t capacity, const char *boot, const dual_rx_record_t *r);
bool dual_format_txaccept(char *out, size_t capacity, const char *boot,
                          const dual_tx_frame_t *f, uint32_t queue_depth);
bool dual_format_txdone(char *out, size_t capacity, const char *boot, uint32_t host_id,
                        unsigned ctx, dual_tx_result_t result, bool ack_requested,
                        uint32_t rf_start_us, uint32_t callback_us);
/* `host_id` correlates the record with the STATS command that asked for it.
 * Every other reply record carries one and the first draft of this formatter
 * did not, which would have left the host unable to await its own request.
 *
 * `starved_polls` and `routing_faults` are the firmware's own counters rather
 * than either stats struct's: the first is a context that was due to poll and
 * could not be offered, which is the fairness number issue #5 asks to be
 * bounded, and the second must stay zero because it would mean the TX
 * lifecycle and the scheduler disagree about which frame owns the radio. */
bool dual_format_stats(char *out, size_t capacity, const char *boot, uint32_t host_id,
                       uint32_t config_generation, const dual_stats_t *rx,
                       const dual_sched_stats_t *tx, uint32_t starved_polls,
                       uint32_t routing_faults);
bool dual_format_error(char *out, size_t capacity, const char *boot, bool has_id, uint32_t id,
                       bool has_ctx, unsigned ctx, const char *reason);

const char *dual_tx_result_name(dual_tx_result_t result);
/* dual_match_name and dual_reason_name live with their types in dual_context.h */

#endif
