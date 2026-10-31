/* Gate instrumentation: the RX event ring, the ISR-side hooks the patched
 * driver calls, and the per-context statistics.
 *
 * This is the union of two predecessors. From ctx1_rx_admission_v25 it keeps
 * the RX revision with its saturation and drop accounting, the CRC snapshot and
 * the cutoff drain, all of which host logic and the durable replay floors
 * depend on. From dual_pan_mac_gate it takes the context classification carried
 * on the record and the hardware-captured ACK timing, which is what the first
 * hardware gate has to measure.
 *
 * Field names the inherited host-test harnesses fill directly (revision,
 * session, time_us, length, mac, rssi, lqi, ack_started, ack_completed,
 * deadline_miss) are kept exactly, so tests/firmware_cli.c and
 * tests/scan_replay.c compile unchanged and simply leave the new fields zero.
 *
 * time_us is the RX event instant. On hardware it is now the PPI capture of
 * RADIO EVENTS_CRCOK rather than a software clock read taken afterwards, which
 * is the same instant measured more precisely; in host-test builds it stays
 * whatever the mock sets.
 */
#ifndef ASSOC_GATE_EVENTS_H
#define ASSOC_GATE_EVENTS_H
#include "commission.h"
#include "dual_context.h"
#define GATE_RING_SIZE 32u

typedef struct {
    /* V25 fields, unchanged in name and meaning. */
    uint32_t revision, session, time_us;
    int8_t rssi;
    uint8_t lqi, length, mac[125];
    bool ack_started, ack_completed, deadline_miss;
    /* Which configuration classified this frame, and to what. */
    uint32_t config_generation;
    dual_match_t match;
    dual_header_t header;
    /* Hardware captures. time_us above is the CRCOK capture; these three are
     * the ACK sequence, each with its own validity because a frame that is not
     * ACKed has none of them. */
    bool ack_address_valid, ack_start_valid, ack_end_valid;
    uint32_t ack_address_us, ack_start_us, ack_end_us;
} gate_event_t;

/* Per-frame classification as recorded, counted on the complete frame.
 * This is deliberately not the same as dual_stats_t in dual_context.c, which
 * counts admission decisions taken during BCC on a partial header and the
 * reasons an ACK was suppressed. One says what arrived, the other says what was
 * answered. */
typedef struct {
    uint32_t rx_total, ctx0_match, ctx1_match, foreign_reject, cross_pair_reject,
             malformed_reject, unsupported_reject, broadcast, ambiguous_reject,
             ack_requested, ack_started, ack_completed, ack_deadline_miss,
             rx_drop, crc_error;
} gate_stats_t;

void gate_hw_init(void);
void gate_hw_session(const commission_t *s);
/* Publishes the configuration generation stamped onto subsequent records. */
void gate_hw_config_generation(uint32_t generation);
uint32_t gate_hw_now_us(void);
uint32_t gate_hw_revision(void);
uint32_t gate_hw_dropped(void);
uint32_t gate_hw_crc_errors(void);
typedef struct {uint32_t count,first_us,last_us;} gate_crc_t;
gate_crc_t gate_hw_crc_snapshot(void);
void gate_hw_stats(gate_stats_t *out);
/* Caller masks RADIO IRQ while testing this cutoff and committing verdict. */
bool gate_hw_cutoff_drained(uint32_t deadline);
void gate_hw_rx_begin(const uint8_t *raw);
void gate_hw_ack_started(void);
void gate_hw_ack_completed(void);
void gate_hw_deadline_miss(void);
void gate_hw_receive(uint8_t *raw,int8_t rssi,uint8_t lqi);
bool gate_hw_pop(gate_event_t *out);
void gate_hw_crc_error(void);
/* The V25 single-context admission predicate. The patched driver hook now calls
 * dual_admit_part instead; these remain because the inherited host-test
 * harnesses link assoc_filter.c, and the linker drops the unused code from the
 * image. */
void assoc_filter_bind(const commission_t *s);
int assoc_filter_part(const uint8_t *raw,uint8_t *received);
#endif
