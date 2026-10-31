/* Offline native tests for RADIOV10 command parsing and record formatting.
 * No COM, no RF, no cryptography, no keys.
 */
#include "dual_records.h"
#include <stdio.h>
#include <string.h>

static int failures, checks;
static void ok(int cond, const char *what)
{
    checks++;
    if (!cond) { failures++; printf("FAIL %s\n", what); }
}

static const char *parse(const char *line, dual_cmd_t *c)
{ return dual_cmd_parse(line, c); }

static void refuses(const char *line, const char *expect)
{
    dual_cmd_t c;
    const char *r = parse(line, &c);
    checks++;
    if (!r || strcmp(r, expect)) {
        failures++;
        printf("FAIL expected %s, got %s for: %s\n", expect, r ? r : "(accepted)", line);
    }
}

#define GOOD_CONFIG "RADIOV10 CONFIG id=7 generation=4 channel=21 " \
    "ctx0_enabled=1 ctx0_pan=fa9b ctx0_short=a326 ctx0_ieee=e2b0275f4d582069 " \
    "ctx1_enabled=1 ctx1_pan=0b7a ctx1_short=6c55 ctx1_ieee=027a56bb75a41437"

#define GOOD_BIND "RADIOV10 BIND id=8 ctx=1 pan=0b7a short=6c55 " \
    "raw_ieee=027a56bb75a41437 tc_ieee=00124b0036a1875f extpan=00124b0036a1875f " \
    "coordinator_short=0000 keyseq=0 generation=16 attempt=cbef428849da4e87b48867ac616247d1 " \
    "max_polls=2 poll_interval_ms=1000 timeout_ms=30000"

static void test_envelope(void)
{
    dual_cmd_t c;
    refuses("", "line_length");
    refuses(RADIO_PREFIX_LINEAGE " INFO id=1", "prefix");
    refuses("RADIOV10", "prefix");
    refuses("RADIOV10 NOPE id=1", "unknown_command");
    refuses("RADIOV10 INFO", "id_missing");
    refuses("RADIOV10 INFO id=1 ", "trailing_space");
    refuses("RADIOV10 INFO id=1 bogus", "field_syntax");
    refuses("RADIOV10 INFO id=1 bogus=", "empty_value");
    refuses("RADIOV10 INFO id=1 unknown=2", "unknown_field");
    refuses("RADIOV10 INFO id=1 id=2", "duplicate_field");
    refuses("RADIOV10 INFO id=abc", "id_invalid");
    ok(parse("RADIOV10 INFO id=1", &c) == NULL && c.kind == CMD_INFO, "INFO accepted");
    ok(parse("RADIOV10 STATS id=2", &c) == NULL && c.kind == CMD_STATS, "STATS accepted");
    ok(parse("RADIOV10 END id=3", &c) == NULL && c.kind == CMD_END, "END accepted");

    /* Non-ASCII must be refused before anything is interpreted. */
    char dirty[64];
    snprintf(dirty, sizeof dirty, "RADIOV10 INFO id=1");
    dirty[10] = (char)0x80;
    refuses(dirty, "non_ascii");
}

static void test_context_field(void)
{
    refuses("RADIOV10 ACK id=1 enabled=1", "ctx_missing");
    refuses("RADIOV10 ACK id=1 ctx=2 enabled=1", "ctx_invalid");
    refuses("RADIOV10 ACK id=1 ctx=9 enabled=1", "ctx_invalid");
    /* A session-wide record must not carry a context at all. */
    refuses("RADIOV10 INFO id=1 ctx=0", "ctx_not_allowed");
    refuses("RADIOV10 STATS id=1 ctx=1", "ctx_not_allowed");
    dual_cmd_t c;
    ok(parse("RADIOV10 ACK id=1 ctx=0 enabled=1", &c) == NULL && c.has_ctx && c.ctx == 0 && c.enabled,
       "ACK on ctx0 accepted");
    ok(parse("RADIOV10 ACK id=2 ctx=1 enabled=0", &c) == NULL && c.ctx == 1 && !c.enabled,
       "ACK disable on ctx1 accepted");
    ok(parse("RADIOV10 SCAN id=3 ctx=1 enabled=1", &c) == NULL && c.kind == CMD_SCAN && c.enabled,
       "SCAN on ctx1 accepted");
    refuses("RADIOV10 ACK id=1 ctx=0 enabled=2", "enabled_invalid");
}

static void test_config(void)
{
    dual_cmd_t c;
    ok(parse(GOOD_CONFIG, &c) == NULL, "well formed CONFIG accepted");
    ok(c.generation == 4 && c.channel == 21, "generation and channel parsed");
    ok(c.ctx_enabled[0] && c.pan[0] == 0xfa9b && c.shortaddr[0] == 0xa326, "ctx0 tuple parsed");
    ok(c.ctx_enabled[1] && c.pan[1] == 0x0b7a && c.shortaddr[1] == 0x6c55, "ctx1 tuple parsed");
    ok(c.ieee[1][0] == 0x02 && c.ieee[1][7] == 0x37, "ctx1 IEEE parsed big endian as written");

    refuses("RADIOV10 CONFIG id=1 channel=21 ctx0_enabled=1 ctx0_pan=fa9b ctx0_short=a326", "generation_missing");
    refuses("RADIOV10 CONFIG id=1 generation=0 ctx0_enabled=1 ctx0_pan=fa9b ctx0_short=a326", "generation_invalid");
    refuses("RADIOV10 CONFIG id=1 generation=2 channel=15 ctx0_enabled=1 ctx0_pan=fa9b ctx0_short=a326", "channel_invalid");
    refuses("RADIOV10 CONFIG id=1 generation=2 ctx0_enabled=0 ctx1_enabled=0", "no_context_enabled");
    refuses("RADIOV10 CONFIG id=1 generation=2 ctx0_enabled=1 ctx0_pan=ffff ctx0_short=a326", "ctx_pan_invalid");
    refuses("RADIOV10 CONFIG id=1 generation=2 ctx0_enabled=1 ctx0_pan=fa9b ctx0_short=fffe", "ctx_short_invalid");
    refuses("RADIOV10 CONFIG id=1 generation=2 ctx0_enabled=1 ctx0_pan=fa9b ctx0_short=a326"
            " ctx1_enabled=1 ctx1_pan=fa9b ctx1_short=a326", "identical_tuple");
    /* Same short under different PAN stays legitimate. */
    ok(parse("RADIOV10 CONFIG id=1 generation=2 ctx0_enabled=1 ctx0_pan=fa9b ctx0_short=a326"
             " ctx1_enabled=1 ctx1_pan=0b7a ctx1_short=a326", &c) == NULL,
       "same short under different PAN accepted");
    refuses("RADIOV10 CONFIG id=1 generation=2 ctx0_enabled=1 ctx0_pan=fa9 ctx0_short=a326", "ctx_pan_invalid");
    refuses("RADIOV10 CONFIG id=1 generation=2 ctx0_enabled=1 ctx0_pan=FA9B ctx0_short=a326", "ctx_pan_invalid");
    refuses("RADIOV10 CONFIG id=1 generation=2 ctx0_enabled=1 ctx0_pan=fa9b ctx0_short=a326 ctx0_bogus=1", "unknown_field");
    refuses("RADIOV10 CONFIG id=1 generation=2 ctx2_enabled=1", "unknown_field");
}

static void test_bind(void)
{
    dual_cmd_t c;
    ok(parse(GOOD_BIND, &c) == NULL, "well formed BIND accepted");
    ok(c.ctx == 1 && c.bind_pan == 0x0b7a && c.bind_short == 0x6c55, "bind tuple parsed");
    ok(c.keyseq == 0 && c.bind_generation == 16, "keyseq and generation parsed");
    ok(!strcmp(c.attempt, "cbef428849da4e87b48867ac616247d1"), "attempt parsed");
    ok(c.max_polls == 2 && c.poll_interval_ms == 1000 && c.timeout_ms == 30000, "poll policy parsed");

    refuses("RADIOV10 BIND id=1 pan=0b7a short=6c55 raw_ieee=027a56bb75a41437"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0000"
            " keyseq=0 generation=1 attempt=a max_polls=2 poll_interval_ms=1000 timeout_ms=30000",
            "ctx_missing");
    /* RAW identity and trust centre identity must differ. */
    refuses("RADIOV10 BIND id=1 ctx=1 pan=0b7a short=6c55 raw_ieee=00124b0036a1875f"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0000"
            " keyseq=0 generation=1 attempt=a max_polls=2 poll_interval_ms=1000 timeout_ms=30000",
            "identity_collision");
    /* extPAN equals the trust centre identity, as key_gate enforced in V25. */
    refuses("RADIOV10 BIND id=1 ctx=1 pan=0b7a short=6c55 raw_ieee=027a56bb75a41437"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a148e5 coordinator_short=0000"
            " keyseq=0 generation=1 attempt=a max_polls=2 poll_interval_ms=1000 timeout_ms=30000",
            "extpan_mismatch");
    refuses("RADIOV10 BIND id=1 ctx=1 pan=0b7a short=fff8 raw_ieee=027a56bb75a41437"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0000"
            " keyseq=0 generation=1 attempt=a max_polls=2 poll_interval_ms=1000 timeout_ms=30000",
            "short_invalid");
    refuses("RADIOV10 BIND id=1 ctx=1 pan=0b7a short=6c55 raw_ieee=027a56bb75a41437"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0001"
            " keyseq=0 generation=1 attempt=a max_polls=2 poll_interval_ms=1000 timeout_ms=30000",
            "coordinator_short_invalid");
    refuses("RADIOV10 BIND id=1 ctx=1 pan=0b7a short=6c55 raw_ieee=027a56bb75a41437"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0000"
            " keyseq=0 generation=1 attempt=a max_polls=9 poll_interval_ms=1000 timeout_ms=30000",
            "poll_policy");
    refuses("RADIOV10 BIND id=1 ctx=1 pan=0b7a short=6c55 raw_ieee=027a56bb75a41437"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0000"
            " keyseq=0 generation=1 attempt=a max_polls=2 poll_interval_ms=99 timeout_ms=30000",
            "poll_policy");
    refuses("RADIOV10 BIND id=1 ctx=1 pan=0b7a short=6c55 raw_ieee=027a56bb75a41437"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0000"
            " keyseq=0 generation=1 attempt=a max_polls=2 poll_interval_ms=5000 timeout_ms=1000",
            "poll_policy");
    refuses("RADIOV10 BIND id=1 ctx=1 pan=0b7a short=6c55 raw_ieee=027a56bb"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0000"
            " keyseq=0 generation=1 attempt=a max_polls=2 poll_interval_ms=1000 timeout_ms=30000",
            "raw_ieee_invalid");
    refuses("RADIOV10 BIND id=1 ctx=1 pan=0b7a short=6c55 raw_ieee=027a56bb75a41437"
            " tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0000"
            " keyseq=0 generation=1 attempt=has-dash max_polls=2 poll_interval_ms=1000 timeout_ms=30000",
            "attempt_invalid");
}

static void test_tx(void)
{
    dual_cmd_t c;
    ok(parse("RADIOV10 TX id=9 ctx=0 class=APPLICATION cca=1 mac=61883d9bfa0000b7c9", &c) == NULL,
       "well formed TX accepted");
    ok(c.klass == TX_CLASS_APPLICATION && c.cca && c.mac_len == 9, "TX fields parsed");
    ok(c.mac[0] == 0x61 && c.mac[1] == 0x88 && c.mac[8] == 0xc9, "TX mac bytes parsed");
    ok(parse("RADIOV10 TX id=10 ctx=1 class=POLL cca=0 mac=61883d7a0b0000556c", &c) == NULL &&
       c.klass == TX_CLASS_POLL && !c.cca, "POLL class parsed");
    ok(parse("RADIOV10 TX id=11 ctx=1 class=MANAGEMENT cca=1 mac=61883d7a0b0000556c", &c) == NULL &&
       c.klass == TX_CLASS_MANAGEMENT, "MANAGEMENT class parsed");

    refuses("RADIOV10 TX id=1 class=POLL cca=1 mac=61883d9bfa0000b7c9", "ctx_missing");
    refuses("RADIOV10 TX id=1 ctx=0 class=NOPE cca=1 mac=61883d9bfa0000b7c9", "class_invalid");
    refuses("RADIOV10 TX id=1 ctx=0 class=POLL cca=1 mac=6188", "mac_invalid");
    refuses("RADIOV10 TX id=1 ctx=0 class=POLL cca=1 mac=61883d9bfa0000b7c", "mac_invalid");
    refuses("RADIOV10 TX id=1 ctx=0 class=POLL cca=2 mac=61883d9bfa0000b7c9", "cca_invalid");
    refuses("RADIOV10 TX id=1 ctx=0 class=POLL cca=1 mac=61883D9BFA0000B7C9", "mac_invalid");
}

static void test_formatting(void)
{
    char line[RADIO_LINE_MAX];
    dual_rx_record_t r; memset(&r, 0, sizeof r);
    r.rx_id = 283; r.config_generation = 4; r.match = MATCH_CTX1; r.reason = REASON_NONE;
    r.has_ctx = true; r.ctx = 1;
    r.rx_end_valid = true; r.rx_end_us = 1000;
    r.ack_address_valid = true; r.ack_address_us = 1010;
    r.ack_start_valid = true; r.ack_start_us = 1192;
    r.ack_end_valid = true; r.ack_end_us = 1256;
    r.ack_started = true; r.ack_completed = true; r.fcs_ok = true;
    r.rssi = -78; r.lqi = 52; r.mac_len = 3; r.mac[0] = 0x61; r.mac[1] = 0x88; r.mac[2] = 0x3d;
    ok(dual_format_rx(line, sizeof line, "abc123", &r), "RX formatted");
    ok(strstr(line, " ctx=1 ") != NULL, "RX carries its context");
    ok(strstr(line, "match=ctx1") != NULL, "RX carries the match");
    ok(strstr(line, "rx_end_us=1000") && strstr(line, "ack_start_us=1192") &&
       strstr(line, "ack_end_us=1256") && strstr(line, "ack_address_us=1010"),
       "RX carries four separate timestamps");
    ok(strstr(line, "rssi=-78") && strstr(line, "lqi=52"), "RX carries RSSI and LQI");
    ok(strstr(line, "mac=61883d") != NULL, "RX mac is lowercase hex");
    ok(line[strlen(line) - 1] == '\n', "RX record ends the line");

    /* A frame outside both contexts is tagged none, never 0 or 1. */
    r.has_ctx = false; r.match = MATCH_NONE; r.reason = REASON_CROSS_PAIR;
    ok(dual_format_rx(line, sizeof line, "abc123", &r), "foreign RX formatted");
    ok(strstr(line, " ctx=none ") != NULL, "foreign RX is not attributed to a context");
    ok(strstr(line, "reason=cross_pair") != NULL, "cross pair reason reported");

    /* Too small a buffer writes nothing rather than a partial record. */
    char small[32];
    memset(small, 'x', sizeof small);
    ok(!dual_format_rx(small, sizeof small, "abc123", &r), "small buffer refused");
    ok(small[0] == 'x', "nothing written into the small buffer");

    dual_tx_frame_t f; memset(&f, 0, sizeof f);
    f.ctx = 0; f.host_id = 1248; f.klass = TX_CLASS_APPLICATION; f.len = 3;
    f.mac[0] = 0x61; f.mac[1] = 0x88; f.mac[2] = 0x11;
    ok(dual_format_txaccept(line, sizeof line, "abc123", &f, 2), "TXACCEPT formatted");
    ok(strstr(line, "id=1248") && strstr(line, "ctx=0") &&
       strstr(line, "class=APPLICATION") && strstr(line, "queue_depth=2") &&
       strstr(line, "retry=0"), "TXACCEPT fields present");

    ok(dual_format_txdone(line, sizeof line, "abc123", 1248, 0, TX_RESULT_NO_ACK, true, 500, 900),
       "TXDONE formatted");
    ok(strstr(line, "result=no_ack") && strstr(line, "ctx=0") && strstr(line, "ack_requested=1"),
       "TXDONE fields present");
    ok(!dual_format_txdone(line, sizeof line, "abc123", 1, DUAL_CONTEXTS, TX_RESULT_OK, true, 0, 0),
       "TXDONE refuses an out of range context");

    dual_stats_t rx; memset(&rx, 0, sizeof rx);
    rx.rx_total = 500; rx.ctx0_match = 300; rx.ctx1_match = 180;
    rx.cross_pair_reject = 2; rx.foreign_reject = 18; rx.ack_suppressed_scanning = 1;
    dual_sched_stats_t tx; memset(&tx, 0, sizeof tx);
    tx.accepted[0] = 60; tx.accepted[1] = 58; tx.terminal[0] = 60; tx.terminal[1] = 58;
    tx.routing_error = 0; tx.starvation = 0;
    ok(dual_format_stats(line, sizeof line, "abc123", 77, 4, &rx, &tx, 5, 0), "STATS formatted");
    ok(strstr(line, " id=77 ") != NULL, "STATS carries the host id it was asked with");
    ok(strstr(line, " starved_polls=5 ") != NULL, "STATS carries the fairness counter");
    ok(strstr(line, " routing_faults=0\n") != NULL, "STATS ends with the routing fault count");
    ok(strstr(line, "ctx0_rx=300") && strstr(line, "ctx1_rx=180") &&
       strstr(line, "cross_pair_reject=2") && strstr(line, "routing_error=0") &&
       strstr(line, "scheduler_starvation=0") && strstr(line, "ack_suppressed_scanning=1"),
       "STATS carries the soak metrics");

    ok(dual_format_error(line, sizeof line, "abc123", true, 5, true, 1, "poll_policy"),
       "ERROR formatted with id and context");
    ok(strstr(line, "id=5") && strstr(line, "ctx=1") && strstr(line, "reason=poll_policy"),
       "ERROR fields present");
    ok(dual_format_error(line, sizeof line, "abc123", false, 0, false, 0, "prefix"),
       "ERROR formatted without id or context");
    ok(!strstr(line, "id=") && !strstr(line, "ctx="), "ERROR omits absent fields");
}

static void test_result_names(void)
{
    ok(!strcmp(dual_tx_result_name(TX_RESULT_OK), "ok"), "ok name");
    ok(!strcmp(dual_tx_result_name(TX_RESULT_NO_ACK), "no_ack"), "no_ack name");
    ok(!strcmp(dual_tx_result_name(TX_RESULT_INVALID_ACK), "invalid_ack"), "invalid_ack name");
    ok(!strcmp(dual_tx_result_name(TX_RESULT_CCA_FAIL), "cca_fail"), "cca_fail name");
    ok(!strcmp(dual_tx_result_name(TX_RESULT_ABORTED), "aborted"), "aborted name");
    ok(!strcmp(dual_match_name(MATCH_AMBIGUOUS), "ambiguous"), "ambiguous name");
    ok(!strcmp(dual_match_name(MATCH_BROADCAST), "broadcast"), "broadcast name");
    ok(!strcmp(dual_reason_name(REASON_FOREIGN), "foreign"), "foreign name");
}

int main(void)
{
    test_envelope();
    test_context_field();
    test_config();
    test_bind();
    test_tx();
    test_formatting();
    test_result_names();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
