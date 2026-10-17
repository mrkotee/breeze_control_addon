/* V28's one behavioural change: a rejoin-chain frame that went on air and
 * drew no ACK, or a bad one, is sent again as it is, up to
 * MAC_MAX_FRAME_RETRIES more times, before the context sees a failure.
 *
 * Why: Gate E attempts 1, 3, 4 and 5 on V27 each lost a context to one
 * secured chain frame (REJOIN twice, ANNOUNCE, TIMEOUT) that drew no ACK or a
 * corrupted one. V27 sent every chain frame exactly once, so a restart needs
 * twelve single-shot frames in a row without a loss, and on this channel that
 * mostly does not happen. 802.15.4 itself retries a frame up to three times.
 *
 * This drives the real src/main.c (through firmware_cli.c) with the fake
 * radio: the lifecycle, the CCA backoff and the watchdog are the image's own.
 * Polls and TYPE07 are pinned as unchanged. No COM, no RF, no flash. */
#include "radio_wire.h"
#define COMMISSION_UNIT_TEST
#include "firmware_cli.c"

static int failures, checks;
static void ok(int cond, const char *what)
{
    checks++;
    if (!cond) { failures++; printf("FAIL %s\n", what); }
}

static uint8_t sent_first[128];

static void reset(void)
{
    memset(sessions, 0, sizeof(sessions)); gate_hw_session(&sessions[0]); open = true;
    mock_inline = false; mock_preair = false; mock_backoff_random = 0; mock_transmits = 0;
    mock_rf_starts = 0; mock_time = 5000000u; busy = false; oh = ot = 0;
    has_id = false; last_id = 0;   /* each scenario is a fresh host session */
    strcpy(boot, "11111111111111111111111111111111");
    command(RADIO_PREFIX " BIND id=1 boot=11111111111111111111111111111111 session=1 generation=13 "
            "epoch=9985b15dcb574c59b87dc2fb379f317f attempt=cbef428849da4e87b48867ac616247d1 "
            "guard=22222222222222222222222222222222 short=27733 ctx=1");
    flush_output();
}

/* A frame queued as dispatch queues one, without the host's ledger: the bytes
 * do not matter to the lifecycle, only that they ask for an ACK. */
static void queue(unsigned kind)
{
    memset(&tx, 0, sizeof(tx));
    const uint8_t mac[] = {0x61, 0x88, 0x42, 0x7a, 0x0b, 0x00, 0x00, 0x55, 0x6c, 0x08, 0x02};
    tx.raw[0] = sizeof mac + 2; memcpy(tx.raw + 1, mac, sizeof mac);
    tx.id = 7; tx.session = 1; tx.ctx = 1; tx.kind = kind;
    tx.start_us = tx.intent_us = gate_hw_now_us(); tx.cca_be = 3; tx.state = OWNER_QUEUED;
    accepted_count++;
    tx_service(); flush_output();
    memcpy(sent_first, mock_sent, sizeof sent_first);
}

static void fail_ack(void)
{
    mock_dma = false; mock_ack_timer = false;
    nrf_802154_transmit_failed(tx.raw, NRF_802154_TX_ERROR_NO_ACK);
    tx_service(); flush_output();
}

static void corrupt_ack(void)
{
    uint8_t a[] = {5, 2, 0, (uint8_t)(tx.raw[3] + 1), 0, 0};
    mock_dma = false; mock_ack_timer = false;
    nrf_802154_transmitted_raw(tx.raw, a, 0, 0);
    tx_service(); flush_output();
}

static void good_ack(void)
{
    uint8_t a[] = {5, 2, 0, tx.raw[3], 0, 0};
    mock_dma = false; mock_ack_timer = false;
    nrf_802154_transmitted_raw(tx.raw, a, 0, 0);
    tx_service(); flush_output();
}

static int done(void) { return tx.terminal && tx.state == OWNER_FREE; }
static int has(const char *field) { return strstr(line, field) != NULL; }
static int stopped(void) { return sessions[1].phase == G_STOPPED; }

int main(void)
{
    if (!radio_power_configure()) return 9;

    /* One lost ACK, then an ACK: two transmissions of the same bytes, one TXDONE. */
    reset(); queue(M_ANNOUNCE);
    ok(mock_transmits == 1, "the first attempt is submitted");
    fail_ack();
    ok(mock_transmits == 2, "a no_ack on a chain frame is sent again");
    ok(!tx.terminal, "and the host has not been told anything yet");
    ok(!memcmp(sent_first, mock_sent, sent_first[0] + 1u),
       "the retry carries the same bytes: same DSN, same frame counter");
    good_ack();
    ok(done() && has("result=local_tx_ok") && has("mac_retries=1"),
       "the ACKed retry is one TXDONE, local_tx_ok, mac_retries=1");
    ok(!stopped(), "and the context is live");

    /* A corrupted ACK is a miss too. */
    reset(); queue(M_REJOIN); corrupt_ack();
    ok(mock_transmits == 2, "an invalid ACK on a chain frame is sent again");
    good_ack();
    ok(done() && has("result=local_tx_ok") && has("mac_retries=1"), "and then succeeds");

    /* TIMEOUT is in the chain as well. */
    reset(); queue(M_TIMEOUT); fail_ack(); fail_ack(); good_ack();
    ok(done() && mock_transmits == 3 && has("mac_retries=2"), "END_DEVICE_TIMEOUT is retried");

    /* Four misses in all: the context sees the failure, as V27 did on the first. */
    reset(); queue(M_ANNOUNCE);
    for (unsigned i = 0; i <= MAC_MAX_FRAME_RETRIES; i++) fail_ack();
    ok(mock_transmits == 1 + MAC_MAX_FRAME_RETRIES, "at most 1 + MAC_MAX_FRAME_RETRIES transmissions");
    ok(done() && has("result=no_ack") && has("mac_retries=3"),
       "the last miss is reported once, with the retries it took");
    ok(stopped(), "and still ends the context");

    /* Unchanged: a poll and TYPE07 stay single-shot. */
    const unsigned single[] = {M_POLL, M_APP};
    for (unsigned i = 0; i < 2; i++) {
        reset(); queue(single[i]); fail_ack();
        ok(mock_transmits == 1 && done() && has("mac_retries=0"),
           "a poll or TYPE07 miss is not retransmitted (V27's rules apply)");
    }

    /* A frame that never went on air is not "retried" here: CCA owns that. */
    reset(); mock_preair = true; queue(M_ANNOUNCE); fail_ack();
    ok(mock_transmits == 1 && done(), "no retry without a TX-start");
    mock_preair = false;

    /* The retry window is measured from the host's intent. */
    reset(); queue(M_ANNOUNCE); mock_time += TX_RETRY_WINDOW_US; fail_ack();
    ok(mock_transmits == 1 && done() && has("result=no_ack"), "no retry once the window has passed");

    /* END while a retry waits in backoff: aborted, never on air again. */
    reset(); queue(M_ANNOUNCE); mock_backoff_random = 31; fail_ack();
    ok(tx.state == OWNER_BACKOFF && mock_transmits == 1, "the retry waits in its backoff");
    command(RADIO_PREFIX " END id=2 boot=11111111111111111111111111111111 session=1"); tx_service(); flush_output();
    ok(done() && has("result=tx_end_abort") && mock_transmits == 1, "END aborts it with nothing more sent");

    /* The whole frame stays inside the intent limit, whatever the retries did
     * to start_us, so the scheduler's backstop never sees it. */
    reset(); queue(M_ANNOUNCE); mock_time += 100000u; fail_ack();
    ok(mock_transmits == 2 && tx.state == OWNER_RADIO, "a retry is on air");
    mock_time = tx.intent_us + TX_INTENT_LIMIT_US + 1u; tx_service(); flush_output();
    ok(done() && has("result=tx_watchdog_abort"), "the intent limit aborts a retry the radio never answered");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
