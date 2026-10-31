#ifndef MANAGEMENT_H
#define MANAGEMENT_H
#include "commission.h"
#include "radio_wire.h"
#define SCAN_US 261120u
#define RESPONSE_US 491520u
/* Session and poll budgets. V25 allowed one context 360 s and 400 polls, which
 * cannot hold a dual soak: the observed readiness cadence is one poll per
 * second per context, so an hour with both contexts live needs about 3600 polls
 * each. The bounds below are per context and leave headroom for the bounded
 * management traffic that precedes readiness. */
#define SESSION_LIMIT_US 0u /* continuous; recovery windows stay bounded */
#define MAX_TOTAL_POLLS_PER_CONTEXT UINT32_MAX
/* V27: a MAC data request carries no frame counter and no security state, so a
 * clean miss (no ACK, a corrupted ACK, a busy channel) is retried by the next
 * poll instead of ending the context. Only this many in a row end it. Secured
 * frames keep V26's rule: their first failure ends the context. */
#define MAX_CONSECUTIVE_POLL_MISSES 3u
/* V28: a rejoin-chain frame (REJOIN, ANNOUNCE, TIMEOUT) that went on air and
 * drew no ACK, or a bad one, is sent again as it is -- the same bytes, the
 * same DSN, the same frame counter -- up to this many more times before the
 * context sees a failure. It is 802.15.4's macMaxFrameRetries (default 3).
 * A parent that took the first copy and lost only its ACK drops the copy as
 * a duplicate, so nothing is spent twice. Polls keep V27's rule, and TYPE07
 * stays single-shot. A retry is attempted only inside TX_RETRY_WINDOW_US of
 * the host's intent, and the whole frame stays inside TX_INTENT_LIMIT_US, the
 * loosest watchdog V27 had, so the scheduler's backstop still never fires. */
#define MAC_MAX_FRAME_RETRIES 3u
#define TX_RETRY_WINDOW_US 250000u
#define TX_INTENT_LIMIT_US 2000000u
/* M_STATS is appended rather than inserted: the verbs[] table in
 * rejoin_transport.c is indexed by this enum, so an insertion would silently
 * renumber every verb after it. */
typedef enum {M_INFO,M_BIND,M_BEACON,M_DISCOVERY_COMMIT,M_REJOIN,M_SHORT_COMMIT,M_ANNOUNCE,M_TIMEOUT,M_ACTIVE,M_POLL,M_STATUS,M_END,M_APP,M_STATS} management_kind_t;
#define MANAGEMENT_VERB_COUNT 14
typedef struct {management_kind_t kind;uint32_t id,session,generation,fc,dsn,revision,short_address,ctx;bool has_ctx;size_t mac_length;char boot[33],epoch[33],attempt[33],guard[33];uint8_t hash[32],mac[68];} management_command_t;
const char *management_parse(const char *,management_command_t *);
const char *management_resume(commission_t *,const management_command_t *,uint32_t);
const char *management_tx(commission_t *,const management_command_t *,uint32_t,uint8_t *,size_t *);
const char *management_control(commission_t *,const management_command_t *,uint32_t);
void management_done(commission_t *,bool,bool,unsigned,uint32_t);
bool management_auto_poll(commission_t *,uint32_t,uint8_t[10]);
bool management_beacon(const commission_t *,const uint8_t *,size_t);
void management_observe(commission_t *,const uint8_t *,size_t,uint32_t,uint32_t,bool);
const char *recovery_name(recovery_phase_t);
const char *management_class(unsigned);
void management_tick(commission_t *,uint32_t);
#endif
