#ifndef ASSOC_H
#define ASSOC_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define ASSOC_COMMAND_MAX 1024u
#define ASSOC_LINE_MAX 1152u
#define ASSOC_RESPONSE_LENGTH 25u
/* Ten existing 320us unit-backoff periods; ONLY after first poll CCA failure. */
#define ASSOC_CCA_RECOVERY_US 3200u
typedef enum { A_IDLE,A_TARGET_SELECTED,A_REQUEST_SENT,A_WAIT_RESPONSE,A_ASSOCIATED,A_REJECTED,A_TIMEOUT,A_UNCERTAIN,A_CANCELLED,A_ERROR } assoc_state_t;
typedef enum { ATX_OK,ATX_NO_ACK,ATX_CCA_FAIL,ATX_INVALID_ACK,ATX_ABORTED,ATX_ERROR } assoc_tx_result_t;
typedef enum { TX_NONE,TX_REQUEST,TX_POLL } assoc_tx_kind_t;
typedef struct { uint16_t pan,coordinator_short;uint8_t raw_ieee[8],coordinator_ieee[8],extpan[8],ctx,dsn,capability;uint32_t max_polls,poll_interval_ms,timeout_ms; } assoc_target_t;
typedef struct { uint16_t pan,source_short;uint8_t extpan[8],dsn;bool permit,coordinator,end_capacity,router_capacity; } assoc_beacon_t;
typedef struct { uint8_t status,dsn,coordinator[8];uint16_t short_address;uint32_t rx_revision; } assoc_result_t;
typedef struct {
    assoc_state_t state;assoc_target_t target;uint32_t session,attempt_floor,start_us,last_poll_us,polls;
    bool request_once,local_ok,response_seen,tx_pending,poll_cca_retry;assoc_tx_kind_t tx_kind;assoc_result_t result;
} assoc_t;
bool assoc_ieee_valid(const uint8_t ieee[8]);
bool assoc_target_valid(const assoc_target_t *t);
size_t assoc_build_request(const assoc_target_t *t,uint32_t dsn,uint8_t *out,size_t capacity);
size_t assoc_build_poll(const assoc_target_t *t,uint32_t dsn,uint8_t *out,size_t capacity);
bool assoc_beacon_parse(const uint8_t *mac,size_t length,assoc_beacon_t *out);
bool assoc_response_parse(const uint8_t *mac,size_t length,const assoc_target_t *t,uint32_t revision,uint32_t attempt_floor,assoc_result_t *out);
void assoc_init(assoc_t *s);
const char *assoc_begin(assoc_t *s,const assoc_target_t *t,uint32_t session);
const char *assoc_request(assoc_t *s,uint32_t now_us,uint32_t revision,uint8_t *out,size_t capacity,size_t *length);
const char *assoc_poll(assoc_t *s,uint32_t now_us,uint8_t *out,size_t capacity,size_t *length);
void assoc_local_done(assoc_t *s,assoc_tx_result_t result);
bool assoc_observe(assoc_t *s,const uint8_t *mac,size_t length,uint32_t revision);
void assoc_tick(assoc_t *s,uint32_t now_us);
void assoc_cancel(assoc_t *s);
bool assoc_active(const assoc_t *s);
const char *assoc_state_name(assoc_state_t s);
const char *assoc_tx_name(assoc_tx_result_t r);
typedef enum { C_INFO,C_BEGIN,C_BEGIN_PERMIT,C_REQUEST,C_POLL,C_STATUS,C_END } assoc_command_kind_t;
typedef struct { assoc_command_kind_t kind;uint32_t id,session,beacon_revision;char boot[33],attempt[33];assoc_target_t target;bool local_policy;uint32_t permit_revision,validation_generation;uint8_t raw_hash[32]; } assoc_command_t;
const char *assoc_command_parse(const char *input,assoc_command_t *out);
#endif
