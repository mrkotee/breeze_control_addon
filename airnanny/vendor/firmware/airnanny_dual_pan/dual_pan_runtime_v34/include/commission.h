#ifndef COMMISSION_H
#define COMMISSION_H
#include "assoc.h"
#include "key_gate.h"
#include "permit_binding.h"
typedef enum {G_IDLE,G_BASELINE,G_ARMED,G_ASSOC,G_WAIT_KEY,G_KEY,G_ANNOUNCE_UNCERTAIN,G_MANAGEMENT,G_STOPPED} commission_phase_t;
typedef enum {GC_INFO,GC_BASELINE,GC_ARM,GC_ASSOC,GC_COMMIT,GC_POLL,GC_KEY,GC_ANNOUNCE,GC_STATUS,GC_END} commission_kind_t;
typedef struct {commission_kind_t kind;assoc_command_t association;key_command_t key;uint32_t id,session,baseline_revision;char boot[33],attempt[33];uint8_t raw[8],tc[8];uint16_t short_address,pan;} commission_command_t;
typedef enum {R_IDLE,R_BOUND,R_SCANNING,R_DISCOVERED,R_PREPARED,R_WAIT_REJOIN,R_REJOINED,R_ANNOUNCED,R_WAIT_TIMEOUT,R_ACTIVE,R_STOPPED} recovery_phase_t;
typedef struct {recovery_phase_t phase;uint32_t start_us,tx_end_us,deadline_us,request_id,scan_floor,beacon_revision,beacon_time,response_revision,response_time,poll_due,polls,total_polls;uint8_t beacon_hash[32],poll_dsn;bool window,pending,scan_once,rejoin_once,announce_once,timeout_once,application_once,application_ready,deadline_valid;uint32_t last_fc,last_idle_poll,scan_attempts,poll_misses,poll_misses_total;char guard[33];bool restartable;} recovery_transport_t;
typedef struct {assoc_t association;key_gate_t keys;commission_phase_t phase;uint32_t generation,baseline_revision,arm_floor;char attempt[33];bool response_ack_clean;recovery_transport_t recovery;} commission_t;
const char *commission_parse(const char *,commission_command_t *);
const char *commission_baseline(commission_t *,const commission_command_t *,uint32_t);
const char *commission_arm(commission_t *,const commission_command_t *,uint32_t);
const char *commission_begin(commission_t *,const assoc_command_t *);
bool commission_observe(commission_t *,const uint8_t *,size_t,uint32_t,bool);
const char *commission_commit(commission_t *,const commission_command_t *,uint32_t);
const char *commission_key(commission_t *,const commission_command_t *);
const char *commission_poll(commission_t *,const commission_command_t *,uint32_t,uint8_t[10]);
const char *commission_announce(commission_t *,const commission_command_t *,uint32_t,uint8_t[55]);
void commission_done(commission_t *,unsigned,assoc_tx_result_t);
void commission_stop(commission_t *);
const char *commission_name(commission_phase_t);
#endif
