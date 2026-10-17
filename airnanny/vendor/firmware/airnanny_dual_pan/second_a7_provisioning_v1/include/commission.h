#ifndef COMMISSION_H
#define COMMISSION_H
#include "assoc.h"
#include "key_gate.h"
#include "permit_binding.h"
typedef enum {G_IDLE,G_BASELINE,G_ARMED,G_ASSOC,G_WAIT_KEY,G_KEY,G_ANNOUNCE_UNCERTAIN,G_MANAGEMENT,G_STOPPED} commission_phase_t;
typedef enum {GC_INFO,GC_BASELINE,GC_ARM,GC_ASSOC,GC_COMMIT,GC_POLL,GC_KEY,GC_ANNOUNCE,GC_STATUS,GC_END} commission_kind_t;
typedef struct {commission_kind_t kind;assoc_command_t association;key_command_t key;uint32_t id,session,baseline_revision;char boot[33],attempt[33];uint8_t raw[8],tc[8];uint16_t short_address,pan;} commission_command_t;
typedef struct {assoc_t association;key_gate_t keys;commission_phase_t phase;uint32_t generation,baseline_revision,arm_floor;char attempt[33];bool response_ack_clean;} commission_t;
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
