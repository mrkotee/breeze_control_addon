#ifndef KEY_GATE_H
#define KEY_GATE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "assoc.h"
typedef enum {K_IDLE,K_UNKEYED,K_INSTALLED,K_QUEUED,K_MANAGEMENT,K_UNCERTAIN,K_STOPPED} key_state_t;
typedef enum {KC_INFO,KC_BIND,KC_POLL,KC_KEY,KC_ANNOUNCE,KC_STATUS,KC_END} key_kind_t;
typedef struct {key_kind_t kind;uint32_t id,generation,max_polls,interval,timeout,fc,intent;uint16_t pan,short_address;uint8_t ctx,dsn,keyseq,raw[8],tc[8],extpan[8],hash[32],mac[55];char boot[33],epoch[33],attempt[33];} key_command_t;
typedef struct {key_state_t state;uint32_t session,generation,start_us,last_poll_us,polls,max_polls,interval,timeout,fc,intent;bool pending,used;uint16_t pan,short_address;uint8_t ctx,raw[8],tc[8],extpan[8],keyseq;char epoch[33],attempt[33];} key_gate_t;
void permit_hash(const uint8_t *,size_t,uint8_t[32]);
const char *key_parse(const char *,key_command_t *);
const char *key_bind(key_gate_t *,const key_command_t *,uint32_t);
const char *key_poll(key_gate_t *,const key_command_t *,uint32_t,uint8_t[10]);
const char *key_installed(key_gate_t *,const key_command_t *);
const char *key_announce(key_gate_t *,const key_command_t *,uint32_t,uint8_t[55]);
void key_done(key_gate_t *,bool,bool);
const char *key_name(key_state_t);
const char *assoc_tx_name(assoc_tx_result_t);
#endif
