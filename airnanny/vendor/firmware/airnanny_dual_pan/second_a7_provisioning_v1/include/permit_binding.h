#ifndef PERMIT_BINDING_H
#define PERMIT_BINDING_H
#include "assoc.h"
#define PERMIT_CACHE_SIZE 8u
typedef struct {bool valid,used;uint32_t revision,time_us;uint8_t length,mac[125],hash[32];} permit_record_t;
typedef struct {permit_record_t records[PERMIT_CACHE_SIZE];uint32_t next,last_generation;} permit_cache_t;
void permit_hash(const uint8_t *data,size_t n,uint8_t out[32]);
void permit_cache_clear(permit_cache_t *c);
void permit_cache_observe(permit_cache_t *c,const uint8_t *m,size_t n,uint32_t revision,uint32_t now);
const char *permit_binding_check(permit_cache_t *c,const assoc_target_t *t,uint32_t revision,const uint8_t hash[32],uint32_t generation,uint32_t now,bool consume);
const char *permit_binding_recheck(permit_cache_t *c,const assoc_target_t *t,uint32_t revision,uint32_t now);
#endif
