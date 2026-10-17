/* SHA256 is only a public raw-record identifier. No Zigbee keys/MIC/AES here. */
#include "permit_binding.h"
#include <string.h>
static uint32_t rotr(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
void permit_hash(const uint8_t *data,size_t n,uint8_t out[32])
{
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t blocks=(n+9+63)/64;
    for(size_t block=0;block<blocks;block++){
        uint8_t bytes[64]={0};for(unsigned i=0;i<64;i++){size_t j=block*64+i;if(j<n)bytes[i]=data[j];else if(j==n)bytes[i]=0x80;}
        if(block==blocks-1){uint64_t bits=(uint64_t)n*8;for(unsigned i=0;i<8;i++)bytes[63-i]=(uint8_t)(bits>>(8*i));}
        uint32_t w[64];for(unsigned i=0;i<16;i++)w[i]=(uint32_t)bytes[i*4]<<24|(uint32_t)bytes[i*4+1]<<16|(uint32_t)bytes[i*4+2]<<8|bytes[i*4+3];
        for(unsigned i=16;i<64;i++){uint32_t x=w[i-15],y=w[i-2];w[i]=w[i-16]+(rotr(x,7)^rotr(x,18)^(x>>3))+w[i-7]+(rotr(y,17)^rotr(y,19)^(y>>10));}
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7];
        for(unsigned i=0;i<64;i++){uint32_t t=z+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+K[i]+w[i];uint32_t u=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));z=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;
    }
    for(unsigned i=0;i<32;i++)out[i]=(uint8_t)(h[i/4]>>(24-8*(i%4)));
}
static uint16_t le(const uint8_t *p){return p[0]|(uint16_t)p[1]<<8;}
static bool outer(const uint8_t *m,size_t n)
{return n==46 && le(m)==0x8841 && le(m+5)==0xffff && le(m+7)==0 && le(m+9)==0x0208 && le(m+11)==0xfffc && le(m+13)==0 && m[17]==0x28;}
void permit_cache_clear(permit_cache_t *c){memset(c,0,sizeof(*c));}
void permit_cache_observe(permit_cache_t *c,const uint8_t *m,size_t n,uint32_t revision,uint32_t now)
{
    if(!revision || !outer(m,n))return;
    for(unsigned i=0;i<PERMIT_CACHE_SIZE;i++)if(c->records[i].valid && c->records[i].revision==revision)return;
    permit_record_t *r=&c->records[c->next++%PERMIT_CACHE_SIZE];memset(r,0,sizeof(*r));r->valid=true;r->revision=revision;r->time_us=now;r->length=(uint8_t)n;memcpy(r->mac,m,n);permit_hash(m,n,r->hash);
}
static permit_record_t *find(permit_cache_t *c,uint32_t revision)
{for(unsigned i=0;i<PERMIT_CACHE_SIZE;i++)if(c->records[i].valid && c->records[i].revision==revision)return &c->records[i];return NULL;}
static const char *record_check(const permit_record_t *r,const assoc_target_t *t,uint32_t now)
{
    if(!r)return "permit_revision_missing";
    if((uint32_t)(now-r->time_us)>10000000)return "permit_evidence_stale";
    /* Narrow V1 context: only ctx0/FA9B; beacon admission retains V3 contexts. */
    if(t->ctx!=0 || t->pan!=0xfa9b || t->pan!=le(r->mac+3) || t->coordinator_short || memcmp(t->coordinator_ieee,r->mac+22,8) || memcmp(t->extpan,t->coordinator_ieee,8))return "permit_target_mismatch";
    return NULL;
}
const char *permit_binding_check(permit_cache_t *c,const assoc_target_t *t,uint32_t revision,const uint8_t hash[32],uint32_t generation,uint32_t now,bool consume)
{
    permit_record_t *r=find(c,revision);const char *error=record_check(r,t,now);if(error)return error;
    if(memcmp(r->hash,hash,32))return "permit_hash_mismatch";
    if(r->used)return "permit_evidence_used";
    if(!generation || generation<=c->last_generation)return "permit_generation_reused";
    if(consume){r->used=true;c->last_generation=generation;}return NULL;
}
const char *permit_binding_recheck(permit_cache_t *c,const assoc_target_t *t,uint32_t revision,uint32_t now)
{permit_record_t *r=find(c,revision);const char *error=record_check(r,t,now);if(error)return error;return r->used?NULL:"permit_evidence_not_reserved";}
