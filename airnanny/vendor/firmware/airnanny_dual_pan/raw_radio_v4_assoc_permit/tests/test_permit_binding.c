#include "permit_binding.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"permit failed %d: %s\n",__LINE__,#x);exit(1);}}while(0)
int main(void)
{
    uint8_t raw[]={0x41,0x88,0x07,0x9b,0xfa,0xff,0xff,0,0,0x08,0x02,0xfc,0xff,0,0,0x3c,0xb4,0x28,0x38,0x12,0x1f,0,0xe5,0x48,0xa1,0x36,0,0x4b,0x12,0,0,0xec,0xca,0xd0,0x24,0xa6,0x16,0x7c,0xb4,0x52,0,0x2e,0x5d,0x27,0x54,0x91};
    permit_cache_t c;permit_cache_clear(&c);uint8_t hash[32];
    const uint8_t abc[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    permit_hash((const uint8_t *)"abc",3,hash);CHECK(!memcmp(hash,abc,32));
    const uint8_t expected_raw[32]={0x80,0xb7,0x61,0x55,0xd5,0x86,0x81,0xe8,0x59,0xa9,0x18,0x59,0x29,0x00,0x65,0x2c,0x36,0xbb,0x96,0xb8,0x05,0x91,0x0d,0xbc,0x5e,0xd8,0x57,0x78,0x29,0x1e,0xa6,0x8d}; permit_hash(raw,sizeof(raw),hash);CHECK(!memcmp(hash,expected_raw,32));
    uint8_t long_raw[125];for(unsigned i=0;i<125;i++)long_raw[i]=(uint8_t)i;const uint8_t expected_long[32]={0x3d,0xaa,0x58,0x2f,0x95,0x63,0x60,0x1e,0x29,0x0f,0x3c,0xd6,0xd3,0x04,0xbf,0xf7,0xe2,0x5a,0x9e,0xe4,0x2a,0x34,0xff,0xba,0xc5,0xcf,0x2b,0xf4,0x01,0x34,0xe0,0xd4};permit_hash(long_raw,125,hash);CHECK(!memcmp(hash,expected_long,32));
    assoc_target_t t={.pan=0xfa9b,.ctx=0};memcpy(t.coordinator_ieee,raw+22,8);memcpy(t.extpan,t.coordinator_ieee,8);
    permit_cache_observe(&c,raw,sizeof(raw),655,1000);permit_hash(raw,sizeof(raw),hash);
    CHECK(c.records[0].valid);CHECK(!permit_binding_check(&c,&t,655,hash,1,1001,false));
    uint8_t wrong[32];memcpy(wrong,hash,32);wrong[0]^=1;
    CHECK(permit_binding_check(&c,&t,655,wrong,1,1001,false));CHECK(permit_binding_check(&c,&t,656,hash,1,1001,false));
    CHECK(permit_binding_check(&c,&t,655,hash,1,10001001,false));
    t.ctx=1;CHECK(permit_binding_check(&c,&t,655,hash,1,1001,false));t.ctx=0;
    t.pan=0x0b7a;CHECK(permit_binding_check(&c,&t,655,hash,1,1001,false));t.pan=0xfa9b;
    t.coordinator_ieee[0]^=1;CHECK(permit_binding_check(&c,&t,655,hash,1,1001,false));t.coordinator_ieee[0]^=1;
    CHECK(!permit_binding_check(&c,&t,655,hash,1,1001,true));CHECK(permit_binding_check(&c,&t,655,hash,2,1001,true));
    CHECK(!permit_binding_recheck(&c,&t,655,1001));CHECK(permit_binding_recheck(&c,&t,655,10001001));
    permit_cache_observe(&c,raw,sizeof(raw),656,1100);CHECK(permit_binding_check(&c,&t,656,hash,1,1101,false));
    CHECK(permit_binding_check(&c,&t,656,hash,0,1101,false));CHECK(!permit_binding_check(&c,&t,656,hash,2,1101,true));
    uint8_t bad[46];memcpy(bad,raw,46);bad[13]=1;permit_cache_observe(&c,bad,46,657,1100);CHECK(permit_binding_check(&c,&t,657,hash,3,1101,false));
    permit_cache_clear(&c);CHECK(permit_binding_check(&c,&t,655,hash,2,1001,false));
    puts("PERMIT binding PASS");printf("PERMIT checks=%u PASS\n",checks);return 0;
}
