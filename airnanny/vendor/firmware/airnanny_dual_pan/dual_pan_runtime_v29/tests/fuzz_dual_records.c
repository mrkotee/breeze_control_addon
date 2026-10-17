/* Mutation fuzz of the RADIOV10 command parser: mutated valid commands must
 * never crash and every accepted command must satisfy the contract invariants.
 * No COM, no RF, no keys. */
#include "dual_records.h"
#include <stdio.h>
#include <string.h>
static unsigned long s = 1234567891234567ull;
static unsigned long xr(void){ s^=s<<13; s^=s>>7; s^=s<<17; return s; }
static const char *seeds[] = {
 "RADIOV10 CONFIG id=7 generation=4 channel=21 ctx0_enabled=1 ctx0_pan=fa9b ctx0_short=a326 ctx0_ieee=e2b0275f4d582069 ctx1_enabled=1 ctx1_pan=0b7a ctx1_short=6c55 ctx1_ieee=027a56bb75a41437",
 "RADIOV10 BIND id=8 ctx=1 pan=0b7a short=6c55 raw_ieee=027a56bb75a41437 tc_ieee=00124b0036a1875f extpan=00124b0036a1875f coordinator_short=0000 keyseq=0 generation=16 attempt=cbef428849da4e87b48867ac616247d1 max_polls=2 poll_interval_ms=1000 timeout_ms=30000",
 "RADIOV10 TX id=9 ctx=0 class=APPLICATION cca=1 mac=61883d9bfa0000b7c9",
 "RADIOV10 ACK id=1 ctx=0 enabled=1",
 "RADIOV10 INFO id=1",
};
int main(void){
    char line[512]; dual_cmd_t c;
    unsigned long accepted=0, refused=0, bad=0;
    for (unsigned long i=0;i<300000;i++){
        const char *seed = seeds[xr()%(sizeof seeds/sizeof *seeds)];
        size_t n = strlen(seed);
        if (n >= sizeof line) continue;
        memcpy(line, seed, n+1);
        unsigned mutations = 1 + (unsigned)(xr()%3);
        for (unsigned m=0;m<mutations;m++){
            if (!n) break;
            size_t pos = xr()%n;
            unsigned mode = (unsigned)(xr()%3);
            if (mode==0) line[pos] = (char)(0x20 + (xr()%95));       /* printable */
            else if (mode==1) line[pos] = (char)(xr()%256);          /* any byte */
            else { line[pos] = '\0'; n = pos; }                      /* truncate */
        }
        const char *r = dual_cmd_parse(line, &c);
        if (r) { refused++; continue; }
        accepted++;
        /* Every accepted command must be self consistent. */
        if (c.kind==CMD_CONFIG){
            if (!c.generation) bad++;
            if (!c.ctx_enabled[0] && !c.ctx_enabled[1]) bad++;
            if (c.ctx_enabled[0] && c.ctx_enabled[1] && c.pan[0]==c.pan[1] && c.shortaddr[0]==c.shortaddr[1]) bad++;
            if (c.channel != 21) bad++;
        }
        if (c.kind==CMD_BIND){
            if (!c.has_ctx || c.ctx>=DUAL_CONTEXTS) bad++;
            if (!memcmp(c.raw,c.tc,8)) bad++;
            if (memcmp(c.tc,c.extpan,8)) bad++;
            if (c.coordinator_short) bad++;
        }
        if (c.kind==CMD_TX){
            if (!c.has_ctx || c.ctx>=DUAL_CONTEXTS) bad++;
            if (c.mac_len < 9 || c.mac_len > DUAL_TX_MAC_MAX) bad++;
        }
        if ((c.kind==CMD_ACK||c.kind==CMD_SCAN) && (!c.has_ctx || c.ctx>=DUAL_CONTEXTS)) bad++;
        if ((c.kind==CMD_INFO||c.kind==CMD_STATS||c.kind==CMD_STATUS||c.kind==CMD_END) && c.has_ctx) bad++;
    }
    printf("mutation fuzz iterations=300000 accepted=%lu refused=%lu invariant_violations=%lu\n",
           accepted, refused, bad);
    return bad ? 1 : 0;
}
