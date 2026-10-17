/* Offline harness. Frozen V17 headers are included read-only, never copied/edited. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airnanny_power.h"
#include "airnanny_night.h"
#include "airnanny_humidifier.h"
static air_safe_baseline_t b;
static air_sequence_t s;
static air_power_t p;
static air_night_confirmation_t n;
static unsigned kind, value;
static uint8_t tx[21], status[23];
static void unhex(const char *text,uint8_t *out,unsigned count) {
    unsigned i,v;for(i=0;i<count;i++){sscanf(text+2*i,"%2x",&v);out[i]=(uint8_t)v;}
}
static void show(int built) {
    unsigned i;
    printf("{\"built\":%d,\"tx\":\"",built);
    for(i=0;i<21;i++)printf("%02x",tx[i]);
    printf("\",\"confirmed\":%u,\"match\":%u,\"accepted\":%u,\"samples\":%u,\"failed\":%u,\"revision\":%u}\n",
        s.confirmed,s.match_valid,kind==5?p.accepted:kind==4?n.accepted:0,
        kind==5?p.samples:kind==4?n.stable_samples:0,kind==5?p.failed:0,s.rx.revision);
}
int main(void) {
    char op[16],basehex[43],statushex[47];unsigned now,gen,live,source,valid,pending;int result,ok=0;
    while(scanf("%15s",op)==1) {
        if(!strcmp(op,"BEGIN")) {
            if(scanf("%u%u%u%u%u%u%u%u%42s%46s",&kind,&value,&now,&gen,&live,&source,&valid,&pending,basehex,statushex)!=10)return 2;
            memset(&b,0,sizeof(b));memset(&s,0,sizeof(s));memset(&p,0,sizeof(p));memset(&n,0,sizeof(n));memset(tx,0,21);
            unhex(basehex,b.raw,21);unhex(statushex,status,23);
            b.valid=valid;b.live=live;b.source=source;b.generation=gen;b.remote_pending=pending;
            air_sequence_observe(&s,status[6],status[21]&1,status[15],status[16],(status[21]>>4)&1,now);
            switch(kind) {
                case 0:ok=air_fan_build(&b,&s.rx,value,tx);break;
                case 1:ok=air_mode_build(&b,&s.rx,value,tx);break;
                case 2:ok=air_temp_build(&b,&s,air_temp_word(status+13),value,now,tx);break;
                case 3:ok=air_humidifier_build(&b,&s,status,value,now,tx);break;
                case 4:ok=air_night_build(&b,&s,air_temp_word(status+13),value,now,tx);break;
                case 5:ok=air_power_build(&b,&s,status,value,now,tx);break;
                default:return 3;
            }
            if(ok) {
                air_sequence_begin(&s,tx,15,now);tx[6]=s.tx_seq_used;air_fan_checksum(tx);
                if(kind==2)air_temp_window(&s);
                if(kind==4)air_night_begin(&n,b.generation);
                if(kind==5)air_power_begin(&p,&s,&b,value);
            }
        } else if(!strcmp(op,"RX")) {
            if(scanf("%u%u%46s",&now,&gen,statushex)!=3)return 4;
            unhex(statushex,status,23);b.generation=gen;
            if(kind==5)air_power_observe(&p,&s,status,gen,now);
            else if(kind==4)air_night_observe(&n,&s,status,air_temp_word(b.raw+7),gen,now);
            else if(kind==3)air_humidifier_observe(&s,status,value,air_temp_word(b.raw+7),1,gen,now);
            else air_temp_observe(&s,status,kind==2,value,now);
        } else if(!strcmp(op,"COMPLETE")) {
            if(scanf("%u%u%d",&now,&gen,&result)!=3)return 5;
            if(kind==5)air_power_complete(&p,&s,result,gen,now);
            else if(kind==4)air_night_complete(&n,&s,result,gen,now);
            else if(kind==3)air_humidifier_complete(&s,result,1,gen,now);
            else air_sequence_complete(&s,result);
        } else return 6;
        show(ok);
    }
    return 0;
}
