#include "key_gate.h"
#include <string.h>
#include <stdlib.h>
static uint16_t le16(const uint8_t *p){return p[0]|(uint16_t)p[1]<<8;}
static uint32_t le32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static bool nonzero(const uint8_t *p,size_t n){uint8_t a=0,b=255;for(size_t i=0;i<n;i++){a|=p[i];b&=p[i];}return a && b!=255;}
static bool hex(const char *s,uint8_t *out,size_t n,bool reverse){if(strlen(s)!=n*2)return false;for(size_t i=0;i<n;i++){unsigned v=0;for(unsigned j=0;j<2;j++){char c=s[i*2+j];unsigned d=c>='0'&&c<='9'?(unsigned)(c-'0'):c>='a'&&c<='f'?(unsigned)(c-'a'+10):16;if(d>15)return false;v=v*16+d;}out[reverse?n-1-i:i]=(uint8_t)v;}return true;}
static bool number(const char *s,uint32_t *out){if(!*s)return false;uint64_t v=0;for(;*s;s++){if(*s<'0'||*s>'9')return false;v=v*10+(*s-'0');if(v>UINT32_MAX)return false;}*out=(uint32_t)v;return true;}
const char *key_parse(const char *input,key_command_t *c)
{
    char copy[ASSOC_COMMAND_MAX];if(!input||strlen(input)>=sizeof(copy))return "input_length";
    for(const char *p=input;*p;p++)if(*p<32||*p>126)return "nonascii";
    strcpy(copy,input);memset(c,0,sizeof(*c));char *p=strtok(copy," ");if(!p||strcmp(p,"RADIOV5"))return "prefix";
    p=strtok(NULL," ");if(!p)return "command";
    const char *names[]={"INFO","BIND_ASSOCIATED","KEY_POLL","KEY_STATE","DEVICE_ANNOUNCE","STATUS","END"};unsigned k;
    for(k=0;k<7;k++){if(!strcmp(p,names[k]))break;}
    if(k==7)return "command";
    c->kind=(key_kind_t)k;
    const char *fields[]={"id","boot","ctx","generation","raw_ieee","short","pan","coordinator","extpan","attempt","max_key_polls","poll_interval_ms","total_timeout_ms","dsn","epoch","keyseq","fc","intent","hash","mac"};
    uint32_t mask=0;
    while((p=strtok(NULL," "))){char *v=strchr(p,'=');if(!v)return "field";*v++=0;unsigned i;for(i=0;i<20;i++)if(!strcmp(p,fields[i]))break;if(i==20||mask&(1u<<i))return "unknown_or_duplicate";mask|=1u<<i;uint32_t n=0;uint8_t b[16];
        if(i==1||i==9||i==14){if(!hex(v,b,16,false))return "token";strcpy(i==1?c->boot:i==9?c->attempt:c->epoch,v);}
        else if(i==4||i==7||i==8){if(!hex(v,i==4?c->raw:i==7?c->tc:c->extpan,8,true))return "ieee";}
        else if(i==5||i==6){if(!hex(v,b,2,true))return "address";if(i==5)c->short_address=le16(b);else c->pan=le16(b);}
        else if(i==18||i==19){if(!hex(v,i==18?c->hash:c->mac,i==18?32:55,false))return "hex";}
        else{if(!number(v,&n))return "number";switch(i){case 0:c->id=n;break;case 2:if(n>1)return "ctx";c->ctx=n;break;case 3:c->generation=n;break;case 10:c->max_polls=n;break;case 11:c->interval=n;break;case 12:c->timeout=n;break;case 13:if(n>255)return "dsn";c->dsn=n;break;case 15:if(n>255)return "keyseq";c->keyseq=n;break;case 16:c->fc=n;break;case 17:c->intent=n;break;default:return "field";}}
    }
    uint32_t want=1;
    if(k!=KC_INFO)want|=2;
    if(k==KC_BIND)want|=0x1ffcu;
    if(k==KC_POLL)want|=(1u<<2)|(1u<<3)|(1u<<13);
    if(k==KC_KEY)want|=(1u<<2)|(1u<<3)|(1u<<14)|(1u<<15);
    if(k==KC_ANNOUNCE)want|=(1u<<2)|(1u<<3)|(1u<<4)|(1u<<5)|(1u<<6)|(1u<<7)|(1u<<14)|(1u<<15)|(1u<<16)|(1u<<17)|(1u<<18)|(1u<<19);
    return mask==want?NULL:"field_set";
}
const char *key_bind(key_gate_t *s,const key_command_t *c,uint32_t now)
{
    if(s->state!=K_IDLE||s->session)return "bind_once_per_boot";
    if(c->ctx!=1||c->pan!=0x0b7a||!c->generation||!c->short_address||c->short_address>=0xfff8||!nonzero(c->raw,8)||!nonzero(c->tc,8)||!memcmp(c->raw,c->tc,8)||memcmp(c->tc,c->extpan,8)||!c->attempt[0]||c->max_polls<1||c->max_polls>8||c->interval<100||c->interval>5000||c->timeout<1000||c->timeout>45000||c->interval>c->timeout)return "bind_policy";
    memset(s,0,sizeof(*s));s->session=1;s->state=K_UNKEYED;s->generation=c->generation;s->ctx=c->ctx;s->pan=c->pan;s->short_address=c->short_address;s->max_polls=c->max_polls;s->interval=c->interval;s->timeout=c->timeout;s->start_us=now;memcpy(s->raw,c->raw,8);memcpy(s->tc,c->tc,8);memcpy(s->extpan,c->extpan,8);strcpy(s->attempt,c->attempt);return NULL;
}
static bool bound(const key_gate_t *s,const key_command_t *c){return s->ctx==c->ctx&&s->generation==c->generation;}
const char *key_poll(key_gate_t *s,const key_command_t *c,uint32_t now,uint8_t out[10])
{
    if(s->state!=K_UNKEYED||!bound(s,c)||s->pending)return "poll_state";
    if((uint32_t)(now-s->start_us)>s->timeout*1000u||s->polls>=s->max_polls||(s->polls&&(uint32_t)(now-s->last_poll_us)<s->interval*1000u))return "poll_bound";
    const uint8_t base[]={0x63,0x88,c->dsn,s->pan,s->pan>>8,0,0,s->short_address,s->short_address>>8,4};memcpy(out,base,10);s->polls++;s->last_poll_us=now;s->pending=true;return NULL;
}
const char *key_installed(key_gate_t *s,const key_command_t *c)
{
    if(s->state!=K_UNKEYED||s->pending||s->ctx!=c->ctx||c->generation<=s->generation||!c->epoch[0])return "key_state";
    s->generation=c->generation;s->keyseq=c->keyseq;strcpy(s->epoch,c->epoch);s->state=K_INSTALLED;return NULL;
}
const char *key_announce(key_gate_t *s,const key_command_t *c,uint32_t now,uint8_t out[55])
{
    (void)now;if(s->state!=K_INSTALLED||s->used||s->pending||!bound(s,c)||c->intent<=s->intent||c->fc==UINT32_MAX||strcmp(c->epoch,s->epoch)||c->keyseq!=s->keyseq||c->pan!=s->pan||c->short_address!=s->short_address||memcmp(c->raw,s->raw,8)||memcmp(c->tc,s->tc,8))return "intent_binding";
    const uint8_t *m=c->mac;uint8_t h[32];permit_hash(m,55,h);
    if(memcmp(h,c->hash,32))return "hash";
    /* Fixed encrypted length: 20-byte APS/ZDO + MIC4. Semantics verified by host. */
    if(le16(m)!=0x8861||le16(m+3)!=s->pan||le16(m+5)!=0||le16(m+7)!=s->short_address||le16(m+9)!=0x0208||le16(m+11)!=0xfffd||le16(m+13)!=s->short_address||m[15]!=60||m[17]!=0x28||le32(m+18)!=c->fc||memcmp(m+22,s->raw,8)||m[30]!=s->keyseq)return "outer_fields";
    s->used=true;s->intent=c->intent;s->fc=c->fc;s->pending=true;s->state=K_QUEUED;memcpy(out,m,55);return NULL;
}
void key_done(key_gate_t *s,bool announce,bool ok){s->pending=false;if(s->state==K_STOPPED)return;if(announce)s->state=ok?K_MANAGEMENT:K_UNCERTAIN;}
const char *key_name(key_state_t k){const char *n[]={"IDLE","ASSOCIATED_UNKEYED","KEY_INSTALLED","ANNOUNCE_QUEUED","MANAGEMENT_PENDING","ANNOUNCE_UNCERTAIN","STOPPED"};return k<=K_STOPPED?n[k]:"INVALID";}
