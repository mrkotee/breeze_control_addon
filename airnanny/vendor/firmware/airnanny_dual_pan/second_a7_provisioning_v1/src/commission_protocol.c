/* Strict adapters to proven V4/V5 parsers. Extra lineage fields never reach wire. */
#include "commission.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bool num(const char *v,uint32_t *out){uint64_t n=0;if(!*v)return false;for(;*v;v++){if(*v<'0'||*v>'9')return false;n=n*10+(*v-'0');if(n>UINT32_MAX)return false;}*out=n;return true;}
static bool hx(const char *v,uint8_t *out,size_t n,bool reverse){if(strlen(v)!=2*n)return false;for(size_t i=0;i<n;i++){unsigned a=0;for(unsigned j=0;j<2;j++){char c=v[2*i+j];unsigned d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:16;if(d>15)return false;a=16*a+d;}out[reverse?n-1-i:i]=a;}return true;}
const char *commission_parse(const char *in,commission_command_t *out){
    if(!in||strlen(in)>=ASSOC_COMMAND_MAX)return "input_length";
    for(const char *p=in;*p;p++)if(*p<32||*p>126)return "nonascii";
    memset(out,0,sizeof(*out));
    if(strncmp(in,"RADIOV7 ",8))return "prefix";
    char adapted[ASSOC_COMMAND_MAX];strcpy(adapted,in);adapted[6]='3';
    if(!strncmp(in+8,"ASSOC ",6)){
        const char *e=assoc_command_parse(adapted,&out->association);if(e)return e;
        if(out->association.kind!=C_BEGIN_PERMIT&&out->association.kind!=C_REQUEST&&out->association.kind!=C_POLL)return "association_verb";
        out->kind=GC_ASSOC;out->id=out->association.id;out->session=out->association.session;strcpy(out->boot,out->association.boot);return NULL;
    }
    char copy[ASSOC_COMMAND_MAX];strcpy(copy,in);char *p=strtok(copy," ");(void)p;p=strtok(NULL," ");if(!p)return "verb";
    const char *names[]={"INFO","BASELINE_READY","ARM","ASSOC_COMMIT","POST_ASSOC_POLL","KEY_STATE","DEVICE_ANNOUNCE","STATUS","END"};
    unsigned kind=0;for(;kind<9;kind++)if(!strcmp(p,names[kind]))break;if(kind==9)return "verb";
    const commission_kind_t mapped[]={GC_INFO,GC_BASELINE,GC_ARM,GC_COMMIT,GC_POLL,GC_KEY,GC_ANNOUNCE,GC_STATUS,GC_END};out->kind=mapped[kind];
    const char *internal[]={"INFO","KEY_POLL","KEY_POLL","BIND_ASSOCIATED","KEY_POLL","KEY_STATE","DEVICE_ANNOUNCE","STATUS","END"};
    snprintf(adapted,sizeof(adapted),"RADIOV5 %s",internal[kind]);
    unsigned mask=0,count=0;char *seen[30];
    while((p=strtok(NULL," "))){
        char *v=strchr(p,'=');if(!v)return "field";*v++=0;
        for(unsigned j=0;j<count;j++)if(!strcmp(seen[j],p))return "duplicate_field";
        if(count==30)return "field_limit";seen[count++]=p;
        bool extra=false;uint32_t n=0;uint8_t b[16];
        if(!strcmp(p,"session")){if(mask&1||!num(v,&out->session)||(!out->session&&kind!=8))return "session";mask|=1;extra=true;}
        else if(!strcmp(p,"baseline_revision")&&(kind==1||kind==2)){if(!num(v,&out->baseline_revision))return "revision";mask|=64;extra=true;}
        else if(!strcmp(p,"attempt")&&kind>=3&&kind<=6){if(!hx(v,b,16,false))return "attempt";strcpy(out->attempt,v);mask|=2;extra=kind!=3;}
        else if(!strcmp(p,"raw_ieee")&&kind>=3&&kind<=6){if(!hx(v,out->raw,8,true))return "raw";mask|=4;extra=kind==4||kind==5;}
        else if(!strcmp(p,"short")&&kind>=3&&kind<=6){if(!hx(v,b,2,true))return "short";out->short_address=b[0]|(uint16_t)b[1]<<8;mask|=8;extra=kind==4||kind==5;}
        else if(!strcmp(p,"pan")&&kind>=3&&kind<=6){if(!hx(v,b,2,true))return "pan";out->pan=b[0]|(uint16_t)b[1]<<8;mask|=16;extra=kind==4||kind==5;}
        else if(!strcmp(p,"coordinator")&&kind>=3&&kind<=6){if(!hx(v,out->tc,8,true))return "tc";mask|=32;extra=kind==4||kind==5;}
        (void)n;
        if(!extra){size_t at=strlen(adapted);int written=snprintf(adapted+at,sizeof(adapted)-at," %s=%s",p,v);if(written<0||(size_t)written>=sizeof(adapted)-at)return "adaptation_length";}
    }
    unsigned want=kind==1||kind==2?64:kind>=3&&kind<=6?63:kind==8?1:0;
    if(mask!=want)return "lineage_field_set";
    if(kind==1||kind==2){if(strlen(adapted)+7>=sizeof(adapted))return "length";strcat(adapted," dsn=0");}
    const char *e=key_parse(adapted,&out->key);if(e)return e;
    out->id=out->key.id;strcpy(out->boot,out->key.boot);return NULL;
}
