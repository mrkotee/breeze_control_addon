#include "assoc.h"
#include <string.h>
static bool number(const char *p,uint32_t *o,unsigned base)
{
    if(!p || !*p)return false;
    uint32_t n=0;
    for(;*p;p++){unsigned d=*p>='0' && *p<='9'?(unsigned)(*p-'0'):*p>='a' && *p<='f'?(unsigned)(*p-'a'+10):99;
        if(d>=base || n>(UINT32_MAX-d)/base)return false;
        n=n*base+d;}
    *o=n;return true;
}
static bool hextext(const char *p,size_t n)
{if(strlen(p)!=n)return false;for(size_t i=0;i<n;i++)if(!((p[i]>='0'&&p[i]<='9')||(p[i]>='a'&&p[i]<='f')))return false;return true;}
static bool ieee(const char *p,uint8_t *o)
{if(!hextext(p,16))return false;for(unsigned i=0;i<8;i++){char s[]={p[2*i],p[2*i+1],0};uint32_t v;if(!number(s,&v,16))return false;o[7-i]=(uint8_t)v;}return true;}
const char *assoc_command_parse(const char *input,assoc_command_t *out)
{
    if(!input || !out)return "input_invalid";
    size_t n=0;
    while(n<ASSOC_COMMAND_MAX && input[n])n++;
    if(!n || n>=ASSOC_COMMAND_MAX)return "line_length";
    char copy[ASSOC_COMMAND_MAX];memcpy(copy,input,n+1);
    char *tokens[28];unsigned count=0;bool start=true;
    for(size_t i=0;i<=n;i++){
        unsigned char c=(unsigned char)copy[i];
        if(c && (c<32 || c>126))return "ascii_only";
        if(!c || c==' '){copy[i]=0;start=true;}
        else if(start){if(count==28)return "token_limit";tokens[count++]=copy+i;start=false;}
    }
    if(count<3 || strcmp(tokens[0],"RADIOV3"))return "protocol";
    memset(out,0,sizeof(*out));unsigned first;
    if(!strcmp(tokens[1],"INFO")){out->kind=C_INFO;first=2;}
    else if(!strcmp(tokens[1],"ASSOC") && count>=4){
        first=3;
        if(!strcmp(tokens[2],"BEGIN"))out->kind=C_BEGIN;
        else if(!strcmp(tokens[2],"BEGIN_PERMIT_EVIDENCE"))out->kind=C_BEGIN_PERMIT;
        else if(!strcmp(tokens[2],"REQUEST"))out->kind=C_REQUEST;
        else if(!strcmp(tokens[2],"POLL"))out->kind=C_POLL;
        else if(!strcmp(tokens[2],"STATUS"))out->kind=C_STATUS;
        else if(!strcmp(tokens[2],"END"))out->kind=C_END;
        else return "unsupported_command";
    }else return "unsupported_command";
    const char *names[]={"id","boot","session","ctx","raw_ieee","target_pan","extpan","coordinator_ieee","coordinator_short","policy","attempt","beacon_revision","max_polls","poll_interval_ms","timeout_ms","dsn","permit_revision","raw_hash","validation_generation"};
    const char *values[19]={0};uint32_t mask=0;
    for(unsigned i=first;i<count;i++){
        char *eq=strchr(tokens[i],'=');if(!eq || eq==tokens[i] || !eq[1])return "key_value";*eq++=0;
        unsigned k;for(k=0;k<19 && strcmp(tokens[i],names[k]);k++){}
        if(k==19 || (mask&(1u<<k)))return "unknown_or_duplicate_field";
        values[k]=eq;mask|=1u<<k;
    }
    uint32_t expected=out->kind==C_INFO?1u:out->kind==C_BEGIN?0xfffbu:out->kind==C_BEGIN_PERMIT?0x7f7fbu:7u;
    if(mask!=expected)return "field_set";
    if(!number(values[0],&out->id,10))return "id_invalid";
    if(out->kind==C_INFO)return NULL;
    if(!hextext(values[1],32))return "boot_invalid";
    memcpy(out->boot,values[1],33);
    if(out->kind!=C_BEGIN && out->kind!=C_BEGIN_PERMIT){if(!number(values[2],&out->session,10) || !out->session)return "session_invalid";return NULL;}
    assoc_target_t *t=&out->target;uint32_t v;
    if(!number(values[3],&v,10) || v>1)return "ctx_invalid";
    t->ctx=(uint8_t)v;
    if(!ieee(values[4],t->raw_ieee) || !ieee(values[6],t->extpan) || !ieee(values[7],t->coordinator_ieee))return "ieee_encoding";
    if(!hextext(values[5],4) || !number(values[5],&v,16))return "pan_encoding";
    t->pan=(uint16_t)v;
    if(!hextext(values[8],4) || !number(values[8],&v,16))return "coordinator_encoding";
    t->coordinator_short=(uint16_t)v;
    if(!strcmp(values[9],"local_experimental_v1")){out->local_policy=true;if((t->raw_ieee[7]&3)!=2)return "local_identity_policy";}
    else if(!strcmp(values[9],"allocated_eui_v1")){if(t->raw_ieee[7]&3)return "allocated_identity_policy";}
    else return "policy_invalid";
    if(!hextext(values[10],32))return "attempt_invalid";
    memcpy(out->attempt,values[10],33);
    if(out->kind==C_BEGIN){if(!number(values[11],&out->beacon_revision,10) || !out->beacon_revision)return "beacon_revision_invalid";}
    else{if(!number(values[16],&out->permit_revision,10) || !out->permit_revision || !number(values[18],&out->validation_generation,10) || !out->validation_generation || !hextext(values[17],64))return "permit_evidence_encoding";
        for(unsigned i=0;i<32;i++){char a[]={values[17][2*i],values[17][2*i+1],0};if(!number(a,&v,16))return "permit_hash_encoding";out->raw_hash[i]=(uint8_t)v;}}
    if(!number(values[12],&t->max_polls,10) || !number(values[13],&t->poll_interval_ms,10) || !number(values[14],&t->timeout_ms,10))return "poll_policy_invalid";
    if(!number(values[15],&v,10) || v>255)return "dsn_invalid";
    t->dsn=(uint8_t)v;t->capability=0x80;
    return assoc_target_valid(t)?NULL:"target_invalid";
}
