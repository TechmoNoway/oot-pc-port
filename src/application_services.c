#include "application_services.h"
static int separate(const void *a,size_t an,const void *b,size_t bn){
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<=y ? y-x>=an:x-y>=bn;
}
int oot_application_resource_prepare(const OotNativePlatform *platform,uint64_t queries,
    const OotArm64State *registers,uint64_t *next_queries,OotArm64State *result)
{
    const void *objects[]={platform,registers,next_queries,result};
    const size_t sizes[]={sizeof(*platform),sizeof(*registers),sizeof(*next_queries),sizeof(*result)};
    for(unsigned n=0;n<4;++n){
        if(!objects[n])return 2;
        for(unsigned k=n+1;k<4;++k)if(!separate(objects[n],sizes[n],objects[k],sizes[k]))return 2;
    }
    if(!oot_native_platform_valid(platform) || queries==UINT64_MAX || !registers->pc ||
       registers->pc>=(UINT64_C(1)<<39) || registers->pc%4 || registers->sp%16 ||
       registers->x[30]<4 || registers->x[30]>=(UINT64_C(1)<<39) || registers->x[30]%4 ||
       (registers->nzcv&UINT32_C(0x0fffffff)))return 2;
    if(!platform->initialized)return 1;
    OotArm64State output=*registers;
    output.x[0]=platform->config.process_id;output.pc=registers->x[30];
    *next_queries=queries+1;*result=output;return 0;
}
int oot_application_services_prepare(const OotApplicationServices *state,uint32_t id,
    uint32_t platform_initialized,const OotArm64State *registers,
    OotApplicationServices *next,OotArm64State *result)
{
    const void *objects[]={state,registers,next,result};
    const size_t sizes[]={sizeof(*state),sizeof(*registers),sizeof(*next),sizeof(*result)};
    for(unsigned n=0;n<4;++n){
        if(!objects[n])return 2;
        for(unsigned k=n+1;k<4;++k)if(!separate(objects[n],sizes[n],objects[k],sizes[k]))return 2;
    }
    if(state->version!=1 || state->graphics_notifications>1 || state->reserved[0] || state->reserved[1] ||
       platform_initialized>1 || !registers->pc || registers->pc>=(UINT64_C(1)<<39) || registers->pc%4 ||
       registers->x[30]<4 || registers->x[30]>=(UINT64_C(1)<<39) || registers->x[30]%4 ||
       registers->sp%16 || (registers->nzcv&UINT32_C(0x0fffffff)))return 2;
    if(!platform_initialized)return 1;
    OotApplicationServices candidate=*state;OotArm64State output=*registers;
    if(id==OOT_APPLICATION_GRAPHICS_NOTIFICATIONS){
        if((uint32_t)registers->x[0]>1)return 1;
        if(state->policy_calls==UINT64_MAX)return 2;
        candidate.graphics_notifications=(uint32_t)registers->x[0];++candidate.policy_calls;
    }else if(id==OOT_APPLICATION_DESIRED_LANGUAGE){
        if(state->language_code!=OOT_APPLICATION_DEFAULT_LANGUAGE)return 1;
        if(state->language_calls==UINT64_MAX)return 2;
        ++candidate.language_calls;output.x[0]=state->language_code;
    }else return 1;
    output.pc=registers->x[30];*next=candidate;*result=output;return 0;
}
