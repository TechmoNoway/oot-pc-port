#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <math.h>
#include "native_nvn_resources.h"
#include <stdlib.h>
#include <string.h>
#define RESOURCE_LIMIT 64u
#define RESOURCE_BYTES OOT_MEMORY_SERVICE_WRITE_LIMIT
typedef struct ResourcePool {uint64_t object,storage,size,references;OotGpuBuffer *shadow;uint8_t seal[256];} ResourcePool;
typedef struct ResourceBuffer {uint64_t object,offset,size;ResourcePool *pool;uint32_t live;uint8_t seal[48];} ResourceBuffer;
typedef struct ResourceDescriptorPool {
    uint64_t object,offset;ResourcePool *pool;uint32_t count,kind;
    /* Private semantic records. Reserved sampler recipes 1/2/3 and reserved
     * texture recipe are retained independently of NVIDIA descriptor bytes. Their
     * binding/materialization consumers remain guarded in this profile. */
    uint8_t *records;uint32_t *sampler_slots;uint8_t seal[32];
} ResourceDescriptorPool;
typedef struct ResourceSampler {OotGpuSampler *sampler;OotGpuSamplerInfo info;uint32_t references;} ResourceSampler;
struct OotNvnResources {
    OotGpu *gpu;OotGuestMemory *memory;uint64_t device;DWORD thread;
    ResourcePool pools[RESOURCE_LIMIT];ResourceBuffer buffers[RESOURCE_LIMIT];
    OotNvnRange forbidden[16];unsigned forbidden_count;
    ResourceSampler samplers[256];
    ResourceDescriptorPool descriptors[32];unsigned descriptor_count;
    unsigned pool_count,buffer_count;OotNvnResourcesReport report;
};
static int span(uint64_t at,uint64_t n){return at>=4096 && n && at<(UINT64_C(1)<<39) && n<=(UINT64_C(1)<<39)-at;}
static int separate(uint64_t a,uint64_t an,uint64_t b,uint64_t bn){return a<=b?an<=b-a:bn<=a-b;}
static uint64_t get(const uint8_t *p,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;++i)v|=(uint64_t)p[i]<<(i*8);return v;}
static int live(const OotNvnResources *r){OotGpuReport s;return r && r->thread==GetCurrentThreadId() && oot_gpu_snapshot(r->gpu,&s) && !s.faulted;}
static int private_output(const OotNvnResources *r,const void *out,size_t size)
{
    uintptr_t a=(uintptr_t)out,b=(uintptr_t)r;
    if(!out || (a<=b ? size>b-a:sizeof(*r)>a-b))return 0;
    b=(uintptr_t)r->memory;if(a<=b ? size>b-a:sizeof(*r->memory)>a-b)return 0;
    b=(uintptr_t)r->memory->regions;size_t bytes=r->memory->count*sizeof(*r->memory->regions);
    if(a<=b ? size>b-a:bytes>a-b)return 0;
    for(size_t n=0;n<r->memory->count;++n){const OotGuestRegion *v=r->memory->regions+n;b=(uintptr_t)v->data;
        if(a<=b ? size>b-a:v->size>a-b)return 0;}
    for(unsigned n=0;n<r->descriptor_count;++n){const ResourceDescriptorPool *d=r->descriptors+n;
        b=(uintptr_t)d->records;if(d->records && (a<=b ? size>b-a:(uint64_t)d->count*32>a-b))return 0;
        b=(uintptr_t)d->sampler_slots;if(d->sampler_slots && (a<=b ? size>b-a:(uint64_t)d->count*4>a-b))return 0;
    }
    return 1;
}
static int pool_bytes(OotNvnResources *r,ResourcePool *p)
{uint8_t bytes[256];return oot_memory_capture_service(r->memory,p->object,bytes,256,3) && !memcmp(bytes,p->seal,256);}
static ResourcePool *pool(OotNvnResources *r,uint64_t at){for(unsigned n=0;n<r->pool_count;++n)if(r->pools[n].object==at && r->pools[n].shadow)return r->pools+n;return NULL;}
static ResourceBuffer *buffer(OotNvnResources *r,uint64_t at){for(unsigned n=0;n<r->buffer_count;++n)if(r->buffers[n].object==at && r->buffers[n].live)return r->buffers+n;return NULL;}
/* Include tombstones: neither stale object identities nor retired VA ranges
 * can accidentally name a later allocation. */
static int unclaimed(OotNvnResources *r,uint64_t at,uint64_t size)
{
    if(!span(at,size) || !separate(at,size,r->device,8))return 0;
    for(unsigned n=0;n<r->forbidden_count;++n)if(!separate(at,size,r->forbidden[n].address,r->forbidden[n].size))return 0;
    for(unsigned n=0;n<r->pool_count;++n){ResourcePool *p=r->pools+n;
        if(!separate(at,size,p->object,256) || !separate(at,size,p->storage,p->size))return 0;}
    for(unsigned n=0;n<r->buffer_count;++n)if(!separate(at,size,r->buffers[n].object,48))return 0;
    for(unsigned n=0;n<r->descriptor_count;++n)if(!separate(at,size,r->descriptors[n].object,32))return 0;
    return 1;
}
OotNvnResources *oot_nvn_resources_create(OotGraphics *g,OotGuestMemory *m,uint64_t device,const OotNvnRange *forbidden,unsigned count)
{
    if(!m || !m->valid || !span(device,8) || count>16 || (count && !forbidden))return NULL;
    OotNvnResources *r=calloc(1,sizeof(*r));if(!r)return NULL;
    r->gpu=oot_gpu_create_renderer(g);if(!r->gpu){free(r);return NULL;}
    for(unsigned n=0;n<count;++n)if(!span(forbidden[n].address,forbidden[n].size)){oot_gpu_destroy(r->gpu);free(r);return NULL;}
    if(count)memcpy(r->forbidden,forbidden,count*sizeof(*forbidden));
    r->forbidden_count=count;
    r->memory=m;r->device=device;r->thread=GetCurrentThreadId();return r;
}
void oot_nvn_resources_destroy(OotNvnResources *r)
{if(r && r->thread==GetCurrentThreadId()){for(unsigned n=0;n<r->descriptor_count;++n)free(r->descriptors[n].records);
        for(unsigned n=0;n<r->descriptor_count;++n)free(r->descriptors[n].sampler_slots);
        oot_gpu_destroy(r->gpu);free(r);}}
int oot_nvn_resources_snapshot(const OotNvnResources *r,OotNvnResourcesReport *out)
{OotGpuReport gpu;if(!live(r) || !private_output(r,out,sizeof(*out)) || !oot_gpu_snapshot(r->gpu,&gpu))return 0;*out=r->report;out->samplers=gpu.samplers;return 1;}
static int flush(OotNvnResources*,ResourcePool*,uint64_t,uint64_t);
int oot_nvn_resources_output(const OotNvnResources *r,uint64_t at,uint64_t size)
{
    if(!live(r) || !span(at,size))return 0;
    for(unsigned n=0;n<r->pool_count;++n)if(!separate(at,size,r->pools[n].object,256))return 0;
    for(unsigned n=0;n<r->buffer_count;++n)if(!separate(at,size,r->buffers[n].object,48))return 0;
    for(unsigned n=0;n<r->descriptor_count;++n)if(!separate(at,size,r->descriptors[n].object,32))return 0;
    return 1;
}
int oot_nvn_resources_resolve(OotNvnResources *r,uint64_t address,uint64_t size,OotGpuBuffer **out,uint64_t *offset)
{
    if(!live(r) || !size || !private_output(r,out,sizeof(*out)) || !private_output(r,offset,sizeof(*offset)) ||
       !separate((uintptr_t)out,sizeof(*out),(uintptr_t)offset,sizeof(*offset)))return 0;
    for(unsigned n=0;n<r->descriptor_count;++n){ResourceDescriptorPool *d=r->descriptors+n;
        if(d->records && !separate(address,size,d->pool->storage+d->offset,(uint64_t)d->count*32))return 0;
    }
    for(unsigned n=0;n<r->pool_count;++n){ResourcePool *p=r->pools+n;
        if(p->shadow && address>=p->storage && address-p->storage<p->size && size<=p->size-(address-p->storage)){
            if(!pool_bytes(r,p) || flush(r,p,address-p->storage,size))return 0;
            *out=p->shadow;*offset=address-p->storage;return 1;
        }}return 0;
}
static int flush(OotNvnResources *r,ResourcePool *p,uint64_t offset,uint64_t size)
{
    if(offset>p->size || size>p->size-offset)return 1;
    if(!size)return 0;
    uint8_t *bytes=malloc((size_t)size);if(!bytes)return 2;
    int status=oot_memory_capture_service(r->memory,p->storage+offset,bytes,(unsigned)size,3)?0:2;
    if(!status && !oot_gpu_upload(r->gpu,p->shadow,offset,bytes,(size_t)size))status=2;
    free(bytes);return status;
}
static int sampler_valid(OotNvnResources *r,uint32_t slot)
{
    if(!slot || slot>256)return 0;
    ResourceSampler *s=r->samplers+slot-1;uint64_t observed_references;OotGpuSamplerInfo info;
    return s->sampler && s->references && oot_gpu_sampler_references(r->gpu,s->sampler,&observed_references) && observed_references==s->references &&
        oot_gpu_sampler_info(r->gpu,s->sampler,&info) && !memcmp(&info,&s->info,sizeof(info));
}
static int sampler_acquire(OotNvnResources *r,const OotGpuSamplerInfo *info,uint32_t *slot)
{
    unsigned free_slot=256;
    for(unsigned n=0;n<256;++n){ResourceSampler *s=r->samplers+n;
        if(s->sampler && !memcmp(&s->info,info,sizeof(*info))){
            if(!sampler_valid(r,n+1) || s->references>=65536 || !oot_gpu_sampler_retain(r->gpu,s->sampler))return 0;
            ++s->references;*slot=n+1;return 1;
        }
        if(!s->sampler && free_slot==256)free_slot=n;
    }
    if(free_slot==256)return 0;
    OotGpuSampler *sampler=oot_gpu_sampler_create(r->gpu,info);if(!sampler)return 0;
    if(!oot_gpu_sampler_retain(r->gpu,sampler)){oot_gpu_sampler_destroy(r->gpu,sampler);return 0;}
    r->samplers[free_slot]=(ResourceSampler){sampler,*info,1};*slot=free_slot+1;return 1;
}
static int sampler_release(OotNvnResources *r,uint32_t slot)
{
    if(!slot || slot>256)return 0;
    ResourceSampler *s=r->samplers+slot-1;
    if(!sampler_valid(r,slot) || !oot_gpu_sampler_release(r->gpu,s->sampler))return 0;
    if(!--s->references){if(!oot_gpu_sampler_destroy(r->gpu,s->sampler))return 0;memset(s,0,sizeof(*s));}
    return 1;
}
static float sampler_float(const uint8_t *p){float f;uint32_t bits=(uint32_t)get(p,4);memcpy(&f,&bits,4);return f;}
static int sampler_address(unsigned input,uint32_t *out)
{
    switch(input){case 1:*out=0;return 1;case 5:*out=3;return 1;case 6:*out=1;return 1;case 7:*out=2;return 1;default:return 0;}
}
static int decode_sampler(OotNvnResources *r,const uint8_t bytes[48],OotGpuSamplerInfo *out)
{
    if(get(bytes,8)!=r->device)return 0;
    uint32_t control=(uint32_t)get(bytes+44,4);unsigned min=(control>>16)&15,mag=(control>>20)&15;
    unsigned reduction=(control>>12)&15,compare=(control>>24)&3,function=control>>26;
    OotGpuSamplerInfo i={0};
    if(min>5 || mag>1 || reduction || compare>1 || function<1 || function>8 || sampler_float(bytes+24)!=0 ||
       !sampler_address(control&15,&i.address_u) || !sampler_address((control>>4)&15,&i.address_v) || !sampler_address((control>>8)&15,&i.address_w))return 0;
    i.min_filter=min&1;i.mag_filter=mag;i.mipmap_mode=min>=4;
    i.min_lod=sampler_float(bytes+8);i.max_lod=sampler_float(bytes+12);i.lod_bias=sampler_float(bytes+16);i.max_anisotropy=sampler_float(bytes+20);
    if(!isfinite(i.min_lod) || !isfinite(i.max_lod) || i.min_lod>i.max_lod)return 0;
    /* Preserve distinct minification/magnification for non-mip filters. */
    if(min<2){i.min_lod=0;i.max_lod=0.25f;}
    i.compare_enable=compare;i.compare_op=function-1;
    if(i.address_u==3 || i.address_v==3 || i.address_w==3){
        float color[4];for(unsigned n=0;n<4;++n)color[n]=sampler_float(bytes+28+n*4);
        if(color[0]==0 && color[1]==0 && color[2]==0 && color[3]==0)i.border_color=0;
        else if(color[0]==0 && color[1]==0 && color[2]==0 && color[3]==1)i.border_color=1;
        else if(color[0]==1 && color[1]==1 && color[2]==1 && color[3]==1)i.border_color=2;
        else return 0;
    }
    *out=i;return 1;
}
int oot_nvn_resources_call4(OotNvnResources *r,uint32_t id,uint64_t object,uint64_t a,uint64_t b,uint64_t c,uint64_t *result)
{
    if(!live(r) || !private_output(r,result,sizeof(*result)) || object%8 || !span(object,8))return 2;
    OotNvnResourcesReport next=r->report;
    if(next.queries==UINT64_MAX || next.maps==UINT64_MAX || next.initializations==UINT64_MAX || next.finalizations==UINT64_MAX ||
       next.flushes==UINT64_MAX || next.invalidations==UINT64_MAX)return 2;
    uint64_t value=0;ResourcePool *p=pool(r,object);ResourceBuffer *v=buffer(r,object);
    if(id==OOT_NVN_SAMPLER_POOL_REGISTER || id==OOT_NVN_SAMPLER_POOL_REGISTER_BUILDER){
        ResourceDescriptorPool *d=NULL;uint32_t index=(uint32_t)a;
        for(unsigned n=0;n<r->descriptor_count;++n)if(r->descriptors[n].object==object && r->descriptors[n].records && r->descriptors[n].kind==1)d=r->descriptors+n;
        if(!d || index<256 || index>=d->count || !span(b,id==OOT_NVN_SAMPLER_POOL_REGISTER?64:48))return 1;
        if(next.sampler_registrations==UINT64_MAX)return 2;
        uint8_t seal[32],bytes[48];p=d->pool;
        if(!pool_bytes(r,p) || !oot_memory_capture_service(r->memory,object,seal,32,3) || memcmp(seal,d->seal,32) ||
           !oot_memory_probe_service(r->memory,p->storage+d->offset,d->count*32,3) ||
           !oot_memory_load_record(r->memory,b+(id==OOT_NVN_SAMPLER_POOL_REGISTER?8:0),bytes,48))return 2;
        OotGpuSamplerInfo info;if(!decode_sampler(r,bytes,&info))return 1;
        uint32_t old=d->sampler_slots[index],created;
        if(old && !sampler_valid(r,old))return 2;
        if(!sampler_acquire(r,&info,&created))return 2;
        if(old && !sampler_release(r,old)){sampler_release(r,created);return 2;}
        d->sampler_slots[index]=created;d->records[index*32]=5;++next.sampler_registrations;
    }else if(id>=OOT_NVN_SAMPLER_POOL_INITIALIZE && id<=OOT_NVN_TEXTURE_POOL_GET_SIZE){
        uint32_t kind=id<=OOT_NVN_SAMPLER_POOL_GET_SIZE?1:2;
        uint32_t relative=id-(kind==1?OOT_NVN_SAMPLER_POOL_INITIALIZE:OOT_NVN_TEXTURE_POOL_INITIALIZE);
        if(next.descriptor_initializations==UINT64_MAX || next.descriptor_finalizations==UINT64_MAX || next.descriptor_queries==UINT64_MAX)return 2;
        if(relative==0){
            p=pool(r,a);uint32_t count=(uint32_t)c;uint64_t bytes=(uint64_t)count*32;uint8_t seal[32];
            if(!p || count<256 || count>65536 || b%32 || b>p->size || bytes>p->size-b ||
               r->descriptor_count>=32 || next.descriptor_slots>65536-count || !unclaimed(r,object,32))return 1;
            for(unsigned n=0;n<r->descriptor_count;++n){ResourceDescriptorPool *d=r->descriptors+n;
                if(d->records && d->pool==p && !separate(b,bytes,d->offset,(uint64_t)d->count*32))return 1;}
            if(!pool_bytes(r,p) || !oot_memory_capture_service(r->memory,object,seal,32,3) ||
               !oot_memory_probe_service(r->memory,p->storage+b,(unsigned)bytes,3))return 2;
            uint8_t *records=calloc(count,32);if(!records)return 2;
            uint32_t *sampler_slots=kind==1?calloc(count,sizeof(*sampler_slots)):NULL;
            if(kind==1 && !sampler_slots){free(records);return 2;}
            if(kind==1){
                unsigned n;
                for(n=0;n<3;++n){OotGpuSamplerInfo info={0};
                    info.min_filter=info.mag_filter=n==2?0:1;info.address_u=info.address_v=info.address_w=2;
                    info.min_lod=0;info.max_lod=0.25f;info.max_anisotropy=n?2.0f:1.0f;info.compare_op=1;
                    if(!sampler_acquire(r,&info,sampler_slots+n))break;
                    records[n*32]=(uint8_t)(n+1);
                }
                if(n!=3){while(n)sampler_release(r,sampler_slots[--n]);free(sampler_slots);free(records);return 2;}
            }else records[0]=4;
            ResourceDescriptorPool *d=r->descriptors+r->descriptor_count++;
            d->object=object;d->offset=b;d->pool=p;d->count=count;d->kind=kind;d->records=records;d->sampler_slots=sampler_slots;memcpy(d->seal,seal,32);
            ++p->references;++next.descriptor_pools;next.descriptor_slots+=count;++next.descriptor_initializations;value=1;
        }else{
            ResourceDescriptorPool *d=NULL;
            for(unsigned n=0;n<r->descriptor_count;++n)if(r->descriptors[n].object==object && r->descriptors[n].records && r->descriptors[n].kind==kind)d=r->descriptors+n;
            if(!d)return 1;
            uint8_t seal[32];p=d->pool;
            if(!p->shadow || !pool_bytes(r,p) || !oot_memory_capture_service(r->memory,object,seal,32,3) || memcmp(seal,d->seal,32) ||
               !oot_memory_probe_service(r->memory,p->storage+d->offset,d->count*32,3))return 2;
            if(relative==1){
                if(d->sampler_slots){
                    uint32_t counts[256]={0};
                    for(unsigned n=0;n<d->count;++n){uint32_t slot=d->sampler_slots[n];
                        if(slot && (slot>256 || ++counts[slot-1]>r->samplers[slot-1].references))return 2;
                    }
                    for(unsigned n=0;n<256;++n)if(counts[n] && !sampler_valid(r,n+1))return 2;
                }
                if(d->sampler_slots){
                    for(unsigned n=0;n<d->count;++n)if(d->sampler_slots[n] && !sampler_release(r,d->sampler_slots[n]))return 2;
                    free(d->sampler_slots);d->sampler_slots=NULL;
                }
                free(d->records);d->records=NULL;--p->references;--next.descriptor_pools;next.descriptor_slots-=d->count;++next.descriptor_finalizations;}
            else{value=relative==2?p->object:relative==3?d->offset:d->count;++next.descriptor_queries;}
        }
    }else if(id==OOT_NVN_POOL_INITIALIZE){
        uint8_t builder[56],seal[256];
        if(!oot_memory_load_record(r->memory,a,builder,sizeof(builder)))return 2;
        uint64_t storage=get(builder+16,8),size=get(builder+24,8);
        if(get(builder+8,8)!=r->device || get(builder+4,4)!=0x22 || (storage|size)&4095 || !size || size>RESOURCE_BYTES ||
           r->pool_count>=RESOURCE_LIMIT || next.bytes>UINT64_C(64)*1024*1024-size ||
           !unclaimed(r,object,256) || !unclaimed(r,storage,size) || !separate(object,256,storage,size) ||
           !separate(object,256,a,56) || !separate(storage,size,a,56))return 1;
        for(unsigned n=32;n<56;++n)if(builder[n])return 1;
        if(!oot_memory_capture_service(r->memory,object,seal,256,3) || !oot_memory_probe_service(r->memory,storage,(unsigned)size,3))return 2;
        OotGpuBuffer *shadow=oot_gpu_buffer_create(r->gpu,size);if(!shadow)return 2;
        ResourcePool *created=r->pools+r->pool_count++;created->object=object;created->storage=storage;created->size=size;created->shadow=shadow;memcpy(created->seal,seal,256);
        ++next.pools;next.bytes+=size;++next.initializations;value=1;
    }else if(id==OOT_NVN_BUFFER_INITIALIZE){
        uint8_t builder[40],seal[48];if(!oot_memory_load_record(r->memory,a,builder,sizeof(builder)))return 2;
        p=pool(r,get(builder+16,8));uint64_t offset=get(builder+24,8),size=get(builder+32,8);
        if(!p || get(builder+8,8)!=r->device || !size || offset>=p->size || size>p->size-offset ||
           r->buffer_count>=RESOURCE_LIMIT || !unclaimed(r,object,48) || !separate(object,48,a,40))return 1;
        if(!pool_bytes(r,p) || !oot_memory_capture_service(r->memory,object,seal,48,3) || !oot_memory_probe_service(r->memory,p->storage+offset,(unsigned)size,3))return 2;
        ResourceBuffer *created=r->buffers+r->buffer_count++;created->object=object;created->offset=offset;created->size=size;created->pool=p;created->live=1;memcpy(created->seal,seal,48);++p->references;++next.buffers;++next.initializations;value=1;
    }else if(id>=OOT_NVN_POOL_FINALIZE && id<=OOT_NVN_POOL_GET_ADDRESS){
        if(!p)return 1;
        uint8_t seal[256];
        if(!oot_memory_capture_service(r->memory,p->object,seal,256,3) || memcmp(seal,p->seal,256) || !oot_memory_probe_service(r->memory,p->storage,(unsigned)p->size,3))return 2;
        if(id==OOT_NVN_POOL_FINALIZE){
            if(p->references)return 1;
            if(!oot_gpu_buffer_destroy(r->gpu,p->shadow))return 2;
            p->shadow=NULL;--next.pools;next.bytes-=p->size;++next.finalizations;
        }else if(id==OOT_NVN_POOL_MAP){value=p->storage;++next.maps;}
        else if(id==OOT_NVN_POOL_GET_SIZE){value=p->size;++next.queries;}
        else if(id==OOT_NVN_POOL_GET_FLAGS){value=0x22;++next.queries;}
        else if(id==OOT_NVN_POOL_GET_ADDRESS){value=p->storage;++next.queries;}
        else{
            if(a>p->size || b>p->size-a)return 1;
            if(id==OOT_NVN_POOL_FLUSH){int status=flush(r,p,a,b);if(status)return status;++next.flushes;}
            else ++next.invalidations; /* No GPU-write commands exist in this subset. */
        }
    }else if(id>=OOT_NVN_BUFFER_FINALIZE && id<=OOT_NVN_BUFFER_INVALIDATE){
        if(!v || !v->pool->shadow)return 1;
        p=v->pool;
        uint8_t seal[48];
        if(!pool_bytes(r,p) || !oot_memory_capture_service(r->memory,v->object,seal,48,3) || memcmp(seal,v->seal,48) || !oot_memory_probe_service(r->memory,p->storage+v->offset,(unsigned)v->size,3))return 2;
        if(id==OOT_NVN_BUFFER_FINALIZE){v->live=0;--p->references;--next.buffers;++next.finalizations;}
        else if(id==OOT_NVN_BUFFER_MAP){value=p->storage+v->offset;++next.maps;}
        else if(id==OOT_NVN_BUFFER_GET_ADDRESS){value=p->storage+v->offset;++next.queries;}
        else if(id==OOT_NVN_BUFFER_GET_POOL){value=p->object;++next.queries;}
        else if(id==OOT_NVN_BUFFER_GET_OFFSET){value=v->offset;++next.queries;}
        else if(id==OOT_NVN_BUFFER_GET_SIZE){value=v->size;++next.queries;}
        else{
            if(a>v->size || b>v->size-a)return 1;
            if(id==OOT_NVN_BUFFER_FLUSH){int status=flush(r,p,v->offset+a,b);if(status)return status;++next.flushes;}
            else ++next.invalidations;
        }
    }else return 1;
    r->report=next;*result=value;return 0;
}

int oot_nvn_resources_call(OotNvnResources *r,uint32_t id,uint64_t object,uint64_t a,uint64_t b,uint64_t *result)
{return oot_nvn_resources_call4(r,id,object,a,b,0,result);}
