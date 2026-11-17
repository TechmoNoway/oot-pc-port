/* Synthetic Vulkan, independent builder bytes and guest-memory publication. */
#define main gpu_fixture_unused_main
#include "native_gpu_test.c"
#undef main
#include "../src/native_nvn_resources.c"
static uint8_t guest[0x20000];
#define BASE UINT64_C(0x100000000)
#define POOL (BASE+0x1000)
#define BUILDER (BASE+0x2000)
#define STORAGE (BASE+0x8000)
#define BUFFER (BASE+0x1400)
#define BUFFER_BUILDER (BASE+0x2400)
static void put(OotGuestMemory *m,uint64_t at,unsigned size,uint64_t value){assert(oot_memory_store(m,at,size,value));}
static void pool_builder(OotGuestMemory *m)
{
    for(unsigned n=0;n<56;n+=8)put(m,BUILDER+n,8,0);
    put(m,BUILDER+4,4,0x22);put(m,BUILDER+8,8,BASE+0x100);
    put(m,BUILDER+16,8,STORAGE);put(m,BUILDER+24,8,8192);
}
static uint64_t call(OotNvnResources *r,unsigned id,uint64_t o,uint64_t a,uint64_t b,int expected)
{
    uint64_t result=UINT64_MAX;OotNvnResourcesReport before=r->report;
    int status=oot_nvn_resources_call(r,id,o,a,b,&result);
    if(status!=expected)fprintf(stderr,"resource id %u got %d expected %d\n",id,status,expected);
    assert(status==expected);
    if(status){assert(result==UINT64_MAX);assert(!memcmp(&r->report,&before,sizeof(before)));}
    return result;
}
typedef struct Publication {OotGuestRegion *regions;HANDLE start;} Publication;
static DWORD WINAPI publish(LPVOID value)
{
    Publication *p=value;OotGuestMemory m;assert(oot_memory_init(&m,p->regions,2));
    uint8_t a[4096],b[4096];memset(a,0x19,sizeof(a));memset(b,0xa7,sizeof(b));
    assert(WaitForSingleObject(p->start,2000)==WAIT_OBJECT_0);
    for(unsigned n=0;n<4000;++n){const uint8_t *bytes=n&1?a:b;
        OotServiceWrite w[2]={{STORAGE,bytes,4096},{STORAGE+4096,bytes,4096}};assert(oot_memory_store_service(&m,w,2));}
    return 0;
}
int main(void)
{
    OotGuestRegion regions[2]={{BASE,0x9000,guest,3},{BASE+0x9000,sizeof(guest)-0x9000,guest+0x9000,3}};
    OotGuestMemory m;assert(oot_memory_init(&m,regions,2));pool_builder(&m);
    OotNvnRange forbidden={BASE+0x3000,4096};
    OotNvnResources *r=oot_nvn_resources_create((OotGraphics*)(uintptr_t)1,&m,BASE+0x100,&forbidden,1);assert(r);
    uint8_t before[sizeof(guest)];memcpy(before,guest,sizeof(guest));
    for(unsigned f=4;f<=7;++f){fault=f;call(r,466,POOL,BUILDER,0,2);assert(!memcmp(before,guest,sizeof(guest)));assert(!buffers && !allocations && !maps);}
    fault=0;
    const uint64_t invalid_flags[]={0,0x21,0x23,0x122,UINT32_MAX};
    for(unsigned n=0;n<5;++n){put(&m,BUILDER+4,4,invalid_flags[n]);call(r,466,POOL,BUILDER,0,1);}pool_builder(&m);
    put(&m,BUILDER+32,1,1);call(r,466,POOL,BUILDER,0,1);pool_builder(&m);
    put(&m,BUILDER+8,8,BASE+0x108);call(r,466,POOL,BUILDER,0,1);pool_builder(&m);
    put(&m,BUILDER+16,8,BASE+0x3000);call(r,466,POOL,BUILDER,0,1);pool_builder(&m);
    put(&m,BUILDER+16,8,STORAGE+1);call(r,466,POOL,BUILDER,0,1);pool_builder(&m);
    put(&m,BUILDER+24,8,UINT64_MAX);call(r,466,POOL,BUILDER,0,1);pool_builder(&m);
    call(r,466,BUILDER,BUILDER,0,1);call(r,466,STORAGE,BUILDER,0,1);
    regions[1].permissions=1;call(r,466,POOL,BUILDER,0,2);regions[1].permissions=3;
    memcpy(before,guest,sizeof(guest));assert(call(r,466,POOL,BUILDER,0,0)==1);assert(!memcmp(before,guest,sizeof(guest)));
    assert(buffers==1 && allocations==1 && maps==1 && r->report.bytes==8192);
    call(r,466,POOL,BUILDER,0,1);call(r,466,POOL+256,BUILDER,0,1);
    assert(call(r,468,POOL,0,0,0)==STORAGE && call(r,469,POOL,0,0,0)==8192 && call(r,470,POOL,0,0,0)==0x22);
    assert(call(r,473,POOL,0,0,0)==STORAGE);
    uint64_t descriptor_result=UINT64_MAX;uint64_t sampler_object=POOL+0x500,texture_object=POOL+0x600;
    assert(oot_nvn_resources_call4(r,483,sampler_object,POOL,0,255,&descriptor_result)==1 && descriptor_result==UINT64_MAX);
    OotNvnResourcesReport saved_report=r->report;sampler_calls=0;sampler_fail_after=3;descriptor_result=UINT64_MAX;
    assert(oot_nvn_resources_call4(r,483,sampler_object,POOL,0,256,&descriptor_result)==2 && descriptor_result==UINT64_MAX);
    assert(!samplers && !r->descriptor_count && !memcmp(&saved_report,&r->report,sizeof(saved_report)));
    sampler_fail_after=0;
    assert(!oot_nvn_resources_call4(r,483,sampler_object,POOL,0,256,&descriptor_result) && descriptor_result==1);
    assert(r->descriptors[0].records[0]==1 && r->descriptors[0].records[32]==2 && r->descriptors[0].records[64]==3);
    assert(samplers==3 && child_devices==1 && r->gpu->report.sampler_anisotropy && r->gpu->report.shader_image_gather_extended);
    call(r,467,POOL,0,0,1);
    assert(call(r,485,sampler_object,0,0,0)==POOL && call(r,486,sampler_object,0,0,0)==0 && call(r,487,sampler_object,0,0,0)==256);
    assert(oot_nvn_resources_call4(r,488,texture_object,POOL,0,256,&descriptor_result)==1);
    OotGpuBuffer *blocked=NULL;uint64_t blocked_offset=UINT64_MAX;assert(!oot_nvn_resources_resolve(r,STORAGE,32,&blocked,&blocked_offset));
    put(&m,sampler_object,1,5);call(r,487,sampler_object,0,0,2);put(&m,sampler_object,1,0);
    call(r,484,sampler_object,0,0,0);call(r,487,sampler_object,0,0,1);assert(!samplers);
    assert(!oot_nvn_resources_call4(r,488,texture_object,POOL,0,256,&descriptor_result) && descriptor_result==1);
    assert(call(r,490,texture_object,0,0,0)==POOL && call(r,491,texture_object,0,0,0)==0 && call(r,492,texture_object,0,0,0)==256);
    call(r,489,texture_object,0,0,0);assert(!r->report.descriptor_pools && !r->report.descriptor_slots);
    for(unsigned n=0;n<40;n+=8)put(&m,BUFFER_BUILDER+n,8,0);
    put(&m,BUFFER_BUILDER+8,8,BASE+0x100);put(&m,BUFFER_BUILDER+16,8,POOL);
    put(&m,BUFFER_BUILDER+24,8,32);put(&m,BUFFER_BUILDER+32,8,4096);
    assert(call(r,474,BUFFER,BUFFER_BUILDER,0,0)==1);
    assert(call(r,476,BUFFER,0,0,0)==STORAGE+32 && call(r,477,BUFFER,0,0,0)==STORAGE+32);
    assert(call(r,478,BUFFER,0,0,0)==POOL && call(r,479,BUFFER,0,0,0)==32 && call(r,480,BUFFER,0,0,0)==4096);
    call(r,467,POOL,0,0,1);call(r,474,BUFFER,BUFFER_BUILDER,0,1);
    put(&m,POOL,1,7);call(r,468,POOL,0,0,2);call(r,476,BUFFER,0,0,2);put(&m,POOL,1,0);
    uint8_t input[8192],output[8192];for(unsigned n=0;n<sizeof(input);++n)input[n]=(uint8_t)(n*13+7);
    OotServiceWrite w={STORAGE,input,sizeof(input)};assert(oot_memory_store_service(&m,&w,1));
    call(r,471,POOL,0,sizeof(input),0);assert(oot_gpu_download(r->gpu,r->pools[0].shadow,0,output,sizeof(output)) && !memcmp(input,output,sizeof(input)));
    put(&m,STORAGE+32,8,UINT64_C(0x123456789abcdef));
    OotGpuBuffer *resolved=NULL;uint64_t offset=UINT64_MAX;
    assert(oot_nvn_resources_resolve(r,STORAGE+32,8,&resolved,&offset) && offset==32);
    assert(oot_gpu_download(r->gpu,resolved,offset,output,8));
    for(unsigned n=0;n<8;++n)assert(output[n]==(uint8_t)(UINT64_C(0x123456789abcdef)>>(n*8)));
    call(r,481,BUFFER,4090,7,1);call(r,471,POOL,UINT64_MAX,1,1);call(r,482,BUFFER,0,4096,0);call(r,472,POOL,0,8192,0);
    memset(output,0x55,sizeof(output));regions[1].permissions=0;
    assert(!oot_memory_capture_service(&m,STORAGE,output,sizeof(output),3));for(unsigned n=0;n<sizeof(output);++n)assert(output[n]==0x55);
    assert(!oot_nvn_resources_resolve(r,STORAGE,8192,&resolved,&offset));regions[1].permissions=3;
    assert(!oot_memory_capture_service(&m,STORAGE,guest,8,1));assert(!oot_memory_probe(&m,STORAGE,17,1));
    assert(!oot_memory_capture_service(&m,STORAGE,output,0,1) && !oot_memory_capture_service(&m,UINT64_MAX,output,2,1));
    assert(!oot_memory_probe_service(&m,STORAGE,OOT_MEMORY_SERVICE_WRITE_LIMIT+1,3));
    DWORD thread=r->thread;r->thread^=1;call(r,468,POOL,0,0,2);r->thread=thread;
    uint64_t saved=r->report.maps;r->report.maps=UINT64_MAX;call(r,468,POOL,0,0,2);r->report.maps=saved;
    uint64_t second=POOL+0x700,second_storage=BASE+0xc000,registered=POOL+0x900,builder=BASE+0x2800,sampler_object_copy=BASE+0x2900;
    put(&m,BUILDER+16,8,second_storage);put(&m,BUILDER+24,8,16384);call(r,466,second,BUILDER,0,0);pool_builder(&m);
    assert(!oot_nvn_resources_call4(r,483,registered,second,0,512,&descriptor_result));
    for(unsigned n=0;n<48;n+=8)put(&m,builder+n,8,0);
    put(&m,builder,8,BASE+0x100);put(&m,builder+12,4,0x447a0000);put(&m,builder+20,4,0x3f800000);put(&m,builder+44,4,0x08010777);
    call(r,494,registered,255,builder,1);call(r,494,registered,512,builder,1);
    call(r,494,registered,256,builder,0);assert(r->report.sampler_registrations==1);
    uint32_t slot=r->descriptors[2].sampler_slots[256];assert(slot && r->samplers[slot-1].info.min_filter==1 && r->samplers[slot-1].info.mag_filter==0 && r->samplers[slot-1].info.max_lod==0.25f);
    uint8_t sampler_bytes[48];assert(oot_memory_load_record(&m,builder,sampler_bytes,48));OotServiceWrite sw={sampler_object_copy+8,sampler_bytes,48};assert(oot_memory_store_service(&m,&sw,1));
    call(r,493,registered,257,sampler_object_copy,0);assert(r->descriptors[2].sampler_slots[257]==slot && r->samplers[slot-1].references==2);
    put(&m,builder,8,BASE+0x108);call(r,494,registered,258,builder,1);put(&m,builder,8,BASE+0x100);
    put(&m,builder+24,4,0x3f800000);call(r,494,registered,258,builder,1);put(&m,builder+24,4,0);
    put(&m,builder+44,4,0x08010770);call(r,494,registered,258,builder,1);put(&m,builder+44,4,0x08010777);
    OotNvnResourcesReport registered_report;assert(oot_nvn_resources_snapshot(r,&registered_report) && registered_report.samplers==4);
    uint32_t saved_slot=r->descriptors[2].sampler_slots[511];r->descriptors[2].sampler_slots[511]=999;
    call(r,484,registered,0,0,2);assert(samplers==4);r->descriptors[2].sampler_slots[511]=saved_slot;
    call(r,484,registered,0,0,0);assert(!samplers);call(r,467,second,0,0,0);
    call(r,475,BUFFER,0,0,0);call(r,476,BUFFER,0,0,1);call(r,474,BUFFER,BUFFER_BUILDER,0,1);
    call(r,467,POOL,0,0,0);call(r,468,POOL,0,0,1);call(r,466,POOL,BUILDER,0,1);call(r,466,POOL+256,BUILDER,0,1);
    assert(!r->report.pools && !r->report.buffers);oot_nvn_resources_destroy(r);
    assert(!refs && !pools && !fences && !buffers && !allocations && !maps);
    memset(input,0x19,sizeof(input));assert(oot_memory_store_service(&m,&w,1));
    Publication pub={regions,CreateEventW(NULL,TRUE,FALSE,NULL)};assert(pub.start);
    HANDLE worker=CreateThread(NULL,0,publish,&pub,0,NULL);assert(worker);SetEvent(pub.start);
    for(unsigned n=0;n<4000;++n){assert(oot_memory_capture_service(&m,STORAGE,output,sizeof(output),3));
        assert(output[0]==0x19 || output[0]==0xa7);for(unsigned i=1;i<sizeof(output);++i)assert(output[i]==output[0]);}
    assert(WaitForSingleObject(worker,10000)==WAIT_OBJECT_0);CloseHandle(worker);CloseHandle(pub.start);
    puts("NVN resource ownership, logical addresses, recapture, rollback and publication passed.");return 0;
}
