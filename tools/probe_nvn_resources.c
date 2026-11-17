/* Explicit physical resource probe; synthetic guest storage, never game draws. */
#include "../src/native_nvn_resources.c"
#include <stdio.h>
#include <inttypes.h>
static uint8_t guest[4*1024*1024];
static int put(OotGuestMemory *m,uint64_t at,unsigned n,uint64_t value){return oot_memory_store(m,at,n,value);}
int main(void)
{
    int ok=0;OotGraphics *g=oot_graphics_create();OotNvnResources *r=NULL;
    OotArm64State state={0},out;OotGraphicsReport gr={0};OotNvnResourcesReport rr={0};OotGpuReport gpu={0};
    state.pc=0x1000;state.sp=0x3000;state.x[30]=0x2000;
    OotGuestRegion region={UINT64_C(0x100000000),sizeof(guest),guest,3};OotGuestMemory m;
    uint64_t base=region.base,result,offset=0,peak_slots=0,peak_samplers=0;OotGpuBuffer *source=NULL,*destination=NULL;
    if(!g || oot_graphics_call(g,OOT_GRAPHICS_BOOT,&state,&out) || !oot_graphics_snapshot(g,&gr) || !oot_memory_init(&m,&region,1))goto done;
    r=oot_nvn_resources_create(g,&m,base+0x100,NULL,0);if(!r)goto done;
    oot_graphics_destroy(g);g=NULL;
    if(!put(&m,base+0x2004,4,0x22) || !put(&m,base+0x2008,8,base+0x100) || !put(&m,base+0x2010,8,base+0x4000) || !put(&m,base+0x2018,8,2*1024*1024) ||
       oot_nvn_resources_call(r,466,base+0x1000,base+0x2000,0,&result) || result!=1)goto done;
    if(!put(&m,base+0x2408,8,base+0x100) || !put(&m,base+0x2410,8,base+0x1000) || !put(&m,base+0x2418,8,0x130000) || !put(&m,base+0x2420,8,4096) ||
       oot_nvn_resources_call(r,474,base+0x1400,base+0x2400,0,&result) || result!=1)goto done;
    if(oot_nvn_resources_call4(r,483,base+0x1600,base+0x1000,0,4096,&result) || result!=1 ||
       oot_nvn_resources_call4(r,488,base+0x1800,base+0x1000,131072,33068,&result) || result!=1)goto done;
    if(r->report.descriptor_slots!=37164 || r->report.descriptor_pools!=2)goto done;
    if(!put(&m,base+0x2800,8,base+0x100) || !put(&m,base+0x280c,4,0x447a0000) || !put(&m,base+0x2814,4,0x3f800000) ||
       !put(&m,base+0x282c,4,0x08110111) || oot_nvn_resources_call(r,494,base+0x1600,256,base+0x2800,&result))goto done;
    uint8_t builder[48];if(!oot_memory_load_record(&m,base+0x2800,builder,48))goto done;
    OotServiceWrite sampler_write={base+0x2908,builder,48};
    if(!oot_memory_store_service(&m,&sampler_write,1) || oot_nvn_resources_call(r,493,base+0x1600,257,base+0x2900,&result) ||
       !oot_nvn_resources_snapshot(r,&rr) || rr.samplers!=4 || rr.sampler_registrations!=2)goto done;
    peak_slots=rr.descriptor_slots;peak_samplers=rr.samplers;
    destination=oot_gpu_buffer_create(r->gpu,8192);if(!destination)goto done;
    uint8_t input[8192],actual[4096];
    for(unsigned iteration=0;iteration<16;++iteration){
        for(unsigned n=0;n<sizeof(input);++n)input[n]=(uint8_t)(n*31+iteration*17);
        OotServiceWrite w={base+0x134000,input,sizeof(input)};
        if(!oot_memory_store_service(&m,&w,1) || !oot_nvn_resources_resolve(r,base+0x134040,4096,&source,&offset) || offset!=0x130040 ||
           !oot_gpu_copy(r->gpu,source,offset,destination,32,4096) || !oot_gpu_download(r->gpu,destination,32,actual,sizeof(actual)) ||
           memcmp(actual,input+64,sizeof(actual)))goto done;
    }
    if(!oot_gpu_buffer_destroy(r->gpu,destination) || oot_nvn_resources_call(r,475,base+0x1400,0,0,&result) ||
       oot_nvn_resources_call(r,484,base+0x1600,0,0,&result) || oot_nvn_resources_call(r,489,base+0x1800,0,0,&result) || oot_nvn_resources_call(r,467,base+0x1000,0,0,&result) || !oot_nvn_resources_snapshot(r,&rr) ||
       !oot_gpu_snapshot(r->gpu,&gpu) || rr.pools || rr.buffers || rr.bytes || rr.initializations!=2 || rr.finalizations!=2 ||
       rr.descriptor_pools || rr.descriptor_slots || rr.descriptor_initializations!=2 || rr.descriptor_finalizations!=2 ||
       rr.samplers || rr.sampler_registrations!=2 || !gpu.sampler_anisotropy || !gpu.shader_image_gather_extended ||
       gpu.buffers || gpu.copies!=16 || gpu.uploads!=16 || gpu.downloads!=16 || gpu.faulted)goto done;
    ok=1;
done:
    printf("{\"status\":\"%s\",\"vendor\":%u,\"device\":%u,\"copies\":%" PRIu64 ",\"recaptures\":%" PRIu64
        ",\"readbacks\":%" PRIu64 ",\"initializations\":%" PRIu64 ",\"finalizations\":%" PRIu64
        ",\"peak_descriptor_slots\":%" PRIu64 ",\"peak_samplers\":%" PRIu64 ",\"sampler_registrations\":%" PRIu64 ",\"sampler_anisotropy\":%u,\"shader_image_gather_extended\":%u,\"descriptor_initializations\":2,\"descriptor_finalizations\":2,\"synthetic_data_only\":true,\"game_frame_proven\":false}\n",ok?"passed":"failed",gr.vendor_id,gr.device_id,
        gpu.copies,gpu.uploads,gpu.downloads,rr.initializations,rr.finalizations,peak_slots,peak_samplers,rr.sampler_registrations,gpu.sampler_anisotropy,gpu.shader_image_gather_extended);
    oot_nvn_resources_destroy(r);oot_graphics_destroy(g);return ok?0:1;
}
