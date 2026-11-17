/* Explicit physical Vulkan probe. Synthetic data only; not a game frame. */
#include "native_gpu.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
int main(void)
{
    int ok=0;OotGraphics *graphics=oot_graphics_create();OotGpu *gpu=NULL;
    OotArm64State state={0},out;OotGraphicsReport gr={0};OotGpuReport report={0};
    state.pc=0x1000;state.sp=0x3000;state.x[30]=0x2000;
    if(!graphics || oot_graphics_call(graphics,OOT_GRAPHICS_BOOT,&state,&out))goto done;
    if(!oot_graphics_snapshot(graphics,&gr))goto done;
    gpu=oot_gpu_create(graphics);if(!gpu)goto done;
    /* The child retains its device owner even after the initial borrow is gone. */
    oot_graphics_destroy(graphics);graphics=NULL;
    OotGpuBuffer *a=oot_gpu_buffer_create(gpu,8192),*b=oot_gpu_buffer_create(gpu,8192);
    if(!a || !b)goto done;
    uint8_t source[8192],dest[8192];
    for(unsigned iteration=0;iteration<16;++iteration){
        for(unsigned n=0;n<sizeof(source);++n)source[n]=(uint8_t)(n*37+iteration*19);
        memset(dest,0xa5,sizeof(dest));
        if(!oot_gpu_upload(gpu,a,0,source,sizeof(source)) || !oot_gpu_copy(gpu,a,0,b,0,sizeof(source)) ||
           !oot_gpu_copy(gpu,b,0,a,0,sizeof(source)) || !oot_gpu_download(gpu,a,0,dest,sizeof(dest)) ||
           memcmp(source,dest,sizeof(source)))goto done;
    }
    OotGpuTexturePool *pool=oot_gpu_texture_pool_create(gpu,4);if(!pool)goto done;
    for(unsigned format=OOT_GPU_RGBA8;format<=OOT_GPU_BGRA8;++format){
        OotGpuTexture *texture=oot_gpu_texture_create(gpu,37,29,format),*resolved=NULL;
        if(!texture || !oot_gpu_texture_pool_set(gpu,pool,format,texture) ||
           !oot_gpu_texture_pool_get(gpu,pool,format,&resolved) || resolved!=texture ||
           oot_gpu_texture_destroy(gpu,texture))goto done;
        for(unsigned iteration=0;iteration<8;++iteration){
            for(unsigned n=0;n<sizeof(source);++n)source[n]=(uint8_t)(n*31+iteration*17+format);
            memset(dest,0xa5,sizeof(dest));
            if(!oot_gpu_upload(gpu,a,0,source,sizeof(source)) || !oot_gpu_texture_upload(gpu,texture,a,4) ||
               !oot_gpu_texture_download(gpu,texture,b,100) || !oot_gpu_download(gpu,b,0,dest,sizeof(dest)) ||
               memcmp(source+4,dest+100,37*29*4))goto done;
        }
        if(!oot_gpu_texture_pool_set(gpu,pool,format,NULL) || !oot_gpu_texture_destroy(gpu,texture))goto done;
    }
    if(!oot_gpu_texture_pool_destroy(gpu,pool))goto done;
    if(!oot_gpu_snapshot(gpu,&report) || report.copies!=32 || report.uploads!=32 || report.downloads!=32 || report.faulted ||
       report.textures || report.texture_bytes || report.texture_uploads!=16 || report.texture_downloads!=16 ||
       report.descriptor_pools || report.descriptor_slots || report.descriptor_updates!=4)goto done;
    ok=1;
done:
    printf("{\"status\":\"%s\",\"vendor\":%u,\"device\":%u,\"api_version\":%u,\"copies\":%" PRIu64
        ",\"uploads\":%" PRIu64 ",\"downloads\":%" PRIu64 ",\"texture_uploads\":%" PRIu64
        ",\"texture_downloads\":%" PRIu64 ",\"descriptor_updates\":%" PRIu64 ",\"live_textures\":%" PRIu64
        ",\"synthetic_data_only\":true,\"game_frame_proven\":false}\n",
        ok?"passed":"failed",gr.vendor_id,gr.device_id,gr.api_version,report.copies,report.uploads,report.downloads,
        report.texture_uploads,report.texture_downloads,report.descriptor_updates,report.textures);
    oot_gpu_destroy(gpu);oot_graphics_destroy(graphics);return ok?0:1;
}
