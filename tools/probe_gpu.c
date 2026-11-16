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
    if(!oot_gpu_snapshot(gpu,&report) || report.copies!=32 || report.uploads!=16 || report.downloads!=16 || report.faulted)goto done;
    ok=1;
done:
    printf("{\"status\":\"%s\",\"vendor\":%u,\"device\":%u,\"api_version\":%u,\"copies\":%" PRIu64
        ",\"uploads\":%" PRIu64 ",\"downloads\":%" PRIu64 ",\"synthetic_data_only\":true,\"game_frame_proven\":false}\n",
        ok?"passed":"failed",gr.vendor_id,gr.device_id,gr.api_version,report.copies,report.uploads,report.downloads);
    oot_gpu_destroy(gpu);oot_graphics_destroy(graphics);return ok?0:1;
}
