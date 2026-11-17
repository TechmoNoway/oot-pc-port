#ifndef OOT_NATIVE_GPU_H
#define OOT_NATIVE_GPU_H
#include "native_graphics.h"
#include <stddef.h>
#include "nvn_layout.h"
typedef struct OotGpu OotGpu;
typedef struct OotGpuBuffer OotGpuBuffer;
typedef struct OotGpuTexture OotGpuTexture;
typedef struct OotGpuTexturePool OotGpuTexturePool;
typedef struct OotGpuSampler OotGpuSampler;
/* Independent normalized host state, not the NVN builder layout. Filter/mipmap
 * are 0 nearest/1 linear; address modes 0 repeat,1 mirror,2 edge,3 border;
 * comparison 0..7 is never..always; border 0 transparent,1 black,2 white. */
typedef struct OotGpuSamplerInfo {
    uint32_t min_filter,mag_filter,mipmap_mode,address_u,address_v,address_w;
    uint32_t compare_enable,compare_op,border_color,reserved;
    float min_lod,max_lod,lod_bias,max_anisotropy;
} OotGpuSamplerInfo;
#define OOT_GPU_RGBA8 1u
#define OOT_GPU_BGRA8 2u
#define OOT_GPU_TEXTURE_DESCRIPTOR_SIZE OOT_NVN_TEXTURE_DESCRIPTOR_SIZE
typedef struct OotGpuTextureInfo {
    uint32_t width,height,format,reserved;
    uint64_t bytes,descriptor_references;
} OotGpuTextureInfo;
typedef struct OotGpuReport {
    uint64_t buffers,bytes,uploads,downloads,copies;
    uint32_t faulted,reserved;
    uint64_t textures,texture_bytes,texture_uploads,texture_downloads;
    uint64_t descriptor_pools,descriptor_slots,descriptor_updates;
    uint64_t samplers;
    uint32_t sampler_anisotropy,shader_image_gather_extended;
} OotGpuReport;
/* Independent host renderer foundation, not NVN guest object publication.
 * Retains the real graphics owner. All calls, queue access and destruction run
 * serially on the creator thread. Buffers die with the GPU owner. */
OotGpu *oot_gpu_create(OotGraphics *graphics);
/* Separate owned logical device; queries and enables both required features.
 * Retains the parent instance/physical device; never mixes parent resources. */
OotGpu *oot_gpu_create_renderer(OotGraphics *graphics);
void oot_gpu_destroy(OotGpu *gpu);
int oot_gpu_snapshot(const OotGpu *gpu,OotGpuReport *out);
OotGpuBuffer *oot_gpu_buffer_create(OotGpu *gpu,uint64_t size);
int oot_gpu_buffer_destroy(OotGpu *gpu,OotGpuBuffer *buffer);
int oot_gpu_upload(OotGpu *gpu,OotGpuBuffer *buffer,uint64_t offset,const void *bytes,size_t size);
int oot_gpu_download(OotGpu *gpu,OotGpuBuffer *buffer,uint64_t offset,void *bytes,size_t size);
/* Synchronous transfer on the owned queue with explicit host/transfer barriers
 * and a real fence. A Vulkan execution failure poisons the owner; it never
 * establishes a successful copy or a frame. */
int oot_gpu_copy(OotGpu *gpu,OotGpuBuffer *source,uint64_t source_offset,
    OotGpuBuffer *destination,uint64_t destination_offset,uint64_t size);
/* Host-only 2D, single-mip/layer, single-sample color images. Pixels are tightly
 * packed; this does not decode NVN block-linear storage or publish guest objects.
 * Image and descriptor identities are never reused within an owner lifetime. */
OotGpuTexture *oot_gpu_texture_create(OotGpu *gpu,uint32_t width,uint32_t height,uint32_t format);
int oot_gpu_texture_destroy(OotGpu *gpu,OotGpuTexture *texture);
int oot_gpu_texture_info(const OotGpu *gpu,const OotGpuTexture *texture,OotGpuTextureInfo *out);
int oot_gpu_texture_upload(OotGpu *gpu,OotGpuTexture *texture,OotGpuBuffer *source,uint64_t offset);
int oot_gpu_texture_download(OotGpu *gpu,OotGpuTexture *texture,OotGpuBuffer *destination,uint64_t offset);
/* Private descriptor records retain live images. They are not native NVIDIA
 * descriptors, Vulkan handles, or bytes to copy into guest memory. */
OotGpuTexturePool *oot_gpu_texture_pool_create(OotGpu *gpu,uint32_t count);
int oot_gpu_texture_pool_destroy(OotGpu *gpu,OotGpuTexturePool *pool);
int oot_gpu_texture_pool_set(OotGpu *gpu,OotGpuTexturePool *pool,uint32_t index,OotGpuTexture *texture);
int oot_gpu_texture_pool_get(const OotGpu *gpu,const OotGpuTexturePool *pool,uint32_t index,OotGpuTexture **out);
OotGpuSampler *oot_gpu_sampler_create(OotGpu*,const OotGpuSamplerInfo*);
int oot_gpu_sampler_destroy(OotGpu*,OotGpuSampler*);
int oot_gpu_sampler_references(const OotGpu*,const OotGpuSampler*,uint64_t*);
int oot_gpu_sampler_retain(OotGpu*,OotGpuSampler*);
int oot_gpu_sampler_release(OotGpu*,OotGpuSampler*);
int oot_gpu_sampler_info(const OotGpu*,const OotGpuSampler*,OotGpuSamplerInfo*);
#endif
