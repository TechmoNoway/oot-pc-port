#ifndef OOT_NATIVE_GPU_H
#define OOT_NATIVE_GPU_H
#include "native_graphics.h"
#include <stddef.h>
typedef struct OotGpu OotGpu;
typedef struct OotGpuBuffer OotGpuBuffer;
typedef struct OotGpuReport {
    uint64_t buffers,bytes,uploads,downloads,copies;
    uint32_t faulted,reserved;
} OotGpuReport;
/* Independent host renderer foundation, not NVN guest object publication.
 * Retains the real graphics owner. All calls, queue access and destruction run
 * serially on the creator thread. Buffers die with the GPU owner. */
OotGpu *oot_gpu_create(OotGraphics *graphics);
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
#endif
