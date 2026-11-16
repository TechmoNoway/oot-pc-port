#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "native_gpu.h"
#include "native_graphics_internal.h"
#define GPU_MAX_BUFFER (UINT64_C(64)*1024*1024)
#define GPU_COMMANDS(X) \
 X(CreateCommandPool) X(DestroyCommandPool) X(AllocateCommandBuffers) X(ResetCommandPool) \
 X(CreateFence) X(DestroyFence) X(ResetFences) X(WaitForFences) X(DeviceWaitIdle) \
 X(CreateBuffer) X(DestroyBuffer) X(GetBufferMemoryRequirements) X(AllocateMemory) \
 X(FreeMemory) X(BindBufferMemory) X(MapMemory) X(UnmapMemory) X(BeginCommandBuffer) \
 X(EndCommandBuffer) X(CmdPipelineBarrier) X(CmdCopyBuffer) X(QueueSubmit)
struct OotGpuBuffer {
    struct OotGpuBuffer *next;
    VkBuffer buffer;VkDeviceMemory memory;void *mapped;uint64_t size;
};
struct OotGpu {
    OotGraphics *graphics;OotGraphicsVulkan vk;DWORD thread;
    VkCommandPool pool;VkCommandBuffer command;VkFence fence;uint32_t pending;
    OotGpuBuffer *buffers;OotGpuReport report;
#define DECLARE(n) PFN_vk##n n;
    GPU_COMMANDS(DECLARE)
#undef DECLARE
};
static int gpu_disjoint(const void *a,size_t an,const void *b,size_t bn)
{ uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<=y?y-x>=an:x-y>=bn; }
static int gpu_live(const OotGpu *g)
{ return g && g->thread==GetCurrentThreadId() && !g->report.faulted && !g->pending; }
static int gpu_buffer(const OotGpu *g,const OotGpuBuffer *b,uint64_t at,uint64_t size)
{
    const OotGpuBuffer *p=g->buffers;while(p && p!=b)p=p->next;
    return p && size && at<=p->size && size<=p->size-at;
}
static void gpu_release_buffer(OotGpu *g,OotGpuBuffer *b)
{
    if(b->mapped)g->UnmapMemory(g->vk.device,b->memory);
    if(b->buffer)g->DestroyBuffer(g->vk.device,b->buffer,NULL);
    if(b->memory)g->FreeMemory(g->vk.device,b->memory,NULL);
    free(b);
}
void oot_gpu_destroy(OotGpu *g)
{
    if(!g || g->thread!=GetCurrentThreadId())return;
    if(g->pending && g->DeviceWaitIdle)g->DeviceWaitIdle(g->vk.device);
    while(g->buffers){OotGpuBuffer *b=g->buffers;g->buffers=b->next;gpu_release_buffer(g,b);}
    if(g->fence && g->DestroyFence)g->DestroyFence(g->vk.device,g->fence,NULL);
    if(g->pool && g->DestroyCommandPool)g->DestroyCommandPool(g->vk.device,g->pool,NULL);
    if(g->graphics)oot_graphics_destroy(g->graphics);
    memset(g,0,sizeof(*g));free(g);
}
OotGpu *oot_gpu_create(OotGraphics *graphics)
{
    OotGpu *g=calloc(1,sizeof(*g));if(!g)return NULL;g->thread=GetCurrentThreadId();
    if(!oot_graphics_acquire_vulkan(graphics,&g->vk)){free(g);return NULL;}g->graphics=graphics;
#define LOAD(n) {PFN_vkVoidFunction p=g->vk.get_device(g->vk.device,"vk"#n);if(!p)goto fail;memcpy(&g->n,&p,sizeof(p));}
    GPU_COMMANDS(LOAD)
#undef LOAD
    VkCommandPoolCreateInfo pool={0};VkCommandPool created_pool=VK_NULL_HANDLE;
    pool.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;pool.queueFamilyIndex=g->vk.family;
    pool.flags=VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    if(g->CreateCommandPool(g->vk.device,&pool,NULL,&created_pool)!=VK_SUCCESS)goto fail;
    g->pool=created_pool;
    VkCommandBufferAllocateInfo command={0};VkCommandBuffer created_command=VK_NULL_HANDLE;
    command.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;command.commandPool=g->pool;
    command.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;command.commandBufferCount=1;
    if(g->AllocateCommandBuffers(g->vk.device,&command,&created_command)!=VK_SUCCESS)goto fail;
    g->command=created_command;
    VkFenceCreateInfo fence={0};VkFence created_fence=VK_NULL_HANDLE;fence.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    if(g->CreateFence(g->vk.device,&fence,NULL,&created_fence)!=VK_SUCCESS)goto fail;
    g->fence=created_fence;
    if(!g->pool || !g->command || !g->fence)goto fail;
    return g;
fail:oot_gpu_destroy(g);return NULL;
}
int oot_gpu_snapshot(const OotGpu *g,OotGpuReport *out)
{
    if(!g || !out || !gpu_disjoint(g,sizeof(*g),out,sizeof(*out)))return 0;
    *out=g->report;return 1;
}
OotGpuBuffer *oot_gpu_buffer_create(OotGpu *g,uint64_t size)
{
    if(!gpu_live(g) || !size || size>GPU_MAX_BUFFER || g->report.buffers>=128 ||
       g->report.bytes>UINT64_MAX-size)return NULL;
    OotGpuBuffer *b=calloc(1,sizeof(*b));if(!b)return NULL;b->size=size;
    VkBufferCreateInfo info={0};VkBuffer created_buffer=VK_NULL_HANDLE;info.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    info.size=size;info.usage=VK_BUFFER_USAGE_TRANSFER_SRC_BIT|VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    info.sharingMode=VK_SHARING_MODE_EXCLUSIVE;
    if(g->CreateBuffer(g->vk.device,&info,NULL,&created_buffer)!=VK_SUCCESS)goto fail;
    b->buffer=created_buffer;
    if(!b->buffer)goto fail;
    VkMemoryRequirements requirements={0};g->GetBufferMemoryRequirements(g->vk.device,b->buffer,&requirements);
    if(requirements.size<size || !requirements.memoryTypeBits)goto fail;
    unsigned type;
    for(type=0;type<g->vk.memory.memoryTypeCount;++type)
        if((requirements.memoryTypeBits&(1u<<type)) && (g->vk.memory.memoryTypes[type].propertyFlags&
            (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT))==
            (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT))break;
    if(type==g->vk.memory.memoryTypeCount)goto fail;
    VkMemoryAllocateInfo allocation={0};VkDeviceMemory created_memory=VK_NULL_HANDLE;
    allocation.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;allocation.allocationSize=requirements.size;allocation.memoryTypeIndex=type;
    if(g->AllocateMemory(g->vk.device,&allocation,NULL,&created_memory)!=VK_SUCCESS)goto fail;
    b->memory=created_memory;
    if(!b->memory || g->BindBufferMemory(g->vk.device,b->buffer,b->memory,0)!=VK_SUCCESS)goto fail;
    void *mapped=NULL;if(g->MapMemory(g->vk.device,b->memory,0,requirements.size,0,&mapped)!=VK_SUCCESS)goto fail;
    if(!mapped)goto fail;
    b->mapped=mapped;
    b->next=g->buffers;g->buffers=b;++g->report.buffers;g->report.bytes+=size;return b;
fail:gpu_release_buffer(g,b);return NULL;
}
int oot_gpu_buffer_destroy(OotGpu *g,OotGpuBuffer *b)
{
    if(!gpu_live(g) || !gpu_buffer(g,b,0,1))return 0;
    OotGpuBuffer **p=&g->buffers;while(*p!=b)p=&(*p)->next;*p=b->next;
    --g->report.buffers;g->report.bytes-=b->size;gpu_release_buffer(g,b);return 1;
}
int oot_gpu_upload(OotGpu *g,OotGpuBuffer *b,uint64_t offset,const void *bytes,size_t size)
{
    if(!gpu_live(g) || !bytes || !gpu_buffer(g,b,offset,size) || g->report.uploads==UINT64_MAX ||
       !gpu_disjoint(bytes,size,g,sizeof(*g)) || !gpu_disjoint(bytes,size,b,sizeof(*b)))return 0;
    memmove((uint8_t*)b->mapped+offset,bytes,size);++g->report.uploads;return 1;
}
int oot_gpu_download(OotGpu *g,OotGpuBuffer *b,uint64_t offset,void *bytes,size_t size)
{
    if(!gpu_live(g) || !bytes || !gpu_buffer(g,b,offset,size) || g->report.downloads==UINT64_MAX ||
       !gpu_disjoint(bytes,size,g,sizeof(*g)) || !gpu_disjoint(bytes,size,b,sizeof(*b)))return 0;
    memmove(bytes,(uint8_t*)b->mapped+offset,size);++g->report.downloads;return 1;
}
int oot_gpu_copy(OotGpu *g,OotGpuBuffer *source,uint64_t source_offset,OotGpuBuffer *dest,uint64_t dest_offset,uint64_t size)
{
    if(!gpu_live(g) || !gpu_buffer(g,source,source_offset,size) || !gpu_buffer(g,dest,dest_offset,size) ||
       (source==dest && (source_offset<=dest_offset?size>dest_offset-source_offset:size>source_offset-dest_offset)) ||
       ((source_offset|dest_offset|size)&3) || g->report.copies==UINT64_MAX)return 0;
    if(g->ResetCommandPool(g->vk.device,g->pool,0)!=VK_SUCCESS || g->ResetFences(g->vk.device,1,&g->fence)!=VK_SUCCESS)goto fail;
    VkCommandBufferBeginInfo begin={0};begin.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;begin.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if(g->BeginCommandBuffer(g->command,&begin)!=VK_SUCCESS)goto fail;
    VkMemoryBarrier barrier={0};barrier.sType=VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    barrier.srcAccessMask=VK_ACCESS_HOST_WRITE_BIT|VK_ACCESS_TRANSFER_WRITE_BIT;
    barrier.dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT|VK_ACCESS_TRANSFER_WRITE_BIT;
    g->CmdPipelineBarrier(g->command,VK_PIPELINE_STAGE_HOST_BIT|VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,0,1,&barrier,0,NULL,0,NULL);
    VkBufferCopy region={source_offset,dest_offset,size};g->CmdCopyBuffer(g->command,source->buffer,dest->buffer,1,&region);
    barrier.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;barrier.dstAccessMask=VK_ACCESS_HOST_READ_BIT;
    g->CmdPipelineBarrier(g->command,VK_PIPELINE_STAGE_TRANSFER_BIT,VK_PIPELINE_STAGE_HOST_BIT,0,1,&barrier,0,NULL,0,NULL);
    if(g->EndCommandBuffer(g->command)!=VK_SUCCESS)goto fail;
    VkSubmitInfo submit={0};submit.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;submit.commandBufferCount=1;submit.pCommandBuffers=&g->command;
    if(g->QueueSubmit(g->vk.queue,1,&submit,g->fence)!=VK_SUCCESS)goto fail;
    g->pending=1;
    if(g->WaitForFences(g->vk.device,1,&g->fence,VK_TRUE,UINT64_C(5000000000))!=VK_SUCCESS)goto fail;
    g->pending=0;++g->report.copies;return 1;
fail:g->report.faulted=1;return 0;
}
