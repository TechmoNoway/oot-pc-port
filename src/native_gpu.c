#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "native_gpu.h"
#include "native_graphics_internal.h"
#include <math.h>
#define GPU_MAX_BUFFER (UINT64_C(64)*1024*1024)
#define GPU_COMMANDS(X) \
 X(CreateCommandPool) X(DestroyCommandPool) X(AllocateCommandBuffers) X(ResetCommandPool) \
 X(CreateFence) X(DestroyFence) X(ResetFences) X(WaitForFences) X(DeviceWaitIdle) \
 X(CreateBuffer) X(DestroyBuffer) X(GetBufferMemoryRequirements) X(AllocateMemory) \
 X(FreeMemory) X(BindBufferMemory) X(MapMemory) X(UnmapMemory) X(BeginCommandBuffer) \
 X(EndCommandBuffer) X(CmdPipelineBarrier) X(CmdCopyBuffer) X(QueueSubmit) \
 X(CreateImage) X(DestroyImage) X(GetImageMemoryRequirements) X(BindImageMemory) \
 X(CreateImageView) X(DestroyImageView) X(CmdCopyBufferToImage) X(CmdCopyImageToBuffer) X(CreateSampler) X(DestroySampler)
struct OotGpuBuffer {
    struct OotGpuBuffer *next;
    VkBuffer buffer;VkDeviceMemory memory;void *mapped;uint64_t size;
};
struct OotGpuTexture {
    struct OotGpuTexture *next;
    VkImage image;VkImageView view;VkDeviceMemory memory;
    VkImageLayout layout;OotGpuTextureInfo info;
    uint64_t identity;
};
typedef struct GpuTextureDescriptor {uint64_t identity,width_height,format,reserved;} GpuTextureDescriptor;
_Static_assert(sizeof(GpuTextureDescriptor)==OOT_GPU_TEXTURE_DESCRIPTOR_SIZE,"private texture descriptor stride");
struct OotGpuTexturePool {
    struct OotGpuTexturePool *next;
    GpuTextureDescriptor *slots;
    uint32_t count;
};
struct OotGpuSampler {
    struct OotGpuSampler *next;VkSampler sampler;OotGpuSamplerInfo info;uint64_t references;
};
struct OotGpu {
    OotGraphics *graphics;OotGraphicsVulkan vk;DWORD thread;
    VkCommandPool pool;VkCommandBuffer command;VkFence fence;uint32_t pending;
    OotGpuBuffer *buffers;OotGpuReport report;
    OotGpuTexture *textures;OotGpuTexturePool *texture_pools;
    uint32_t texture_identities,pool_identities;
    OotGpuSampler *samplers;uint32_t sampler_identities,child_device;
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
static void gpu_release_texture(OotGpu *g,OotGpuTexture *t)
{
    if(t->view)g->DestroyImageView(g->vk.device,t->view,NULL);
    if(t->image)g->DestroyImage(g->vk.device,t->image,NULL);
    if(t->memory)g->FreeMemory(g->vk.device,t->memory,NULL);
    t->view=VK_NULL_HANDLE;t->image=VK_NULL_HANDLE;t->memory=VK_NULL_HANDLE;
}
void oot_gpu_destroy(OotGpu *g)
{
    if(!g || g->thread!=GetCurrentThreadId())return;
    if(g->pending && g->DeviceWaitIdle)g->DeviceWaitIdle(g->vk.device);
    while(g->texture_pools){OotGpuTexturePool *p=g->texture_pools;g->texture_pools=p->next;free(p->slots);free(p);}
    while(g->textures){OotGpuTexture *t=g->textures;g->textures=t->next;gpu_release_texture(g,t);free(t);}
    while(g->samplers){OotGpuSampler *s=g->samplers;g->samplers=s->next;if(s->sampler)g->DestroySampler(g->vk.device,s->sampler,NULL);free(s);}
    while(g->buffers){OotGpuBuffer *b=g->buffers;g->buffers=b->next;gpu_release_buffer(g,b);}
    if(g->fence && g->DestroyFence)g->DestroyFence(g->vk.device,g->fence,NULL);
    if(g->pool && g->DestroyCommandPool)g->DestroyCommandPool(g->vk.device,g->pool,NULL);
    if(g->child_device)g->vk.destroy_device(g->vk.device,NULL);
    if(g->graphics)oot_graphics_destroy(g->graphics);
    memset(g,0,sizeof(*g));free(g);
}
static OotGpu *gpu_create(OotGraphics *graphics,int renderer)
{
    OotGpu *g=calloc(1,sizeof(*g));if(!g)return NULL;g->thread=GetCurrentThreadId();
    if(!oot_graphics_acquire_vulkan(graphics,&g->vk)){free(g);return NULL;}g->graphics=graphics;
    if(renderer){
        VkPhysicalDeviceFeatures available={0},enabled={0};
        if(!g->vk.features || !g->vk.create_device || !g->vk.destroy_device)goto fail;
        g->vk.features(g->vk.physical,&available);
        if(!available.samplerAnisotropy || !available.shaderImageGatherExtended)goto fail;
        enabled.samplerAnisotropy=enabled.shaderImageGatherExtended=VK_TRUE;
        float priority=1;VkDeviceQueueCreateInfo queue={0};queue.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        queue.queueFamilyIndex=g->vk.family;queue.queueCount=1;queue.pQueuePriorities=&priority;
        VkDeviceCreateInfo device={0};device.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        device.queueCreateInfoCount=1;device.pQueueCreateInfos=&queue;device.pEnabledFeatures=&enabled;
        const char *extension=VK_KHR_SWAPCHAIN_EXTENSION_NAME;
        device.enabledExtensionCount=1;device.ppEnabledExtensionNames=&extension;
        VkDevice created=VK_NULL_HANDLE;
        if(g->vk.create_device(g->vk.physical,&device,NULL,&created)!=VK_SUCCESS)goto fail;
        if(!created)goto fail;
        g->vk.device=created;g->child_device=1;g->vk.queue=VK_NULL_HANDLE;
        PFN_vkGetDeviceQueue get_queue=NULL;PFN_vkVoidFunction proc=g->vk.get_device(created,"vkGetDeviceQueue");
        if(!proc)goto fail;
        memcpy(&get_queue,&proc,sizeof(proc));get_queue(created,g->vk.family,0,&g->vk.queue);
        if(!g->vk.queue)goto fail;
        g->report.sampler_anisotropy=g->report.shader_image_gather_extended=1;
    }
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
OotGpu *oot_gpu_create(OotGraphics *graphics){return gpu_create(graphics,0);}
OotGpu *oot_gpu_create_renderer(OotGraphics *graphics){return gpu_create(graphics,1);}
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

static OotGpuTexture *gpu_texture(const OotGpu *g,const OotGpuTexture *candidate)
{
    OotGpuTexture *t=g->textures;while(t && t!=candidate)t=t->next;
    return t && t->image ? t:NULL;
}
static OotGpuTexturePool *gpu_texture_pool(const OotGpu *g,const OotGpuTexturePool *candidate)
{
    OotGpuTexturePool *p=g->texture_pools;while(p && p!=candidate)p=p->next;
    return p && p->slots ? p:NULL;
}
static int gpu_texture_output(const OotGpu *g,const void *out,size_t size)
{
    if(!out || !gpu_disjoint(out,size,g,sizeof(*g)))return 0;
    for(const OotGpuTexture *t=g->textures;t;t=t->next)if(!gpu_disjoint(out,size,t,sizeof(*t)))return 0;
    for(const OotGpuSampler *s=g->samplers;s;s=s->next)if(!gpu_disjoint(out,size,s,sizeof(*s)))return 0;
    for(const OotGpuTexturePool *p=g->texture_pools;p;p=p->next)
        if(!gpu_disjoint(out,size,p,sizeof(*p)) || (p->slots &&
           !gpu_disjoint(out,size,p->slots,(size_t)p->count*sizeof(*p->slots))))return 0;
    for(const OotGpuBuffer *b=g->buffers;b;b=b->next)
        if(!gpu_disjoint(out,size,b,sizeof(*b)) || !gpu_disjoint(out,size,b->mapped,(size_t)b->size))return 0;
    return 1;
}
OotGpuTexture *oot_gpu_texture_create(OotGpu *g,uint32_t width,uint32_t height,uint32_t format)
{
    VkFormat vf=format==OOT_GPU_RGBA8?VK_FORMAT_R8G8B8A8_UNORM:VK_FORMAT_B8G8R8A8_UNORM;
    VkImageUsageFlags usage=VK_IMAGE_USAGE_TRANSFER_SRC_BIT|VK_IMAGE_USAGE_TRANSFER_DST_BIT|VK_IMAGE_USAGE_SAMPLED_BIT;
    if(!gpu_live(g) || !g->vk.image_format || !width || !height || width>4096 || height>4096 ||
       (format!=OOT_GPU_RGBA8 && format!=OOT_GPU_BGRA8) || g->texture_identities>=128 ||
       width>g->vk.properties.limits.maxImageDimension2D || height>g->vk.properties.limits.maxImageDimension2D)return NULL;
    VkImageFormatProperties supported={0};
    if(g->vk.image_format(g->vk.physical,vf,VK_IMAGE_TYPE_2D,VK_IMAGE_TILING_OPTIMAL,usage,0,&supported)!=VK_SUCCESS ||
       width>supported.maxExtent.width || height>supported.maxExtent.height || !supported.maxExtent.depth ||
       !supported.maxMipLevels || !supported.maxArrayLayers || !(supported.sampleCounts&VK_SAMPLE_COUNT_1_BIT))return NULL;
    OotGpuTexture *t=calloc(1,sizeof(*t));if(!t)return NULL;
    t->info=(OotGpuTextureInfo){width,height,format,0,(uint64_t)width*height*4,0};
    VkImageCreateInfo image={0};image.sType=VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    image.imageType=VK_IMAGE_TYPE_2D;image.format=vf;image.extent=(VkExtent3D){width,height,1};
    image.mipLevels=1;image.arrayLayers=1;image.samples=VK_SAMPLE_COUNT_1_BIT;image.tiling=VK_IMAGE_TILING_OPTIMAL;
    image.usage=usage;image.sharingMode=VK_SHARING_MODE_EXCLUSIVE;image.initialLayout=VK_IMAGE_LAYOUT_UNDEFINED;
    VkImage created=VK_NULL_HANDLE;
    if(g->CreateImage(g->vk.device,&image,NULL,&created)!=VK_SUCCESS)goto fail;
    t->image=created;if(!t->image)goto fail;
    VkMemoryRequirements requirements={0};g->GetImageMemoryRequirements(g->vk.device,t->image,&requirements);
    if(requirements.size<t->info.bytes || requirements.size>GPU_MAX_BUFFER*2 ||
       requirements.size>supported.maxResourceSize || !requirements.memoryTypeBits)goto fail;
    unsigned type;
    for(type=0;type<g->vk.memory.memoryTypeCount;++type)
        if((requirements.memoryTypeBits&(1u<<type)) &&
           (g->vk.memory.memoryTypes[type].propertyFlags&VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT))break;
    if(type==g->vk.memory.memoryTypeCount)goto fail;
    VkMemoryAllocateInfo allocation={0};allocation.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocation.allocationSize=requirements.size;allocation.memoryTypeIndex=type;
    VkDeviceMemory memory=VK_NULL_HANDLE;
    if(g->AllocateMemory(g->vk.device,&allocation,NULL,&memory)!=VK_SUCCESS)goto fail;
    t->memory=memory;if(!memory || g->BindImageMemory(g->vk.device,t->image,memory,0)!=VK_SUCCESS)goto fail;
    VkImageViewCreateInfo view={0};view.sType=VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;view.image=t->image;
    view.viewType=VK_IMAGE_VIEW_TYPE_2D;view.format=vf;
    view.subresourceRange=(VkImageSubresourceRange){VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1};
    VkImageView created_view=VK_NULL_HANDLE;
    if(g->CreateImageView(g->vk.device,&view,NULL,&created_view)!=VK_SUCCESS)goto fail;
    t->view=created_view;if(!t->view)goto fail;
    t->identity=++g->texture_identities;t->next=g->textures;g->textures=t;
    ++g->report.textures;g->report.texture_bytes+=t->info.bytes;return t;
fail:gpu_release_texture(g,t);free(t);return NULL;
}
int oot_gpu_texture_destroy(OotGpu *g,OotGpuTexture *t)
{
    if(!gpu_live(g) || !gpu_texture(g,t) || t->info.descriptor_references)return 0;
    --g->report.textures;g->report.texture_bytes-=t->info.bytes;gpu_release_texture(g,t);return 1;
}
int oot_gpu_texture_info(const OotGpu *g,const OotGpuTexture *t,OotGpuTextureInfo *out)
{
    if(!gpu_live(g) || !gpu_texture(g,t) || !gpu_texture_output(g,out,sizeof(*out)))return 0;
    *out=t->info;return 1;
}
static int gpu_texture_transfer(OotGpu *g,OotGpuTexture *t,OotGpuBuffer *b,uint64_t offset,int download)
{
    if(!gpu_live(g) || !gpu_texture(g,t) || !gpu_buffer(g,b,offset,t->info.bytes) || (offset&3) ||
       (download && t->layout==VK_IMAGE_LAYOUT_UNDEFINED) ||
       (download?g->report.texture_downloads:g->report.texture_uploads)==UINT64_MAX)return 0;
    if(g->ResetCommandPool(g->vk.device,g->pool,0)!=VK_SUCCESS || g->ResetFences(g->vk.device,1,&g->fence)!=VK_SUCCESS)goto fail;
    VkCommandBufferBeginInfo begin={0};begin.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if(g->BeginCommandBuffer(g->command,&begin)!=VK_SUCCESS)goto fail;
    VkMemoryBarrier host={0};host.sType=VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    host.srcAccessMask=VK_ACCESS_HOST_WRITE_BIT|VK_ACCESS_TRANSFER_WRITE_BIT;
    host.dstAccessMask=VK_ACCESS_TRANSFER_READ_BIT|VK_ACCESS_TRANSFER_WRITE_BIT;
    g->CmdPipelineBarrier(g->command,VK_PIPELINE_STAGE_HOST_BIT|VK_PIPELINE_STAGE_TRANSFER_BIT,
        VK_PIPELINE_STAGE_TRANSFER_BIT,0,1,&host,0,NULL,0,NULL);
    VkImageMemoryBarrier image={0};image.sType=VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;image.image=t->image;
    image.oldLayout=t->layout;image.newLayout=download?VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL:VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
    image.srcQueueFamilyIndex=image.dstQueueFamilyIndex=VK_QUEUE_FAMILY_IGNORED;
    image.subresourceRange=(VkImageSubresourceRange){VK_IMAGE_ASPECT_COLOR_BIT,0,1,0,1};
    image.srcAccessMask=t->layout==VK_IMAGE_LAYOUT_UNDEFINED?0:VK_ACCESS_MEMORY_READ_BIT|VK_ACCESS_MEMORY_WRITE_BIT;
    image.dstAccessMask=download?VK_ACCESS_TRANSFER_READ_BIT:VK_ACCESS_TRANSFER_WRITE_BIT;
    g->CmdPipelineBarrier(g->command,VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,VK_PIPELINE_STAGE_TRANSFER_BIT,0,0,NULL,0,NULL,1,&image);
    VkBufferImageCopy copy={0};copy.bufferOffset=offset;
    copy.imageSubresource=(VkImageSubresourceLayers){VK_IMAGE_ASPECT_COLOR_BIT,0,0,1};
    copy.imageExtent=(VkExtent3D){t->info.width,t->info.height,1};
    if(download)g->CmdCopyImageToBuffer(g->command,t->image,image.newLayout,b->buffer,1,&copy);
    else g->CmdCopyBufferToImage(g->command,b->buffer,t->image,image.newLayout,1,&copy);
    image.oldLayout=image.newLayout;image.newLayout=VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    image.srcAccessMask=download?VK_ACCESS_TRANSFER_READ_BIT:VK_ACCESS_TRANSFER_WRITE_BIT;
    image.dstAccessMask=VK_ACCESS_SHADER_READ_BIT;
    host.srcAccessMask=VK_ACCESS_TRANSFER_WRITE_BIT;host.dstAccessMask=VK_ACCESS_HOST_READ_BIT;
    g->CmdPipelineBarrier(g->command,VK_PIPELINE_STAGE_TRANSFER_BIT,
        VK_PIPELINE_STAGE_ALL_COMMANDS_BIT|VK_PIPELINE_STAGE_HOST_BIT,0,1,&host,0,NULL,1,&image);
    if(g->EndCommandBuffer(g->command)!=VK_SUCCESS)goto fail;
    VkSubmitInfo submit={0};submit.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount=1;submit.pCommandBuffers=&g->command;
    if(g->QueueSubmit(g->vk.queue,1,&submit,g->fence)!=VK_SUCCESS)goto fail;
    g->pending=1;
    if(g->WaitForFences(g->vk.device,1,&g->fence,VK_TRUE,UINT64_C(5000000000))!=VK_SUCCESS)goto fail;
    g->pending=0;t->layout=image.newLayout;
    if(download)++g->report.texture_downloads;else ++g->report.texture_uploads;
    return 1;
fail:g->report.faulted=1;return 0;
}
int oot_gpu_texture_upload(OotGpu *g,OotGpuTexture *t,OotGpuBuffer *b,uint64_t offset)
{return gpu_texture_transfer(g,t,b,offset,0);}
int oot_gpu_texture_download(OotGpu *g,OotGpuTexture *t,OotGpuBuffer *b,uint64_t offset)
{return gpu_texture_transfer(g,t,b,offset,1);}
OotGpuTexturePool *oot_gpu_texture_pool_create(OotGpu *g,uint32_t count)
{
    if(!gpu_live(g) || !count || count>4096 || g->pool_identities>=32 || g->report.descriptor_slots>4096-count)return NULL;
    OotGpuTexturePool *p=calloc(1,sizeof(*p));if(!p)return NULL;
    p->slots=calloc(count,sizeof(*p->slots));if(!p->slots){free(p);return NULL;}
    p->count=count;p->next=g->texture_pools;g->texture_pools=p;++g->pool_identities;
    ++g->report.descriptor_pools;g->report.descriptor_slots+=count;return p;
}
static OotGpuTexture *gpu_texture_identity(const OotGpu *g,uint64_t id)
{
    if(!id)return NULL;
    OotGpuTexture *t=g->textures;while(t && t->identity!=id)t=t->next;
    return t && t->image?t:NULL;
}
static int gpu_descriptor_texture(const OotGpu *g,const GpuTextureDescriptor *d,OotGpuTexture **out)
{
    OotGpuTexture *t=gpu_texture_identity(g,d->identity);
    if(d->reserved || (d->identity && (!t || !t->info.descriptor_references ||
        d->width_height!=((uint64_t)t->info.width<<32|t->info.height) || d->format!=t->info.format)) ||
       (!d->identity && (d->format || d->width_height)))return 0;
    *out=t;return 1;
}
int oot_gpu_texture_pool_destroy(OotGpu *g,OotGpuTexturePool *p)
{
    if(!gpu_live(g) || !gpu_texture_pool(g,p))return 0;
    for(unsigned n=0;n<p->count;++n){OotGpuTexture *t;if(!gpu_descriptor_texture(g,p->slots+n,&t))return 0;}
    for(unsigned n=0;n<p->count;++n){OotGpuTexture *t=gpu_texture_identity(g,p->slots[n].identity);if(t)--t->info.descriptor_references;}
    --g->report.descriptor_pools;g->report.descriptor_slots-=p->count;
    free(p->slots);p->slots=NULL;p->count=0;return 1;
}
int oot_gpu_texture_pool_set(OotGpu *g,OotGpuTexturePool *p,uint32_t index,OotGpuTexture *t)
{
    if(!gpu_live(g) || !gpu_texture_pool(g,p) || index>=p->count || (t && !gpu_texture(g,t)) ||
       g->report.descriptor_updates==UINT64_MAX)return 0;
    OotGpuTexture *old;if(!gpu_descriptor_texture(g,p->slots+index,&old))return 0;
    if(old)--old->info.descriptor_references;
    GpuTextureDescriptor d={0};
    if(t){++t->info.descriptor_references;d.identity=t->identity;d.width_height=((uint64_t)t->info.width<<32)|t->info.height;d.format=t->info.format;}
    p->slots[index]=d;++g->report.descriptor_updates;return 1;
}
int oot_gpu_texture_pool_get(const OotGpu *g,const OotGpuTexturePool *p,uint32_t index,OotGpuTexture **out)
{
    if(!gpu_live(g) || !gpu_texture_pool(g,p) || index>=p->count || !gpu_texture_output(g,out,sizeof(*out)))return 0;
    OotGpuTexture *t;if(!gpu_descriptor_texture(g,p->slots+index,&t))return 0;
    *out=t;return 1;
}

_Static_assert(sizeof(OotGpuSamplerInfo)==56,"normalized sampler state has no padding");
static OotGpuSampler *gpu_sampler(const OotGpu *g,const OotGpuSampler *candidate)
{OotGpuSampler *s=g->samplers;while(s && s!=candidate)s=s->next;return s && s->sampler?s:NULL;}
OotGpuSampler *oot_gpu_sampler_create(OotGpu *g,const OotGpuSamplerInfo *input)
{
    if(!gpu_live(g) || !input || g->sampler_identities>=1024 || g->report.samplers>=256 ||
       g->report.samplers>=g->vk.properties.limits.maxSamplerAllocationCount)return NULL;
    OotGpuSamplerInfo i=*input;
    if(i.min_filter>1 || i.mag_filter>1 || i.mipmap_mode>1 || i.address_u>3 || i.address_v>3 || i.address_w>3 ||
       i.compare_enable>1 || i.compare_op>7 || i.border_color>2 || i.reserved ||
       !isfinite(i.min_lod) || !isfinite(i.max_lod) || !isfinite(i.lod_bias) || !isfinite(i.max_anisotropy) ||
       i.min_lod>i.max_lod || fabsf(i.lod_bias)>g->vk.properties.limits.maxSamplerLodBias || i.max_anisotropy<1 ||
       i.max_anisotropy>g->vk.properties.limits.maxSamplerAnisotropy ||
       (i.max_anisotropy>1 && !g->report.sampler_anisotropy))return NULL;
    OotGpuSampler *s=calloc(1,sizeof(*s));if(!s)return NULL;
    VkSamplerCreateInfo c={0};c.sType=VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO;c.minFilter=(VkFilter)i.min_filter;
    c.magFilter=(VkFilter)i.mag_filter;c.mipmapMode=(VkSamplerMipmapMode)i.mipmap_mode;
    c.addressModeU=(VkSamplerAddressMode)i.address_u;c.addressModeV=(VkSamplerAddressMode)i.address_v;c.addressModeW=(VkSamplerAddressMode)i.address_w;
    c.mipLodBias=i.lod_bias;c.minLod=i.min_lod;c.maxLod=i.max_lod;c.anisotropyEnable=i.max_anisotropy>1;
    c.maxAnisotropy=i.max_anisotropy;c.compareEnable=i.compare_enable;c.compareOp=(VkCompareOp)i.compare_op;
    c.borderColor=(VkBorderColor)(i.border_color*2);
    VkSampler created=VK_NULL_HANDLE;
    if(g->CreateSampler(g->vk.device,&c,NULL,&created)!=VK_SUCCESS || !created){free(s);return NULL;}
    s->sampler=created;s->info=i;s->next=g->samplers;g->samplers=s;++g->sampler_identities;++g->report.samplers;return s;
}
int oot_gpu_sampler_destroy(OotGpu *g,OotGpuSampler *s)
{
    if(!gpu_live(g) || !gpu_sampler(g,s) || s->references)return 0;
    g->DestroySampler(g->vk.device,s->sampler,NULL);s->sampler=VK_NULL_HANDLE;--g->report.samplers;return 1;
}
int oot_gpu_sampler_retain(OotGpu *g,OotGpuSampler *s)
{if(!gpu_live(g) || !gpu_sampler(g,s) || s->references==UINT64_MAX)return 0;++s->references;return 1;}
int oot_gpu_sampler_release(OotGpu *g,OotGpuSampler *s)
{if(!gpu_live(g) || !gpu_sampler(g,s) || !s->references)return 0;--s->references;return 1;}
int oot_gpu_sampler_info(const OotGpu *g,const OotGpuSampler *s,OotGpuSamplerInfo *out)
{if(!gpu_live(g) || !gpu_sampler(g,s) || !gpu_texture_output(g,out,sizeof(*out)))return 0;*out=s->info;return 1;}

int oot_gpu_sampler_references(const OotGpu *g,const OotGpuSampler *s,uint64_t *out)
{if(!gpu_live(g) || !gpu_sampler(g,s) || !gpu_texture_output(g,out,sizeof(*out)))return 0;*out=s->references;return 1;}
