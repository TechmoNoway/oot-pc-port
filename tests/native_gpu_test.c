/* Synthetic Vulkan command/memory lifetime fixture. No driver is loaded. */
#undef NDEBUG
#include "../src/native_gpu.c"
#include <assert.h>
#include <stdio.h>
static unsigned fault,refs,pools,fences,buffers,allocations,maps,idle,next_id=4,barriers;
static unsigned images,views,texture_test,copy_download;
static unsigned widths[256],bindings[256];static void *backing[256];
static VkImage pending_image;static VkBuffer pending_image_buffer;static VkBufferImageCopy image_copy;
static VkImageLayout layouts[256];
static VkBuffer pending_src,pending_dst;static VkBufferCopy pending_copy;
#define ID(h) ((unsigned)(uintptr_t)(h))
#define UNUSED(x) (void)(x)
#define FAIL(n) if(fault==(n))return VK_ERROR_INITIALIZATION_FAILED
static VkResult VKAPI_CALL pool_create(VkDevice d,const VkCommandPoolCreateInfo *i,const VkAllocationCallbacks *a,VkCommandPool *o)
{ UNUSED(d);UNUSED(a);assert(i->queueFamilyIndex==2);FAIL(1);*o=(VkCommandPool)(uintptr_t)1;++pools;return VK_SUCCESS; }
static void VKAPI_CALL pool_destroy(VkDevice d,VkCommandPool p,const VkAllocationCallbacks *a)
{ UNUSED(d);UNUSED(p);UNUSED(a);assert(pools);--pools; }
static VkResult VKAPI_CALL command_allocate(VkDevice d,const VkCommandBufferAllocateInfo *i,VkCommandBuffer *o)
{ UNUSED(d);assert(i->commandBufferCount==1);FAIL(2);*o=(VkCommandBuffer)(uintptr_t)2;return VK_SUCCESS; }
static VkResult VKAPI_CALL pool_reset(VkDevice d,VkCommandPool p,VkCommandPoolResetFlags f)
{ UNUSED(d);UNUSED(p);UNUSED(f);FAIL(9);barriers=0;return VK_SUCCESS; }
static VkResult VKAPI_CALL fence_create(VkDevice d,const VkFenceCreateInfo *i,const VkAllocationCallbacks *a,VkFence *o)
{ UNUSED(d);UNUSED(i);UNUSED(a);FAIL(3);*o=(VkFence)(uintptr_t)3;++fences;return VK_SUCCESS; }
static void VKAPI_CALL fence_destroy(VkDevice d,VkFence f,const VkAllocationCallbacks *a)
{ UNUSED(d);UNUSED(f);UNUSED(a);assert(fences);--fences; }
static VkResult VKAPI_CALL fence_reset(VkDevice d,uint32_t n,const VkFence *f)
{ UNUSED(d);UNUSED(f);assert(n==1);FAIL(10);return VK_SUCCESS; }
static VkResult VKAPI_CALL fence_wait(VkDevice d,uint32_t n,const VkFence *f,VkBool32 all,uint64_t timeout)
{ UNUSED(d);UNUSED(f);assert(n==1 && all && timeout==UINT64_C(5000000000));return fault==14?VK_TIMEOUT:VK_SUCCESS; }
static VkResult VKAPI_CALL device_idle(VkDevice d)
{ UNUSED(d);++idle;return VK_SUCCESS; }
static VkResult VKAPI_CALL buffer_create(VkDevice d,const VkBufferCreateInfo *i,const VkAllocationCallbacks *a,VkBuffer *o)
{ UNUSED(d);UNUSED(a);FAIL(4);assert(next_id<256);*o=(VkBuffer)(uintptr_t)next_id;widths[next_id++]=(unsigned)i->size;++buffers;return VK_SUCCESS; }
static void VKAPI_CALL buffer_destroy(VkDevice d,VkBuffer b,const VkAllocationCallbacks *a)
{ UNUSED(d);UNUSED(a);assert(widths[ID(b)] && buffers);widths[ID(b)]=0;--buffers; }
static void VKAPI_CALL requirements(VkDevice d,VkBuffer b,VkMemoryRequirements *o)
{ UNUSED(d);o->size=widths[ID(b)];o->alignment=16;o->memoryTypeBits=fault==15?2:1; }
static VkResult VKAPI_CALL memory_allocate(VkDevice d,const VkMemoryAllocateInfo *i,const VkAllocationCallbacks *a,VkDeviceMemory *o)
{ UNUSED(d);UNUSED(a);FAIL(5);assert(next_id<256 && i->memoryTypeIndex==0);backing[next_id]=malloc((size_t)i->allocationSize);assert(backing[next_id]);*o=(VkDeviceMemory)(uintptr_t)next_id++;++allocations;return VK_SUCCESS; }
static void VKAPI_CALL memory_free(VkDevice d,VkDeviceMemory m,const VkAllocationCallbacks *a)
{ UNUSED(d);UNUSED(a);assert(backing[ID(m)] && allocations);free(backing[ID(m)]);backing[ID(m)]=NULL;--allocations; }
static VkResult VKAPI_CALL memory_bind(VkDevice d,VkBuffer b,VkDeviceMemory m,VkDeviceSize offset)
{ UNUSED(d);assert(offset==0);FAIL(6);bindings[ID(b)]=ID(m);return VK_SUCCESS; }
static VkResult VKAPI_CALL memory_map(VkDevice d,VkDeviceMemory m,VkDeviceSize at,VkDeviceSize size,VkMemoryMapFlags f,void **o)
{ UNUSED(d);UNUSED(size);UNUSED(f);assert(at==0);FAIL(7);*o=backing[ID(m)];++maps;return VK_SUCCESS; }
static void VKAPI_CALL memory_unmap(VkDevice d,VkDeviceMemory m)
{ UNUSED(d);UNUSED(m);assert(maps);--maps; }
static VkResult VKAPI_CALL command_begin(VkCommandBuffer c,const VkCommandBufferBeginInfo *i)
{ UNUSED(c);UNUSED(i);FAIL(11);return VK_SUCCESS; }
static VkResult VKAPI_CALL command_end(VkCommandBuffer c)
{ UNUSED(c);assert(barriers==(texture_test?3u:2u));FAIL(12);return VK_SUCCESS; }
static void VKAPI_CALL barrier(VkCommandBuffer c,VkPipelineStageFlags from,VkPipelineStageFlags to,VkDependencyFlags f,
    uint32_t n,const VkMemoryBarrier *b,uint32_t nb,const VkBufferMemoryBarrier *bb,uint32_t ni,const VkImageMemoryBarrier *ib)
{
    UNUSED(c);assert(!f && !nb && !bb);
    if(texture_test){
        if(barriers==0)assert(n==1 && !ni && !ib && from==(VK_PIPELINE_STAGE_HOST_BIT|VK_PIPELINE_STAGE_TRANSFER_BIT) &&
            to==VK_PIPELINE_STAGE_TRANSFER_BIT && b->srcAccessMask==(VK_ACCESS_HOST_WRITE_BIT|VK_ACCESS_TRANSFER_WRITE_BIT));
        else{
            assert(ni==1 && ib && ib->subresourceRange.aspectMask==VK_IMAGE_ASPECT_COLOR_BIT &&
                ib->subresourceRange.levelCount==1 && ib->subresourceRange.layerCount==1 &&
                ib->srcQueueFamilyIndex==VK_QUEUE_FAMILY_IGNORED && ib->dstQueueFamilyIndex==VK_QUEUE_FAMILY_IGNORED);
            assert(ib->oldLayout==layouts[ID(ib->image)]);
            if(barriers==1)assert(!n && !b && from==VK_PIPELINE_STAGE_ALL_COMMANDS_BIT && to==VK_PIPELINE_STAGE_TRANSFER_BIT &&
                (ib->newLayout==VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL || ib->newLayout==VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL));
            else assert(barriers==2 && n==1 && from==VK_PIPELINE_STAGE_TRANSFER_BIT &&
                to==(VK_PIPELINE_STAGE_ALL_COMMANDS_BIT|VK_PIPELINE_STAGE_HOST_BIT) && b->dstAccessMask==VK_ACCESS_HOST_READ_BIT &&
                ib->newLayout==VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL && ib->dstAccessMask==VK_ACCESS_SHADER_READ_BIT);
            layouts[ID(ib->image)]=ib->newLayout;
        }
        ++barriers;return;
    }
    assert(n==1 && !ni && !ib);
    if(!barriers)assert(from==(VK_PIPELINE_STAGE_HOST_BIT|VK_PIPELINE_STAGE_TRANSFER_BIT) && to==VK_PIPELINE_STAGE_TRANSFER_BIT &&
        b->srcAccessMask==(VK_ACCESS_HOST_WRITE_BIT|VK_ACCESS_TRANSFER_WRITE_BIT) && b->dstAccessMask==(VK_ACCESS_TRANSFER_READ_BIT|VK_ACCESS_TRANSFER_WRITE_BIT));
    else assert(barriers==1 && from==VK_PIPELINE_STAGE_TRANSFER_BIT && to==VK_PIPELINE_STAGE_HOST_BIT &&
        b->srcAccessMask==VK_ACCESS_TRANSFER_WRITE_BIT && b->dstAccessMask==VK_ACCESS_HOST_READ_BIT);
    ++barriers;
}
static void VKAPI_CALL copy(VkCommandBuffer c,VkBuffer src,VkBuffer dst,uint32_t n,const VkBufferCopy *r)
{ UNUSED(c);assert(barriers==1 && n==1);pending_src=src;pending_dst=dst;pending_copy=*r; }
static VkResult VKAPI_CALL submit(VkQueue q,uint32_t n,const VkSubmitInfo *i,VkFence f)
{
    UNUSED(q);UNUSED(f);assert(n==1 && i->commandBufferCount==1 && barriers==(texture_test?3u:2u));FAIL(13);
    if(texture_test){
        uint8_t *pixels=backing[bindings[ID(pending_image)]];
        uint8_t *bytes=(uint8_t*)backing[bindings[ID(pending_image_buffer)]]+image_copy.bufferOffset;
        size_t size=(size_t)image_copy.imageExtent.width*image_copy.imageExtent.height*4;
        if(copy_download)memcpy(bytes,pixels,size);else memcpy(pixels,bytes,size);
        return VK_SUCCESS;
    }
    memcpy((uint8_t*)backing[bindings[ID(pending_dst)]]+pending_copy.dstOffset,
        (uint8_t*)backing[bindings[ID(pending_src)]]+pending_copy.srcOffset,(size_t)pending_copy.size);return VK_SUCCESS;
}
static VkResult VKAPI_CALL image_format(VkPhysicalDevice p,VkFormat f,VkImageType t,VkImageTiling tiling,
    VkImageUsageFlags usage,VkImageCreateFlags flags,VkImageFormatProperties *out)
{
    UNUSED(p);assert((f==VK_FORMAT_R8G8B8A8_UNORM || f==VK_FORMAT_B8G8R8A8_UNORM) && t==VK_IMAGE_TYPE_2D &&
        tiling==VK_IMAGE_TILING_OPTIMAL && !flags && usage==(VK_IMAGE_USAGE_TRANSFER_SRC_BIT|VK_IMAGE_USAGE_TRANSFER_DST_BIT|VK_IMAGE_USAGE_SAMPLED_BIT));
    if(fault==16)return VK_ERROR_FORMAT_NOT_SUPPORTED;
    *out=(VkImageFormatProperties){{4096,4096,1},1,1,VK_SAMPLE_COUNT_1_BIT,GPU_MAX_BUFFER*2};return VK_SUCCESS;
}
static VkResult VKAPI_CALL image_create(VkDevice d,const VkImageCreateInfo *i,const VkAllocationCallbacks *a,VkImage *out)
{
    UNUSED(d);UNUSED(a);*out=(VkImage)(uintptr_t)0xdead;FAIL(17);
    assert(next_id<256 && i->extent.depth==1 && i->mipLevels==1 && i->arrayLayers==1 &&
        i->samples==VK_SAMPLE_COUNT_1_BIT && i->initialLayout==VK_IMAGE_LAYOUT_UNDEFINED);
    unsigned id=next_id++;widths[id]=i->extent.width*i->extent.height*4;layouts[id]=VK_IMAGE_LAYOUT_UNDEFINED;
    *out=(VkImage)(uintptr_t)id;++images;return VK_SUCCESS;
}
static void VKAPI_CALL image_destroy(VkDevice d,VkImage image,const VkAllocationCallbacks *a)
{UNUSED(d);UNUSED(a);assert(ID(image)<256 && widths[ID(image)] && images);widths[ID(image)]=0;--images;}
static VkResult VKAPI_CALL image_bind(VkDevice d,VkImage image,VkDeviceMemory memory,VkDeviceSize at)
{UNUSED(d);assert(!at);FAIL(18);bindings[ID(image)]=ID(memory);return VK_SUCCESS;}
static void VKAPI_CALL image_requirements(VkDevice d,VkImage image,VkMemoryRequirements *out)
{UNUSED(d);out->size=fault==20?0:widths[ID(image)];out->alignment=16;out->memoryTypeBits=fault==21?2:1;}
static VkResult VKAPI_CALL view_create(VkDevice d,const VkImageViewCreateInfo *i,const VkAllocationCallbacks *a,VkImageView *out)
{UNUSED(d);UNUSED(a);*out=(VkImageView)(uintptr_t)0xdead;FAIL(19);assert(i->viewType==VK_IMAGE_VIEW_TYPE_2D && widths[ID(i->image)]);*out=(VkImageView)i->image;++views;return VK_SUCCESS;}
static void VKAPI_CALL view_destroy(VkDevice d,VkImageView view,const VkAllocationCallbacks *a)
{UNUSED(d);UNUSED(a);assert(ID(view)<256 && widths[ID(view)] && views);--views;}
static void image_command(VkImage image,VkImageLayout layout,VkBuffer buffer,uint32_t n,const VkBufferImageCopy *r,int download)
{
    assert(texture_test && barriers==2 && n==1 && r->imageSubresource.layerCount==1 && !r->bufferRowLength &&
        !r->bufferImageHeight && !r->imageOffset.x && !r->imageOffset.y && !r->imageOffset.z && r->imageExtent.depth==1 &&
        r->imageSubresource.aspectMask==VK_IMAGE_ASPECT_COLOR_BIT && !r->imageSubresource.mipLevel);
    assert(layout==(download?VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL:VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL));
    assert(r->bufferOffset+(uint64_t)r->imageExtent.width*r->imageExtent.height*4<=widths[ID(buffer)]);
    pending_image=image;pending_image_buffer=buffer;image_copy=*r;copy_download=(unsigned)download;
}
static void VKAPI_CALL image_upload(VkCommandBuffer c,VkBuffer b,VkImage i,VkImageLayout l,uint32_t n,const VkBufferImageCopy *r)
{UNUSED(c);image_command(i,l,b,n,r,0);}
static void VKAPI_CALL image_download(VkCommandBuffer c,VkImage i,VkImageLayout l,VkBuffer b,uint32_t n,const VkBufferImageCopy *r)
{UNUSED(c);image_command(i,l,b,n,r,1);}
static PFN_vkVoidFunction VKAPI_CALL get_device(VkDevice d,const char *name)
{
    UNUSED(d);PFN_vkVoidFunction p=NULL;if(fault==8 && !strcmp(name,"vkCmdCopyBuffer"))return NULL;
#define MATCH(api,impl) if(!strcmp(name,"vk"#api)){PFN_vk##api typed=impl;memcpy(&p,&typed,sizeof(p));return p;}
    MATCH(CreateCommandPool,pool_create) MATCH(DestroyCommandPool,pool_destroy) MATCH(AllocateCommandBuffers,command_allocate)
    MATCH(ResetCommandPool,pool_reset) MATCH(CreateFence,fence_create) MATCH(DestroyFence,fence_destroy)
    MATCH(ResetFences,fence_reset) MATCH(WaitForFences,fence_wait) MATCH(DeviceWaitIdle,device_idle)
    MATCH(CreateBuffer,buffer_create) MATCH(DestroyBuffer,buffer_destroy) MATCH(GetBufferMemoryRequirements,requirements)
    MATCH(AllocateMemory,memory_allocate) MATCH(FreeMemory,memory_free) MATCH(BindBufferMemory,memory_bind)
    MATCH(MapMemory,memory_map) MATCH(UnmapMemory,memory_unmap) MATCH(BeginCommandBuffer,command_begin)
    MATCH(EndCommandBuffer,command_end) MATCH(CmdPipelineBarrier,barrier) MATCH(CmdCopyBuffer,copy) MATCH(QueueSubmit,submit)
    MATCH(CreateImage,image_create) MATCH(DestroyImage,image_destroy) MATCH(GetImageMemoryRequirements,image_requirements)
    MATCH(BindImageMemory,image_bind) MATCH(CreateImageView,view_create) MATCH(DestroyImageView,view_destroy)
    MATCH(CmdCopyBufferToImage,image_upload) MATCH(CmdCopyImageToBuffer,image_download)
#undef MATCH
    return p;
}
int oot_graphics_acquire_vulkan(OotGraphics *g,OotGraphicsVulkan *out)
{
    assert(g);memset(out,0,sizeof(*out));out->device=(VkDevice)(uintptr_t)1;out->queue=(VkQueue)(uintptr_t)2;
    out->family=2;out->get_device=get_device;out->memory.memoryTypeCount=1;
    out->image_format=image_format;out->properties.limits.maxImageDimension2D=4096;
    out->memory.memoryTypes[0].propertyFlags=VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT|VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    ++refs;return 1;
}
void oot_graphics_destroy(OotGraphics *g){assert(g && refs);--refs;}
static OotGpu *owner(void){return oot_gpu_create((OotGraphics*)(uintptr_t)1);}
static void texture_cases(void)
{
    const unsigned create_faults[]={5,16,17,18,19,20,21};
    for(unsigned n=0;n<sizeof(create_faults)/sizeof(create_faults[0]);++n){
        fault=0;OotGpu *g=owner();assert(g);fault=create_faults[n];
        OotGpuReport before=g->report;assert(!oot_gpu_texture_create(g,7,5,OOT_GPU_RGBA8));
        assert(!memcmp(&before,&g->report,sizeof(before)));oot_gpu_destroy(g);
        assert(!refs && !pools && !fences && !buffers && !images && !views && !allocations && !maps);
    }
    fault=0;texture_test=1;OotGpu *g=owner(),*other=owner();assert(g && other);
    OotGpuTexture *t=oot_gpu_texture_create(g,7,5,OOT_GPU_RGBA8),*u=oot_gpu_texture_create(g,3,9,OOT_GPU_BGRA8);assert(t && u);
    assert(!oot_gpu_texture_create(g,0,5,1) && !oot_gpu_texture_create(g,4097,5,1) && !oot_gpu_texture_create(g,5,5,99));
    OotGpuBuffer *b=oot_gpu_buffer_create(g,256);assert(b);uint8_t input[256],output[256];
    for(unsigned n=0;n<256;++n)input[n]=(uint8_t)(n*17+3);
    assert(!oot_gpu_texture_download(g,t,b,0));
    assert(oot_gpu_upload(g,b,0,input,sizeof(input)));
    for(unsigned n=0;n<4;++n){
        assert(oot_gpu_upload(g,b,0,input,sizeof(input)));
        assert(oot_gpu_texture_upload(g,t,b,4) && oot_gpu_texture_download(g,t,b,100));
        assert(oot_gpu_download(g,b,0,output,sizeof(output)) && !memcmp(input+4,output+100,140));
    }
    OotGpuReport before=g->report;
    DWORD original_thread=g->thread;g->thread^=1;
    assert(!oot_gpu_texture_upload(g,t,b,0) && !oot_gpu_texture_create(g,1,1,1) && !oot_gpu_texture_destroy(g,t));
    g->thread=original_thread;
    assert(!oot_gpu_texture_upload(g,t,b,1) && !oot_gpu_texture_upload(g,t,b,120) &&
        !oot_gpu_texture_upload(other,t,b,0) && !oot_gpu_texture_upload(g,(OotGpuTexture*)(uintptr_t)7,b,0));
    assert(!memcmp(&before,&g->report,sizeof(before)));
    OotGpuTextureInfo info;assert(oot_gpu_texture_info(g,t,&info) && info.width==7 && info.height==5 && info.bytes==140);
    assert(!oot_gpu_texture_info(g,t,(OotGpuTextureInfo*)t));
    OotGpuTexturePool *p=oot_gpu_texture_pool_create(g,4);assert(p && !oot_gpu_texture_pool_create(g,4097));
    OotGpuTexture *result=(OotGpuTexture*)(uintptr_t)1;
    assert(oot_gpu_texture_pool_get(g,p,0,&result) && !result);
    assert(oot_gpu_texture_pool_set(g,p,0,t) && oot_gpu_texture_pool_set(g,p,1,t));
    assert(!oot_gpu_texture_destroy(g,t) && oot_gpu_texture_pool_get(g,p,1,&result) && result==t);
    assert(oot_gpu_texture_pool_set(g,p,0,u) && t->info.descriptor_references==1 && u->info.descriptor_references==1);
    before=g->report;GpuTextureDescriptor saved=p->slots[1];p->slots[1].format^=1;
    result=(OotGpuTexture*)(uintptr_t)1;assert(!oot_gpu_texture_pool_get(g,p,1,&result) && result==(OotGpuTexture*)(uintptr_t)1);
    assert(!oot_gpu_texture_pool_set(g,p,1,u) && !oot_gpu_texture_pool_destroy(g,p));
    p->slots[1]=saved;
    assert(!oot_gpu_texture_pool_set(other,p,0,t) && !oot_gpu_texture_pool_set(g,p,4,t) &&
        !oot_gpu_texture_pool_get(g,p,0,(OotGpuTexture**)p->slots));
    assert(!memcmp(&before,&g->report,sizeof(before)));
    assert(oot_gpu_texture_pool_destroy(g,p) && !oot_gpu_texture_pool_destroy(g,p));
    assert(!t->info.descriptor_references && !u->info.descriptor_references);
    assert(oot_gpu_texture_destroy(g,t));OotGpuTexture *v=oot_gpu_texture_create(g,7,5,OOT_GPU_RGBA8);assert(v && v!=t);
    assert(!oot_gpu_texture_destroy(g,t) && !oot_gpu_texture_info(g,t,&info));
    assert(oot_gpu_texture_destroy(g,u));oot_gpu_destroy(g);oot_gpu_destroy(other);
    for(unsigned f=9;f<=14;++f){
        fault=0;g=owner();t=oot_gpu_texture_create(g,7,5,1);b=oot_gpu_buffer_create(g,256);assert(t && b);fault=f;
        assert(!oot_gpu_texture_upload(g,t,b,0) && g->report.faulted && !g->report.texture_uploads);
        assert(!oot_gpu_texture_destroy(g,t));oot_gpu_destroy(g);
    }
    assert(!refs && !pools && !fences && !buffers && !images && !views && !allocations && !maps);
    texture_test=0;puts("Synthetic GPU textures and descriptor lifetime checks passed.");
}
int main(void)
{
    for(fault=1;fault<=8;++fault){
        OotGpu *g=owner();
        if(fault<=3 || fault==8)assert(!g);else{assert(g && !oot_gpu_buffer_create(g,256));oot_gpu_destroy(g);}
        assert(!refs && !pools && !fences && !buffers && !allocations && !maps);
    }
    fault=0;OotGpu *g=owner();assert(g);uint8_t input[256],output[256];
    for(unsigned n=0;n<256;++n)input[n]=(uint8_t)(n*37+19);
    OotGpuBuffer *a=oot_gpu_buffer_create(g,256),*b=oot_gpu_buffer_create(g,256);assert(a && b);
    assert(!oot_gpu_buffer_create(g,0) && !oot_gpu_buffer_create(g,GPU_MAX_BUFFER+1));
    assert(oot_gpu_upload(g,a,0,input,256));assert(oot_gpu_copy(g,a,0,b,0,256));
    assert(oot_gpu_copy(g,b,16,a,32,128));assert(oot_gpu_download(g,a,32,output,128));assert(!memcmp(input+16,output,128));
    OotGpuReport before=g->report;
    assert(!oot_gpu_copy(g,a,0,a,4,16) && !oot_gpu_copy(g,a,1,b,0,4) && !oot_gpu_copy(g,a,0,b,0,257));
    assert(!oot_gpu_upload(g,a,255,input,2) && !oot_gpu_download(g,a,0,NULL,1));
    assert(!memcmp(&before,&g->report,sizeof(before)));
    DWORD thread=g->thread;g->thread^=1;assert(!oot_gpu_copy(g,a,0,b,0,4));g->thread=thread;
    assert(oot_gpu_buffer_destroy(g,a));assert(!oot_gpu_buffer_destroy(g,a));oot_gpu_destroy(g);
    assert(!refs && !pools && !fences && !buffers && !allocations && !maps);
    for(fault=9;fault<=14;++fault){
        unsigned saved=fault;fault=0;g=owner();a=oot_gpu_buffer_create(g,256);b=oot_gpu_buffer_create(g,256);fault=saved;
        assert(!oot_gpu_copy(g,a,0,b,0,256) && g->report.faulted && !g->report.copies);
        assert(!oot_gpu_upload(g,a,0,input,1));oot_gpu_destroy(g);
        assert(!refs && !pools && !fences && !buffers && !allocations && !maps);
    }
    assert(idle==1);texture_cases();puts("Synthetic GPU buffer transfers, barriers, fences and failure ownership passed.");return 0;
}
