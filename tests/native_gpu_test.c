/* Synthetic Vulkan command/memory lifetime fixture. No driver is loaded. */
#undef NDEBUG
#include "../src/native_gpu.c"
#include <assert.h>
#include <stdio.h>
static unsigned fault,refs,pools,fences,buffers,allocations,maps,idle,next_id=4,barriers;
static unsigned widths[256],bindings[256];static void *backing[256];
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
{ UNUSED(c);assert(barriers==2);FAIL(12);return VK_SUCCESS; }
static void VKAPI_CALL barrier(VkCommandBuffer c,VkPipelineStageFlags from,VkPipelineStageFlags to,VkDependencyFlags f,
    uint32_t n,const VkMemoryBarrier *b,uint32_t nb,const VkBufferMemoryBarrier *bb,uint32_t ni,const VkImageMemoryBarrier *ib)
{
    UNUSED(c);assert(!f && n==1 && !nb && !bb && !ni && !ib);
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
    UNUSED(q);UNUSED(f);assert(n==1 && i->commandBufferCount==1 && barriers==2);FAIL(13);
    memcpy((uint8_t*)backing[bindings[ID(pending_dst)]]+pending_copy.dstOffset,
        (uint8_t*)backing[bindings[ID(pending_src)]]+pending_copy.srcOffset,(size_t)pending_copy.size);return VK_SUCCESS;
}
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
#undef MATCH
    return p;
}
int oot_graphics_acquire_vulkan(OotGraphics *g,OotGraphicsVulkan *out)
{
    assert(g);memset(out,0,sizeof(*out));out->device=(VkDevice)(uintptr_t)1;out->queue=(VkQueue)(uintptr_t)2;
    out->family=2;out->get_device=get_device;out->memory.memoryTypeCount=1;
    out->memory.memoryTypes[0].propertyFlags=VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    ++refs;return 1;
}
void oot_graphics_destroy(OotGraphics *g){assert(g && refs);--refs;}
static OotGpu *owner(void){return oot_gpu_create((OotGraphics*)(uintptr_t)1);}
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
    assert(idle==1);puts("Synthetic GPU buffer transfers, barriers, fences and failure ownership passed.");return 0;
}
