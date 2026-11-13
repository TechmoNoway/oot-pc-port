/* Synthetic Vulkan dispatch only. Never loads a driver or creates GPU handles. */
#include "../src/native_graphics.c"
#undef NDEBUG
#include <assert.h>
#include <stdio.h>

static unsigned failure,instances,devices,instance_destroys,device_destroys;
static VkResult VKAPI_CALL fake_create_instance(const VkInstanceCreateInfo *info,
    const VkAllocationCallbacks *allocator,VkInstance *out)
{
    assert(!allocator && info->enabledExtensionCount==2);
    if(failure==7){*out=(VkInstance)(uintptr_t)0xdead;return VK_ERROR_INITIALIZATION_FAILED;}
    if(failure==1)return VK_ERROR_INITIALIZATION_FAILED;
    *out=(VkInstance)(uintptr_t)1;++instances;return VK_SUCCESS;
}
static void VKAPI_CALL fake_destroy_instance(VkInstance instance,const VkAllocationCallbacks *allocator)
{ assert(instance && !allocator && instances && !devices);--instances;++instance_destroys; }
static VkResult VKAPI_CALL fake_enumerate(VkInstance instance,uint32_t *count,VkPhysicalDevice *out)
{
    assert(instance);
    if(failure==2 || (failure==3 && out))return VK_ERROR_INITIALIZATION_FAILED;
    *count=1;if(out)*out=(VkPhysicalDevice)(uintptr_t)2;return VK_SUCCESS;
}
static void VKAPI_CALL fake_families(VkPhysicalDevice physical,uint32_t *count,VkQueueFamilyProperties *out)
{
    assert(physical);*count=failure==4 ? 0:1;
    if(out && *count){memset(out,0,sizeof(*out));out->queueFlags=VK_QUEUE_GRAPHICS_BIT;out->queueCount=1;}
}
static void VKAPI_CALL fake_properties(VkPhysicalDevice physical,VkPhysicalDeviceProperties *out)
{
    assert(physical);memset(out,0,sizeof(*out));out->apiVersion=VK_API_VERSION_1_0;
    out->vendorID=123;out->deviceID=456;strcpy(out->deviceName,"Synthetic graphics fixture");
}
static VkResult VKAPI_CALL fake_create_device(VkPhysicalDevice physical,const VkDeviceCreateInfo *info,
    const VkAllocationCallbacks *allocator,VkDevice *out)
{
    assert(physical && !allocator && info->queueCreateInfoCount==1 && info->enabledExtensionCount==1);
    assert(info->pQueueCreateInfos->queueCount==1 && info->pQueueCreateInfos->flags==0);
    if(failure==8){*out=(VkDevice)(uintptr_t)0xdead;return VK_ERROR_INITIALIZATION_FAILED;}
    if(failure==5)return VK_ERROR_INITIALIZATION_FAILED;
    *out=(VkDevice)(uintptr_t)3;++devices;return VK_SUCCESS;
}
static void VKAPI_CALL fake_destroy_device(VkDevice device,const VkAllocationCallbacks *allocator)
{ assert(device && !allocator && devices);--devices;++device_destroys; }
static void VKAPI_CALL fake_queue(VkDevice device,uint32_t family,uint32_t index,VkQueue *out)
{ assert(device && family==0 && index==0);*out=failure==6 ? VK_NULL_HANDLE:(VkQueue)(uintptr_t)4; }
static PFN_vkVoidFunction VKAPI_CALL fake_get(VkInstance instance,const char *name)
{
    PFN_vkVoidFunction result=NULL;(void)instance;
    if((failure==9 && !strcmp(name,"vkGetDeviceQueue")) ||
       (failure==10 && !strcmp(name,"vkCreateInstance")))return NULL;
#define MATCH(api,impl) if(!strcmp(name,#api)){PFN_##api typed=impl;memcpy(&result,&typed,sizeof(result));return result;}
    MATCH(vkCreateInstance,fake_create_instance)
    MATCH(vkDestroyInstance,fake_destroy_instance)
    MATCH(vkEnumeratePhysicalDevices,fake_enumerate)
    MATCH(vkGetPhysicalDeviceQueueFamilyProperties,fake_families)
    MATCH(vkGetPhysicalDeviceProperties,fake_properties)
    MATCH(vkCreateDevice,fake_create_device)
    MATCH(vkDestroyDevice,fake_destroy_device)
    MATCH(vkGetDeviceQueue,fake_queue)
#undef MATCH
    return result;
}
static OotArm64State registers(void)
{
    OotArm64State s={0};
    for(unsigned n=0;n<31;++n)s.x[n]=UINT64_C(0xfedcba9876543200)+n;
    s.pc=0x1000;s.sp=0x3000;s.nzcv=0xa0000000;s.x[30]=0x2000;return s;
}
int main(void)
{
    OotArm64State s=registers(),out,old,expected=s;OotGraphicsReport a,b;
    expected.pc=s.x[30];
    for(failure=1;failure<=10;++failure){
        OotGraphics *g=oot_graphics_create();assert(g);g->get_instance=fake_get;g->destroy_instance=fake_destroy_instance;
        memset(&out,0xa5,sizeof(out));old=out;
        assert(oot_graphics_snapshot(g,&a));
        assert(oot_graphics_call(g,OOT_GRAPHICS_BOOT,&s,&out)!=0);
        assert(!memcmp(&old,&out,sizeof(out)) && !instances && !devices);
        assert(oot_graphics_snapshot(g,&b) && !memcmp(&a,&b,sizeof(a)));
        oot_graphics_destroy(g);
    }
    failure=0;
    OotGraphics *g=oot_graphics_create();assert(g);g->get_instance=fake_get;g->destroy_instance=fake_destroy_instance;
    memset(&out,0xa5,sizeof(out));old=out;
    assert(oot_graphics_call(g,OOT_GRAPHICS_CHECK,&s,&out)==1);
    assert(!memcmp(&old,&out,sizeof(out)));
    assert(oot_graphics_call(g,OOT_GRAPHICS_BOOT,&s,&out)==0);
    assert(!memcmp(out.x,expected.x,sizeof(out.x)) && out.sp==expected.sp &&
           out.pc==expected.pc && out.nzcv==expected.nzcv && instances==1 && devices==1);
    assert(oot_graphics_call(g,OOT_GRAPHICS_BOOT,&s,&out)==0);
    assert(instances==1 && devices==1);
    assert(oot_graphics_call(g,OOT_GRAPHICS_CHECK,&s,&out)==0);
    assert(oot_graphics_snapshot(g,&a) && a.ready==1 && a.calls==3 && a.boots==2 && a.checks==1);
    assert(a.working_memory==s.x[0] && a.working_size==s.x[1]);
    assert(a.vendor_id==123 && a.device_id==456);
    s.x[1]^=UINT64_C(1)<<40;old=out;
    assert(oot_graphics_call(g,OOT_GRAPHICS_BOOT,&s,&out)==1);
    assert(!memcmp(&old,&out,sizeof(out)));
    assert(oot_graphics_snapshot(g,&b) && !memcmp(&a,&b,sizeof(a)));
    s.x[1]^=UINT64_C(1)<<40;
    assert(oot_graphics_call(g,999,&s,&out)==1);
    assert(oot_graphics_call(g,OOT_GRAPHICS_BOOT,&s,&s)==2);
    assert(oot_graphics_call(g,OOT_GRAPHICS_BOOT,NULL,&out)==2);
    s.sp++;assert(oot_graphics_call(g,OOT_GRAPHICS_BOOT,&s,&out)==2);s.sp--;
    g->report.calls=UINT64_MAX;old=out;
    assert(oot_graphics_call(g,OOT_GRAPHICS_CHECK,&s,&out)==2 && !memcmp(&out,&old,sizeof(out)));
    oot_graphics_destroy(g);assert(!instances && !devices);
    assert(instance_destroys>=5 && device_destroys>=2);
    puts("Synthetic native graphics lifecycle and failure isolation passed.");return 0;
}
