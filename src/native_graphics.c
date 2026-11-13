#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define VK_NO_PROTOTYPES
#include <windows.h>
#include <vulkan/vulkan_core.h>
#include <vulkan/vulkan_win32.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "native_graphics.h"

struct OotGraphics {
    HMODULE module;
    PFN_vkGetInstanceProcAddr get_instance;
    PFN_vkDestroyInstance destroy_instance;
    PFN_vkDestroyDevice destroy_device;
    VkInstance instance;
    VkPhysicalDevice physical;
    VkDevice device;
    VkQueue queue;
    OotGraphicsReport report;
    OotDisplayReport display_report;
    HINSTANCE window_module;
    ATOM window_class;
    HWND window;
    DWORD window_thread;
    VkSurfaceKHR surface;
    PFN_vkDestroySurfaceKHR destroy_surface;
};

static int disjoint(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y ? y-x>=an:x-y>=bn;
}
static int live(const OotGraphics *g)
{ return g->instance && g->physical && g->device && g->queue && g->destroy_instance && g->destroy_device; }
static void release_display(OotGraphics *g)
{
    if(g->surface && g->destroy_surface)g->destroy_surface(g->instance,g->surface,NULL);
    if(g->window)DestroyWindow(g->window);
    if(g->window_class)UnregisterClassW((LPCWSTR)(ULONG_PTR)g->window_class,g->window_module);
    g->surface=VK_NULL_HANDLE;g->window=NULL;g->window_class=0;g->window_thread=0;
    g->window_module=NULL;g->destroy_surface=NULL;
}
static void release_resources(OotGraphics *g)
{
    release_display(g);
    /* Bootstrap submits no work and creates no device children. Extend this
     * teardown when a later renderer starts owning either kind of resource. */
    if(g->device && g->destroy_device)g->destroy_device(g->device,NULL);
    if(g->instance && g->destroy_instance)g->destroy_instance(g->instance,NULL);
    if(g->module)FreeLibrary(g->module);
}
static int loader(OotGraphics *g)
{
    FARPROC get,destroy;
    _Static_assert(sizeof(get)==sizeof(g->get_instance),"Windows Vulkan procedure representation");
    _Static_assert(sizeof(destroy)==sizeof(g->destroy_instance),"Windows Vulkan procedure representation");
    g->module=LoadLibraryExW(L"vulkan-1.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!g->module)return 0;
    get=GetProcAddress(g->module,"vkGetInstanceProcAddr");
    /* The Windows loader exports core 1.0 commands. Resolve destruction before
     * allocation so even a later procedure-resolution failure can unwind. */
    destroy=GetProcAddress(g->module,"vkDestroyInstance");
    if(!get || !destroy)return 0;
    memcpy(&g->get_instance,&get,sizeof(get));
    memcpy(&g->destroy_instance,&destroy,sizeof(destroy));return 1;
}
static int procedure(const OotGraphics *g,const char *name,void *target,size_t size)
{
    PFN_vkVoidFunction p=g->get_instance(g->instance,name);
    if(!p || size!=sizeof(p))return 0;
    memcpy(target,&p,size);return 1;
}
#define PROC(g,api,target) procedure(g,#api,&(target),sizeof(target))
static int bootstrap(OotGraphics *g)
{
    PFN_vkCreateInstance create_instance=NULL;
    PFN_vkEnumeratePhysicalDevices enumerate=NULL;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties families=NULL;
    PFN_vkGetPhysicalDeviceProperties properties=NULL;
    PFN_vkCreateDevice create_device=NULL;
    PFN_vkGetDeviceQueue get_queue=NULL;
    const char *instance_extensions[]={"VK_KHR_surface","VK_KHR_win32_surface"};
    const char *device_extensions[]={"VK_KHR_swapchain"};
    const float priority=1.0f;
    VkApplicationInfo app={0};VkInstanceCreateInfo ci={0};VkInstance created_instance=VK_NULL_HANDLE;
    VkPhysicalDevice *physical=NULL;uint32_t count=0;int success=0;
    if(!g->get_instance && !loader(g))return 0;
    if(!g->destroy_instance || !PROC(g,vkCreateInstance,create_instance))return 0;
    app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;app.pApplicationName="oot-pc-port";
    app.apiVersion=VK_API_VERSION_1_0;
    ci.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;ci.pApplicationInfo=&app;
    ci.enabledExtensionCount=2;ci.ppEnabledExtensionNames=instance_extensions;
    if(create_instance(&ci,NULL,&created_instance)!=VK_SUCCESS || !created_instance)return 0;
    g->instance=created_instance;
    if(!PROC(g,vkEnumeratePhysicalDevices,enumerate) ||
       !PROC(g,vkGetPhysicalDeviceQueueFamilyProperties,families) ||
       !PROC(g,vkGetPhysicalDeviceProperties,properties) ||
       !PROC(g,vkCreateDevice,create_device) || !PROC(g,vkDestroyDevice,g->destroy_device) ||
       !PROC(g,vkGetDeviceQueue,get_queue))return 0;
    if(enumerate(g->instance,&count,NULL)!=VK_SUCCESS || !count || count>64)return 0;
    physical=calloc(count,sizeof(*physical));if(!physical)return 0;
    if(enumerate(g->instance,&count,physical)!=VK_SUCCESS || !count)goto done;
    for(uint32_t n=0;n<count && !success;++n){
        uint32_t family_count=0;VkQueueFamilyProperties *queues;
        families(physical[n],&family_count,NULL);
        if(!family_count || family_count>65536)continue;
        queues=calloc(family_count,sizeof(*queues));if(!queues)goto done;
        families(physical[n],&family_count,queues);
        for(uint32_t k=0;k<family_count;++k){
            VkDeviceQueueCreateInfo qi={0};VkDeviceCreateInfo di={0};
            VkPhysicalDeviceProperties props;VkDevice created_device=VK_NULL_HANDLE;
            if(!queues[k].queueCount || !(queues[k].queueFlags&VK_QUEUE_GRAPHICS_BIT))continue;
            qi.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
            qi.queueFamilyIndex=k;qi.queueCount=1;qi.pQueuePriorities=&priority;
            di.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;di.queueCreateInfoCount=1;di.pQueueCreateInfos=&qi;
            di.enabledExtensionCount=1;di.ppEnabledExtensionNames=device_extensions;
            if(create_device(physical[n],&di,NULL,&created_device)!=VK_SUCCESS || !created_device)continue;
            g->device=created_device;
            get_queue(g->device,k,0,&g->queue);
            if(!g->queue){g->destroy_device(g->device,NULL);g->device=VK_NULL_HANDLE;continue;}
            properties(physical[n],&props);g->physical=physical[n];
            g->report.api_version=props.apiVersion;g->report.driver_version=props.driverVersion;
            g->report.vendor_id=props.vendorID;g->report.device_id=props.deviceID;g->report.queue_family=k;
            memcpy(g->report.device_name,props.deviceName,sizeof(g->report.device_name));
            g->report.device_name[sizeof(g->report.device_name)-1]=0;success=1;break;
        }
        free(queues);
    }
done:
    free(physical);return success;
}

static int initialize_display(OotGraphics *g,const void *owner)
{
    PFN_vkCreateWin32SurfaceKHR create_surface=NULL;
    PFN_vkGetPhysicalDeviceSurfaceSupportKHR support=NULL;
    WNDCLASSEXW wc={0};wchar_t name[64];VkWin32SurfaceCreateInfoKHR ci={0};
    VkSurfaceKHR created_surface=VK_NULL_HANDLE;VkBool32 supported=VK_FALSE;
    if(!PROC(g,vkCreateWin32SurfaceKHR,create_surface) ||
       !PROC(g,vkDestroySurfaceKHR,g->destroy_surface) ||
       !PROC(g,vkGetPhysicalDeviceSurfaceSupportKHR,support))return 0;
    g->window_module=GetModuleHandleW(NULL);if(!g->window_module)return 0;
    if(swprintf(name,sizeof(name)/sizeof(*name),L"oot-pc-port-%p",owner)<0)return 0;
    wc.cbSize=sizeof(wc);wc.lpfnWndProc=DefWindowProcW;
    wc.hInstance=g->window_module;wc.lpszClassName=name;
    g->window_class=RegisterClassExW(&wc);if(!g->window_class)return 0;
    /* A real, hidden surface probe. Guest dimensions/visibility belong to a
     * later proved Layer API; do not advertise this size as guest capability. */
    g->window=CreateWindowExW(0,(LPCWSTR)(ULONG_PTR)g->window_class,L"oot-pc-port",
        WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,1280,720,NULL,NULL,g->window_module,NULL);
    if(!g->window)return 0;
    g->window_thread=GetCurrentThreadId();
    ci.sType=VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR;
    ci.hinstance=g->window_module;ci.hwnd=g->window;
    if(create_surface(g->instance,&ci,NULL,&created_surface)!=VK_SUCCESS || !created_surface)return 0;
    g->surface=created_surface;
    if(support(g->physical,g->report.queue_family,g->surface,&supported)!=VK_SUCCESS || supported!=VK_TRUE)return 0;
    return 1;
}
#undef PROC

OotGraphics *oot_graphics_create(void)
{
    OotGraphics *g=calloc(1,sizeof(*g));
    if(g){g->report.version=1;g->display_report.version=1;}return g;
}
void oot_graphics_destroy(OotGraphics *g)
{ if(g){release_resources(g);memset(g,0,sizeof(*g));free(g);} }
int oot_graphics_snapshot(const OotGraphics *g,OotGraphicsReport *out)
{
    if(!g || !out || !disjoint(g,sizeof(*g),out,sizeof(*out)))return 0;
    *out=g->report;return 1;
}
int oot_graphics_display_snapshot(const OotGraphics *g,OotDisplayReport *out)
{
    if(!g || !out || !disjoint(g,sizeof(*g),out,sizeof(*out)))return 0;
    *out=g->display_report;return 1;
}
int oot_graphics_call(OotGraphics *g,uint32_t id,const OotArm64State *s,OotArm64State *out)
{
    OotArm64State result;OotGraphics next;
    if(!g || !s || !out || !disjoint(g,sizeof(*g),s,sizeof(*s)) ||
       !disjoint(g,sizeof(*g),out,sizeof(*out)) || !disjoint(s,sizeof(*s),out,sizeof(*out)))return 2;
    if(g->report.version!=1 || g->report.ready>1 || g->report.reserved ||
       (g->report.ready && !live(g)) || !s->pc || s->pc>=(UINT64_C(1)<<39) || s->pc%4 ||
       s->sp%16 || s->x[30]<4 || s->x[30]>=(UINT64_C(1)<<39) || s->x[30]%4 ||
       (s->nzcv&UINT32_C(0x0fffffff)))return 2;
    if(id==OOT_DISPLAY_INITIALIZE){
        if(g->display_report.version!=1 || g->display_report.reserved || g->display_report.ready>1 ||
           g->display_report.calls==UINT64_MAX || g->display_report.initializations==UINT64_MAX)return 2;
        if(!g->report.ready || !live(g))return 1;
        if(g->display_report.ready){
            if(g->window_thread!=GetCurrentThreadId())return 2;
            if(!g->surface || !g->window_class || !g->destroy_surface ||
               !IsWindow(g->window) || g->display_report.presentation_supported!=1)return 1;
        }
        result=*s;result.pc=s->x[30];next=*g;
        if(!next.display_report.ready){
            if(!initialize_display(&next,g)){release_display(&next);return 1;}
            next.display_report.ready=1;next.display_report.presentation_supported=1;
        }
        ++next.display_report.calls;++next.display_report.initializations;
        *g=next;*out=result;return 0;
    }
    if(id!=OOT_GRAPHICS_BOOT && id!=OOT_GRAPHICS_CHECK)return 1;
    if(g->report.calls==UINT64_MAX || (id==OOT_GRAPHICS_BOOT ? g->report.boots:g->report.checks)==UINT64_MAX)return 2;
    if(id==OOT_GRAPHICS_CHECK && !g->report.ready)return 1;
    if(id==OOT_GRAPHICS_BOOT && g->report.ready &&
       (s->x[0]!=g->report.working_memory || s->x[1]!=g->report.working_size))return 1;
    result=*s;result.pc=s->x[30];next=*g;
    if(id==OOT_GRAPHICS_BOOT){
        if(!next.report.ready){
            if(!bootstrap(&next)){release_resources(&next);return 1;}
            next.report.ready=1;next.report.working_memory=s->x[0];next.report.working_size=s->x[1];
        }
        ++next.report.boots;
    }else ++next.report.checks;
    ++next.report.calls;*g=next;*out=result;return 0;
}
