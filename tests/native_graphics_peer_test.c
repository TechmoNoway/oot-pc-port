/* Artificial monitor/window/Vulkan peers, independent of any game image. */
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
static ATOM WINAPI peer_register(const WNDCLASSEXW*);
static HWND WINAPI peer_window(DWORD,LPCWSTR,LPCWSTR,DWORD,int,int,int,int,HWND,HMENU,HINSTANCE,LPVOID);
static BOOL WINAPI peer_destroy(HWND);
static BOOL WINAPI peer_unregister(LPCWSTR,HINSTANCE);
static BOOL WINAPI peer_is_window(HWND);
static DWORD WINAPI peer_thread(void);
static DPI_AWARENESS_CONTEXT WINAPI peer_dpi_context(DPI_AWARENESS_CONTEXT);
static HMONITOR WINAPI peer_monitor_point(POINT,DWORD);
static BOOL WINAPI peer_monitor_info(HMONITOR,LPMONITORINFO);
static BOOL WINAPI peer_settings(LPCWSTR,DWORD,DEVMODEW*,DWORD);
static UINT WINAPI peer_dpi(HWND);
static BOOL WINAPI peer_adjust(LPRECT,DWORD,BOOL,DWORD,UINT);
static BOOL WINAPI peer_position(HWND,HWND,int,int,int,int,UINT);
static BOOL WINAPI peer_client(HWND,LPRECT);
static HMONITOR WINAPI peer_monitor_window(HWND,DWORD);
static BOOL WINAPI peer_show(HWND,int);
static BOOL WINAPI peer_visible(HWND);
#define RegisterClassExW peer_register
#define CreateWindowExW peer_window
#define DestroyWindow peer_destroy
#define UnregisterClassW peer_unregister
#define IsWindow peer_is_window
#define GetCurrentThreadId peer_thread
#define SetThreadDpiAwarenessContext peer_dpi_context
#define MonitorFromPoint peer_monitor_point
#define GetMonitorInfoW peer_monitor_info
#define EnumDisplaySettingsExW peer_settings
#define GetDpiForWindow peer_dpi
#define AdjustWindowRectExForDpi peer_adjust
#define SetWindowPos peer_position
#define GetClientRect peer_client
#define MonitorFromWindow peer_monitor_window
#define ShowWindow peer_show
#define IsWindowVisible peer_visible
#define main old_graphics_fixture
#include "native_graphics_test.c"
#undef main

static unsigned fault,classes,windows,surfaces,next_handle=10;
static DWORD thread_id=37;
static DPI_AWARENESS_CONTEXT dpi_context=DPI_AWARENESS_CONTEXT_UNAWARE;
static struct {int active,visible,width,height;} slots[512];
static unsigned handle(HWND window){unsigned n=(unsigned)(uintptr_t)window;assert(n<512);return n;}
static ATOM WINAPI peer_register(const WNDCLASSEXW *info)
{ assert(info->cbSize==sizeof(*info) && info->lpfnWndProc && info->hInstance);if(fault==5)return 0;++classes;return (ATOM)++next_handle; }
static HWND WINAPI peer_window(DWORD ex,LPCWSTR cls,LPCWSTR title,DWORD style,int x,int y,int w,int h,
    HWND parent,HMENU menu,HINSTANCE module,LPVOID param)
{
    assert(!ex && cls && title && !(style&WS_VISIBLE) && x==0 && y==0 && w>0 && h>0);
    assert(!parent && !menu && module && !param && dpi_context==DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    if(fault==6)return NULL;
    unsigned n=++next_handle;assert(n<512);slots[n].active=1;++windows;return(HWND)(uintptr_t)n;
}
static BOOL WINAPI peer_destroy(HWND window)
{ if(handle(window)==499)return TRUE;assert(slots[handle(window)].active);slots[handle(window)].active=0;--windows;return TRUE; }
static BOOL WINAPI peer_unregister(LPCWSTR cls,HINSTANCE module)
{ assert(cls && module);if((uintptr_t)cls==499)return TRUE;assert(classes);--classes;return TRUE; }
static BOOL WINAPI peer_is_window(HWND window){return window && (handle(window)==499 || slots[handle(window)].active);}
static DWORD WINAPI peer_thread(void){return thread_id;}
static DPI_AWARENESS_CONTEXT WINAPI peer_dpi_context(DPI_AWARENESS_CONTEXT wanted)
{
    if(fault==1 && wanted==DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)return NULL;
    DPI_AWARENESS_CONTEXT old=dpi_context;dpi_context=wanted;return old;
}
static HMONITOR WINAPI peer_monitor_point(POINT point,DWORD flags)
{ assert(!point.x && !point.y && flags==MONITOR_DEFAULTTOPRIMARY);return(HMONITOR)(uintptr_t)7; }
static BOOL WINAPI peer_monitor_info(HMONITOR monitor,LPMONITORINFO output)
{
    MONITORINFOEXW *info=(MONITORINFOEXW*)output;
    assert((uintptr_t)monitor==7 && info->cbSize==sizeof(*info));if(fault==2)return FALSE;
    info->rcMonitor=(RECT){0,0,2560,1440};info->rcWork=info->rcMonitor;info->dwFlags=MONITORINFOF_PRIMARY;
    wcscpy(info->szDevice,L"Artificial monitor");return TRUE;
}
static BOOL WINAPI peer_settings(LPCWSTR device,DWORD which,DEVMODEW *mode,DWORD flags)
{
    assert(device && which==ENUM_CURRENT_SETTINGS && mode->dmSize==sizeof(*mode) && !flags);
    if(fault==3)return FALSE;
    mode->dmFields=DM_PELSWIDTH|DM_PELSHEIGHT|DM_DISPLAYFREQUENCY;
    mode->dmPelsWidth=fault==4?1920:2560;mode->dmPelsHeight=1440;mode->dmDisplayFrequency=165;return TRUE;
}
static UINT WINAPI peer_dpi(HWND window){assert(peer_is_window(window));return fault==7?0:144;}
static BOOL WINAPI peer_adjust(LPRECT rectangle,DWORD style,BOOL menu,DWORD ex,UINT dpi)
{
    assert(rectangle && style==WS_POPUP && !menu && !ex && dpi==144);if(fault==8)return FALSE;
    return TRUE;
}
static BOOL WINAPI peer_position(HWND window,HWND after,int x,int y,int width,int height,UINT flags)
{
    assert(peer_is_window(window) && !after && !x && !y && flags==(SWP_NOACTIVATE|SWP_NOZORDER));
    if(fault==9)return FALSE;
    slots[handle(window)].width=width;slots[handle(window)].height=height;return TRUE;
}
static BOOL WINAPI peer_client(HWND window,LPRECT rectangle)
{ assert(peer_is_window(window));*rectangle=(RECT){0,0,slots[handle(window)].width,slots[handle(window)].height+(fault==10)};return TRUE; }
static HMONITOR WINAPI peer_monitor_window(HWND window,DWORD flags)
{ assert(peer_is_window(window) && flags==MONITOR_DEFAULTTONULL);return fault==11?NULL:(HMONITOR)(uintptr_t)7; }
static BOOL WINAPI peer_show(HWND window,int command)
{ assert(peer_is_window(window) && command==SW_SHOWNOACTIVATE);if(fault!=14)slots[handle(window)].visible=1;return FALSE; }
static BOOL WINAPI peer_visible(HWND window){return peer_is_window(window) && slots[handle(window)].visible;}
static VkResult VKAPI_CALL peer_surface(VkInstance instance,const VkWin32SurfaceCreateInfoKHR *info,
    const VkAllocationCallbacks *allocator,VkSurfaceKHR *out)
{
    assert(instance && !allocator && info->hwnd && windows);
    if(fault==12){*out=(VkSurfaceKHR)(uintptr_t)0xdead;return VK_ERROR_INITIALIZATION_FAILED;}
    ++surfaces;*out=(VkSurfaceKHR)(uintptr_t)++next_handle;return VK_SUCCESS;
}
static void VKAPI_CALL peer_surface_destroy(VkInstance instance,VkSurfaceKHR surface,const VkAllocationCallbacks *allocator)
{ assert(instance && surface && !allocator);if((uintptr_t)surface==499)return;assert(surfaces);--surfaces; }
static VkResult VKAPI_CALL peer_support(VkPhysicalDevice physical,uint32_t family,VkSurfaceKHR surface,VkBool32 *out)
{ assert(physical && !family && surface);*out=fault==13?VK_FALSE:VK_TRUE;return VK_SUCCESS; }
static PFN_vkVoidFunction VKAPI_CALL peer_get(VkInstance instance,const char *name)
{
    PFN_vkVoidFunction result=NULL;
    if(fault==15 && !strcmp(name,"vkDestroySurfaceKHR"))return NULL;
#define PEER_PROC(api,impl) if(!strcmp(name,#api)){PFN_##api typed=impl;memcpy(&result,&typed,sizeof(result));return result;}
    PEER_PROC(vkCreateWin32SurfaceKHR,peer_surface)
    PEER_PROC(vkDestroySurfaceKHR,peer_surface_destroy)
    PEER_PROC(vkGetPhysicalDeviceSurfaceSupportKHR,peer_support)
#undef PEER_PROC
    return fake_get(instance,name);
}
static OotGraphics *parent_graphics(void)
{
    OotGraphics *g=oot_graphics_create();OotArm64State s=registers(),out;
    assert(g);g->get_instance=peer_get;g->destroy_instance=fake_destroy_instance;
    assert(oot_graphics_call(g,OOT_GRAPHICS_BOOT,&s,&out)==0);
    g->display_report.ready=1;g->display_report.presentation_supported=1;g->window_thread=thread_id;
    g->window=(HWND)(uintptr_t)499;g->window_class=499;g->window_module=GetModuleHandleW(NULL);
    g->surface=(VkSurfaceKHR)(uintptr_t)499;g->destroy_surface=peer_surface_destroy;return g;
}
#ifndef OOT_PEER_FIXTURE_ONLY
int main(void)
{
    old_graphics_fixture();failure=0;
    OotGraphics *g=parent_graphics();
    for(fault=1;fault<=4;++fault){
        assert(!oot_graphics_display_peer_open(g));assert(g->references==1);
        assert(dpi_context==DPI_AWARENESS_CONTEXT_UNAWARE);
    }
    fault=0;OotGraphicsDisplayPeer *display=oot_graphics_display_peer_open(g);OotGraphicsPeerReport report={0};
    assert(display && oot_graphics_display_peer_report(display,&report) && report.width==2560 && report.height==1440);
    assert(report.refresh==165 && g->references==2 && display->references==1);
    assert(!oot_graphics_display_peer_report(display,(OotGraphicsPeerReport*)display));
    for(fault=5;fault<=15;++fault){
        assert(!oot_graphics_layer_peer_open(display,1920,1080));
        assert(!classes && !windows && !surfaces && display->references==1);
        assert(dpi_context==DPI_AWARENESS_CONTEXT_UNAWARE);
    }
    fault=0;OotGraphicsLayerPeer *layer=oot_graphics_layer_peer_open(display,1920,1080);
    assert(layer && oot_graphics_layer_peer_report(layer,&report) && report.width==1920 && report.height==1080);
    assert(report.dpi==144 && report.visible && report.presentation_supported);
    assert(!oot_graphics_layer_peer_report(layer,(OotGraphicsPeerReport*)layer));
    assert(display->references==2 && g->references==2);
    ++thread_id;assert(!oot_graphics_layer_peer_live(layer) && !oot_graphics_display_peer_open(g));--thread_id;
    slots[handle(layer->window)].width=1000;assert(!oot_graphics_layer_peer_live(layer));slots[handle(layer->window)].width=1920;
    assert(oot_graphics_layer_peer_live(layer));
    assert(!oot_graphics_layer_peer_open(display,0,100) && !oot_graphics_layer_peer_open(display,100,2161));
    oot_graphics_destroy(g);oot_graphics_display_peer_close(display);
    assert(oot_graphics_layer_peer_live(layer));oot_graphics_layer_peer_close(layer);
    assert(!classes && !windows && !surfaces && !devices && !instances);
    puts("Display monitor and separate layer ownership, DPI, rollback and lifetime passed.");return 0;
}
#endif
