/* Independent synthetic Win32/surface dispatch; no window or GPU is created. */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define VK_NO_PROTOTYPES
#include <windows.h>
#include <vulkan/vulkan_core.h>
#include <vulkan/vulkan_win32.h>
static ATOM WINAPI test_register(const WNDCLASSEXW *);
static HWND WINAPI test_window(DWORD,LPCWSTR,LPCWSTR,DWORD,int,int,int,int,HWND,HMENU,HINSTANCE,LPVOID);
static BOOL WINAPI test_destroy_window(HWND);
static BOOL WINAPI test_unregister(LPCWSTR,HINSTANCE);
static BOOL WINAPI test_is_window(HWND);
static DWORD WINAPI test_thread(void);
#define RegisterClassExW test_register
#define CreateWindowExW test_window
#define DestroyWindow test_destroy_window
#define UnregisterClassW test_unregister
#define IsWindow test_is_window
#define GetCurrentThreadId test_thread
#define main existing_graphics_fixture
#include "native_graphics_test.c"
#undef main

static unsigned display_failure,classes,windows,surfaces,display_creations;
static DWORD current_thread=123;
static ATOM WINAPI test_register(const WNDCLASSEXW *info)
{
    assert(info && info->cbSize==sizeof(*info) && info->hInstance && info->lpfnWndProc);
    if(display_failure==1)return 0;
    ++classes;return 17;
}
static HWND WINAPI test_window(DWORD ex,LPCWSTR cls,LPCWSTR title,DWORD style,
    int x,int y,int width,int height,HWND parent,HMENU menu,HINSTANCE module,LPVOID param)
{
    (void)x;(void)y;
    assert(!ex && cls && title && module && !parent && !menu && !param && classes);
    assert(!(style&WS_VISIBLE) && width>0 && height>0);
    if(display_failure==2)return NULL;
    ++windows;return (HWND)(uintptr_t)18;
}
static BOOL WINAPI test_destroy_window(HWND window)
{ assert(window && windows && !surfaces);--windows;return TRUE; }
static BOOL WINAPI test_unregister(LPCWSTR name,HINSTANCE module)
{ assert(name && module && classes && !windows && !surfaces);--classes;return TRUE; }
static BOOL WINAPI test_is_window(HWND window)
{ return window && windows && display_failure!=7; }
static DWORD WINAPI test_thread(void) { return current_thread; }
static VkResult VKAPI_CALL test_surface(VkInstance instance,const VkWin32SurfaceCreateInfoKHR *info,
    const VkAllocationCallbacks *allocator,VkSurfaceKHR *out)
{
    assert(instance && !allocator && info->sType==VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR);
    assert(info->hinstance && info->hwnd && windows && info->pNext==NULL && !info->flags);
    if(display_failure==3){*out=(VkSurfaceKHR)(uintptr_t)0xdead;return VK_ERROR_INITIALIZATION_FAILED;}
    ++surfaces;++display_creations;*out=(VkSurfaceKHR)(uintptr_t)19;return VK_SUCCESS;
}
static void VKAPI_CALL test_destroy_surface(VkInstance instance,VkSurfaceKHR surface,
    const VkAllocationCallbacks *allocator)
{ assert(instance && surface && !allocator && surfaces && windows && devices);--surfaces; }
static VkResult VKAPI_CALL test_support(VkPhysicalDevice physical,uint32_t family,VkSurfaceKHR surface,VkBool32 *out)
{
    assert(physical && family==0 && surface && surfaces);
    *out=display_failure==4 ? VK_FALSE:VK_TRUE;
    return display_failure==5 ? VK_ERROR_SURFACE_LOST_KHR:VK_SUCCESS;
}
static PFN_vkVoidFunction VKAPI_CALL display_get(VkInstance instance,const char *name)
{
    PFN_vkVoidFunction result=NULL;
    if(display_failure==6 && !strcmp(name,"vkDestroySurfaceKHR"))return NULL;
#define MATCH(api,impl) if(!strcmp(name,#api)){PFN_##api typed=impl;memcpy(&result,&typed,sizeof(result));return result;}
    MATCH(vkCreateWin32SurfaceKHR,test_surface)
    MATCH(vkDestroySurfaceKHR,test_destroy_surface)
    MATCH(vkGetPhysicalDeviceSurfaceSupportKHR,test_support)
#undef MATCH
    return fake_get(instance,name);
}
#ifndef OOT_DISPLAY_FIXTURE_ONLY
static OotGraphics *booted(void)
{
    OotGraphics *g=oot_graphics_create();OotArm64State s=registers(),out;
    assert(g);g->get_instance=display_get;g->destroy_instance=fake_destroy_instance;
    assert(oot_graphics_call(g,OOT_GRAPHICS_BOOT,&s,&out)==0);return g;
}
int main(void)
{
    OotArm64State s=registers(),out,old,expected=s;OotDisplayReport before,after;OotGraphicsReport a,b;
    expected.pc=s.x[30];memset(&out,0xa5,sizeof(out));memcpy(&old,&out,sizeof(out));
    OotGraphics *cold=oot_graphics_create();assert(cold);
    assert(oot_graphics_call(cold,OOT_DISPLAY_INITIALIZE,&s,&out)==1);
    assert(!memcmp(&old,&out,sizeof(out)) && !classes && !windows && !surfaces);
    oot_graphics_destroy(cold);
    for(display_failure=1;display_failure<=6;++display_failure){
        OotGraphics *g=booted();
        assert(oot_graphics_display_snapshot(g,&before) && oot_graphics_snapshot(g,&a));
        assert(oot_graphics_call(g,OOT_DISPLAY_INITIALIZE,&s,&out)!=0);
        assert(!memcmp(&old,&out,sizeof(out)) && !classes && !windows && !surfaces);
        assert(oot_graphics_display_snapshot(g,&after) && !memcmp(&before,&after,sizeof(before)));
        assert(oot_graphics_snapshot(g,&b) && !memcmp(&a,&b,sizeof(a)) && instances==1 && devices==1);
        oot_graphics_destroy(g);assert(!devices && !instances);
    }
    display_failure=0;OotGraphics *g=booted();unsigned created=display_creations;
    assert(oot_graphics_call(g,OOT_DISPLAY_INITIALIZE,&s,&out)==0);
    /* Compare every declared register field. C struct assignment need not copy
     * padding, which is not architectural state. Failed outputs stay byte-exact. */
    assert(!memcmp(out.x,expected.x,sizeof(out.x)) && out.sp==expected.sp &&
        out.pc==expected.pc && out.nzcv==expected.nzcv);
    assert(classes==1 && windows==1 && surfaces==1 && display_creations==created+1);
    assert(oot_graphics_call(g,OOT_DISPLAY_INITIALIZE,&s,&out)==0 && display_creations==created+1);
    assert(oot_graphics_display_snapshot(g,&before) && before.ready==1 && before.calls==2 &&
        before.initializations==2 && before.presentation_supported==1);
    assert(oot_graphics_snapshot(g,&a) && a.calls==1 && a.boots==1 && a.checks==0);
    memcpy(&old,&out,sizeof(out));current_thread++;
    assert(oot_graphics_call(g,OOT_DISPLAY_INITIALIZE,&s,&out)==2 && !memcmp(&old,&out,sizeof(out)));
    current_thread--;display_failure=7;
    assert(oot_graphics_call(g,OOT_DISPLAY_INITIALIZE,&s,&out)==1 && !memcmp(&old,&out,sizeof(out)));
    display_failure=0;
    assert(oot_graphics_display_snapshot(g,&after) && !memcmp(&before,&after,sizeof(before)));
    g->display_report.calls=UINT64_MAX;
    assert(oot_graphics_call(g,OOT_DISPLAY_INITIALIZE,&s,&out)==2 && !memcmp(&old,&out,sizeof(out)));
    g->display_report.calls=2;g->display_report.initializations=UINT64_MAX;
    assert(oot_graphics_call(g,OOT_DISPLAY_INITIALIZE,&s,&out)==2 && !memcmp(&old,&out,sizeof(out)));
    assert(oot_graphics_call(g,OOT_DISPLAY_INITIALIZE,&s,&s)==2);
    assert(oot_graphics_display_snapshot(g,(OotDisplayReport *)g)==0);
    oot_graphics_destroy(g);assert(!classes && !windows && !surfaces && !instances && !devices);
    puts("Display resource lifecycle and failure isolation passed.");return 0;
}
#endif
