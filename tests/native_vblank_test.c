/* Independent synthetic edge source plus explicit opt-in physical probe. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
static unsigned duplicate_calls,fail_duplicate;
static LONG fail_reset,fail_signal;
static BOOL WINAPI test_duplicate(HANDLE,HANDLE,HANDLE,LPHANDLE,DWORD,BOOL,DWORD);
static BOOL WINAPI test_reset(HANDLE);
static BOOL WINAPI test_signal(HANDLE);
#define DuplicateHandle test_duplicate
#define ResetEvent test_reset
#define SetEvent test_signal
#include "../src/native_vblank.c"
#undef DuplicateHandle
#undef ResetEvent
#undef SetEvent
static BOOL WINAPI test_duplicate(HANDLE a,HANDLE b,HANDLE c,LPHANDLE out,DWORD access,BOOL inherit,DWORD flags)
{
    ++duplicate_calls;
    if(fail_duplicate && duplicate_calls==fail_duplicate){*out=(HANDLE)(uintptr_t)0xdead;return FALSE;}
    return DuplicateHandle(a,b,c,out,access,inherit,flags);
}
static BOOL WINAPI test_reset(HANDLE event)
{
    if(InterlockedExchange(&fail_reset,0)){SetLastError(ERROR_INVALID_HANDLE);return FALSE;}
    return ResetEvent(event);
}
static BOOL WINAPI test_signal(HANDLE event)
{
    if(InterlockedExchange(&fail_signal,0)){SetLastError(ERROR_INVALID_HANDLE);return FALSE;}
    return SetEvent(event);
}
typedef struct FakeBackend { HANDLE pulse;LONG fail_open,fail_wait,opens,closes; } FakeBackend;
static int fake_open(void *opaque,HMONITOR monitor)
{
    FakeBackend *state=opaque;assert(monitor==(HMONITOR)(uintptr_t)11);
    InterlockedIncrement(&state->opens);
    if(InterlockedCompareExchange(&state->fail_open,0,0))return 0;
    SetEvent(state->pulse);return 1;
}
static int fake_wait(void *opaque,HANDLE stop)
{
    FakeBackend *state=opaque;HANDLE handles[]={stop,state->pulse};
    DWORD result=WaitForMultipleObjects(2,handles,FALSE,INFINITE);
    if(result==WAIT_OBJECT_0)return 0;
    if(result!=WAIT_OBJECT_0+1 || InterlockedCompareExchange(&state->fail_wait,0,0))return -1;
    return 1;
}
static void fake_close(void *opaque){InterlockedIncrement(&((FakeBackend*)opaque)->closes);}
static void await_ticks(OotVblankSource *source,uint64_t ticks)
{
    ULONGLONG deadline=GetTickCount64()+1000;OotVblankSnapshot report;
    do{assert(oot_vblank_snapshot(source,&report));if(report.ticks>=ticks)return;Sleep(1);}while(GetTickCount64()<deadline);
    assert(0 && "worker did not consume the synthetic edge");
}
static void synthetic(void)
{
    const Backend backend={fake_open,fake_wait,fake_close};DWORD before,after;
    assert(GetProcessHandleCount(GetCurrentProcess(),&before));
    FakeBackend fake={0};fake.pulse=CreateEventW(NULL,FALSE,FALSE,NULL);assert(fake.pulse);
    fake.fail_open=1;
    assert(!create_source((HMONITOR)(uintptr_t)11,&backend,&fake,0));
    assert(fake.opens==1 && fake.closes==1);fake.fail_open=0;
    OotVblankSource *source=create_source((HMONITOR)(uintptr_t)11,&backend,&fake,0);
    assert(source);OotVblankSnapshot report;HANDLE read=NULL;
    assert(oot_vblank_snapshot(source,&report) && report.ready && report.ticks==1 && report.signaled && !report.failed);
    assert(oot_vblank_duplicate_read(source,&read) && read);
    HANDLE pair_data=(HANDLE)(uintptr_t)0x51,pair_failure=(HANDLE)(uintptr_t)0x52;
    DWORD pair_before,pair_after;assert(GetProcessHandleCount(GetCurrentProcess(),&pair_before));
    fail_duplicate=duplicate_calls+2;
    assert(!oot_vblank_duplicate_wait_handles(source,&pair_data,&pair_failure));
    assert(pair_data==(HANDLE)(uintptr_t)0x51 && pair_failure==(HANDLE)(uintptr_t)0x52);
    assert(GetProcessHandleCount(GetCurrentProcess(),&pair_after) && pair_after==pair_before);
    fail_duplicate=0;
    assert(oot_vblank_duplicate_wait_handles(source,&pair_data,&pair_failure));
    assert(!oot_vblank_duplicate_wait_handles(source,&pair_data,&pair_data));
    assert(WaitForSingleObject(read,0)==WAIT_OBJECT_0);
    assert(!ResetEvent(read) && GetLastError()==ERROR_ACCESS_DENIED);
    InterlockedExchange(&fail_reset,1);
    assert(oot_vblank_reset(source,1)==OOT_VBLANK_UNAVAILABLE);
    assert(oot_vblank_snapshot(source,&report) && report.signaled && report.ticks==1);
    assert(WaitForSingleObject(read,0)==WAIT_OBJECT_0);
    assert(oot_vblank_reset(source,1)==OOT_VBLANK_CLEARED);
    assert(WaitForSingleObject(read,0)==WAIT_TIMEOUT);
    assert(oot_vblank_reset(source,1)==OOT_VBLANK_ALREADY_RESET);
    assert(oot_vblank_reset(source,0)==OOT_VBLANK_CLEARED);
    for(uint64_t n=2;n<=4;++n){SetEvent(fake.pulse);await_ticks(source,n);}
    assert(WaitForSingleObject(read,0)==WAIT_OBJECT_0);
    assert(oot_vblank_snapshot(source,&report) && report.ticks==4 && report.signaled);
    assert(!oot_vblank_snapshot(source,(OotVblankSnapshot*)source));
    assert(!oot_vblank_duplicate_read(source,(HANDLE*)source));
    assert(oot_vblank_reset(source,2)==OOT_VBLANK_UNAVAILABLE);
    InterlockedExchange(&fake.fail_wait,1);SetEvent(fake.pulse);
    assert(WaitForSingleObject(source->failure,1000)==WAIT_OBJECT_0);
    assert(WaitForSingleObject(pair_failure,0)==WAIT_OBJECT_0);
    assert(oot_vblank_snapshot(source,&report) && report.failed && !report.ready && report.ticks==4);
    HANDLE unchanged=(HANDLE)(uintptr_t)0x55;
    assert(!oot_vblank_duplicate_read(source,&unchanged) && unchanged==(HANDLE)(uintptr_t)0x55);
    assert(oot_vblank_reset(source,0)==OOT_VBLANK_UNAVAILABLE);
    CloseHandle(read);CloseHandle(pair_data);CloseHandle(pair_failure);oot_vblank_destroy(source);
    assert(fake.closes==2);
    InterlockedExchange(&fake.fail_wait,0);
    source=create_source((HMONITOR)(uintptr_t)11,&backend,&fake,0);assert(source);
    AcquireSRWLockExclusive(&source->lock);source->ticks=UINT64_MAX;ReleaseSRWLockExclusive(&source->lock);
    SetEvent(fake.pulse);
    assert(WaitForSingleObject(source->failure,1000)==WAIT_OBJECT_0);
    assert(oot_vblank_snapshot(source,&report) && report.failed && report.ticks==UINT64_MAX);
    oot_vblank_destroy(source);assert(fake.closes==3);
    source=create_source((HMONITOR)(uintptr_t)11,&backend,&fake,0);assert(source);
    assert(oot_vblank_reset(source,1)==OOT_VBLANK_CLEARED);
    InterlockedExchange(&fail_signal,1);SetEvent(fake.pulse);
    assert(WaitForSingleObject(source->failure,1000)==WAIT_OBJECT_0);
    assert(oot_vblank_snapshot(source,&report) && report.failed && report.ticks==1 && !report.signaled);
    oot_vblank_destroy(source);assert(fake.closes==4);
    /* Two owners must not consume/reset each other's signals. */
    FakeBackend second_fake={0};second_fake.pulse=CreateEventW(NULL,FALSE,FALSE,NULL);assert(second_fake.pulse);
    source=create_source((HMONITOR)(uintptr_t)11,&backend,&fake,0);
    OotVblankSource *second=create_source((HMONITOR)(uintptr_t)11,&backend,&second_fake,0);
    assert(source && second && oot_vblank_reset(source,1)==OOT_VBLANK_CLEARED);
    assert(oot_vblank_snapshot(second,&report) && report.ticks==1 && report.signaled);
    SetEvent(fake.pulse);await_ticks(source,2);
    assert(oot_vblank_snapshot(second,&report) && report.ticks==1 && report.signaled);
    oot_vblank_destroy(source);oot_vblank_destroy(second);CloseHandle(second_fake.pulse);
    assert(fake.closes==5 && second_fake.closes==1);CloseHandle(fake.pulse);
    assert(GetProcessHandleCount(GetCurrentProcess(),&after) && after==before);
    assert(!oot_vblank_create(NULL));
    puts("Synthetic edge, level signal, reset, ownership, failure and cleanup passed.");
}
static void physical(void)
{
    POINT point={0,0};OotVblankSource *source=oot_vblank_create(MonitorFromPoint(point,MONITOR_DEFAULTTOPRIMARY));
    OotVblankSnapshot report;HANDLE read=NULL;
    assert(source && oot_vblank_duplicate_read(source,&read));
    for(unsigned n=0;n<16;++n){
        assert(WaitForSingleObject(read,1000)==WAIT_OBJECT_0);
        assert(oot_vblank_reset(source,1)==OOT_VBLANK_CLEARED);
    }
    assert(oot_vblank_snapshot(source,&report) && report.ready && report.ticks>=16);
    CloseHandle(read);oot_vblank_destroy(source);
    printf("{\"physical_edges_observed\":%llu,\"successful_waits_and_resets\":16,\"guest_capability\":false}\n",
        (unsigned long long)report.ticks);
}
int main(int argc,char **argv)
{
    if(argc==2 && !strcmp(argv[1],"--physical"))physical();else synthetic();
    return 0;
}

