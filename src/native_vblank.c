/* Owned host vertical-blank backend; no timer and no guest code execution. */
#define COBJMACROS
#include "native_vblank.h"
#include <dxgi.h>
#include <stdlib.h>
#include <string.h>

typedef struct Backend {
    int (*open)(void *,HMONITOR);
    int (*wait)(void *,HANDLE); /* 1 actual edge, 0 stop, -1 unavailable. */
    void (*close)(void *);
} Backend;
typedef struct DxgiBackend { HMODULE module;IDXGIOutput *output; } DxgiBackend;
struct OotVblankSource {
    SRWLOCK lock;
    HANDLE stop,ready,event,failure,thread;
    HMONITOR monitor;
    uint64_t ticks;
    int failed,signaled,initialized;
    Backend backend;
    void *backend_state;
    int free_backend;
};

static int dxgi_open(void *opaque,HMONITOR monitor)
{
    DxgiBackend *state=opaque;IDXGIFactory1 *factory=NULL;
    HRESULT (WINAPI *create)(REFIID,void **)=NULL;FARPROC raw;
    state->module=LoadLibraryExW(L"dxgi.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!state->module)return 0;
    raw=GetProcAddress(state->module,"CreateDXGIFactory1");
    _Static_assert(sizeof(raw)==sizeof(create),"Windows function pointer representation");
    memcpy(&create,&raw,sizeof(create));if(!create)return 0;
    if(create(&IID_IDXGIFactory1,(void**)&factory)!=S_OK || !factory)return 0;
    for(UINT a=0;a<64 && !state->output;++a){
        IDXGIAdapter1 *adapter=NULL;
        if(IDXGIFactory1_EnumAdapters1(factory,a,&adapter)!=S_OK || !adapter)break;
        for(UINT n=0;n<64;++n){
            IDXGIOutput *output=NULL;DXGI_OUTPUT_DESC desc;
            if(IDXGIAdapter1_EnumOutputs(adapter,n,&output)!=S_OK || !output)break;
            if(IDXGIOutput_GetDesc(output,&desc)==S_OK && desc.AttachedToDesktop && desc.Monitor==monitor){
                state->output=output;break;
            }
            IDXGIOutput_Release(output);
        }
        IDXGIAdapter1_Release(adapter);
    }
    IDXGIFactory1_Release(factory);return state->output!=NULL;
}
static int dxgi_wait(void *opaque,HANDLE stop)
{
    DxgiBackend *state=opaque;
    if(WaitForSingleObject(stop,0)==WAIT_OBJECT_0)return 0;
    return IDXGIOutput_WaitForVBlank(state->output)==S_OK ? 1:-1;
}
static void dxgi_close(void *opaque)
{
    DxgiBackend *state=opaque;
    if(state->output)IDXGIOutput_Release(state->output);
    if(state->module)FreeLibrary(state->module);
    memset(state,0,sizeof(*state));
}
static DWORD WINAPI worker(void *opaque)
{
    OotVblankSource *source=opaque;int opened=source->backend.open(source->backend_state,source->monitor);
    if(opened){
        for(;;){
            int edge;
            if(WaitForSingleObject(source->stop,0)==WAIT_OBJECT_0)break;
            edge=source->backend.wait(source->backend_state,source->stop);
            if(edge==0)break;
            AcquireSRWLockExclusive(&source->lock);
            if(edge<0 || source->ticks==UINT64_MAX || !SetEvent(source->event)){
                source->failed=1;ReleaseSRWLockExclusive(&source->lock);break;
            }
            source->signaled=1;++source->ticks;source->initialized=1;
            ReleaseSRWLockExclusive(&source->lock);
            SetEvent(source->ready);
        }
    } else {
        AcquireSRWLockExclusive(&source->lock);source->failed=1;ReleaseSRWLockExclusive(&source->lock);
    }
    AcquireSRWLockExclusive(&source->lock);
    if(source->failed)SetEvent(source->failure);
    ReleaseSRWLockExclusive(&source->lock);
    SetEvent(source->ready);source->backend.close(source->backend_state);return 0;
}
static OotVblankSource *create_source(HMONITOR monitor,const Backend *backend,void *state,int free_state)
{
    OotVblankSource *source;
    if(!monitor || !backend || !backend->open || !backend->wait || !backend->close || !state){
        if(free_state)free(state);
        return NULL;
    }
    source=calloc(1,sizeof(*source));if(!source){if(free_state)free(state);return NULL;}
    InitializeSRWLock(&source->lock);source->monitor=monitor;source->backend=*backend;
    source->backend_state=state;source->free_backend=free_state;
    source->stop=CreateEventW(NULL,TRUE,FALSE,NULL);source->ready=CreateEventW(NULL,TRUE,FALSE,NULL);
    source->event=CreateEventW(NULL,TRUE,FALSE,NULL);source->failure=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!source->stop || !source->ready || !source->event || !source->failure)goto failure;
    source->thread=CreateThread(NULL,0,worker,source,0,NULL);if(!source->thread)goto failure;
    if(WaitForSingleObject(source->ready,5000)!=WAIT_OBJECT_0)goto failure;
    AcquireSRWLockShared(&source->lock);int live=source->initialized && !source->failed;ReleaseSRWLockShared(&source->lock);
    if(!live)goto failure;
    return source;
failure:
    oot_vblank_destroy(source);return NULL;
}
OotVblankSource *oot_vblank_create(HMONITOR monitor)
{
    static const Backend backend={dxgi_open,dxgi_wait,dxgi_close};
    return create_source(monitor,&backend,calloc(1,sizeof(DxgiBackend)),1);
}
void oot_vblank_destroy(OotVblankSource *source)
{
    if(!source)return;
    if(source->stop)SetEvent(source->stop);
    if(source->thread){WaitForSingleObject(source->thread,INFINITE);CloseHandle(source->thread);}
    if(source->stop)CloseHandle(source->stop);
    if(source->ready)CloseHandle(source->ready);
    if(source->event)CloseHandle(source->event);
    if(source->failure)CloseHandle(source->failure);
    if(source->free_backend)free(source->backend_state);
    free(source);
}
static int disjoint(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y ? y-x>=an:x-y>=bn;
}
int oot_vblank_snapshot(OotVblankSource *source,OotVblankSnapshot *out)
{
    if(!source || !out || !disjoint(source,sizeof(*source),out,sizeof(*out)))return 0;
    AcquireSRWLockShared(&source->lock);
    *out=(OotVblankSnapshot){source->ticks,(uint32_t)(source->initialized && !source->failed),
        (uint32_t)source->failed,(uint32_t)source->signaled,0};
    ReleaseSRWLockShared(&source->lock);return 1;
}
int oot_vblank_duplicate_read(OotVblankSource *source,HANDLE *out)
{
    HANDLE copy=NULL;int success=0;
    if(!source || !out || !disjoint(source,sizeof(*source),out,sizeof(*out)))return 0;
    AcquireSRWLockShared(&source->lock);
    if(source->initialized && !source->failed && DuplicateHandle(GetCurrentProcess(),source->event,
        GetCurrentProcess(),&copy,SYNCHRONIZE,FALSE,0) && copy){*out=copy;success=1;}
    ReleaseSRWLockShared(&source->lock);return success;
}
int oot_vblank_reset(OotVblankSource *source,int require_signal)
{
    int result=OOT_VBLANK_UNAVAILABLE;
    if(!source || (require_signal!=0 && require_signal!=1))return result;
    AcquireSRWLockExclusive(&source->lock);
    if(source->initialized && !source->failed){
        if(require_signal && !source->signaled)result=OOT_VBLANK_ALREADY_RESET;
        else if(ResetEvent(source->event)){source->signaled=0;result=OOT_VBLANK_CLEARED;}
    }
    ReleaseSRWLockExclusive(&source->lock);return result;
}
int oot_vblank_duplicate_wait_handles(OotVblankSource *source,HANDLE *data,HANDLE *failure)
{
    HANDLE first=NULL,second=NULL;int success=0;
    if(!source || !data || !failure || !disjoint(source,sizeof(*source),data,sizeof(*data)) ||
       !disjoint(source,sizeof(*source),failure,sizeof(*failure)) ||
       !disjoint(data,sizeof(*data),failure,sizeof(*failure)))return 0;
    AcquireSRWLockShared(&source->lock);
    if(source->initialized && !source->failed &&
       DuplicateHandle(GetCurrentProcess(),source->event,GetCurrentProcess(),&first,SYNCHRONIZE,FALSE,0) && first){
        if(DuplicateHandle(GetCurrentProcess(),source->failure,GetCurrentProcess(),&second,SYNCHRONIZE,FALSE,0) && second){
            *data=first;*failure=second;success=1;
        } else CloseHandle(first);
    }
    ReleaseSRWLockShared(&source->lock);return success;
}

