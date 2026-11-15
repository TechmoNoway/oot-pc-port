/* Synthetic edges over real Windows events, private to the object fixture. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "../src/native_vblank.c"
#include <assert.h>
typedef struct ObjectEdgeFixture {HANDLE pulse;LONG failed;} ObjectEdgeFixture;
static int object_edge_open(void *opaque,HMONITOR monitor)
{ assert((uintptr_t)monitor==7);return SetEvent(((ObjectEdgeFixture*)opaque)->pulse)!=0; }
static int object_edge_wait(void *opaque,HANDLE stop)
{
    ObjectEdgeFixture *fixture=opaque;HANDLE waits[]={stop,fixture->pulse};
    DWORD result=WaitForMultipleObjects(2,waits,FALSE,INFINITE);
    if(result==WAIT_OBJECT_0)return 0;
    return result==WAIT_OBJECT_0+1 && !InterlockedCompareExchange(&fixture->failed,0,0)?1:-1;
}
static void object_edge_close(void *opaque){CloseHandle(((ObjectEdgeFixture*)opaque)->pulse);}
OotVblankSource *oot_test_object_vblank_create(HMONITOR monitor)
{
    static const Backend backend={object_edge_open,object_edge_wait,object_edge_close};
    ObjectEdgeFixture *fixture=calloc(1,sizeof(*fixture));assert(fixture);
    fixture->pulse=CreateEventW(NULL,FALSE,FALSE,NULL);assert(fixture->pulse);
    return create_source(monitor,&backend,fixture,1);
}
void oot_test_object_edge(OotVblankSource *source,int fail)
{
    ObjectEdgeFixture *fixture=source->backend_state;
    InterlockedExchange(&fixture->failed,fail);SetEvent(fixture->pulse);
}
