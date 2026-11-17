#define OOT_PEER_FIXTURE_ONLY
#include "native_graphics_peer_test.c"
#include "../src/native_vblank.h"
OotVblankSource *oot_test_object_vblank_create(HMONITOR);
void oot_test_object_edge(OotVblankSource*,int);
#define oot_vblank_create oot_test_object_vblank_create
#include "../src/native_objects.c"
#undef oot_vblank_create
#include OOT_OBJECT_TEST_DECLARATION

static void object_call3(OotObjects *objects,uint32_t id,uint64_t x0,uint64_t x1,uint64_t x2,int expected)
{
    OotArm64State state=registers(),before;
    state.x[0]=x0;state.x[1]=x1;state.x[2]=x2;before=state;
    int status=oot_objects_call(objects,id,&state);
    if(status!=expected)fprintf(stderr,"object handler %u: got %d, expected %d\n",id,status,expected);
    assert(status==expected);
    if(status){assert(!memcmp(&state,&before,sizeof(state)));return;}
    assert(state.pc==before.x[30] && state.sp==before.sp && state.nzcv==before.nzcv);
    for(unsigned n=0;n<31;++n)if(n || !oot_objects_returns_value(id))assert(state.x[n]==before.x[n]);
    if(oot_objects_returns_value(id) && id!=OOT_NVN_GET_PROC)assert(state.x[0]<=UINT32_MAX);
    if(id==OOT_NVN_DEVICE_INITIALIZE)assert(state.x[0]==1);
    if(id==OOT_NVN_DEVICE_GET_ORIGIN)assert(state.x[0]==objects->nvn_report.window_origin);
    if(id==OOT_NVN_DEVICE_GET_DEPTH)assert(state.x[0]==objects->nvn_report.depth_mode);
#ifdef OOT_NVN_OWNER_TEST
    if(id==OOT_NVN_GET_PROC)assert(state.x[0]==object_test_procs[2].entry);
#endif
}
static void object_call(OotObjects *objects,uint32_t id,uint64_t x0,uint64_t x1,int expected)
{ object_call3(objects,id,x0,x1,0,expected); }
static uint64_t read_value(OotGuestMemory *memory,uint64_t at,unsigned size)
{ uint64_t value=0;assert(oot_memory_load(memory,at,size,&value));return value; }
int main(int argc,char **argv)
{
    assert(argc==2);char error[200];OotRuntimeImage *image=oot_runtime_open(argv[1],error,sizeof(error));assert(image);
    OotGuestMemory *memory=oot_runtime_memory(image);OotGraphics *g=parent_graphics();
    const OotObjectDeclaration *d=&object_test_declaration;OotObjectDeclaration bad=*d;
    uint64_t out=d->layer+0x400,event_out=out+0x40,handle_array=out+0x100;
    bad.image_sha256[0]^=1;assert(!oot_objects_create(image,memory,g,&bad));
    bad=*d;bad.vptr_address[2]=bad.vptr_address[1];assert(!oot_objects_create(image,memory,g,&bad));
    bad=*d;bad.tables[7].sha256[0]^=1;assert(!oot_objects_create(image,memory,g,&bad));
    bad=*d;bad.flags=OOT_OBJECT_REFRESH;assert(!oot_objects_create(image,memory,g,&bad));
    bad=*d;bad.flags=OOT_OBJECT_NVN_RESOURCES;assert(!oot_objects_create(image,memory,g,&bad));
    bad=*d;bad.flags=0;
    OotObjects *no_event=oot_objects_create(image,memory,g,&bad);assert(no_event);
    assert(!oot_objects_handler_valid(no_event,OOT_OBJECT_VSYNC_EVENT));
    assert(!oot_objects_handler_valid(no_event,OOT_NVN_POOL_INITIALIZE));
    object_call(no_event,OOT_OBJECT_VSYNC_EVENT,d->layer+0x400,d->display,1);
    oot_objects_destroy(no_event);
    OotObjects *objects=oot_objects_create(image,memory,g,d);assert(objects);
#ifdef OOT_NVN_OWNER_TEST
    OotNvnDeclaration bad_nvn=object_test_nvn;bad_nvn.table_sha256[0]^=1;
    assert(!oot_objects_bind_nvn(objects,&bad_nvn));
    assert(oot_objects_bind_nvn(objects,&object_test_nvn));
    assert(!oot_objects_bind_nvn(objects,&object_test_nvn));
#endif
    if(d->flags&OOT_OBJECT_REFRESH)object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display,1,2);
    assert(oot_memory_store(memory,out,8,0xabcdef));
    object_call(objects,OOT_OBJECT_OPEN_DISPLAY,out,0,2);
    assert(read_value(memory,out,8)==0xabcdef && objects->report.calls==0 && !objects->display);
    for(unsigned n=0;n<OOT_OBJECT_VPTRS;++n)assert(oot_memory_store(memory,d->vptr_address[n],8,d->vptr_value[n]));
    if(d->flags&OOT_OBJECT_REFRESH)object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display,1,1);
    object_call(objects,OOT_OBJECT_OPEN_DISPLAY,d->display,0,2);
    object_call(objects,OOT_OBJECT_OPEN_DISPLAY,0,0,2);
    assert(objects->report.calls==0 && !objects->display && g->references==1);
    fault=2;object_call(objects,OOT_OBJECT_OPEN_DISPLAY,out,0,1);fault=0;
    assert(read_value(memory,out,8)==0xabcdef && objects->report.calls==0);
    object_call(objects,OOT_OBJECT_OPEN_DISPLAY,out,0,0);
    assert(read_value(memory,out,8)==d->display && objects->report.references==1);
    object_call(objects,OOT_OBJECT_OPEN_DISPLAY,out,0,0);assert(objects->report.references==2);
    if(d->flags&OOT_OBJECT_REFRESH){
        OotRefreshReport r,before;assert(oot_objects_refresh_snapshot(objects,&r));
        assert(r.version==1 && !r.capability_bits && !r.updates);
        for(unsigned n=0;n<8;++n){
            uint64_t value=UINT64_C(0xaabbccdd12345670)+n;
            object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display,value,0);
            assert(oot_objects_refresh_snapshot(objects,&r));
            assert(r.capability_bits==((value&1)<<1) && r.update_mask==2 && r.updates==n+1);
        }
        before=r;object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display+8,1,0);
        assert(oot_objects_refresh_snapshot(objects,&r) && r.updates==before.updates &&
            r.capability_bits==before.capability_bits && r.ignored==1);
        objects->refresh.updates=UINT64_MAX;before=objects->refresh;
        object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display,0,2);
        assert(!memcmp(&before,&objects->refresh,sizeof(before)));objects->refresh.updates=r.updates;
        objects->refresh.ignored=UINT64_MAX;before=objects->refresh;
        object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,0,0,2);
        assert(!memcmp(&before,&objects->refresh,sizeof(before)));objects->refresh.ignored=r.ignored;
        assert(!oot_objects_refresh_snapshot(objects,&objects->refresh));
        objects->refresh.capability_bits=0x80;
        object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display,1,0);
        assert(objects->refresh.capability_bits==0x82);
        object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display,0,0);
        assert(objects->refresh.capability_bits==0x80);
        uint64_t word=read_value(memory,d->vptr_address[0],8);
        assert(oot_memory_store(memory,d->vptr_address[0],8,0));before=objects->refresh;
        object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display,0,2);
        assert(!memcmp(&before,&objects->refresh,sizeof(before)));
        assert(oot_memory_store(memory,d->vptr_address[0],8,word));
        ++thread_id;object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display,0,2);--thread_id;
        assert(!memcmp(&before,&objects->refresh,sizeof(before)));
    } else {
        OotRefreshReport r;memset(&r,0x6b,sizeof(r));OotRefreshReport before=r;
        assert(!oot_objects_refresh_snapshot(objects,&r) && !memcmp(&r,&before,sizeof(r)));
        object_call(objects,OOT_OBJECT_REFRESH_CAPABILITY,d->display,1,1);
    }
    object_call(objects,OOT_OBJECT_CREATE_LAYER,out,d->display+8,1);
    fault=12;object_call(objects,OOT_OBJECT_CREATE_LAYER,out,d->display,1);fault=0;
    assert(!objects->layer && !windows && !surfaces && objects->report.creates==0);
    object_call(objects,OOT_OBJECT_CREATE_LAYER,out,d->display,0);
    assert(read_value(memory,out,8)==d->layer && objects->report.creates==1 && windows==1 && surfaces==1);
    object_call(objects,OOT_OBJECT_CREATE_LAYER,out,d->display,0);
    assert(read_value(memory,out,8)==0 && objects->report.creates==1);
    object_call(objects,OOT_OBJECT_NATIVE_WINDOW,out,d->layer+8,1);
    object_call(objects,OOT_OBJECT_NATIVE_WINDOW,out,d->layer,0);
    assert(read_value(memory,out,8)==d->native_window && objects->report.window_getters==1);
    uint64_t saved=read_value(memory,d->vptr_address[4],8);
    assert(oot_memory_store(memory,d->vptr_address[4],8,0));
    object_call(objects,OOT_OBJECT_NATIVE_WINDOW,out,d->layer,2);
    assert(oot_memory_store(memory,d->vptr_address[4],8,saved));
    ++thread_id;object_call(objects,OOT_OBJECT_NATIVE_WINDOW,out,d->layer,2);--thread_id;
    objects->report.window_getters=UINT64_MAX;object_call(objects,OOT_OBJECT_NATIVE_WINDOW,out,d->layer,2);
    objects->report.window_getters=1;
#ifdef OOT_NVN_OWNER_TEST
    uint64_t nvn_name=out+0x180,nvn_builder=out+0x100,nvn_device=out;
    uint8_t zeros[24]={0};OotNvnReport nr,nr_before;
    assert(oot_memory_store_record(memory,nvn_name,(const uint8_t*)"nvnDeviceInitialize",20));
    object_call(objects,OOT_NVN_GET_PROC,0,nvn_name,0);
    assert(oot_objects_nvn_snapshot(objects,&nr) && nr.lookups==1 && !nr.device);
    assert(oot_memory_store_record(memory,nvn_builder,zeros,24));
    uint64_t untouched_device=read_value(memory,nvn_device,8);
    object_call(objects,OOT_NVN_DEVICE_INITIALIZE,nvn_device,nvn_builder,0);
    assert(read_value(memory,nvn_device,8)==untouched_device);
    assert(oot_objects_nvn_snapshot(objects,&nr) && nr.device==nvn_device && nr.initializations==1);
    nr_before=nr;object_call(objects,OOT_NVN_DEVICE_INITIALIZE,nvn_device,nvn_builder,1);
    assert(!memcmp(&nr_before,&objects->nvn_report,sizeof(nr_before)));
    object_call(objects,OOT_NVN_GET_PROC,nvn_device,nvn_name,0);
    nr_before=objects->nvn_report;
    object_call(objects,OOT_NVN_GET_PROC,nvn_device+8,nvn_name,1);
    assert(!memcmp(&nr_before,&objects->nvn_report,sizeof(nr_before)));
    assert(oot_memory_store_record(memory,nvn_name,(const uint8_t*)"nvnUnknown",11));
    object_call(objects,OOT_NVN_GET_PROC,0,nvn_name,1);
    assert(!memcmp(&nr_before,&objects->nvn_report,sizeof(nr_before)));
    uint64_t first_proc=read_value(memory,object_test_nvn.table,8);
    assert(oot_memory_store(memory,object_test_nvn.table,8,0));
    object_call(objects,OOT_NVN_GET_PROC,0,nvn_name,2);
    assert(!memcmp(&nr_before,&objects->nvn_report,sizeof(nr_before)));
    assert(oot_memory_store(memory,object_test_nvn.table,8,first_proc));
    uint64_t query_out=out+0x20;
    const unsigned layout_values[]={32,32,256,256,4,8};
    for(unsigned n=0;n<6;++n){
        uint64_t old=read_value(memory,query_out,8);nr_before=objects->nvn_report;
        object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,UINT64_C(0xff00000000)+15+n,query_out,
            d->flags&OOT_OBJECT_NVN_LAYOUT?0:1);
        assert(read_value(memory,query_out,8)==(d->flags&OOT_OBJECT_NVN_LAYOUT?((old&UINT64_C(0xffffffff00000000))|layout_values[n]):old));
        if(!(d->flags&OOT_OBJECT_NVN_LAYOUT))assert(!memcmp(&nr_before,&objects->nvn_report,sizeof(nr_before)));
        else{
            nr_before=objects->nvn_report;old=read_value(memory,query_out,8);
            object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,15+n,d->display,2);
            object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,15+n,(UINT64_C(1)<<39)-2,2);
            object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,0,15+n,query_out,1);
            assert(!memcmp(&nr_before,&objects->nvn_report,sizeof(nr_before)) && read_value(memory,query_out,8)==old);
        }
    }
    for(unsigned query=0;query<2;++query){
        assert(oot_memory_store(memory,query_out,8,UINT64_C(0xaabbccdd12345678)));
        object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,UINT64_C(0xff00000000)+query,query_out,0);
        assert(read_value(memory,query_out,8)==(UINT64_C(0xaabbccdd00000000)|(query?40:231)));
    }
    nr_before=objects->nvn_report;uint64_t old_query=read_value(memory,query_out,8);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,42,query_out,0);
    assert(read_value(memory,query_out,8)==UINT64_C(0xaabbccdd00000000));
    nr_before=objects->nvn_report;old_query=read_value(memory,query_out,8);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,90,query_out,0);
    assert(read_value(memory,query_out,8)==old_query);nr_before=objects->nvn_report;
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,2,query_out,1);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,0,0,query_out,1);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,0,nvn_device,2);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,0,object_test_nvn.table,2);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,0,d->display,2);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,0,0,2);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,0,d->anchor,2);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,0,(UINT64_C(1)<<39)-2,2);
    assert(!memcmp(&nr_before,&objects->nvn_report,sizeof(nr_before)));
    assert(read_value(memory,query_out,8)==old_query);
    objects->nvn_report.integer_queries=UINT64_MAX;
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,0,query_out,2);
    assert(read_value(memory,query_out,8)==old_query);
    objects->nvn_report=nr_before;
    for(unsigned value=0;value<2;++value){
        object_call(objects,OOT_NVN_DEVICE_SET_ORIGIN,nvn_device,UINT64_C(0xabcdef00000000)+value,0);
        object_call(objects,OOT_NVN_DEVICE_SET_DEPTH,nvn_device,value^1,0);
        object_call(objects,OOT_NVN_DEVICE_GET_ORIGIN,nvn_device,0,0);
        object_call(objects,OOT_NVN_DEVICE_GET_DEPTH,nvn_device,0,0);
        assert(objects->nvn_report.window_origin==value && objects->nvn_report.depth_mode==(value^1));
        assert(read_value(memory,nvn_device,8)==untouched_device);
    }
    nr_before=objects->nvn_report;
    object_call(objects,OOT_NVN_DEVICE_SET_ORIGIN,nvn_device,2,1);
    object_call(objects,OOT_NVN_DEVICE_SET_DEPTH,nvn_device,2,1);
    object_call(objects,OOT_NVN_DEVICE_GET_ORIGIN,nvn_device+8,0,1);
    object_call(objects,OOT_NVN_DEVICE_GET_DEPTH,0,0,1);
    assert(!memcmp(&nr_before,&objects->nvn_report,sizeof(nr_before)));
    objects->nvn_report.state_updates=UINT64_MAX;
    object_call(objects,OOT_NVN_DEVICE_SET_DEPTH,nvn_device,0,2);
    objects->nvn_report=nr_before;objects->nvn_report.state_queries=UINT64_MAX;
    object_call(objects,OOT_NVN_DEVICE_GET_ORIGIN,nvn_device,0,2);
    objects->nvn_report=nr_before;
    object_call(objects,OOT_NVN_DEVICE_FINALIZE,nvn_device,0,0);
    object_call3(objects,OOT_NVN_DEVICE_GET_INTEGER,nvn_device,0,query_out,1);
    assert(!objects->nvn_report.device && objects->nvn_report.finalizations==1);
    assert(oot_memory_store(memory,nvn_builder+4,4,1));nr_before=objects->nvn_report;
    object_call(objects,OOT_NVN_DEVICE_INITIALIZE,nvn_device,nvn_builder,1);
    assert(!memcmp(&nr_before,&objects->nvn_report,sizeof(nr_before)));
#endif
    /* Sparse publication preserves the constructor's unwritten gap/tail. */
    uint8_t initial[64],after[64];memset(initial,0x6b,sizeof(initial));
    assert(oot_memory_store_record(memory,event_out,initial,sizeof(initial)));
    object_call(objects,OOT_OBJECT_VSYNC_EVENT,event_out,d->display,1);
    assert(!objects->event && !objects->vblank && objects->report.vsync_events==0);
    assert(oot_memory_load_record(memory,event_out,after,sizeof(after)) && !memcmp(initial,after,sizeof(initial)));
    initial[40]=0;assert(oot_memory_store_record(memory,event_out,initial,sizeof(initial)));
    DWORD before_handles=0,after_handles=0;assert(GetProcessHandleCount(GetCurrentProcess(),&before_handles));
    object_call(objects,OOT_OBJECT_VSYNC_EVENT,event_out,d->display,0);
    assert(oot_memory_load_record(memory,event_out,after,sizeof(after)));
    assert(objects_get(after,8)==event_out && objects_get(after+8,8)==event_out);
    assert(after[16]==1 && after[17]==1 && after[18]==1 && !after[19] && after[40]==2);
    assert(!memcmp(after+28,initial+28,12) && !memcmp(after+41,initial+41,23));
    uint32_t old_token=objects->token;assert(old_token==objects_get(after+20,4));
    object_call(objects,OOT_OBJECT_VSYNC_EVENT,event_out,d->display,0);assert(objects->report.vsync_events==1);
    assert(oot_memory_store(memory,handle_array,4,old_token));
    OotArm64State state=registers(),before_state;
    state.x[1]=handle_array;state.x[2]=1;state.x[3]=UINT64_MAX;before_state=state;
    assert(oot_objects_service(objects,0x18,&state)==0 && state.x[0]==0 && state.x[1]==0 && state.pc==before_state.pc+4);
    state=registers();state.x[0]=old_token;assert(oot_objects_service(objects,0x17,&state)==0 && state.x[0]==0);
    state=registers();state.x[0]=old_token;assert(oot_objects_service(objects,0x17,&state)==0 && state.x[0]==0xfa01);
    state=registers();state.x[0]=old_token;assert(oot_objects_service(objects,0x12,&state)==0 && state.x[0]==0);
    state=registers();state.x[0]=old_token+1;before_state=state;
    assert(oot_objects_service(objects,0x16,&state)==1 && !memcmp(&state,&before_state,sizeof(state)));
    state=registers();state.x[1]=handle_array;state.x[2]=1;state.x[3]=0;before_state=state;
    assert(oot_objects_service(objects,0x18,&state)==1 && !memcmp(&state,&before_state,sizeof(state)));
    object_call(objects,OOT_OBJECT_CLOSE_DISPLAY,d->display,0,0);assert(objects->report.references==1);
    object_call(objects,OOT_OBJECT_CLOSE_DISPLAY,d->display,0,1);
    state=registers();state.x[0]=old_token;assert(oot_objects_service(objects,0x16,&state)==0);
    before_state=state;assert(oot_objects_service(objects,0x16,&state)==1 && !memcmp(&state,&before_state,sizeof(state)));
    object_call(objects,OOT_OBJECT_DESTROY_LAYER,d->layer,0,0);assert(!classes && !windows && !surfaces);
    object_call(objects,OOT_OBJECT_CLOSE_DISPLAY,d->display,0,0);assert(objects->report.references==0);
    assert(GetProcessHandleCount(GetCurrentProcess(),&after_handles) && before_handles==after_handles);
    object_call(objects,OOT_OBJECT_OPEN_DISPLAY,out,0,0);
    /* Original DestroySystemEvent clears its tag independently of CloseHandle. */
    assert(oot_memory_store(memory,event_out+40,1,0));
    object_call(objects,OOT_OBJECT_VSYNC_EVENT,event_out,d->display,0);assert(objects->token!=old_token);
    assert(oot_memory_store(memory,handle_array,4,objects->token));
    oot_test_object_edge(objects->vblank,1);
    assert(WaitForSingleObject(objects->failure,2000)==WAIT_OBJECT_0);
    state=registers();state.x[1]=handle_array;state.x[2]=1;state.x[3]=UINT64_MAX;before_state=state;
    assert(oot_objects_service(objects,0x18,&state)==1 && !memcmp(&state,&before_state,sizeof(state)));
    oot_objects_destroy(objects);oot_graphics_destroy(g);oot_runtime_close(image);
    assert(!classes && !windows && !surfaces && !devices && !instances);
    puts("Object publication, ownership, ABI, event tokens, failures and cleanup passed.");return 0;
}
