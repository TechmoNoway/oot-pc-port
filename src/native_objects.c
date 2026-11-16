#include "native_objects.h"
#include "native_vblank.h"
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#define OBJECT_ADDRESS_LIMIT (UINT64_C(1)<<39)
struct OotObjects {
    OotRuntimeImage *image;
    OotGuestMemory *memory;
    OotGraphics *graphics;
    OotObjectDeclaration declaration;
    OotObjectsReport report;
    OotRefreshReport refresh;
    OotNvnDeclaration nvn;
    OotNvnProc *procedures;
    OotNvnReport nvn_report;
    DWORD thread;
    OotGraphicsDisplayPeer *display;
    OotGraphicsLayerPeer *layer;
    OotVblankSource *vblank;
    HANDLE event,failure;
    uint32_t token,next_token,event_published;
};
static int objects_disjoint(const void *a,size_t an,const void *b,size_t bn)
{ uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;return x<=y?y-x>=an:x-y>=bn; }
static int objects_span(uint64_t at,uint64_t size)
{ return at>=4096 && size && at<OBJECT_ADDRESS_LIMIT && size<=OBJECT_ADDRESS_LIMIT-at; }
static int objects_separate(uint64_t a,uint64_t an,uint64_t b,uint64_t bn)
{ return a<=b?an<=b-a:bn<=a-b; }
static void objects_put32(uint8_t *out,uint32_t value)
{ for(unsigned n=0;n<4;++n)out[n]=(uint8_t)(value>>(8*n)); }
static void objects_put64(uint8_t *out,uint64_t value)
{ for(unsigned n=0;n<8;++n)out[n]=(uint8_t)(value>>(8*n)); }
static uint64_t objects_get(const uint8_t *in,unsigned size)
{ uint64_t value=0;for(unsigned n=0;n<size;++n)value|=(uint64_t)in[n]<<(8*n);return value; }
static int objects_tables(OotObjects *objects)
{
    uint8_t bytes[512],digest[32];
    for(unsigned n=0;n<OOT_OBJECT_TABLES;++n){
        const OotObjectTable *table=objects->declaration.tables+n;
        if(!oot_memory_load_native_input(objects->memory,table->address,bytes,table->size) ||
           BCryptHash(BCRYPT_SHA256_ALG_HANDLE,NULL,0,bytes,table->size,digest,sizeof(digest))<0 ||
           memcmp(digest,table->sha256,sizeof(digest)))return 0;
    }
    return 1;
}
static int objects_vptrs(OotObjects *objects)
{
    uint8_t bytes[8];
    for(unsigned n=0;n<OOT_OBJECT_VPTRS;++n)
        if(!oot_memory_load_record(objects->memory,objects->declaration.vptr_address[n],bytes,8) ||
           objects_get(bytes,8)!=objects->declaration.vptr_value[n])return 0;
    return 1;
}
static int objects_output(OotObjects *objects,uint64_t at,unsigned size)
{
    const OotObjectDeclaration *d=&objects->declaration;
    if(!objects_span(at,size) || !objects_separate(at,size,d->display,d->display_size) ||
       !objects_separate(at,size,d->layer,d->layer_size))return 0;
    if(objects->procedures && (!objects_separate(at,size,objects->nvn.table,(uint64_t)objects->nvn.count*8) ||
       (objects->nvn_report.device && !objects_separate(at,size,objects->nvn_report.device,8))))return 0;
    for(unsigned n=0;n<OOT_OBJECT_TABLES;++n)
        if(!objects_separate(at,size,d->tables[n].address,d->tables[n].size))return 0;
    for(unsigned offset=0;offset<size;offset+=16){
        unsigned count=size-offset;if(count>16)count=16;
        if(!oot_memory_probe(objects->memory,at+offset,count,OOT_MEMORY_WRITE))return 0;
    }
    return 1;
}
OotObjects *oot_objects_create(OotRuntimeImage *image,OotGuestMemory *memory,OotGraphics *graphics,
    const OotObjectDeclaration *d)
{
    OotObjects *objects;
    if(!image || !memory || !memory->valid || !graphics || !d || d->version!=OOT_OBJECT_DECLARATION_VERSION ||
       d->flags&~(OOT_OBJECT_VSYNC|OOT_OBJECT_REFRESH|OOT_OBJECT_NVN) ||
       ((d->flags&OOT_OBJECT_REFRESH) && !(d->flags&OOT_OBJECT_VSYNC)) ||
       ((d->flags&OOT_OBJECT_NVN) && (d->flags&3)!=3) ||
       d->reserved || !d->width || d->width>3840 || !d->height || d->height>2160 ||
       !objects_span(d->display,d->display_size) || !objects_span(d->layer,d->layer_size) ||
       (d->display|d->layer)&7 || !objects_separate(d->display,d->display_size,d->layer,d->layer_size) ||
       d->vptr_address[0]!=d->display || d->vptr_address[1]!=d->layer || d->native_window!=d->vptr_address[3] ||
       oot_runtime_check_code(image,d->image_sha256,d->anchor,d->anchor_size,d->anchor_sha256)!=OOT_CODE_MATCH)return NULL;
    for(unsigned n=0;n<OOT_OBJECT_TABLES;++n){
        const OotObjectTable *t=d->tables+n;
        if(!objects_span(t->address,t->size) || t->address%8 || t->size<24 || t->size>512 || t->size%8 || t->reserved ||
           !objects_separate(t->address,t->size,d->display,d->display_size) ||
           !objects_separate(t->address,t->size,d->layer,d->layer_size))return NULL;
        for(unsigned k=0;k<n;++k)
            if(!objects_separate(t->address,t->size,d->tables[k].address,d->tables[k].size))return NULL;
    }
    for(unsigned n=0;n<OOT_OBJECT_VPTRS;++n){
        uint64_t at=d->vptr_address[n];int table_found=0;
        if(at%8 || (n==0 ? at!=d->display:
            at<d->layer || at-d->layer>d->layer_size || d->layer_size-(at-d->layer)<8))return NULL;
        for(unsigned k=0;k<n;++k)if(at==d->vptr_address[k])return NULL;
        for(unsigned k=0;k<OOT_OBJECT_TABLES;++k)if(d->vptr_value[n]==d->tables[k].address+16)table_found=1;
        if(!table_found)return NULL;
    }
    objects=calloc(1,sizeof(*objects));if(!objects)return NULL;
    objects->image=image;objects->memory=memory;objects->graphics=graphics;objects->declaration=*d;
    objects->thread=GetCurrentThreadId();objects->report.version=1;objects->next_token=0x40000000;
    objects->refresh.version=1;
    if(!objects_tables(objects)){free(objects);return NULL;}
    return objects;
}
void oot_objects_destroy(OotObjects *objects)
{
    if(!objects)return;
    if(objects->event)CloseHandle(objects->event);
    if(objects->failure)CloseHandle(objects->failure);
    oot_vblank_destroy(objects->vblank);
    oot_graphics_layer_peer_close(objects->layer);oot_graphics_display_peer_close(objects->display);
    free(objects->procedures);memset(objects,0,sizeof(*objects));free(objects);
}
int oot_objects_handler_valid(const OotObjects *objects,uint32_t id)
{ return objects && ((id>=OOT_OBJECT_OPEN_DISPLAY && id<=OOT_OBJECT_NATIVE_WINDOW) ||
    (id==OOT_OBJECT_VSYNC_EVENT && (objects->declaration.flags&OOT_OBJECT_VSYNC)) ||
    (id==OOT_OBJECT_REFRESH_CAPABILITY && (objects->declaration.flags&OOT_OBJECT_REFRESH)) ||
    (id>=OOT_NVN_GET_PROC && id<=OOT_NVN_DEVICE_GET_DEPTH && objects->procedures)); }
int oot_objects_returns_value(uint32_t id)
{ return id==OOT_OBJECT_OPEN_DISPLAY || id==OOT_OBJECT_CREATE_LAYER || id==OOT_OBJECT_NATIVE_WINDOW || id==OOT_OBJECT_VSYNC_EVENT ||
    id==OOT_NVN_GET_PROC || id==OOT_NVN_DEVICE_INITIALIZE || id==OOT_NVN_DEVICE_GET_ORIGIN || id==OOT_NVN_DEVICE_GET_DEPTH; }
int oot_objects_snapshot(const OotObjects *objects,OotObjectsReport *out)
{
    if(!objects || !out || !objects_disjoint(objects,sizeof(*objects),out,sizeof(*out)))return 0;
    *out=objects->report;return 1;
}
int oot_objects_refresh_snapshot(const OotObjects *objects,OotRefreshReport *out)
{
    if(!objects || !out || !(objects->declaration.flags&OOT_OBJECT_REFRESH) ||
       !objects_disjoint(objects,sizeof(*objects),out,sizeof(*out)))return 0;
    *out=objects->refresh;return 1;
}
static int objects_nvn_table(OotObjects *objects,const OotNvnDeclaration *d)
{
    uint8_t bytes[8192],digest[32];unsigned size=d->count*8;
    for(unsigned at=0;at<size;){
        unsigned n=size-at;if(n>OOT_MEMORY_NATIVE_INPUT_LIMIT)n=OOT_MEMORY_NATIVE_INPUT_LIMIT;
        if(!oot_memory_load_native_input(objects->memory,d->table+at,bytes+at,n))return 0;
        at+=n;
    }
    if(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,NULL,0,bytes,size,digest,32)<0 || memcmp(digest,d->table_sha256,32))return 0;
    for(unsigned n=0;n<d->count;++n)if(objects_get(bytes+n*8,8)!=d->procedures[n].entry)return 0;
    return 1;
}
int oot_objects_bind_nvn(OotObjects *objects,const OotNvnDeclaration *d)
{
    OotNvnProc *copy;
    if(!objects || !d || objects->thread!=GetCurrentThreadId() || !(objects->declaration.flags&OOT_OBJECT_NVN) ||
       objects->procedures || objects->report.calls || d->version!=1 || !d->count || d->count>1024 ||
       !d->procedures || d->table%8 || !objects_span(d->table,(uint64_t)d->count*8))return 0;
    for(unsigned n=0;n<d->count;++n){
        const OotNvnProc *p=d->procedures+n;
        const char *end=memchr(p->name,0,sizeof(p->name));
        if(!end || end-p->name<4 || strncmp(p->name,"nvn",3) || p->entry%4 || !objects_span(p->entry,4) ||
           (n && strcmp(d->procedures[n-1].name,p->name)>=0))return 0;
    }
    if(!objects_nvn_table(objects,d))return 0;
    copy=calloc(d->count,sizeof(*copy));if(!copy)return 0;
    memcpy(copy,d->procedures,d->count*sizeof(*copy));objects->nvn=*d;objects->procedures=copy;
    objects->nvn.procedures=copy;return 1;
}
int oot_objects_nvn_snapshot(const OotObjects *objects,OotNvnReport *out)
{
    if(!objects || !out || !objects->procedures || !objects_disjoint(objects,sizeof(*objects),out,sizeof(*out)))return 0;
    *out=objects->nvn_report;return 1;
}
static int objects_write_pointer(OotObjects *objects,uint64_t at,uint64_t value)
{ uint8_t bytes[8];objects_put64(bytes,value);return oot_memory_store_record(objects->memory,at,bytes,8); }
int oot_objects_call(OotObjects *objects,uint32_t id,OotArm64State *state)
{
    OotArm64State next;OotObjectsReport report;const OotObjectDeclaration *d;
    OotGraphicsDisplayPeer *new_display=NULL;OotGraphicsLayerPeer *new_layer=NULL;
    if(!objects || !state || !objects_disjoint(objects,sizeof(*objects),state,sizeof(*state)) ||
       objects->thread!=GetCurrentThreadId() || !state->pc || state->pc%4 || state->pc>=OBJECT_ADDRESS_LIMIT ||
       state->sp%16 || !state->x[30] || state->x[30]%4 || state->x[30]>=OBJECT_ADDRESS_LIMIT ||
       state->nzcv&UINT32_C(0x0fffffff))return 2;
    if(!oot_objects_handler_valid(objects,id))return 1;
    if(!objects_tables(objects) || !objects_vptrs(objects))return 2;
    if(objects->report.calls==UINT64_MAX)return 2;
    d=&objects->declaration;next=*state;report=objects->report;
    if(id>=OOT_NVN_GET_PROC && id<=OOT_NVN_DEVICE_GET_DEPTH){
        OotNvnReport nr=objects->nvn_report;OotGraphicsReport gr;
        if(!objects_nvn_table(objects,&objects->nvn))return 2;
        if(!oot_graphics_snapshot(objects->graphics,&gr) || !gr.ready)return 1;
        if(id==OOT_NVN_GET_PROC){
            char name[128];unsigned n;
            if(state->x[0] && state->x[0]!=nr.device)return 1;
            if(nr.lookups==UINT64_MAX)return 2;
            for(n=0;n<sizeof(name);++n){
                if(!oot_memory_load_record(objects->memory,state->x[1]+n,(uint8_t*)name+n,1))return 2;
                if(!name[n])break;
            }
            if(n==sizeof(name))return 1;
            unsigned lo=0,hi=objects->nvn.count;
            while(lo<hi){unsigned mid=lo+(hi-lo)/2;int c=strcmp(name,objects->procedures[mid].name);if(c>0)lo=mid+1;else hi=mid;}
            if(lo==objects->nvn.count || strcmp(name,objects->procedures[lo].name))return 1;
            next.x[0]=objects->procedures[lo].entry;++nr.lookups;
        } else if(id==OOT_NVN_DEVICE_INITIALIZE){
            uint8_t builder[24];
            if(nr.device || !state->x[0] || state->x[0]%8 || !objects_output(objects,state->x[0],8) ||
               !objects_separate(state->x[0],8,state->x[1],24))return 1;
            if(!oot_memory_load_record(objects->memory,state->x[1],builder,sizeof(builder)))return 2;
            /* Only the source-proved zero/default builder is supported. No
             * guest SDK layout/handle is fabricated: identity stays in this
             * private owner and all other NVN consumers remain closed. */
            for(unsigned n=0;n<sizeof(builder);++n)if(builder[n])return 1;
            if(nr.initializations==UINT64_MAX)return 2;
            nr.device=state->x[0];nr.window_origin=0;nr.depth_mode=0;++nr.initializations;next.x[0]=1;
        } else if(id==OOT_NVN_DEVICE_GET_INTEGER){
            /* Exact original SDK ABI version queries. Hardware capability and
             * resource-limit queries require their own enabled Vulkan proof. */
            uint32_t query=(uint32_t)state->x[1];uint8_t bytes[4];
            if(!nr.device || nr.device!=state->x[0] || (query>1 && query!=42 && query!=90))return 1;
            if(nr.integer_queries==UINT64_MAX || !objects_output(objects,state->x[2],4))return 2;
            /* Explicit negative ASTC/debug capabilities: no ASTC feature,
             * software decoder or NVN debug layer is enabled. */
            objects_put32(bytes,query==0?231:query==1?40:0);
            if(!oot_memory_store_record(objects->memory,state->x[2],bytes,4))return 2;
            ++nr.integer_queries;
        } else if(id>=OOT_NVN_DEVICE_SET_ORIGIN && id<=OOT_NVN_DEVICE_GET_DEPTH){
            if(!nr.device || nr.device!=state->x[0])return 1;
            if(id==OOT_NVN_DEVICE_SET_ORIGIN || id==OOT_NVN_DEVICE_SET_DEPTH){
                uint32_t value=(uint32_t)state->x[1];if(value>1)return 1;
                if(nr.state_updates==UINT64_MAX)return 2;
                if(id==OOT_NVN_DEVICE_SET_ORIGIN)nr.window_origin=value;else nr.depth_mode=value;
                ++nr.state_updates;
            }else{
                if(nr.state_queries==UINT64_MAX)return 2;
                next.x[0]=id==OOT_NVN_DEVICE_GET_ORIGIN?nr.window_origin:nr.depth_mode;++nr.state_queries;
            }
        } else {
            if(!nr.device || nr.device!=state->x[0])return 1;
            if(nr.finalizations==UINT64_MAX)return 2;
            nr.device=0;++nr.finalizations;
        }
        objects->nvn_report=nr;
    } else if(id==OOT_OBJECT_OPEN_DISPLAY){
        if(report.opens==UINT64_MAX || report.references==UINT64_MAX)return 2;
        if(!objects_output(objects,state->x[0],8))return 2;
        if(objects->display){if(!oot_graphics_display_peer_live(objects->display))return 1;}
        else{new_display=oot_graphics_display_peer_open(objects->graphics);if(!new_display)return 1;}
        if(!objects_write_pointer(objects,state->x[0],d->display)){oot_graphics_display_peer_close(new_display);return 2;}
        if(new_display)objects->display=new_display;
        ++report.references;++report.opens;report.display_open=1;next.x[0]=0;
    } else if(id==OOT_OBJECT_CLOSE_DISPLAY){
        if(state->x[0]!=d->display || !report.references || !objects->display)return 1;
        if(report.closes==UINT64_MAX)return 2;
        if(report.references==1 && (objects->layer || objects->event))return 1;
        --report.references;++report.closes;
        if(!report.references){
            if(objects->failure){CloseHandle(objects->failure);objects->failure=NULL;}
            oot_vblank_destroy(objects->vblank);objects->vblank=NULL;objects->event_published=0;
            oot_graphics_display_peer_close(objects->display);objects->display=NULL;report.display_open=0;
        }
    } else if(id==OOT_OBJECT_CREATE_LAYER){
        if(state->x[1]!=d->display || !report.references || !oot_graphics_display_peer_live(objects->display))return 1;
        if(report.creates==UINT64_MAX)return 2;
        if(!objects_output(objects,state->x[0],8))return 2;
        if(objects->layer){
            if(!oot_graphics_layer_peer_live(objects->layer))return 1;
            if(!objects_write_pointer(objects,state->x[0],0))return 2;
            next.x[0]=0x272;
        } else {
            new_layer=oot_graphics_layer_peer_open(objects->display,d->width,d->height);if(!new_layer)return 1;
            if(!objects_write_pointer(objects,state->x[0],d->layer)){oot_graphics_layer_peer_close(new_layer);return 2;}
            objects->layer=new_layer;report.layer_open=1;++report.creates;next.x[0]=0;
        }
    } else if(id==OOT_OBJECT_DESTROY_LAYER){
        if(state->x[0]!=d->layer || !objects->layer)return 1;
        if(report.destroys==UINT64_MAX)return 2;
        oot_graphics_layer_peer_close(objects->layer);objects->layer=NULL;report.layer_open=0;++report.destroys;
    } else if(id==OOT_OBJECT_NATIVE_WINDOW){
        if(state->x[1]!=d->layer || !report.references || !oot_graphics_layer_peer_live(objects->layer))return 1;
        if(report.window_getters==UINT64_MAX)return 2;
        if(!objects_output(objects,state->x[0],8) || !objects_write_pointer(objects,state->x[0],d->native_window))return 2;
        next.x[0]=0;++report.window_getters;
    } else if(id==OOT_OBJECT_REFRESH_CAPABILITY){
        if(state->x[0]!=d->display){
            if(objects->refresh.ignored==UINT64_MAX)return 2;
            ++objects->refresh.ignored;
        } else {
            if(!report.references || !oot_graphics_display_peer_live(objects->display))return 1;
            if(objects->refresh.updates==UINT64_MAX)return 2;
            /* The audited public bool is W1 bit zero. The backend sends the
             * pair (enabled ? 2 : 0, 2); this records the owned capability,
             * without claiming a physical mode change or an IPC result. */
            objects->refresh.capability_bits=(objects->refresh.capability_bits&~UINT64_C(2))|((state->x[1]&1)<<1);
            objects->refresh.update_mask=2;++objects->refresh.updates;
        }
    } else {
        uint8_t prefix[28]={0},tag=2,old_tag;OotServiceWrite writes[2];HANDLE event=NULL,failure_event=NULL;
        OotVblankSource *source;
        if(state->x[1]!=d->display || !report.references || !oot_graphics_display_peer_live(objects->display))return 1;
        if(objects->event_published)next.x[0]=0xa72;
        else {
            if(report.vsync_events==UINT64_MAX || objects->next_token>=0x7fffffff)return 2;
            if(state->x[0]%8 || !objects_output(objects,state->x[0],28) || !objects_output(objects,state->x[0]+40,1))return 2;
            if(!oot_memory_load_record(objects->memory,state->x[0]+40,&old_tag,1))return 2;
            if(old_tag)return 1;
            source=oot_vblank_create(oot_graphics_display_peer_monitor(objects->display));if(!source)return 1;
            if(!oot_vblank_duplicate_wait_handles(source,&event,&failure_event)){oot_vblank_destroy(source);return 1;}
            objects_put64(prefix,state->x[0]);objects_put64(prefix+8,state->x[0]);
            prefix[16]=1;prefix[17]=1;prefix[18]=1;objects_put32(prefix+20,objects->next_token);
            writes[0]=(OotServiceWrite){state->x[0],prefix,sizeof(prefix)};
            writes[1]=(OotServiceWrite){state->x[0]+40,&tag,1};
            if(!oot_memory_store_service(objects->memory,writes,2)){
                CloseHandle(event);CloseHandle(failure_event);oot_vblank_destroy(source);return 2;
            }
            objects->vblank=source;objects->event=event;objects->failure=failure_event;
            objects->token=objects->next_token++;objects->event_published=1;
            ++report.vsync_events;report.event_open=1;next.x[0]=0;
        }
    }
    ++report.calls;next.pc=state->x[30];objects->report=report;*state=next;return 0;
}
int oot_objects_service(OotObjects *objects,uint32_t id,OotArm64State *state)
{
    OotArm64State next;OotVblankSnapshot snapshot;uint64_t *counter=NULL;
    if(!objects || !state || !objects_disjoint(objects,sizeof(*objects),state,sizeof(*state)) ||
       objects->thread!=GetCurrentThreadId() || state->pc%4 || state->pc>=OBJECT_ADDRESS_LIMIT-4 ||
       state->nzcv&UINT32_C(0x0fffffff))return 2;
    if(!(objects->declaration.flags&OOT_OBJECT_VSYNC) || !objects->event)return 1;
    next=*state;
    if(id==0x18){
        uint8_t bytes[4];HANDLE waits[]={objects->failure,objects->event};
        if((uint32_t)state->x[2]!=1 || state->x[3]!=UINT64_MAX)return 1;
        counter=&objects->report.waits;if(*counter==UINT64_MAX)return 2;
        if(!oot_memory_load_record(objects->memory,state->x[1],bytes,4))return 2;
        if(objects_get(bytes,4)!=objects->token)return 1;
        if(!oot_vblank_snapshot(objects->vblank,&snapshot) || !snapshot.ready ||
           WaitForMultipleObjects(2,waits,FALSE,INFINITE)!=WAIT_OBJECT_0+1 ||
           !oot_vblank_snapshot(objects->vblank,&snapshot) || !snapshot.ready)return 1;
        next.x[0]=0;next.x[1]=0;
    } else {
        if((uint32_t)state->x[0]!=objects->token)return 1;
        if(id==0x12 || id==0x17){
            int result;counter=id==0x12?&objects->report.clears:&objects->report.resets;
            if(*counter==UINT64_MAX)return 2;
            result=oot_vblank_reset(objects->vblank,id==0x17);if(result==OOT_VBLANK_UNAVAILABLE)return 1;
            next.x[0]=result==OOT_VBLANK_ALREADY_RESET?UINT32_C(0xfa01):0;
        } else if(id==0x16){
            counter=&objects->report.handle_closes;if(*counter==UINT64_MAX)return 2;
            if(!CloseHandle(objects->event))return 1;
            objects->event=NULL;objects->report.event_open=0;next.x[0]=0;
        } else return 1;
    }
    ++*counter;next.pc+=4;*state=next;return 0;
}
