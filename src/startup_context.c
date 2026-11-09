#include "startup_context.h"
#include "host.h"
#include "startup_init_atomic.h"
#include "native_math.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#define STARTUP_IMAGE_VIEW_LIMIT 128u
#define STARTUP_REGION_LIMIT 130u
#define STARTUP_ADDRESS_LIMIT (UINT64_C(1) << 39)
#define STARTUP_PAGE UINT64_C(4096)
#define STARTUP_HEAP_LIMIT (UINT64_C(64) * 1024 * 1024)
#define SDK_HEAP_LIMIT (UINT64_C(2) * 1024 * 1024 * 1024)
#define SDK_CURRENT_PROCESS UINT32_C(0xffff8001)
#define SDK_CURRENT_THREAD UINT32_C(0xffff8000)

struct OotStartupContext {
    OotRuntimeImage *image;
    OotStartupConfig config;
    OotSdkConfig sdk;
    OotSdkNative native;
    OotNativePlatform platform;
    OotNativeServices services;
    OotStartupVectorState vectors;
    OotGuestMemory memory;
    OotGuestRegion image_regions[STARTUP_IMAGE_VIEW_LIMIT], regions[STARTUP_REGION_LIMIT];
    uint32_t image_kinds[STARTUP_IMAGE_VIEW_LIMIT], image_attributes[STARTUP_IMAGE_VIEW_LIMIT];
    uint64_t permission_updates, permission_locks;
    size_t image_count;
    uint8_t *tls, *heap;
    uint64_t heap_size, clock_origin, host_frequency, tpidr_el0, fixed_memory;
    uint32_t references, sdk_enabled;
};

static int valid_span(uint64_t base, uint64_t size)
{
    return base >= STARTUP_PAGE && size && base <= STARTUP_ADDRESS_LIMIT - STARTUP_PAGE &&
        size <= STARTUP_ADDRESS_LIMIT - STARTUP_PAGE - base;
}

static int separated(uint64_t a, uint64_t n, uint64_t b, uint64_t z)
{
    return (a <= b && n <= b-a && STARTUP_PAGE <= b-a-n) ||
        (b <= a && z <= a-b && STARTUP_PAGE <= a-b-z);
}

static int compare_region(const void *a, const void *b)
{
    const OotGuestRegion *x = a, *y = b;
    return x->base < y->base ? -1 : x->base > y->base;
}

static int page_model(const OotGuestMemory *memory)
{
    size_t i;
    if (!memory || memory->valid != 1) return 0;
    for (i = 0; i < memory->count; ++i)
        if ((memory->regions[i].base | memory->regions[i].size) & (STARTUP_PAGE-1)) return 0;
    return 1;
}

/* Prepare the complete replacement before publishing metadata. No borrowed
 * view may be used concurrently with this single-threaded operation. */
static int set_heap_mapping(OotStartupContext *c, uint64_t size)
{
    OotGuestRegion table[STARTUP_REGION_LIMIT];
    OotGuestMemory checked;
    size_t count = c->image_count;
    memcpy(table,c->image_regions,count*sizeof(*table));
    table[count++] = (OotGuestRegion){c->config.tls_base,c->config.tls_size,c->tls,OOT_MEMORY_READ | OOT_MEMORY_WRITE};
    if (size) table[count++] = (OotGuestRegion){c->config.heap_base,size,c->heap,OOT_MEMORY_READ | OOT_MEMORY_WRITE};
    qsort(table,count,sizeof(*table),compare_region);
    if (!oot_memory_init(&checked,table,count)) return 0;
    if (c->sdk_enabled && (c->sdk.flags & OOT_SDK_INITIALIZATION)) {
        /* Reserve once, commit only published pages. VirtualFree decommit is
         * atomic for this owned committed range; a failed OS call leaves the
         * old mapping metadata live. Regrowth receives zero-filled pages. */
        if (size>c->heap_size && !VirtualAlloc(c->heap+(size_t)c->heap_size,
            (SIZE_T)(size-c->heap_size),MEM_COMMIT,PAGE_READWRITE)) return 0;
        if (size<c->heap_size && !VirtualFree(c->heap+(size_t)size,
            (SIZE_T)(c->heap_size-size),MEM_DECOMMIT)) return 0;
    }
    memcpy(c->regions,table,count*sizeof(*table));
    c->memory = checked; c->memory.regions = c->regions;
    c->heap_size = size;
    return 1;
}

void oot_startup_context_destroy(OotStartupContext *c)
{
    if (!c || --c->references) return;
    if (c->tls) (void)host_memory_release(c->tls);
    if (c->heap) (void)host_memory_release(c->heap);
    SecureZeroMemory(c->sdk.entropy,sizeof(c->sdk.entropy));
    oot_runtime_close(c->image);
    free(c);
}

int oot_startup_context_retain(OotStartupContext *c)
{
    if (!c || c->references == UINT32_MAX) return 0;
    ++c->references;
    return 1;
}

static OotStartupContext *create_context(OotRuntimeImage *image,
    const OotStartupConfig *config, const OotSdkConfig *sdk, uint32_t *error)
{
    OotStartupContext *c;
    OotGuestMemory *memory;
    size_t i;
    uint64_t fixed_memory;
    HostInfo info;
    uint32_t failure = OOT_STARTUP_CONTEXT_BAD_ARGUMENT;
    if (error) *error = failure;
    if (!image || !config || !config->main_thread_handle || config->main_thread_handle > UINT32_MAX ||
        config->tls_base % STARTUP_PAGE || config->tls_size < 512 || config->tls_size > 65536 || config->tls_size % 512 ||
        config->heap_base % OOT_STARTUP_HEAP_ALIGNMENT || !config->heap_capacity ||
        config->heap_capacity > (sdk ? SDK_HEAP_LIMIT : STARTUP_HEAP_LIMIT) ||
        config->heap_capacity > SIZE_MAX || config->heap_capacity % OOT_STARTUP_HEAP_ALIGNMENT ||
        config->tick_frequency > UINT32_MAX || !valid_span(config->tls_base,config->tls_size) ||
        !valid_span(config->heap_base,config->heap_capacity)) return NULL;
    if (sdk && (sdk->version != OOT_SDK_CONTEXT_VERSION ||
        sdk->flags & ~(OOT_SDK_EXPLICIT_ENTROPY | OOT_SDK_PROCESS_INFO | OOT_SDK_NO_REMOTE_ARENA |
            OOT_SDK_MAIN_THREAD | OOT_SDK_NO_ALIAS_EXTRA | OOT_SDK_PAGE_ALLOCATION | OOT_SDK_OBSERVED_MAIN_TLR | OOT_SDK_NATIVE_FUNCTIONS | OOT_SDK_INITIALIZATION) ||
        ((sdk->flags & (OOT_SDK_NO_REMOTE_ARENA | OOT_SDK_MAIN_THREAD | OOT_SDK_NO_ALIAS_EXTRA |
            OOT_SDK_PAGE_ALLOCATION | OOT_SDK_OBSERVED_MAIN_TLR)) && !(sdk->flags & OOT_SDK_PROCESS_INFO)) ||
        ((sdk->flags & OOT_SDK_OBSERVED_MAIN_TLR) && !(sdk->flags & OOT_SDK_MAIN_THREAD)) ||
        ((sdk->flags & OOT_SDK_NATIVE_FUNCTIONS) &&
         (sdk->flags & (OOT_SDK_MAIN_THREAD | OOT_SDK_PROCESS_INFO)) != (OOT_SDK_MAIN_THREAD | OOT_SDK_PROCESS_INFO)))) return NULL;
    if (sdk && (sdk->flags & OOT_SDK_INITIALIZATION) && !(sdk->flags & OOT_SDK_NATIVE_FUNCTIONS)) return NULL;
    if (sdk && (sdk->flags & OOT_SDK_OBSERVED_MAIN_TLR) &&
        (config->tls_size < 0x114 || config->main_thread_handle > UINT32_C(0x3fffffff))) return NULL;
    if (sdk && (sdk->flags & OOT_SDK_MAIN_THREAD) &&
        (!sdk->main_thread_id || sdk->main_thread_priority >= 64 || sdk->main_thread_core >= 64 ||
         !(sdk->priority_mask & (UINT64_C(1) << sdk->main_thread_priority)) ||
         !(sdk->core_mask & (UINT64_C(1) << sdk->main_thread_core)))) {
        if (error) *error = OOT_STARTUP_CONTEXT_BAD_LAYOUT;
        return NULL;
    }
    if (!separated(config->tls_base,config->tls_size,config->heap_base,config->heap_capacity)) {
        if (error) *error = OOT_STARTUP_CONTEXT_BAD_LAYOUT;
        return NULL;
    }
    memory = oot_runtime_memory(image);
    if (!memory || !memory->valid || !memory->count || memory->count > 64) {
        if (error) *error = OOT_STARTUP_CONTEXT_BAD_IMAGE;
        return NULL;
    }
    if (sdk && (sdk->flags & OOT_SDK_PAGE_ALLOCATION) &&
        (config->tls_size % STARTUP_PAGE || !page_model(memory))) {
        if (error) *error = OOT_STARTUP_CONTEXT_BAD_LAYOUT;
        return NULL;
    }
    fixed_memory = config->tls_size;
    for (i = 0; i < memory->count; ++i) {
        const OotGuestRegion *r = &memory->regions[i];
        if (r->size > UINT64_MAX-fixed_memory) {
            if (error) *error = OOT_STARTUP_CONTEXT_BAD_IMAGE;
            return NULL;
        }
        fixed_memory += r->size;
        if (!separated(config->tls_base,config->tls_size,r->base,r->size) ||
            !separated(config->heap_base,config->heap_capacity,r->base,r->size)) {
            if (error) *error = OOT_STARTUP_CONTEXT_BAD_LAYOUT;
            return NULL;
        }
    }
    if (sdk && (sdk->flags & OOT_SDK_PROCESS_INFO)) {
        if (!sdk->core_mask || !sdk->priority_mask || sdk->is_application > 1 ||
            (sdk->aslr_base | sdk->aslr_size | sdk->alias_base | sdk->alias_size) & (STARTUP_PAGE-1) ||
            sdk->aslr_base >= STARTUP_ADDRESS_LIMIT || !sdk->aslr_size ||
            sdk->aslr_size > STARTUP_ADDRESS_LIMIT-sdk->aslr_base || !valid_span(sdk->alias_base,sdk->alias_size) ||
            sdk->total_memory < fixed_memory || config->heap_capacity > sdk->total_memory-fixed_memory ||
            !separated(sdk->alias_base,sdk->alias_size,config->tls_base,config->tls_size) ||
            !separated(sdk->alias_base,sdk->alias_size,config->heap_base,config->heap_capacity)) {
            if (error) *error = OOT_STARTUP_CONTEXT_BAD_LAYOUT;
            return NULL;
        }
        for (i = 0; i < memory->count; ++i) {
            const OotGuestRegion *r = &memory->regions[i];
            if (!separated(sdk->alias_base,sdk->alias_size,r->base,r->size) ||
                (oot_runtime_region_kind(image,i) != 5 &&
                (r->base < sdk->aslr_base || r->size > sdk->aslr_size ||
                 r->base-sdk->aslr_base > sdk->aslr_size-r->size))) {
                if (error) *error = OOT_STARTUP_CONTEXT_BAD_LAYOUT;
                return NULL;
            }
        }
    }
    c = calloc(1,sizeof(*c));
    if (!c) { if (error) *error = OOT_STARTUP_CONTEXT_ALLOCATION; return NULL; }
    c->references = 1; c->config = *config;
    c->fixed_memory = fixed_memory;
    if (sdk) { c->sdk = *sdk; c->sdk_enabled = 1; }
    if (sdk && (sdk->flags & OOT_SDK_NATIVE_FUNCTIONS)) {
        const OotNativeConfig native_config={OOT_SDK_NATIVE_VERSION,0,0,1,sdk->main_thread_id};
        if (!oot_sdk_native_init(&c->native,&native_config)) {
            free(c); if (error) *error=OOT_STARTUP_CONTEXT_BAD_ARGUMENT; return NULL;
        }
    }
    if (sdk && (sdk->flags & OOT_SDK_INITIALIZATION)) {
        const OotNativePlatformConfig platform={1,0,0,1,0,0,1,sdk->main_thread_id};
        FILETIME utc;
        ULARGE_INTEGER stamp;
        uint64_t ticks;
        OotNativeServicesConfig services={1,OOT_NATIVE_CATALOGUE_EMPTY,OOT_NATIVE_PARENTAL_ALLOWED,0,0,0,0};
        failure=OOT_STARTUP_CONTEXT_BAD_CLOCK;
        if (!host_query_info(&info) || !info.counter_frequency || info.counter_frequency>UINT64_C(1000000000) ||
            !host_counter_read(&ticks)) { free(c); if (error) *error=failure; return NULL; }
        GetSystemTimeAsFileTime(&utc); stamp.LowPart=utc.dwLowDateTime; stamp.HighPart=utc.dwHighDateTime;
        if (stamp.QuadPart<UINT64_C(116444736000000000)) { free(c); if (error) *error=failure; return NULL; }
        services.clock_frequency=info.counter_frequency; services.clock_ticks=ticks;
        services.clock_unix_seconds=(stamp.QuadPart-UINT64_C(116444736000000000))/UINT64_C(10000000);
        if (!oot_native_platform_init(&c->platform,&platform) || !oot_native_services_init(&c->services,&services)) {
            free(c); if (error) *error=OOT_STARTUP_CONTEXT_BAD_ARGUMENT; return NULL;
        }
    }
    if (!oot_runtime_retain(image)) { free(c); if (error) *error = OOT_STARTUP_CONTEXT_BAD_IMAGE; return NULL; }
    c->image = image; c->image_count = memory->count;
    memcpy(c->image_regions,memory->regions,memory->count*sizeof(*memory->regions));
    for (i = 0; i < c->image_count; ++i) {
        c->image_kinds[i] = oot_runtime_region_kind(image,i);
        if (!c->image_kinds[i]) { failure = OOT_STARTUP_CONTEXT_BAD_IMAGE; goto failed; }
    }
    if (sdk && !(sdk->flags & OOT_SDK_EXPLICIT_ENTROPY)) {
        failure = OOT_STARTUP_CONTEXT_BAD_ENTROPY;
        if (BCryptGenRandom(NULL,(PUCHAR)c->sdk.entropy,(ULONG)sizeof(c->sdk.entropy),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) goto failed;
    }
    failure = OOT_STARTUP_CONTEXT_ALLOCATION;
    c->tls = host_memory_allocate((size_t)config->tls_size);
    c->heap = sdk && (sdk->flags & OOT_SDK_INITIALIZATION) ?
        VirtualAlloc(NULL,(SIZE_T)config->heap_capacity,MEM_RESERVE,PAGE_READWRITE) :
        host_memory_allocate((size_t)config->heap_capacity);
    if (!c->tls || !c->heap) goto failed;
    if (sdk && (sdk->flags & OOT_SDK_OBSERVED_MAIN_TLR))
        for (i = 0; i < 4; ++i) c->tls[0x110+i] = (uint8_t)(config->main_thread_handle >> (8*i));
    failure = OOT_STARTUP_CONTEXT_BAD_MEMORY;
    if (!set_heap_mapping(c,0)) goto failed;
    if (config->tick_frequency) {
        failure = OOT_STARTUP_CONTEXT_BAD_CLOCK;
        if (!host_query_info(&info) || !info.counter_frequency || info.counter_frequency > UINT32_MAX ||
            !host_counter_read(&c->clock_origin)) goto failed;
        c->host_frequency = info.counter_frequency;
    }
    if (error) *error = OOT_STARTUP_CONTEXT_OK;
    return c;
failed:
    if (error) *error = failure;
    oot_startup_context_destroy(c);
    return NULL;
}

OotStartupContext *oot_startup_context_create(OotRuntimeImage *image,
    const OotStartupConfig *config, uint32_t *error)
{
    return create_context(image,config,NULL,error);
}

OotStartupContext *oot_startup_context_create_sdk(OotRuntimeImage *image,
    const OotStartupConfig *config, const OotSdkConfig *sdk, uint32_t *error)
{
    if (!sdk) { if (error) *error = OOT_STARTUP_CONTEXT_BAD_ARGUMENT; return NULL; }
    return create_context(image,config,sdk,error);
}

int oot_startup_context_sdk_enabled(const OotStartupContext *c) { return c && c->sdk_enabled == 1; }
uint64_t oot_startup_context_tpidr_el0(const OotStartupContext *c) { return oot_startup_context_sdk_enabled(c) ? c->tpidr_el0 : 0; }

static int valid_memory(const OotStartupContext *c)
{
    OotGuestRegion expected[STARTUP_REGION_LIMIT];
    size_t i, count;
    if (!c || !c->memory.valid || c->memory.regions != c->regions) return 0;
    count = c->image_count;
    memcpy(expected,c->image_regions,count*sizeof(*expected));
    expected[count++] = (OotGuestRegion){c->config.tls_base,c->config.tls_size,c->tls,OOT_MEMORY_READ | OOT_MEMORY_WRITE};
    if (c->heap_size) expected[count++] = (OotGuestRegion){c->config.heap_base,c->heap_size,c->heap,OOT_MEMORY_READ | OOT_MEMORY_WRITE};
    if (c->memory.count != count) return 0;
    qsort(expected,count,sizeof(*expected),compare_region);
    for (i = 0; i < count; ++i)
        if (c->regions[i].base != expected[i].base || c->regions[i].size != expected[i].size ||
            c->regions[i].data != expected[i].data || c->regions[i].permissions != expected[i].permissions) return 0;
    return c->memory.valid == 1;
}

int oot_startup_context_protection_stats(const OotStartupContext *c, OotStartupProtectionStats *stats)
{
    OotStartupProtectionStats result={0};
    if (!stats || !oot_startup_context_init_enabled(c) || !valid_memory(c)) return 0;
    for (size_t n=0;n<c->image_count;++n) if (c->image_kinds[n]==3 || c->image_kinds[n]==4) {
        if (c->image_regions[n].permissions==OOT_MEMORY_READ) result.readonly_bytes+=c->image_regions[n].size;
        if (c->image_attributes[n]&16u) result.locked_bytes+=c->image_regions[n].size;
    }
    result.permission_updates=c->permission_updates;result.permission_locks=c->permission_locks;
    *stats=result;return 1;
}

OotGuestMemory *oot_startup_context_memory(OotStartupContext *c) { return valid_memory(c) ? &c->memory : NULL; }
OotRuntimeImage *oot_startup_context_image(OotStartupContext *c) { return c ? c->image : NULL; }
uint64_t oot_startup_context_tls_pointer(const OotStartupContext *c) { return c ? c->config.tls_base : 0; }
uint64_t oot_startup_context_heap_size(const OotStartupContext *c) { return c ? c->heap_size : 0; }
int oot_startup_context_init_enabled(const OotStartupContext *c)
{ return c && c->sdk_enabled && !!(c->sdk.flags & OOT_SDK_INITIALIZATION); }
int oot_startup_context_handler_valid(const OotStartupContext *c, uint32_t id)
{ return oot_startup_context_native_enabled(c) && (oot_sdk_native_handler_valid(id) ||
    (oot_startup_context_init_enabled(c) && (id==OOT_NATIVE_MATH_LOG || id==OOT_NATIVE_OS_GET_SYSTEM_TICK || oot_native_platform_handler_valid(id) || oot_native_services_handler_valid(id)))); }
int oot_startup_context_returns_value(const OotStartupContext *c, uint32_t id)
{ return oot_startup_context_init_enabled(c) && (id==OOT_NATIVE_OS_GET_SYSTEM_TICK || oot_native_platform_returns_value(id) || oot_native_services_returns_value(id)); }
const OotNativePlatform *oot_startup_context_platform(const OotStartupContext *c)
{ return oot_startup_context_init_enabled(c) ? &c->platform : NULL; }
const OotNativeServices *oot_startup_context_services(const OotStartupContext *c)
{ return oot_startup_context_init_enabled(c) ? &c->services : NULL; }
int oot_startup_context_native_enabled(const OotStartupContext *c)
{ return c && c->sdk_enabled && !!(c->sdk.flags & OOT_SDK_NATIVE_FUNCTIONS); }
const OotSdkNative *oot_startup_context_native(const OotStartupContext *c)
{ return oot_startup_context_native_enabled(c) ? &c->native : NULL; }

int oot_startup_context_native_call(OotStartupContext *c, uint32_t id,
    OotArm64State *state, OotSdkNativeReport *report)
{
    OotSdkNative next;
    OotArm64State result;
    OotNativePlatform platform={0};
    OotNativeServices services={0};
    OotNativePlatformReport platform_report={0};
    OotNativePlatformWrite platform_write={0};
    OotNativeServicesWrite services_write={0};
    int status, provider=0;
    uint64_t write_address=0;
    uint32_t write_size=0;
    const uint8_t *write_bytes=NULL;
    if (report && state) {
        uintptr_t a=(uintptr_t)report,b=(uintptr_t)state;
        if (a<=b ? b-a<sizeof(*report) : a-b<sizeof(*state)) return OOT_NATIVE_FAULT;
    }
    if (report) *report=(OotNativeReport){OOT_NATIVE_UNSUPPORTED,id,OOT_NATIVE_OK,0};
    if (!oot_startup_context_native_enabled(c)) return OOT_NATIVE_UNSUPPORTED;
    if (!state || !valid_memory(c) || state->pc%4 || state->pc>=STARTUP_ADDRESS_LIMIT ||
        (state->nzcv & UINT32_C(0x0fffffff))) {
        if (report) *report=(OotNativeReport){OOT_NATIVE_FAULT,id,OOT_NATIVE_BAD_STATE,0};
        return OOT_NATIVE_FAULT;
    }
    if(oot_startup_context_init_enabled(c) && id==OOT_NATIVE_MATH_LOG){
        uint64_t input,output;
        if(state->sp%16 || state->x[30]<4 || state->x[30]>=STARTUP_ADDRESS_LIMIT || state->x[30]%4 || c->native.calls==UINT64_MAX){
            if(report)*report=(OotNativeReport){OOT_NATIVE_FAULT,id,OOT_NATIVE_BAD_STATE,0};
            return OOT_NATIVE_FAULT;
        }
        memcpy(&input,c->vectors.q[0],8);status=oot_native_math_prepare(id,input,&output);
        if(report)*report=(OotNativeReport){(uint32_t)status,id,status==OOT_NATIVE_FAULT ? OOT_NATIVE_BAD_STATE:OOT_NATIVE_OK,0};
        if(status)return status;
        memcpy(c->vectors.q[0],&output,8);++c->native.calls;state->pc=state->x[30];return OOT_NATIVE_IMPLEMENTED;
    } else if (oot_startup_context_init_enabled(c) && id==OOT_NATIVE_OS_GET_SYSTEM_TICK) {
        uint64_t now,elapsed,seconds,remainder,ticks;
        if(!c->config.tick_frequency || !c->host_frequency)return OOT_NATIVE_UNSUPPORTED;
        if(state->sp%16 || state->x[30]<4 || state->x[30]>=STARTUP_ADDRESS_LIMIT || state->x[30]%4 ||
           c->native.calls==UINT64_MAX || !host_counter_read(&now) || now<c->clock_origin) {
            if(report)*report=(OotNativeReport){OOT_NATIVE_FAULT,id,OOT_NATIVE_BAD_STATE,0};
            return OOT_NATIVE_FAULT;
        }
        elapsed=now-c->clock_origin;seconds=elapsed/c->host_frequency;remainder=elapsed%c->host_frequency;
        if(seconds>INT64_MAX/c->config.tick_frequency){
            if(report)*report=(OotNativeReport){OOT_NATIVE_FAULT,id,OOT_NATIVE_LIMIT,0};
            return OOT_NATIVE_FAULT;
        }
        ticks=seconds*c->config.tick_frequency+(remainder*c->config.tick_frequency)/c->host_frequency;
        if(ticks>INT64_MAX){if(report)*report=(OotNativeReport){OOT_NATIVE_FAULT,id,OOT_NATIVE_LIMIT,0};return OOT_NATIVE_FAULT;}
        result=*state;result.x[0]=ticks;result.pc=state->x[30];
        ++c->native.calls;*state=result;
        if(report)*report=(OotNativeReport){OOT_NATIVE_IMPLEMENTED,id,OOT_NATIVE_OK,0};
        return OOT_NATIVE_IMPLEMENTED;
    } else if (oot_startup_context_init_enabled(c) && oot_native_platform_handler_valid(id)) {
        provider=1;
        status=oot_native_platform_prepare(&c->platform,id,state,&c->memory,&platform,&result,&platform_write,&platform_report);
        if (report) *report=(OotNativeReport){platform_report.status,platform_report.handler,platform_report.error,platform_report.size};
        write_address=platform_write.address;write_size=platform_write.size;write_bytes=platform_write.bytes;
    } else if (oot_startup_context_init_enabled(c) && oot_native_services_handler_valid(id)) {
        provider=2;
        status=oot_native_services_prepare(&c->services,id,state,&c->memory,&services,&result,&services_write,report);
        write_address=services_write.address;write_size=services_write.size;write_bytes=services_write.bytes;
    } else status=oot_sdk_native_prepare(&c->native,id,state,&c->memory,&next,&result,report);
    if (status!=OOT_NATIVE_IMPLEMENTED) {
        if (report && report->status!=(uint32_t)status)
            *report=(OotNativeReport){(uint32_t)status,id,OOT_NATIVE_BAD_STATE,0};
        return status;
    }
    if (result.pc!=state->x[30] || result.sp!=state->sp || result.nzcv!=state->nzcv ||
        memcmp(result.x+1,state->x+1,30*sizeof(*state->x)) ||
        (!oot_startup_context_returns_value(c,id) && result.x[0]!=state->x[0])) {
        if (report) *report=(OotNativeReport){OOT_NATIVE_FAULT,id,OOT_NATIVE_BAD_STATE,0};
        return OOT_NATIVE_FAULT;
    }
    if (provider && c->native.calls==UINT64_MAX) {
        if (report) *report=(OotNativeReport){OOT_NATIVE_FAULT,id,OOT_NATIVE_LIMIT,0};
        return OOT_NATIVE_FAULT;
    }
    if (write_size && (write_size>OOT_MEMORY_RECORD_LIMIT ||
        !oot_memory_store_record(&c->memory,write_address,write_bytes,write_size))) {
        if (report) *report=(OotNativeReport){OOT_NATIVE_FAULT,id,OOT_NATIVE_BAD_MEMORY,0};
        return OOT_NATIVE_FAULT;
    }
    if (provider==1) c->platform=platform;
    else if (provider==2) c->services=services;
    if (provider) ++c->native.calls;
    else c->native=next;
    *state=result;
    return OOT_NATIVE_IMPLEMENTED;
}

const OotStartupVectorState *oot_startup_context_vectors(const OotStartupContext *c)
{ return oot_startup_context_init_enabled(c) ? &c->vectors : NULL; }
int oot_startup_context_vector_preview(OotStartupContext *c, uint32_t word,
    const OotArm64State *state, OotArm64State *result, OotStartupVectorState *next)
{
    OotStartupVectorWrite write;
    if (!oot_startup_context_init_enabled(c)) return OOT_STARTUP_SERVICE_UNSUPPORTED;
    if (!valid_memory(c)) return OOT_STARTUP_SERVICE_FAULT;
    return oot_startup_vector_prepare(&c->vectors,word,state,&c->memory,next,result,&write);
}
int oot_startup_context_vector_step(OotStartupContext *c, uint32_t word, OotArm64State *state)
{
    OotStartupVectorState next;
    OotStartupVectorWrite write;
    OotArm64State result;
    int status;
    if (!oot_startup_context_init_enabled(c)) return OOT_STARTUP_SERVICE_UNSUPPORTED;
    if (!valid_memory(c) || !state) return OOT_STARTUP_SERVICE_FAULT;
    status=oot_startup_vector_prepare(&c->vectors,word,state,&c->memory,&next,&result,&write);
    if (status!=OOT_STARTUP_SERVICE_IMPLEMENTED) return status;
    if (result.sp%16 || result.sp<oot_runtime_stack_base(c->image) ||
        result.sp>oot_runtime_stack_pointer(c->image)) return OOT_STARTUP_SERVICE_FAULT;
    if (write.size && !oot_memory_store_record(&c->memory,write.address,write.bytes,write.size))
        return OOT_STARTUP_SERVICE_FAULT;
    c->vectors=next; *state=result;
    return OOT_STARTUP_SERVICE_IMPLEMENTED;
}

int oot_startup_context_system(OotStartupContext *c, uint32_t word, OotArm64State *state)
{
    OotArm64State result;
    uint32_t operation = word & ~UINT32_C(31), reg = word & 31u;
    if (!c || !state || state->pc >= STARTUP_ADDRESS_LIMIT-4 || state->pc % 4 ||
        (state->nzcv & UINT32_C(0x0fffffff)) || !valid_memory(c)) return OOT_STARTUP_SERVICE_FAULT;
    if (!c->sdk_enabled) return OOT_STARTUP_SERVICE_UNSUPPORTED;
    if (oot_startup_init_atomic_kind(word)) {
        if (!oot_startup_context_init_enabled(c)) return OOT_STARTUP_SERVICE_UNSUPPORTED;
        return oot_startup_init_atomic_step(word,state,&c->memory);
    }
    if (word==UINT32_C(0xd50320ff)) {
        const uint64_t mask=(UINT64_C(1)<<39)-1;
        if (!oot_startup_context_init_enabled(c)) return OOT_STARTUP_SERVICE_UNSUPPORTED;
        result=*state;
        result.x[30]=(state->x[30]&mask) | ((state->x[30]&(UINT64_C(1)<<55)) ? ~mask:0);
        result.pc+=4; *state=result;
        return OOT_STARTUP_SERVICE_IMPLEMENTED;
    }
    if ((word & UINT32_C(0xfffff0ff)) == UINT32_C(0xd50330bf)) {
        unsigned option=(word>>8)&15u;
        if (!oot_startup_context_native_enabled(c) || !(option&3u)) return OOT_STARTUP_SERVICE_UNSUPPORTED;
        if (!oot_memory_barrier(&c->memory,option)) return OOT_STARTUP_SERVICE_FAULT;
        result=*state; result.pc+=4; *state=result;
        return OOT_STARTUP_SERVICE_IMPLEMENTED;
    }
    if ((word & UINT32_C(0xbfa07c00)) == UINT32_C(0x88a07c00)) {
        uint32_t rs = (word >> 16) & 31u, rn = (word >> 5) & 31u;
        unsigned size = word & UINT32_C(0x40000000) ? 8u : 4u;
        uint64_t address = oot_arm64_read(state,rn,64,1), observed;
        uint64_t expected = oot_arm64_read(state,rs,size*8,0);
        uint64_t desired = oot_arm64_read(state,reg,size*8,0);
        if (!oot_memory_compare_exchange(&c->memory,address,size,rn == 31,expected,desired,&observed))
            return OOT_STARTUP_SERVICE_FAULT;
        result = *state;
        oot_arm64_write(&result,rs,size*8,0,observed);
        result.pc += 4;
        *state = result;
        return OOT_STARTUP_SERVICE_IMPLEMENTED;
    }
    if (operation != UINT32_C(0xd53bd060) && operation != UINT32_C(0xd53bd040) &&
        operation != UINT32_C(0xd51bd040)) return OOT_STARTUP_SERVICE_UNSUPPORTED;
    result = *state;
    if (operation == UINT32_C(0xd51bd040)) c->tpidr_el0 = reg == 31 ? 0 : state->x[reg];
    else if (reg != 31) result.x[reg] = operation == UINT32_C(0xd53bd060) ? c->config.tls_base : c->tpidr_el0;
    result.pc += 4;
    *state = result;
    return OOT_STARTUP_SERVICE_IMPLEMENTED;
}

int oot_startup_context_initial_state(const OotStartupContext *c, uint64_t entry, OotArm64State *state)
{
    if (!valid_memory(c) || !state || !entry || entry % 4 || entry >= STARTUP_ADDRESS_LIMIT) return 0;
    *state = (OotArm64State){0};
    state->x[1] = c->config.main_thread_handle;
    state->sp = oot_runtime_stack_pointer(c->image);
    state->pc = entry;
    return 1;
}

static int service_result(OotStartupServiceReport *out, uint32_t id, uint32_t status, uint32_t error)
{
    if (out) { out->id = id; out->status = status; out->error = error; }
    return (int)status;
}

static void put32(uint8_t *bytes, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4; ++i) bytes[i] = (uint8_t)(value >> (8*i));
}

static void put64(uint8_t *bytes, uint64_t value)
{
    put32(bytes,(uint32_t)value); put32(bytes+4,(uint32_t)(value >> 32));
}

/* The page model reports its real guest mappings and free gaps. Execute is a
 * query property of text, separate from backend data-access permissions. */
static int query_record(const OotStartupContext *c, uint64_t address, uint8_t bytes[40])
{
    uint64_t base = 0, end = STARTUP_ADDRESS_LIMIT;
    uint32_t state = 0, permission = 0, attribute = 0;
    size_t i, j;
    if (!page_model(&c->memory)) return 0;
    if (address >= STARTUP_ADDRESS_LIMIT) {
        base = STARTUP_ADDRESS_LIMIT; end = 0; state = 0x10;
    } else for (i = 0; i < c->memory.count; ++i) {
        const OotGuestRegion *r = &c->regions[i];
        if (address < r->base) { end = r->base; break; }
        if (address-r->base >= r->size) { base = r->base+r->size; continue; }
        base = r->base; end = base+r->size; permission = r->permissions;
        if (base == c->config.tls_base) state = 0xc;
        else if (c->heap_size && base == c->config.heap_base) state = 5;
        else {
            for (j = 0; j < c->image_count; ++j) if (c->image_regions[j].base == base) break;
            if (j == c->image_count) return 0;
            attribute=c->image_attributes[j];
            switch (c->image_kinds[j]) {
            case 1: state = 3; permission = 5; break; /* Static RX text. */
            case 2: state = 3; permission = 1; break; /* Static R data. */
            case 3: case 4: state = 4; break;
            case 5: state = 0xb; permission = 3; break;
            default: return 0;
            }
        }
        break;
    }
    memset(bytes,0,40);
    put64(bytes,base); put64(bytes+8,end-base); put32(bytes+16,state); put32(bytes+20,attribute); put32(bytes+24,permission);
    return 1;
}

/* Monotonic original-image RELRO views. Only initialized image data can be
 * sealed read-only or permission-locked without changing R/RW access.
 * Heap, TLS, stack, text, cache
 * modes, permission upgrades and unmapping remain outside this profile. */
static int protect_image(OotStartupContext *c, uint64_t address, uint64_t size, int lock)
{
    OotGuestRegion views[STARTUP_IMAGE_VIEW_LIMIT], table[STARTUP_REGION_LIMIT];
    uint32_t kinds[STARTUP_IMAGE_VIEW_LIMIT], attributes[STARTUP_IMAGE_VIEW_LIMIT];
    OotGuestMemory checked;
    uint64_t end,cursor=address;
    size_t count=0,table_count;
    if (!oot_startup_context_init_enabled(c) || !valid_memory(c) ||
        !size || (address|size)%STARTUP_PAGE || address>=STARTUP_ADDRESS_LIMIT ||
        size>STARTUP_ADDRESS_LIMIT-address ||
        (lock ? c->permission_locks:c->permission_updates)==UINT64_MAX) return 0;
    end=address+size;
    for (size_t n=0;n<c->image_count;++n) {
        OotGuestRegion r=c->image_regions[n];
        uint64_t stop=r.base+r.size,begin=r.base,cut;
        uint32_t attribute=c->image_attributes[n];
        int overlaps=address<stop && r.base<end;
        if (overlaps) {
            uint64_t low=address>r.base ? address:r.base,high=end<stop ? end:stop;
            if (low!=cursor || (c->image_kinds[n]!=3 && c->image_kinds[n]!=4) ||
                (r.permissions!=OOT_MEMORY_READ && r.permissions!=(OOT_MEMORY_READ|OOT_MEMORY_WRITE)) ||
                (!lock && (attribute&16u))) return 0;
            cursor=high;
        }
        while (begin<stop) {
            cut=stop;
            if (begin<address && address<cut) cut=address;
            if (begin<end && end<cut) cut=end;
            if (count==STARTUP_IMAGE_VIEW_LIMIT) return 0;
            views[count]=(OotGuestRegion){begin,cut-begin,r.data+(size_t)(begin-r.base),r.permissions};
            kinds[count]=c->image_kinds[n];attributes[count]=attribute;
            if (begin>=address && cut<=end) {
                if (lock) attributes[count]|=16u;
                else views[count].permissions=OOT_MEMORY_READ;
            }
            ++count;begin=cut;
        }
    }
    if (cursor!=end) return 0;
    table_count=count;
    memcpy(table,views,count*sizeof(*table));
    table[table_count++]=(OotGuestRegion){c->config.tls_base,c->config.tls_size,c->tls,OOT_MEMORY_READ|OOT_MEMORY_WRITE};
    if (c->heap_size) table[table_count++]=(OotGuestRegion){c->config.heap_base,c->heap_size,c->heap,OOT_MEMORY_READ|OOT_MEMORY_WRITE};
    qsort(table,table_count,sizeof(*table),compare_region);
    if (!oot_memory_init(&checked,table,table_count)) return 0;
    memcpy(c->image_regions,views,count*sizeof(*views));
    memcpy(c->image_kinds,kinds,count*sizeof(*kinds));
    memcpy(c->image_attributes,attributes,count*sizeof(*attributes));
    c->image_count=count;
    memcpy(c->regions,table,table_count*sizeof(*table));
    c->memory=checked;c->memory.regions=c->regions;
    if (lock) ++c->permission_locks;
    else ++c->permission_updates;
    return 1;
}

/* Independent experimental process-query contract. The input handle is W2,
 * not X2, and no C-wrapper output pointer is written by the trap itself.
 * Unmodelled IDs/domains stop without fabricating a kernel result code. */
static int get_info(const OotStartupContext *c, const OotArm64State *state, uint64_t *value)
{
    uint64_t id = state->x[1], subtype = state->x[3];
    uint32_t handle = (uint32_t)state->x[2];
    if (!c->sdk_enabled) return 0;
    if (id == 11) {
        if (handle || subtype >= 4) return 0;
        *value = c->sdk.entropy[subtype];
        return 1;
    }
    if (!(c->sdk.flags & OOT_SDK_PROCESS_INFO)) return 0;
    if (id == 8) {
        if (handle || subtype) return 0;
        *value = 0; /* This explicit model has no guest debug object. */
        return 1;
    }
    if (handle != SDK_CURRENT_PROCESS || subtype) return 0;
    switch (id) {
    case 0: *value = c->sdk.core_mask; break;
    case 1: *value = c->sdk.priority_mask; break;
    case 2: *value = c->sdk.alias_base; break;
    case 3: *value = c->sdk.alias_size; break;
    case 4: *value = c->config.heap_base; break;
    case 5: *value = c->config.heap_capacity; break;
    case 6: case 21: *value = c->sdk.total_memory; break;
    case 7: case 22: *value = c->fixed_memory+c->heap_size; break;
    case 12: *value = c->sdk.aslr_base; break;
    case 13: *value = c->sdk.aslr_size; break;
    case 14: *value = oot_runtime_stack_base(c->image); break;
    case 15: *value = oot_runtime_stack_pointer(c->image)-oot_runtime_stack_base(c->image); break;
    case 16: case 17: *value = 0; break; /* No guest kernel-resource arena is allocated. */
    case 18: *value = c->sdk.program_id; break;
    case 23: *value = c->sdk.is_application; break;
    case 28:
        if (!(c->sdk.flags & OOT_SDK_NO_ALIAS_EXTRA)) return 0;
        *value = 0;
        break;
    case 29: case 30: case 31: case 32:
        if (!(c->sdk.flags & OOT_SDK_NO_REMOTE_ARENA)) return 0;
        /* Explicit absent backing has no extent, committed usage or peak. */
        *value = 0;
        break;
    case 33:
        if (!(c->sdk.flags & OOT_SDK_PAGE_ALLOCATION) || !page_model(&c->memory)) return 0;
        *value = STARTUP_PAGE;
        break;
    default: return 0;
    }
    return 1;
}

static int main_thread_handle(const OotStartupContext *c, uint64_t input)
{
    uint32_t handle = (uint32_t)input;
    return c->sdk_enabled && (c->sdk.flags & OOT_SDK_MAIN_THREAD) &&
        (handle == (uint32_t)c->config.main_thread_handle || handle == SDK_CURRENT_THREAD);
}

int oot_startup_context_service(OotStartupContext *c, uint32_t id,
    OotArm64State *state, OotStartupServiceReport *out)
{
    OotStartupServiceReport report = {0};
    OotArm64State result;
    uint8_t record[40];
    uint64_t i, size, now, elapsed, seconds, remainder, ticks;
    if (out) *out = report;
    if (!c || !state || state->pc >= STARTUP_ADDRESS_LIMIT-4 || state->pc % 4 ||
        (state->nzcv & UINT32_C(0x0fffffff)))
        return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    if (!valid_memory(c))
        return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_MEMORY);
    result = *state;
    switch (id) {
    case 0x02: /* The observed RELRO path downgrades image data to R. */
        if (!oot_startup_context_init_enabled(c) || (uint32_t)state->x[2]!=1)
            return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
        if (!protect_image(c,state->x[0],state->x[1],0))
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_MEMORY);
        result.x[0]=0;
        break;
    case 0x03: /* PermissionLocked only, bound to the original W2/W3=16 path. */
        if (!oot_startup_context_init_enabled(c) || (uint32_t)state->x[2]!=16 || (uint32_t)state->x[3]!=16)
            return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
        if (!protect_image(c,state->x[0],state->x[1],1))
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_MEMORY);
        result.x[0]=0;
        break;
    case 0x01: /* SetHeapSize: x1=size; returns w0=result, x1=base. */
        size = state->x[1];
        if (size > c->config.heap_capacity || size % OOT_STARTUP_HEAP_ALIGNMENT)
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
        i = c->heap_size;
        if (!set_heap_mapping(c,size))
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_MEMORY);
        /* Removed pages are no longer published in any permitted context view.
         * Clear them now so a subsequent grow observes zero-filled pages. */
        if (size < i && !oot_startup_context_init_enabled(c)) memset(c->heap+(size_t)size,0,(size_t)(i-size));
        result.x[0] = 0; result.x[1] = c->config.heap_base;
        break;
    case 0x06: /* QueryMemory: x0=MemoryInfo*, x2=address; w0=result,w1=PageInfo. */
        if (!query_record(c,state->x[2],record))
            return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
        if (!oot_memory_store_record(&c->memory,state->x[0],record,(unsigned)sizeof(record)))
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_MEMORY);
        result.x[0] = 0; result.x[1] = 0;
        break;
    case 0x0c: /* GetThreadPriority: w1=handle; w0=result,w1=priority. */
        if (!main_thread_handle(c,state->x[1]))
            return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
        result.x[0] = 0; result.x[1] = c->sdk.main_thread_priority;
        break;
    case 0x0e: /* GetThreadCoreMask: w2=handle; w0=result,w1=ideal,x2=affinity. */
        if (!main_thread_handle(c,state->x[2]))
            return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
        result.x[0] = 0; result.x[1] = c->sdk.main_thread_core;
        result.x[2] = UINT64_C(1) << c->sdk.main_thread_core;
        break;
    case 0x10: /* GetCurrentProcessorNumber returns w0 directly. */
        if (!c->sdk_enabled || !(c->sdk.flags & OOT_SDK_MAIN_THREAD))
            return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
        result.x[0] = c->sdk.main_thread_core;
        break;
    case 0x1e: /* GetSystemTick; frequency is an explicit process-model input. */
        if (!c->config.tick_frequency)
            return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
        if (!host_counter_read(&now) || now < c->clock_origin)
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_CLOCK);
        elapsed = now-c->clock_origin; seconds = elapsed/c->host_frequency; remainder = elapsed%c->host_frequency;
        if (seconds > UINT64_MAX/c->config.tick_frequency)
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_CLOCK);
        ticks = seconds*c->config.tick_frequency;
        i = (remainder*c->config.tick_frequency)/c->host_frequency;
        if (i > UINT64_MAX-ticks)
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_CLOCK);
        result.x[0] = ticks+i;
        break;
    case 0x27: /* OutputDebugString: captured guest bytes, no direct output. */
        size = state->x[1];
        if (size > OOT_STARTUP_DEBUG_LIMIT)
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
        for (i = 0; i < size; ++i) {
            if (i > UINT64_MAX-state->x[0] || !oot_memory_load(&c->memory,state->x[0]+i,1,&ticks))
                return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_MEMORY);
            report.text[i] = (char)(uint8_t)ticks;
        }
        report.text_size = (uint32_t)size;
        report.text[size] = 0;
        result.x[0] = 0;
        break;
    case 0x25: /* GetThreadId: w1=handle; w0=result,x1=id. */
        if (!main_thread_handle(c,state->x[1]))
            return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
        result.x[0] = 0; result.x[1] = c->sdk.main_thread_id;
        break;
    case 0x29: /* GetInfo: x1=id,w2=handle,x3=subtype; w0=result,x1=value. */
        if (!get_info(c,state,&ticks))
            return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
        result.x[0] = 0; result.x[1] = ticks;
        break;
    default:
        return service_result(out,id,OOT_STARTUP_SERVICE_UNSUPPORTED,OOT_STARTUP_CONTEXT_OK);
    }
    result.pc += 4;
    report.result = result.x[0]; report.status = OOT_STARTUP_SERVICE_IMPLEMENTED; report.id = id;
    *state = result;
    if (out) *out = report;
    return OOT_STARTUP_SERVICE_IMPLEMENTED;
}
