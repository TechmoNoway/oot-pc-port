#include "startup_context.h"
#include "host.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

#define STARTUP_REGION_LIMIT 66u
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
    OotGuestMemory memory;
    OotGuestRegion image_regions[64], regions[STARTUP_REGION_LIMIT];
    uint32_t image_kinds[64];
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
            OOT_SDK_MAIN_THREAD | OOT_SDK_NO_ALIAS_EXTRA | OOT_SDK_PAGE_ALLOCATION | OOT_SDK_OBSERVED_MAIN_TLR) ||
        ((sdk->flags & (OOT_SDK_NO_REMOTE_ARENA | OOT_SDK_MAIN_THREAD | OOT_SDK_NO_ALIAS_EXTRA |
            OOT_SDK_PAGE_ALLOCATION | OOT_SDK_OBSERVED_MAIN_TLR)) && !(sdk->flags & OOT_SDK_PROCESS_INFO)) ||
        ((sdk->flags & OOT_SDK_OBSERVED_MAIN_TLR) && !(sdk->flags & OOT_SDK_MAIN_THREAD)))) return NULL;
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
    c->heap = host_memory_allocate((size_t)config->heap_capacity);
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

OotGuestMemory *oot_startup_context_memory(OotStartupContext *c) { return valid_memory(c) ? &c->memory : NULL; }
OotRuntimeImage *oot_startup_context_image(OotStartupContext *c) { return c ? c->image : NULL; }
uint64_t oot_startup_context_tls_pointer(const OotStartupContext *c) { return c ? c->config.tls_base : 0; }
uint64_t oot_startup_context_heap_size(const OotStartupContext *c) { return c ? c->heap_size : 0; }

int oot_startup_context_system(OotStartupContext *c, uint32_t word, OotArm64State *state)
{
    OotArm64State result;
    uint32_t operation = word & ~UINT32_C(31), reg = word & 31u;
    if (!c || !state || state->pc >= STARTUP_ADDRESS_LIMIT-4 || state->pc % 4 ||
        (state->nzcv & UINT32_C(0x0fffffff)) || !valid_memory(c)) return OOT_STARTUP_SERVICE_FAULT;
    if (!c->sdk_enabled) return OOT_STARTUP_SERVICE_UNSUPPORTED;
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
    uint32_t state = 0, permission = 0;
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
            switch (c->image_kinds[j]) {
            case 1: state = 3; permission = 5; break; /* Static RX text. */
            case 2: state = 3; permission = 1; break; /* Static R data. */
            case 3: case 4: state = 4; permission = 3; break;
            case 5: state = 0xb; permission = 3; break;
            default: return 0;
            }
        }
        break;
    }
    memset(bytes,0,40);
    put64(bytes,base); put64(bytes+8,end-base); put32(bytes+16,state); put32(bytes+24,permission);
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
    case 0x01: /* SetHeapSize: x1=size; returns w0=result, x1=base. */
        size = state->x[1];
        if (size > c->config.heap_capacity || size % OOT_STARTUP_HEAP_ALIGNMENT)
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
        i = c->heap_size;
        if (!set_heap_mapping(c,size))
            return service_result(out,id,OOT_STARTUP_SERVICE_FAULT,OOT_STARTUP_CONTEXT_BAD_MEMORY);
        /* Removed pages are no longer published in any permitted context view.
         * Clear them now so a subsequent grow observes zero-filled pages. */
        if (size < i) memset(c->heap+(size_t)size,0,(size_t)(i-size));
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
