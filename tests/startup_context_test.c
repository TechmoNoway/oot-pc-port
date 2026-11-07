#include "startup_context.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { fprintf(stderr,"startup context failure line %d: %s\n",__LINE__,#expression); return 1; } } while (0)

static void put32(uint8_t *p, uint32_t x)
{
    unsigned i;
    for (i = 0; i < 4; ++i) p[i] = (uint8_t)(x >> (8*i));
}
static void put64(uint8_t *p, uint64_t x)
{
    put32(p,(uint32_t)x); put32(p+4,(uint32_t)(x >> 32));
}

static int fixture(const char *path, int pages)
{
    uint8_t bytes[12704] = {0};
    uint64_t bases[] = {0x10000,0x12000,0x14000,0x16000,0x800000}, sizes[] = {4096,4096,4096,4096,4096};
    uint32_t permissions[] = {1,1,3,3,3}, kinds[] = {1,2,3,4,5};
    size_t i, count = pages ? 5 : 3, cursor = 96+count*64, payload_begin = cursor, length = pages ? sizeof(bytes) : 368;
    FILE *file;
    if (!pages) {
        sizes[0] = 16; sizes[1] = 64; sizes[2] = 4096; bases[2] = 0x800000;
        permissions[1] = 3; kinds[1] = 3; kinds[2] = 5;
    }
    memcpy(bytes,"OOTMEM1",7); put32(bytes+8,1); put32(bytes+12,(uint32_t)count);
    put64(bytes+16,0x801000); put64(bytes+24,pages ? 20480 : 4176); put64(bytes+32,96);
    put64(bytes+40,cursor); put64(bytes+48,length);
    for (i = 0; i < count; ++i) {
        uint8_t *d = bytes+96+i*64;
        uint64_t payload = kinds[i] >= 4 ? 0 : sizes[i];
        put64(d,bases[i]); put64(d+8,sizes[i]); put64(d+16,cursor); put64(d+24,payload);
        put32(d+32,permissions[i]); put32(d+36,kinds[i]); memcpy(d+40,kinds[i] == 5 ? "stack" : "main",kinds[i] == 5 ? 5u : 4u);
        cursor += (size_t)payload;
    }
    bytes[payload_begin] = 0xc0; bytes[payload_begin+1] = 0x03; bytes[payload_begin+2] = 0x5f; bytes[payload_begin+3] = 0xd6;
    payload_begin += (size_t)sizes[0];
    bytes[payload_begin] = 'A'; bytes[payload_begin+1] = 0; bytes[payload_begin+2] = '\n'; bytes[payload_begin+3] = 0xff;
    if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE,NULL,0,bytes+96,(ULONG)(length-96),bytes+64,32) < 0) return 0;
    file = fopen(path,"wb");
    if (!file) return 0;
    i = fwrite(bytes,1,length,file);
    return fclose(file) == 0 && i == length;
}

static int same(const OotArm64State *a, const OotArm64State *b)
{
    return !memcmp(a->x,b->x,sizeof(a->x)) && a->sp == b->sp && a->pc == b->pc && a->nzcv == b->nzcv;
}

static int record_checks(void)
{
    uint8_t first[24], second[40], bytes[65], before[64], output[64];
    OotGuestRegion regions[] = {{0x100,24,first,3},{0x118,40,second,3}};
    OotGuestMemory memory;
    unsigned i;
    for (i = 0; i < 65; ++i) bytes[i] = (uint8_t)(i+1);
    CHECK(oot_memory_init(&memory,regions,2));
    CHECK(oot_memory_store_record(&memory,0x100,bytes,64));
    CHECK(oot_memory_load_record(&memory,0x100,output,64) && !memcmp(output,bytes,64));
    CHECK(oot_memory_store_record(&memory,0x108,bytes+4,40));
    CHECK(oot_memory_load_record(&memory,0x108,output,40) && !memcmp(output,bytes+4,40));
    CHECK(oot_memory_load_record(&memory,0x100,before,64));
    CHECK(!oot_memory_store_record(&memory,0x130,bytes,40));
    CHECK(memory.fault.size == 40 && memory.fault.failing_address == 0x140 && memory.fault.reason == OOT_MEMORY_UNMAPPED);
    CHECK(oot_memory_load_record(&memory,0x100,output,64) && !memcmp(output,before,64));
    memset(output,0x5a,sizeof(output));
    CHECK(!oot_memory_load_record(&memory,0x130,output,40));
    for (i = 0; i < sizeof(output); ++i) CHECK(output[i] == 0x5a);
    CHECK(!oot_memory_store_record(&memory,0x100,bytes,65) && memory.fault.reason == OOT_MEMORY_CONFIGURATION);
    CHECK(!oot_memory_store_record(&memory,0x100,NULL,40) && memory.fault.reason == OOT_MEMORY_CONFIGURATION);
    CHECK(!oot_memory_load_record(&memory,0x100,NULL,40) && memory.fault.reason == OOT_MEMORY_CONFIGURATION);
    CHECK(!oot_memory_store_record(&memory,0x100,bytes,0) && memory.fault.reason == OOT_MEMORY_CONFIGURATION);
    CHECK(!oot_memory_store_record(&memory,UINT64_MAX-3,bytes,40) && memory.fault.reason == OOT_MEMORY_ADDRESS_WRAP);
    CHECK(!oot_memory_probe(&memory,0x100,40,OOT_MEMORY_WRITE) && memory.fault.reason == OOT_MEMORY_CONFIGURATION);
    regions[1].permissions = 1;
    CHECK(!oot_memory_store_record(&memory,0x108,bytes,40) && memory.fault.failing_address == 0x118 && memory.fault.reason == OOT_MEMORY_PERMISSION);
    CHECK(oot_memory_load_record(&memory,0x100,output,64) && !memcmp(output,before,64));
    return 0;
}

static int query_checks(const char *path)
{
    const uint64_t address_limit = UINT64_C(1)<<39;
    struct QueryCase { uint64_t address, base, size; uint32_t state, permission; } cases[] = {
        {0,0,0x10000,0,0}, {0x10003,0x10000,0x1000,3,5},
        {0x11020,0x11000,0x1000,0,0}, {0x120ff,0x12000,0x1000,3,1},
        {0x14100,0x14000,0x1000,4,3}, {0x16fff,0x16000,0x1000,4,3},
        {0x600100,0x600000,0x1000,0xc,3}, {0x800010,0x800000,0x1000,0xb,3},
        {0x200123,0x17000,0x600000-0x17000,0,0},
        {address_limit-1,0x801000,address_limit-0x801000,0,0},
        {address_limit,address_limit,0-address_limit,0x10,0},
        {UINT64_MAX,address_limit,0-address_limit,0x10,0}
    };
    OotStartupConfig config = {0x600000,4096,0x200000,0x200000,0x1234,0};
    OotStartupContext *context;
    OotRuntimeImage *image;
    OotStartupServiceReport report;
    OotArm64State state, expected, before;
    OotGuestMemory *memory;
    uint8_t record[40], wanted[40], tail[32];
    uint32_t error;
    char message[192];
    unsigned i;
    CHECK(fixture(path,1));
    image = oot_runtime_open(path,message,sizeof(message)); CHECK(image != NULL);
    context = oot_startup_context_create(image,&config,&error); CHECK(context != NULL);
    memory = oot_startup_context_memory(context); CHECK(memory != NULL);
    CHECK(oot_startup_context_initial_state(context,0x10000,&state));
    state.x[7] = 0xabcdef; state.nzcv = 0xa0000000;
    for (i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        state.x[0] = 0x14040; state.x[1] = 0x800020; state.x[2] = cases[i].address;
        expected = state; expected.pc += 4; expected.x[0] = expected.x[1] = 0;
        memset(wanted,0,sizeof(wanted)); put64(wanted,cases[i].base); put64(wanted+8,cases[i].size);
        put32(wanted+16,cases[i].state); put32(wanted+24,cases[i].permission);
        CHECK(oot_startup_context_service(context,6,&state,&report) == 0 && same(&state,&expected));
        CHECK(oot_memory_load_record(memory,0x14040,record,40) && !memcmp(record,wanted,40));
    }
    state.x[1] = config.heap_capacity; CHECK(oot_startup_context_service(context,1,&state,&report) == 0);
    state.x[0] = 0x14040; state.x[2] = config.heap_base+1;
    CHECK(oot_startup_context_service(context,6,&state,&report) == 0);
    memset(wanted,0,40); put64(wanted,config.heap_base); put64(wanted+8,config.heap_capacity); put32(wanted+16,5); put32(wanted+24,3);
    CHECK(oot_memory_load_record(memory,0x14040,record,40) && !memcmp(record,wanted,40));
    memset(tail,0x6d,sizeof(tail)); CHECK(oot_memory_store_record(memory,0x14fe0,tail,32));
    state.x[0] = 0x14fe0; state.x[2] = 0x10000; before = state;
    CHECK(oot_startup_context_service(context,6,&state,&report) == 2 && same(&state,&before));
    CHECK(memory->fault.size == 40 && memory->fault.failing_address == 0x15000);
    CHECK(oot_memory_load_record(memory,0x14fe0,record,32) && !memcmp(record,tail,32));
    state.x[0] = 0x10000; before = state;
    CHECK(oot_startup_context_service(context,6,&state,&report) == 2 && same(&state,&before));
    CHECK(memory->fault.reason == OOT_MEMORY_PERMISSION);
    oot_startup_context_destroy(context); oot_runtime_close(image);
    return 0;
}

static int info_check(OotStartupContext *c, uint64_t id, uint64_t handle,
    uint64_t subtype, int supported, uint64_t value)
{
    OotArm64State state, expected;
    OotStartupServiceReport report;
    uint64_t sentinel;
    unsigned i;
    CHECK(oot_startup_context_initial_state(c,0x10000,&state));
    for (i = 0; i < 31; ++i) state.x[i] = UINT64_C(0xfedcba9876543210)+i;
    state.x[0] = 0x14040; state.x[1] = id; state.x[2] = handle; state.x[3] = subtype;
    state.nzcv = 0xb0000000;
    CHECK(oot_memory_store(oot_startup_context_memory(c),0x14040,8,UINT64_C(0xa1b2c3d4e5f60718)));
    expected = state;
    if (supported) { expected.pc += 4; expected.x[0] = 0; expected.x[1] = value; }
    CHECK(oot_startup_context_service(c,0x29,&state,&report) == (supported ? 0 : 1));
    CHECK(same(&state,&expected) && report.id == 0x29 && !report.error && !report.text_size);
    CHECK(oot_memory_load(oot_startup_context_memory(c),0x14040,8,&sentinel) && sentinel == UINT64_C(0xa1b2c3d4e5f60718));
    return 0;
}

static int thread_service_check(OotStartupContext *c, uint32_t id, uint64_t handle,
    int supported, const OotSdkConfig *sdk)
{
    OotArm64State state, expected;
    OotStartupServiceReport report;
    uint64_t sentinel;
    unsigned i;
    CHECK(oot_startup_context_initial_state(c,0x10000,&state));
    for (i = 0; i < 31; ++i) state.x[i] = UINT64_C(0xfedcba9876543210)+i;
    state.x[0] = 0x14040; state.x[1] = state.x[2] = handle;
    state.nzcv = 0xb0000000;
    CHECK(oot_memory_store(oot_startup_context_memory(c),0x14040,8,UINT64_C(0xa1b2c3d4e5f60718)));
    expected = state;
    if (supported) {
        expected.pc += 4; expected.x[0] = 0;
        switch (id) {
        case 0x0c: expected.x[1] = sdk->main_thread_priority; break;
        case 0x0e:
            expected.x[1] = sdk->main_thread_core;
            expected.x[2] = UINT64_C(1) << sdk->main_thread_core;
            break;
        case 0x10: expected.x[0] = sdk->main_thread_core; break;
        case 0x25: expected.x[1] = sdk->main_thread_id; break;
        default: CHECK(0);
        }
    }
    CHECK(oot_startup_context_service(c,id,&state,&report) == (supported ? 0 : 1));
    CHECK(same(&state,&expected) && report.id == id && !report.error && !report.text_size);
    CHECK(report.result == (supported ? expected.x[0] : 0));
    CHECK(oot_memory_load(oot_startup_context_memory(c),0x14040,8,&sentinel) && sentinel == UINT64_C(0xa1b2c3d4e5f60718));
    return 0;
}

static int cas_checks(OotStartupContext *c, OotStartupContext *legacy)
{
    OotArm64State state, before, expected;
    OotGuestMemory *memory = oot_startup_context_memory(c);
    uint64_t observed, initial, desired, address;
    uint32_t word;
    unsigned size, order, match, i;
    for (size = 4; size <= 8; size += 4) for (order = 0; order < 4; ++order)
        for (match = 0; match < 2; ++match) {
            CHECK(oot_startup_context_initial_state(c,0x10000,&state));
            for (i = 0; i < 31; ++i) state.x[i] = UINT64_C(0xabcdef1234567800)+i;
            initial = size == 4 ? UINT64_C(0x89abcdef) : UINT64_C(0xfedcba9876543210);
            desired = UINT64_C(0x123456786543210f); address = 0x14080;
            state.x[2] = (initial ^ match) | (size == 4 ? UINT64_C(0xabcdef1200000000) : 0);
            state.x[3] = desired; state.x[4] = address; state.nzcv = 0xd0000000;
            CHECK(oot_memory_store(memory,address,size,initial));
            expected = state; expected.x[2] = initial; expected.pc += 4;
            word = (size == 8 ? UINT32_C(0xc8a07c00) : UINT32_C(0x88a07c00)) |
                ((order & 1) << 22) | ((order >> 1) << 15) | (2u << 16) | (4u << 5) | 3u;
            CHECK(oot_startup_context_system(c,word,&state) == 0 && same(&state,&expected));
            if (size == 4) desired &= UINT32_MAX;
            CHECK(oot_memory_load(memory,address,size,&observed) && observed == (match ? initial : desired));
        }
    /* Expected/desired ZR and aliased source registers use the before-state. */
    CHECK(oot_startup_context_initial_state(c,0x10000,&state));
    state.x[3] = UINT64_C(0x123456789abcdef0); state.x[4] = 0x14080;
    CHECK(oot_memory_store(memory,0x14080,8,0));
    expected = state; expected.pc += 4;
    CHECK(oot_startup_context_system(c,UINT32_C(0xc8bf7c83),&state) == 0 && same(&state,&expected));
    CHECK(oot_memory_load(memory,0x14080,8,&observed) && observed == UINT64_C(0x123456789abcdef0));
    state.x[2] = observed; expected = state; expected.pc += 4;
    CHECK(oot_startup_context_system(c,UINT32_C(0xc8a27c9f),&state) == 0 && same(&state,&expected));
    CHECK(oot_memory_load(memory,0x14080,8,&observed) && !observed);
    state.x[2] = 0x14080; state.x[3] = 0x99;
    CHECK(oot_memory_store(memory,0x14080,8,0x14080));
    expected = state; expected.pc += 4;
    CHECK(oot_startup_context_system(c,UINT32_C(0xc8a27c43),&state) == 0 && same(&state,&expected));
    CHECK(oot_memory_load(memory,0x14080,8,&observed) && observed == 0x99);
    state.x[2] = 0x99; expected = state; expected.pc += 4;
    CHECK(oot_startup_context_system(c,UINT32_C(0xc8a27c82),&state) == 0 && same(&state,&expected));
    CHECK(oot_memory_load(memory,0x14080,8,&observed) && observed == 0x99);
    /* SP uses the pre-instruction SP with natural and 16-byte alignment. */
    state.sp = 0x800080; state.x[2] = 1; state.x[3] = 2;
    CHECK(oot_memory_store(memory,state.sp,8,1));
    expected = state; expected.pc += 4;
    CHECK(oot_startup_context_system(c,UINT32_C(0xc8a27fe3),&state) == 0 && same(&state,&expected));
    CHECK(oot_memory_load(memory,state.sp,8,&observed) && observed == 2);
    for (size = 4; size <= 8; size += 4) {
        const uint64_t faults[] = {0x14081,0x15000,0x10000};
        for (i = 0; i < sizeof(faults)/sizeof(*faults); ++i) {
            CHECK(oot_startup_context_initial_state(c,0x10000,&state));
            state.x[2] = 0x99; state.x[3] = 0x33; state.x[4] = faults[i]; before = state;
            CHECK(oot_memory_store(memory,0x14080,8,0x99));
            word = (size == 8 ? UINT32_C(0xc8a27c83) : UINT32_C(0x88a27c83));
            CHECK(oot_startup_context_system(c,word,&state) == 2 && same(&state,&before));
            CHECK(oot_memory_load(memory,0x14080,8,&observed) && observed == 0x99);
        }
    }
    state.sp = 0x800084; before = state;
    CHECK(oot_startup_context_system(c,UINT32_C(0x88a27fe3),&state) == 2 && same(&state,&before));
    CHECK(oot_startup_context_initial_state(legacy,0x10000,&state));
    state.x[2] = 0; state.x[3] = 1; state.x[4] = 0x14080; before = state;
    CHECK(oot_startup_context_system(legacy,UINT32_C(0x88a27c83),&state) == 1 && same(&state,&before));
    CHECK(oot_startup_context_system(c,UINT32_C(0x08a27c83),&state) == 1 && same(&state,&before));
    return 0;
}

static int sdk_checks(const char *path)
{
    const uint64_t address_limit = UINT64_C(1)<<39;
    OotStartupConfig config = {0x600000,4096,0x200000,0x200000,0x1234,0}, bad;
    OotSdkConfig sdk = {OOT_SDK_CONTEXT_VERSION,OOT_SDK_EXPLICIT_ENTROPY | OOT_SDK_PROCESS_INFO,
        {UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210),0,UINT64_MAX},
        0xf,UINT64_C(0xffffffffffffffff),0,UINT64_C(1)<<39,UINT64_C(0x100000000),0x200000,
        UINT64_C(0x04004860224dec00),1,0x400000,0,0,0}, wrong;
    struct InfoCase { uint64_t id, value; } cases[] = {
        {0,0xf},{1,UINT64_MAX},{2,UINT64_C(0x100000000)},{3,0x200000},
        {4,0x200000},{5,0x200000},{6,0x400000},{7,24576},
        {12,0},{13,UINT64_C(1)<<39},{14,0x800000},{15,4096},{16,0},{17,0},
        {18,UINT64_C(0x04004860224dec00)},{21,0x400000},{22,24576},{23,1}
    };
    OotStartupContext *c, *old, *random, *entropy_only, *larger, *no_remote, *thread;
    OotRuntimeImage *image;
    OotArm64State state, expected, before;
    OotStartupServiceReport report;
    OotGuestMemory *memory, saved;
    uint64_t entropy[4];
    uint32_t error, reg;
    char message[192];
    size_t i;
    CHECK(sizeof(OotStartupConfig) == 6*sizeof(uint64_t));
    CHECK(fixture(path,1));
    image = oot_runtime_open(path,message,sizeof(message)); CHECK(image != NULL);
    c = oot_startup_context_create_sdk(image,&config,&sdk,&error); CHECK(c != NULL && !error);
    old = oot_startup_context_create(image,&config,&error); CHECK(old != NULL);
    CHECK(oot_startup_context_sdk_enabled(c) && !oot_startup_context_sdk_enabled(old) && !oot_startup_context_sdk_enabled(NULL));
    CHECK(!oot_startup_context_tpidr_el0(c) && !oot_startup_context_tpidr_el0(old) && !oot_startup_context_tpidr_el0(NULL));
    for (i = 0; i < 4; ++i) {
        CHECK(!info_check(c,11,0,i,1,sdk.entropy[i]));
        CHECK(!info_check(c,11,UINT64_C(0x1234567800000000),i,1,sdk.entropy[i]));
    }
    CHECK(!info_check(c,11,0,4,0,0));
    CHECK(!info_check(c,11,0,UINT64_MAX,0,0));
    CHECK(!info_check(c,11,1,2,0,0));
    CHECK(!info_check(c,11,0xffff8001,2,0,0));
    CHECK(!info_check(old,11,0,2,0,0));
    CHECK(!info_check(old,8,0,0,0,0));
    CHECK(!info_check(c,8,0,0,1,0));
    CHECK(!info_check(c,8,1,0,0,0));
    CHECK(!info_check(c,8,0,1,0,0));
    for (i = 0; i < sizeof(cases)/sizeof(*cases); ++i) {
        CHECK(!info_check(c,cases[i].id,0xffff8001,0,1,cases[i].value));
        CHECK(!info_check(c,cases[i].id,UINT64_C(0x12345678ffff8001),0,1,cases[i].value));
        CHECK(!info_check(c,cases[i].id,0,0,0,0));
        CHECK(!info_check(c,cases[i].id,0xffff8001,1,0,0));
        CHECK(!info_check(old,cases[i].id,0xffff8001,0,0,0));
    }
    CHECK(!info_check(c,9,0,0,0,0));
    CHECK(!info_check(c,20,0xffff8001,0,0,0));
    CHECK(!info_check(c,24,0xffff8001,0,0,0));
    CHECK(!info_check(c,33,0xffff8001,0,0,0));
    CHECK(!info_check(c,UINT64_MAX,0,0,0,0));
    wrong = sdk; wrong.flags |= OOT_SDK_MAIN_THREAD | OOT_SDK_NO_ALIAS_EXTRA;
    wrong.main_thread_id = UINT64_C(0xfedcba9876543210); wrong.main_thread_priority = 63; wrong.main_thread_core = 3;
    thread = oot_startup_context_create_sdk(image,&config,&wrong,&error); CHECK(thread != NULL && !error);
    wrong.main_thread_id = 1; wrong.main_thread_priority = 0; wrong.main_thread_core = 0;
    {
        const uint32_t services[] = {0x0c,0x0e,0x25};
        const uint64_t handles[] = {0x1234,0xffff8000,UINT64_C(0x13579bdfffff8000),UINT64_C(0x13579bdf00001234)};
        const uint64_t bad_handles[] = {0,1,0x1235,0xffff8001,UINT64_MAX};
        OotSdkConfig expected_thread = sdk;
        size_t service, handle;
        expected_thread.main_thread_id = UINT64_C(0xfedcba9876543210);
        expected_thread.main_thread_priority = 63; expected_thread.main_thread_core = 3;
        for (service = 0; service < sizeof(services)/sizeof(*services); ++service) {
            for (handle = 0; handle < sizeof(handles)/sizeof(*handles); ++handle)
                CHECK(!thread_service_check(thread,services[service],handles[handle],1,&expected_thread));
            for (handle = 0; handle < sizeof(bad_handles)/sizeof(*bad_handles); ++handle)
                CHECK(!thread_service_check(thread,services[service],bad_handles[handle],0,NULL));
            CHECK(!thread_service_check(c,services[service],0x1234,0,NULL));
            CHECK(!thread_service_check(old,services[service],0xffff8000,0,NULL));
        }
        CHECK(!thread_service_check(thread,0x10,UINT64_MAX,1,&expected_thread));
        CHECK(!thread_service_check(c,0x10,0,0,NULL));
        CHECK(!thread_service_check(old,0x10,0,0,NULL));
    }
    CHECK(!info_check(thread,28,0xffff8001,0,1,0));
    CHECK(!info_check(thread,28,UINT64_C(0x12345678ffff8001),0,1,0));
    CHECK(!info_check(thread,28,0,0,0,0));
    CHECK(!info_check(thread,28,0xffff8000,0,0,0));
    CHECK(!info_check(thread,28,0xffff8001,1,0,0));
    CHECK(!info_check(thread,28,0xffff8001,UINT64_MAX,0,0));
    CHECK(!info_check(thread,29,0xffff8001,0,0,0));
    CHECK(!info_check(thread,33,0xffff8001,0,0,0));
    CHECK(!info_check(c,28,0xffff8001,0,0,0));
    for (i = 0; i < 256; ++i) {
        if (i == 1 || i == 6 || i == 0x0c || i == 0x0e || i == 0x10 ||
            i == 0x1e || i == 0x25 || i == 0x27 || i == 0x29) continue;
        CHECK(oot_startup_context_initial_state(thread,0x10000,&state));
        state.x[1] = 0x1234; state.x[2] = 0xffff8000; before = state;
        CHECK(oot_startup_context_service(thread,(uint32_t)i,&state,&report) == 1 && same(&state,&before));
    }
    oot_startup_context_destroy(thread);
    wrong = sdk; wrong.flags |= OOT_SDK_PAGE_ALLOCATION;
    thread = oot_startup_context_create_sdk(image,&config,&wrong,&error); CHECK(thread != NULL && !error);
    CHECK(!info_check(thread,33,0xffff8001,0,1,4096));
    CHECK(!info_check(thread,33,UINT64_C(0x12345678ffff8001),0,1,4096));
    CHECK(!info_check(thread,33,0,0,0,0));
    CHECK(!info_check(thread,33,0xffff8000,0,0,0));
    CHECK(!info_check(thread,33,0xffff8001,1,0,0));
    CHECK(!info_check(thread,34,0xffff8001,0,0,0));
    oot_startup_context_destroy(thread);
    bad = config; bad.tls_size = 512;
    CHECK(!oot_startup_context_create_sdk(image,&bad,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
    {
        OotRuntimeImage *unaligned;
        CHECK(fixture(path,0));
        unaligned = oot_runtime_open(path,message,sizeof(message)); CHECK(unaligned != NULL);
        CHECK(!oot_startup_context_create_sdk(unaligned,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
        oot_runtime_close(unaligned);
        CHECK(fixture(path,1));
    }
    wrong = sdk; wrong.flags |= OOT_SDK_MAIN_THREAD | OOT_SDK_OBSERVED_MAIN_TLR;
    wrong.main_thread_id = 1; wrong.main_thread_priority = wrong.main_thread_core = 0;
    bad = config;
    thread = oot_startup_context_create_sdk(image,&bad,&wrong,&error); CHECK(thread != NULL && !error);
    bad.main_thread_handle = 0x76543210;
    {
        uint8_t bytes[64], expected_bytes[64];
        size_t offset, byte;
        for (offset = 0; offset < config.tls_size; offset += sizeof(bytes)) {
            memset(expected_bytes,0,sizeof(expected_bytes));
            for (byte = 0; byte < sizeof(bytes); ++byte)
                if (offset+byte >= 0x110 && offset+byte < 0x114)
                    expected_bytes[byte] = (uint8_t)(config.main_thread_handle >> (8*(offset+byte-0x110)));
            CHECK(oot_memory_load_record(oot_startup_context_memory(thread),config.tls_base+offset,bytes,sizeof(bytes)));
            CHECK(!memcmp(bytes,expected_bytes,sizeof(bytes)));
            CHECK(oot_memory_load_record(oot_startup_context_memory(c),config.tls_base+offset,bytes,sizeof(bytes)));
            for (byte = 0; byte < sizeof(bytes); ++byte) CHECK(!bytes[byte]);
        }
    }
    oot_startup_context_destroy(thread);
    bad = config; bad.main_thread_handle = UINT32_C(0x3fffffff);
    thread = oot_startup_context_create_sdk(image,&bad,&wrong,&error); CHECK(thread != NULL && !error);
    CHECK(oot_memory_load(oot_startup_context_memory(thread),config.tls_base+0x110,4,&entropy[0]) && entropy[0] == UINT32_C(0x3fffffff));
    oot_startup_context_destroy(thread);
    bad.main_thread_handle = UINT32_C(0x40000000);
    CHECK(!oot_startup_context_create_sdk(image,&bad,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    bad.main_thread_handle = UINT32_MAX;
    CHECK(!oot_startup_context_create_sdk(image,&bad,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    thread = oot_startup_context_create(image,&bad,&error); CHECK(thread != NULL && !error);
    oot_startup_context_destroy(thread);
    wrong.flags &= ~OOT_SDK_OBSERVED_MAIN_TLR;
    thread = oot_startup_context_create_sdk(image,&bad,&wrong,&error); CHECK(thread != NULL && !error);
    oot_startup_context_destroy(thread);
    CHECK(!cas_checks(c,old));
    wrong = sdk; wrong.flags |= OOT_SDK_NO_REMOTE_ARENA;
    no_remote = oot_startup_context_create_sdk(image,&config,&wrong,&error); CHECK(no_remote != NULL && !error);
    wrong.flags &= ~OOT_SDK_NO_REMOTE_ARENA;
    for (i = 29; i <= 32; ++i) {
        /* The opt-in is copied, never inherited from mutable caller flags. */
        CHECK(!info_check(no_remote,i,0xffff8001,0,1,0));
        CHECK(!info_check(no_remote,i,UINT64_C(0x12345678ffff8001),0,1,0));
        CHECK(!info_check(no_remote,i,0,0,0,0));
        CHECK(!info_check(no_remote,i,0x1234,0,0,0));
        CHECK(!info_check(no_remote,i,0xffff8000,0,0,0));
        CHECK(!info_check(no_remote,i,0xffff8001,1,0,0));
        CHECK(!info_check(no_remote,i,0xffff8001,UINT64_MAX,0,0));
        CHECK(!info_check(c,i,0xffff8001,0,0,0));
        CHECK(!info_check(old,i,0xffff8001,0,0,0));
    }
    CHECK(!info_check(no_remote,28,0xffff8001,0,0,0));
    CHECK(!info_check(no_remote,33,0xffff8001,0,0,0));
    CHECK(!info_check(no_remote,UINT64_MAX,0xffff8001,0,0,0));
    CHECK(!info_check(no_remote,9,0,0,0,0));
    CHECK(!info_check(no_remote,20,0xffff8001,0,0,0));
    CHECK(!info_check(no_remote,0,0xffff8001,0,1,sdk.core_mask));
    CHECK(!info_check(no_remote,11,0,2,1,sdk.entropy[2]));
    /* Declaring absent remote backing cannot grant an allocation syscall. */
    for (i = 0; i < 256; ++i) {
        if (i == 1 || i == 6 || i == 0x1e || i == 0x27 || i == 0x29) continue;
        CHECK(oot_startup_context_initial_state(no_remote,0x10000,&state));
        state.x[0] = 0x14040; state.x[1] = 0x200000; state.x[2] = 0xffff8001;
        state.nzcv = 0x90000000; before = state;
        CHECK(oot_startup_context_service(no_remote,(uint32_t)i,&state,&report) == 1 && same(&state,&before));
        CHECK(report.id == i && !report.error && !report.text_size);
        CHECK(!oot_startup_context_heap_size(no_remote));
    }
    oot_startup_context_destroy(no_remote);
    CHECK(oot_startup_context_initial_state(c,0x10000,&state));
    state.x[1] = config.heap_capacity;
    CHECK(oot_startup_context_service(c,1,&state,&report) == 0);
    CHECK(!info_check(c,7,0xffff8001,0,1,24576+config.heap_capacity));
    CHECK(!info_check(c,22,0xffff8001,0,1,24576+config.heap_capacity));
    state.x[1] = 0; CHECK(oot_startup_context_service(c,1,&state,&report) == 0);
    CHECK(!info_check(c,7,0xffff8001,0,1,24576));
    /* Configs are copied; changing caller-owned metadata/entropy has no effect. */
    wrong = sdk; sdk.entropy[2] = 0xaaaaaaaa; sdk.core_mask = 0x80;
    CHECK(!info_check(c,11,0,2,1,0));
    CHECK(!info_check(c,0,0xffff8001,0,1,0xf));
    sdk = wrong;
    for (reg = 0; reg < 32; ++reg) {
        CHECK(oot_startup_context_initial_state(c,0x10000,&state));
        for (i = 0; i < 31; ++i) state.x[i] = UINT64_C(0x1234000000000000)+i;
        state.nzcv = 0xa0000000;
        before = state; expected = state; expected.pc += 4;
        CHECK(oot_startup_context_system(c,UINT32_C(0xd51bd040)|reg,&state) == 0 && same(&state,&expected));
        CHECK(oot_startup_context_tpidr_el0(c) == (reg == 31 ? 0 : before.x[reg]));
        expected = state; expected.pc += 4;
        if (reg != 31) expected.x[reg] = before.x[reg];
        CHECK(oot_startup_context_system(c,UINT32_C(0xd53bd040)|reg,&state) == 0 && same(&state,&expected));
        expected = state; expected.pc += 4;
        if (reg != 31) expected.x[reg] = config.tls_base;
        CHECK(oot_startup_context_system(c,UINT32_C(0xd53bd060)|reg,&state) == 0 && same(&state,&expected));
    }
    state.x[2] = UINT64_C(0xabcdef9876543210);
    CHECK(oot_startup_context_system(c,UINT32_C(0xd51bd042),&state) == 0);
    before = state;
    CHECK(oot_startup_context_system(c,UINT32_C(0xd51bd060),&state) == 1 && same(&state,&before));
    CHECK(oot_startup_context_system(old,UINT32_C(0xd53bd060),&state) == 1 && same(&state,&before));
    CHECK(oot_startup_context_system(c,UINT32_C(0xd53bd020),&state) == 1 && same(&state,&before));
    CHECK(oot_startup_context_tpidr_el0(c) == UINT64_C(0xabcdef9876543210));
    state.pc = 3; before = state;
    CHECK(oot_startup_context_system(c,UINT32_C(0xd51bd05f),&state) == 2 && same(&state,&before));
    state.pc = address_limit-4; before = state;
    CHECK(oot_startup_context_system(c,UINT32_C(0xd51bd05f),&state) == 2 && same(&state,&before));
    state.pc = 0x10000; state.nzcv = 1; before = state;
    CHECK(oot_startup_context_system(c,UINT32_C(0xd51bd05f),&state) == 2 && same(&state,&before));
    state.nzcv = 0; before = state;
    memory = oot_startup_context_memory(c); saved = *memory; memory->valid = 0;
    CHECK(oot_startup_context_system(c,UINT32_C(0xd51bd05f),&state) == 2 && same(&state,&before));
    *memory = saved;
    CHECK(oot_startup_context_tpidr_el0(c) == UINT64_C(0xabcdef9876543210));
    CHECK(oot_startup_context_system(NULL,UINT32_C(0xd51bd05f),&state) == 2);
    CHECK(oot_startup_context_system(c,UINT32_C(0xd51bd05f),NULL) == 2);
    wrong = sdk; wrong.flags = OOT_SDK_EXPLICIT_ENTROPY;
    entropy_only = oot_startup_context_create_sdk(image,&config,&wrong,&error); CHECK(entropy_only != NULL);
    CHECK(!info_check(entropy_only,11,0,1,1,sdk.entropy[1]));
    CHECK(!info_check(entropy_only,0,0xffff8001,0,0,0));
    CHECK(!info_check(entropy_only,8,0,0,0,0));
    oot_startup_context_destroy(entropy_only);
    wrong.flags = 0;
    random = oot_startup_context_create_sdk(image,&config,&wrong,&error); CHECK(random != NULL);
    for (i = 0; i < 4; ++i) {
        CHECK(oot_startup_context_initial_state(random,0x10000,&state));
        state.x[1] = 11; state.x[2] = 0; state.x[3] = i;
        CHECK(oot_startup_context_service(random,0x29,&state,&report) == 0);
        entropy[i] = state.x[1];
    }
    for (i = 0; i < 4; ++i) CHECK(!info_check(random,11,0,i,1,entropy[i]));
    for (i = 29; i <= 32; ++i) CHECK(!info_check(random,i,0xffff8001,0,0,0));
    oot_startup_context_destroy(random);
    wrong = sdk; wrong.flags = OOT_SDK_PROCESS_INFO;
    no_remote = oot_startup_context_create_sdk(image,&config,&wrong,&error); CHECK(no_remote != NULL);
    wrong.flags |= OOT_SDK_NO_REMOTE_ARENA;
    for (i = 29; i <= 32; ++i) CHECK(!info_check(no_remote,i,0xffff8001,0,0,0));
    oot_startup_context_destroy(no_remote);
    CHECK(!oot_startup_context_create_sdk(image,&config,NULL,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong = sdk; wrong.version++;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong = sdk; wrong.flags |= 0x80;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong = sdk; wrong.flags = OOT_SDK_NO_REMOTE_ARENA;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong.flags |= OOT_SDK_EXPLICIT_ENTROPY;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong = sdk; wrong.flags = OOT_SDK_MAIN_THREAD;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong.flags = OOT_SDK_NO_ALIAS_EXTRA;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong.flags = OOT_SDK_PAGE_ALLOCATION;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong.flags = OOT_SDK_OBSERVED_MAIN_TLR | OOT_SDK_PROCESS_INFO;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong.flags = OOT_SDK_OBSERVED_MAIN_TLR | OOT_SDK_MAIN_THREAD;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    wrong = sdk; wrong.flags |= OOT_SDK_MAIN_THREAD;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
    wrong.main_thread_id = UINT64_MAX; wrong.main_thread_priority = 64;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
    wrong.main_thread_priority = 63; wrong.main_thread_core = 64;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
    wrong.main_thread_core = 4;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
    wrong.main_thread_core = 0; wrong.priority_mask = 1;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
    wrong = sdk; wrong.core_mask = 0;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
    wrong = sdk; wrong.priority_mask = 0;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong = sdk; wrong.is_application = 2;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong = sdk; wrong.total_memory = config.heap_capacity;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong = sdk; wrong.total_memory = config.heap_capacity+24576-1;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong.total_memory++;
    larger = oot_startup_context_create_sdk(image,&config,&wrong,&error); CHECK(larger != NULL);
    CHECK(!info_check(larger,6,0xffff8001,0,1,wrong.total_memory));
    oot_startup_context_destroy(larger);
    wrong = sdk; wrong.aslr_size = 0;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong = sdk; wrong.aslr_base = 4096; wrong.aslr_size = address_limit;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong = sdk; wrong.aslr_size = 0x10000;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong = sdk; wrong.alias_base = config.heap_base;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong = sdk; wrong.alias_base = config.tls_base;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong = sdk; wrong.alias_base = 0x800000;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    wrong = sdk; wrong.alias_base++;
    CHECK(!oot_startup_context_create_sdk(image,&config,&wrong,&error));
    bad = config; bad.heap_base = 0x10000000; bad.heap_capacity = UINT64_C(66)*1024*1024;
    wrong = sdk; wrong.total_memory = UINT64_C(128)*1024*1024;
    CHECK(!oot_startup_context_create(image,&bad,&error));
    larger = oot_startup_context_create_sdk(image,&bad,&wrong,&error); CHECK(larger != NULL);
    CHECK(!info_check(larger,5,0xffff8001,0,1,bad.heap_capacity));
    oot_startup_context_destroy(larger);
    bad.heap_capacity = UINT64_C(3)*1024*1024*1024;
    CHECK(!oot_startup_context_create_sdk(image,&bad,&wrong,&error) && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    oot_startup_context_destroy(c); oot_startup_context_destroy(old); oot_runtime_close(image);
    return 0;
}

int main(int argc, char **argv)
{
    OotRuntimeImage *image;
    OotStartupContext *c, *clock, *rejected;
    OotStartupConfig config = {0x600000,512,0x200000,0x200000,0x1234,0}, bad;
    OotStartupServiceReport report;
    OotArm64State s, before, expected;
    OotGuestMemory *memory, view;
    OotGuestRegion region, *mutable_region;
    uint64_t value, ticks;
    uint32_t error;
    char message[192];
    unsigned i;
    CHECK(argc == 2);
    CHECK(fixture(argv[1],0));
    image = oot_runtime_open(argv[1],message,sizeof(message)); CHECK(image != NULL);
    c = oot_startup_context_create(image,&config,&error); CHECK(c != NULL && error == 0);
    CHECK(oot_startup_context_tls_pointer(c) == config.tls_base);
    CHECK(oot_startup_context_image(c) == image);
    CHECK(oot_startup_context_heap_size(c) == 0);
    CHECK(oot_startup_context_initial_state(c,0x10000,&s));
    CHECK(s.pc == 0x10000 && s.sp == 0x801000 && s.x[0] == 0 && s.x[1] == config.main_thread_handle && !s.nzcv);
    for (i = 2; i < 31; ++i) CHECK(!s.x[i]);
    before = s; CHECK(!oot_startup_context_initial_state(c,3,&s) && same(&s,&before));
    memory = oot_startup_context_memory(c); CHECK(memory != NULL && memory->count == 4);
    for (i = 0; i < 512; i += 8) CHECK(oot_memory_load(memory,config.tls_base+i,8,&value) && !value);
    CHECK(oot_memory_store(memory,config.tls_base,8,0xabc));
    CHECK(!oot_memory_load(memory,config.tls_base-1,1,&value));
    CHECK(!oot_memory_store(memory,config.tls_base+512,1,1));
    CHECK(!oot_memory_load(memory,config.heap_base,1,&value));
    s.x[1] = 4096; s.nzcv = 0xa0000000; before = s;
    CHECK(oot_startup_context_service(c,1,&s,&report) == OOT_STARTUP_SERVICE_FAULT && same(&s,&before));
    CHECK(!oot_startup_context_heap_size(c) && report.error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    s.x[1] = 0x21; s.x[2] = 0xffff8001; s.x[3] = 0; before = s;
    CHECK(oot_startup_context_service(c,0x29,&s,&report) == OOT_STARTUP_SERVICE_UNSUPPORTED && same(&s,&before));
    CHECK(oot_startup_context_service(c,6,&s,&report) == OOT_STARTUP_SERVICE_UNSUPPORTED && same(&s,&before));
    CHECK(oot_startup_context_service(c,0x1e,&s,&report) == OOT_STARTUP_SERVICE_UNSUPPORTED && same(&s,&before));
    s.x[0] = 0x12020; s.x[1] = config.heap_capacity; expected = s;
    expected.pc += 4; expected.x[0] = 0; expected.x[1] = config.heap_base;
    CHECK(oot_startup_context_service(c,1,&s,&report) == OOT_STARTUP_SERVICE_IMPLEMENTED && same(&s,&expected));
    CHECK(oot_startup_context_heap_size(c) == config.heap_capacity);
    CHECK(memory == oot_startup_context_memory(c) && memory->count == 5);
    CHECK(oot_memory_store(memory,config.heap_base+config.heap_capacity-8,8,0x11223344));
    CHECK(!oot_memory_store(memory,config.heap_base+config.heap_capacity-4,8,0x55667788));
    CHECK(oot_memory_load(memory,config.heap_base+config.heap_capacity-8,8,&value) && value == 0x11223344);
    s.x[1] = 0; CHECK(oot_startup_context_service(c,1,&s,&report) == 0);
    CHECK(!oot_memory_load(memory,config.heap_base,1,&value));
    s.x[1] = config.heap_capacity; CHECK(oot_startup_context_service(c,1,&s,&report) == 0);
    CHECK(oot_memory_load(memory,config.heap_base+config.heap_capacity-8,8,&value) && !value);
    s.x[0] = 0x12000; s.x[1] = 4; expected = s; expected.x[0] = 0; expected.pc += 4;
    CHECK(oot_startup_context_service(c,0x27,&s,&report) == 0 && same(&s,&expected));
    CHECK(report.text_size == 4 && report.text[0] == 'A' && !report.text[1] && report.text[2] == '\n' && (uint8_t)report.text[3] == 0xff && !report.text[4]);
    s.x[0] = 0x1203f; s.x[1] = 2; before = s;
    CHECK(oot_startup_context_service(c,0x27,&s,&report) == 2 && same(&s,&before) && !report.text_size);
    CHECK(oot_memory_load(memory,0x12000,4,&value) && value == UINT64_C(0xff0a0041));
    s.x[1] = OOT_STARTUP_DEBUG_LIMIT+1; before = s;
    CHECK(oot_startup_context_service(c,0x27,&s,&report) == 2 && same(&s,&before));
    s.x[0] = UINT64_MAX; s.x[1] = 2; before = s;
    CHECK(oot_startup_context_service(c,0x27,&s,&report) == 2 && same(&s,&before));
    view = *memory; memory->valid = 2; before = s;
    CHECK(!oot_startup_context_memory(c));
    CHECK(oot_startup_context_service(c,1,&s,&report) == 2 && same(&s,&before));
    *memory = view; mutable_region = (OotGuestRegion *)memory->regions; region = *mutable_region;
    mutable_region->permissions = 3; CHECK(!oot_startup_context_memory(c));
    *mutable_region = region; CHECK(oot_startup_context_memory(c) == memory);
    memory->count++; CHECK(!oot_startup_context_memory(c)); *memory = view;
    memory->regions = NULL; CHECK(!oot_startup_context_memory(c)); *memory = view;
    bad = config; bad.tls_base = 0x800000;
    rejected = oot_startup_context_create(image,&bad,&error); CHECK(!rejected && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
    bad = config; bad.heap_base = 0x600000;
    rejected = oot_startup_context_create(image,&bad,&error); CHECK(!rejected && error == OOT_STARTUP_CONTEXT_BAD_LAYOUT);
    bad = config; bad.tls_base = (UINT64_C(1)<<39)-4096; bad.tls_size = 65536;
    rejected = oot_startup_context_create(image,&bad,&error); CHECK(!rejected && error == OOT_STARTUP_CONTEXT_BAD_ARGUMENT);
    bad = config; bad.main_thread_handle = UINT64_MAX;
    CHECK(!oot_startup_context_create(image,&bad,&error));
    bad = config; bad.tick_frequency = UINT64_C(1)<<32;
    CHECK(!oot_startup_context_create(image,&bad,&error));
    config.tick_frequency = 19200000;
    clock = oot_startup_context_create(image,&config,&error); CHECK(clock != NULL);
    CHECK(oot_startup_context_initial_state(clock,0x10000,&s)); s.x[4] = 0xabcdef; s.nzcv = 0x50000000;
    expected = s; expected.pc += 4;
    CHECK(oot_startup_context_service(clock,0x1e,&s,&report) == 0);
    ticks = s.x[0]; expected.x[0] = ticks; CHECK(same(&s,&expected));
    CHECK(oot_startup_context_service(clock,0x1e,&s,&report) == 0 && s.x[0] >= ticks);
    oot_startup_context_destroy(clock);
    CHECK(oot_startup_context_retain(c)); oot_startup_context_destroy(c);
    oot_runtime_close(image); /* Context still owns the image and its regions. */
    config.tls_base = 0; config.main_thread_handle = 0;
    CHECK(oot_startup_context_initial_state(c,0x10000,&s) && s.x[1] == 0x1234);
    CHECK(oot_memory_load(oot_startup_context_memory(c),0x600000,8,&value) && value == 0xabc);
    CHECK(oot_startup_context_service(c,0xff,&s,NULL) == 1);
    oot_startup_context_destroy(c);
    CHECK(!record_checks());
    CHECK(!query_checks(argv[1]));
    CHECK(!sdk_checks(argv[1]));
    CHECK(!oot_startup_context_retain(NULL));
    CHECK(oot_startup_context_service(NULL,1,&s,&report) == 2);
    printf("Startup context self-test passed: %u checks.\n",checks);
    return 0;
}
