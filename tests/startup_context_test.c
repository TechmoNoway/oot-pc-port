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
    CHECK(!oot_startup_context_retain(NULL));
    CHECK(oot_startup_context_service(NULL,1,&s,&report) == 2);
    printf("Startup context self-test passed: %u checks.\n",checks);
    return 0;
}
