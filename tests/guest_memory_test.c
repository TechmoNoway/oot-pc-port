#include "guest_memory.h"
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "memory check failed at line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)

int main(void)
{
    uint8_t first[16] = {0}, second[16] = {0}, snapshot[16];
    uint64_t value = 0;
    OotGuestMemory memory;
    OotGuestRegion adjacent[] = {
        {UINT64_C(0x100000000), sizeof(first), first, OOT_MEMORY_READ | OOT_MEMORY_WRITE},
        {UINT64_C(0x100000010), sizeof(second), second, OOT_MEMORY_READ | OOT_MEMORY_WRITE}
    };
    OotGuestRegion invalid[2];
    OotGuestRegion top = {UINT64_MAX - 15, sizeof(first), first, 3};
    unsigned width;

    CHECK(oot_memory_init(&memory, adjacent, 2));
    for (width = 1; width <= 8; width *= 2) {
        CHECK(oot_memory_store(&memory, adjacent[0].base + 1, width, UINT64_C(0xfedcba9876543210)));
        CHECK(oot_memory_load(&memory, adjacent[0].base + 1, width, &value));
        CHECK(value == (UINT64_C(0xfedcba9876543210) & (UINT64_MAX >> ((8 - width) * 8))));
    }
    CHECK(first[1] == 0x10 && first[8] == 0xfe);
    /* Cross distinct native allocations through adjacent guest regions. */
    CHECK(oot_memory_store(&memory, adjacent[0].base + 13, 8, UINT64_C(0x8070605040302010)));
    CHECK(first[13] == 0x10 && second[0] == 0x40 && second[4] == 0x80);
    CHECK(oot_memory_load(&memory, adjacent[0].base + 13, 8, &value));
    CHECK(value == UINT64_C(0x8070605040302010));

    /* Permissions and a guard gap must fail before touching any backing bytes. */
    adjacent[1].permissions = OOT_MEMORY_READ;
    CHECK(oot_memory_init(&memory, adjacent, 2));
    memcpy(snapshot, first, sizeof(first));
    CHECK(!oot_memory_store(&memory, adjacent[0].base + 13, 8, 0));
    CHECK(memory.fault.reason == OOT_MEMORY_PERMISSION && memory.fault.access == OOT_MEMORY_WRITE);
    CHECK(memory.fault.address == adjacent[0].base + 13 && memory.fault.failing_address == adjacent[1].base);
    CHECK(memory.fault.size == 8 && memcmp(snapshot, first, sizeof(first)) == 0);
    CHECK(second[0] == 0x40);
    adjacent[1].base += 1;
    CHECK(oot_memory_init(&memory, adjacent, 2));
    value = UINT64_MAX;
    CHECK(!oot_memory_load(&memory, adjacent[0].base + 13, 8, &value));
    CHECK(value == UINT64_MAX && memory.fault.reason == OOT_MEMORY_UNMAPPED);
    CHECK(memory.fault.failing_address == adjacent[0].base + 16);
    CHECK(!oot_memory_store(&memory, adjacent[0].base + 13, 8, 0));
    CHECK(memcmp(snapshot, first, sizeof(first)) == 0);
    CHECK(!oot_memory_load(&memory, adjacent[0].base - 1, 1, &value));
    CHECK(memory.fault.reason == OOT_MEMORY_UNMAPPED);
    adjacent[1].permissions = OOT_MEMORY_WRITE;
    CHECK(oot_memory_init(&memory, adjacent, 2));
    CHECK(!oot_memory_load(&memory, adjacent[1].base, 1, &value));
    CHECK(memory.fault.reason == OOT_MEMORY_PERMISSION && memory.fault.access == OOT_MEMORY_READ);
    CHECK(oot_memory_store(&memory, adjacent[1].base, 1, 0xaa));
    CHECK(memory.fault.reason == OOT_MEMORY_OK);
    CHECK(second[0] == 0xaa);

    /* A region may contain UINT64_MAX; an access may not wrap to address zero. */
    CHECK(oot_memory_init(&memory, &top, 1));
    CHECK(oot_memory_store(&memory, UINT64_MAX, 1, 0x80));
    CHECK(oot_memory_load(&memory, UINT64_MAX, 1, &value) && value == 0x80);
    memcpy(snapshot, first, sizeof(first));
    CHECK(!oot_memory_store(&memory, UINT64_MAX - 3, 8, 0));
    CHECK(memory.fault.reason == OOT_MEMORY_ADDRESS_WRAP);
    CHECK(memcmp(snapshot, first, sizeof(first)) == 0);
    CHECK(!oot_memory_load(&memory, UINT64_MAX, 2, &value));
    CHECK(memory.fault.reason == OOT_MEMORY_ADDRESS_WRAP && value == 0x80);

    /* Reject malformed tables, and do not retain a previously usable mapping. */
    memcpy(invalid, adjacent, sizeof(invalid));
    invalid[1].base = invalid[0].base + 15;
    CHECK(!oot_memory_init(&memory, invalid, 2));
    CHECK(!memory.valid && memory.fault.reason == OOT_MEMORY_CONFIGURATION);
    CHECK(!oot_memory_load(&memory, invalid[0].base, 1, &value));
    CHECK(memory.fault.reason == OOT_MEMORY_CONFIGURATION);
    invalid[1] = invalid[0]; invalid[0] = adjacent[1];
    CHECK(!oot_memory_init(&memory, invalid, 2));
    invalid[0] = top; invalid[0].size = 17;
    CHECK(!oot_memory_init(&memory, invalid, 1));
    invalid[0] = top; invalid[0].size = 0;
    CHECK(!oot_memory_init(&memory, invalid, 1));
    invalid[0] = top; invalid[0].permissions = 4;
    CHECK(!oot_memory_init(&memory, invalid, 1));
    invalid[0] = top; invalid[0].data = NULL;
    CHECK(!oot_memory_init(&memory, invalid, 1));
    CHECK(!oot_memory_init(&memory, NULL, 1));
    CHECK(!oot_memory_init(&memory, adjacent, 4097));
    CHECK(oot_memory_init(&memory, NULL, 0));
    CHECK(!oot_memory_load(&memory, 0, 1, &value));
    CHECK(memory.fault.reason == OOT_MEMORY_UNMAPPED);
    CHECK(!oot_memory_load(&memory, 0, 3, &value));
    CHECK(memory.fault.reason == OOT_MEMORY_CONFIGURATION);
    CHECK(!oot_memory_load(&memory, 0, 1, NULL));
    CHECK(!oot_memory_load(NULL, 0, 1, &value));
    CHECK(!oot_memory_store(NULL, 0, 1, 0));
    CHECK(!oot_memory_init(NULL, NULL, 0));
    oot_memory_clear_fault(NULL);
    puts("Guest memory self-test passed.");
    return 0;
}
