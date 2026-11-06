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
    CHECK(oot_memory_probe(&memory, adjacent[0].base + 8, 16, OOT_MEMORY_WRITE));
    CHECK(first[8] == 0 && second[0] == 0);
    CHECK(!oot_memory_probe(&memory, adjacent[0].base, 0, OOT_MEMORY_WRITE));
    CHECK(memory.fault.reason == OOT_MEMORY_CONFIGURATION);
    CHECK(!oot_memory_probe(&memory, adjacent[0].base, 17, OOT_MEMORY_WRITE));
    CHECK(!oot_memory_probe(&memory, adjacent[0].base, 8, 3));
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
    CHECK(!oot_memory_probe(&memory, adjacent[0].base + 13, 8, OOT_MEMORY_WRITE));
    CHECK(memory.fault.reason == OOT_MEMORY_PERMISSION && memory.fault.failing_address == adjacent[1].base);
    CHECK(memcmp(snapshot, first, sizeof(first)) == 0 && second[0] == 0x40);
    CHECK(oot_memory_probe(&memory, adjacent[0].base + 13, 8, OOT_MEMORY_READ));
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
    CHECK(oot_memory_probe(&memory, adjacent[1].base, 8, OOT_MEMORY_WRITE));
    CHECK(!oot_memory_probe(&memory, adjacent[1].base, 8, OOT_MEMORY_READ));
    CHECK(second[0] == 0xaa);

    /* A region may contain UINT64_MAX; an access may not wrap to address zero. */
    CHECK(oot_memory_init(&memory, &top, 1));
    CHECK(oot_memory_store(&memory, UINT64_MAX, 1, 0x80));
    CHECK(oot_memory_load(&memory, UINT64_MAX, 1, &value) && value == 0x80);
    memcpy(snapshot, first, sizeof(first));
    CHECK(!oot_memory_probe(&memory, UINT64_MAX - 3, 8, OOT_MEMORY_WRITE));
    CHECK(memory.fault.reason == OOT_MEMORY_ADDRESS_WRAP && memcmp(snapshot, first, sizeof(first)) == 0);
    CHECK(!oot_memory_store(&memory, UINT64_MAX - 3, 8, 0));
    CHECK(memory.fault.reason == OOT_MEMORY_ADDRESS_WRAP);
    CHECK(memcmp(snapshot, first, sizeof(first)) == 0);
    CHECK(!oot_memory_load(&memory, UINT64_MAX, 2, &value));
    CHECK(memory.fault.reason == OOT_MEMORY_ADDRESS_WRAP && value == 0x80);

    {
        uint8_t a[8] = {0}, b[8] = {0}, saved[8];
        uint64_t one = 0, two = 0;
        OotGuestRegion pair_regions[] = {{0x1000, 8, a, 3}, {0x1008, 8, b, 3}};
        CHECK(oot_memory_init(&memory, pair_regions, 2));
        CHECK(oot_memory_store_pair(&memory, 0x1000, 8, UINT64_MAX, UINT64_C(0x0123456789abcdef)));
        CHECK(oot_memory_load_pair(&memory, 0x1000, 8, &one, &two));
        CHECK(one == UINT64_MAX && two == UINT64_C(0x0123456789abcdef) && b[0] == 0xef && b[7] == 0x01);
        CHECK(oot_memory_store_pair(&memory, 0x1000, 4, UINT64_MAX, UINT64_C(0x1234567887654321)));
        CHECK(oot_memory_load_pair(&memory, 0x1000, 4, &one, &two));
        CHECK(one == UINT64_C(0xffffffff) && two == UINT64_C(0x87654321));
        memcpy(saved, a, sizeof(a));
        pair_regions[1].permissions = 1;
        CHECK(oot_memory_init(&memory, pair_regions, 2));
        CHECK(!oot_memory_store_pair(&memory, 0x1000, 8, 0, 0));
        CHECK(memory.fault.size == 16 && memory.fault.failing_address == 0x1008 && memcmp(saved, a, 8) == 0);
        CHECK(oot_memory_init(&memory, pair_regions, 1));
        one = 0x1234; two = 0x5678;
        CHECK(!oot_memory_load_pair(&memory, 0x1000, 8, &one, &two));
        CHECK(one == 0x1234 && two == 0x5678 && memory.fault.reason == OOT_MEMORY_UNMAPPED);
        CHECK(!oot_memory_load_pair(&memory, 0x1000, 8, &one, &one));
        CHECK(!oot_memory_load_pair(&memory, 0x1000, 8, NULL, &two));
        CHECK(!oot_memory_store_pair(&memory, 0x1000, 1, 0, 0));
        CHECK(!oot_memory_load(&memory, 0x1000, 16, &one));
    }

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
