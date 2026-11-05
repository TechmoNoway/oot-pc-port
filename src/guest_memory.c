#include "guest_memory.h"

void oot_memory_clear_fault(OotGuestMemory *memory)
{
    if (memory != NULL)
        memory->fault = (OotMemoryFault){0};
}

static int fail(OotGuestMemory *memory, uint64_t address, unsigned size,
                unsigned access, unsigned reason, uint64_t failing_address)
{
    if (memory != NULL)
        memory->fault = (OotMemoryFault){address, failing_address, size, access, reason};
    return 0;
}

int oot_memory_init(OotGuestMemory *memory, const OotGuestRegion *regions, size_t count)
{
    size_t index;
    if (memory == NULL)
        return 0;
    *memory = (OotGuestMemory){0};
    if (count > 4096 || (count != 0 && regions == NULL))
        return fail(memory, 0, 0, 0, OOT_MEMORY_CONFIGURATION, 0);
    for (index = 0; index < count; ++index) {
        const OotGuestRegion *region = &regions[index];
        if (region->size == 0 || region->size > SIZE_MAX || region->data == NULL ||
            region->size - 1 > UINT64_MAX - region->base || (region->permissions & ~3u) != 0)
            return fail(memory, region->base, 0, 0, OOT_MEMORY_CONFIGURATION, region->base);
        if (index != 0) {
            const OotGuestRegion *previous = &regions[index - 1];
            if (region->base <= previous->base || region->base - previous->base < previous->size)
                return fail(memory, region->base, 0, 0, OOT_MEMORY_CONFIGURATION, region->base);
        }
    }
    memory->regions = regions;
    memory->count = count;
    memory->valid = 1;
    return 1;
}

static const OotGuestRegion *find_region(const OotGuestMemory *memory, uint64_t address)
{
    size_t low = 0, high = memory->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (memory->regions[middle].base <= address)
            low = middle + 1;
        else
            high = middle;
    }
    if (low != 0) {
        const OotGuestRegion *region = &memory->regions[low - 1];
        if (address - region->base < region->size)
            return region;
    }
    return NULL;
}

static int check(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned access)
{
    unsigned index;
    oot_memory_clear_fault(memory);
    if (memory == NULL || !memory->valid || (size != 1 && size != 2 && size != 4 && size != 8))
        return fail(memory, address, size, access, OOT_MEMORY_CONFIGURATION, address);
    if ((uint64_t)(size - 1) > UINT64_MAX - address)
        return fail(memory, address, size, access, OOT_MEMORY_ADDRESS_WRAP, address);
    for (index = 0; index < size; ++index) {
        const OotGuestRegion *region = find_region(memory, address + index);
        if (region == NULL)
            return fail(memory, address, size, access, OOT_MEMORY_UNMAPPED, address + index);
        if ((region->permissions & access) == 0)
            return fail(memory, address, size, access, OOT_MEMORY_PERMISSION, address + index);
    }
    return 1;
}

int oot_memory_load(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t *value)
{
    unsigned index;
    uint64_t result = 0;
    if (value == NULL)
        return fail(memory, address, size, OOT_MEMORY_READ, OOT_MEMORY_CONFIGURATION, address);
    if (!check(memory, address, size, OOT_MEMORY_READ))
        return 0;
    for (index = 0; index < size; ++index) {
        const OotGuestRegion *region = find_region(memory, address + index);
        result |= (uint64_t)region->data[(size_t)(address + index - region->base)] << (index * 8);
    }
    *value = result;
    return 1;
}

int oot_memory_store(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t value)
{
    unsigned index;
    if (!check(memory, address, size, OOT_MEMORY_WRITE))
        return 0;
    for (index = 0; index < size; ++index) {
        const OotGuestRegion *region = find_region(memory, address + index);
        region->data[(size_t)(address + index - region->base)] = (uint8_t)(value >> (index * 8));
    }
    return 1;
}
