#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "guest_memory.h"
#include <string.h>

/* One total order per linked backend instance. Never call external code while
 * holding this nonrecursive lock. Caller-owned state/fault views stay separate.
 * All concurrent participants must use this backend, including ordinary stores. */
static SRWLOCK transfer_lock = SRWLOCK_INIT;

void oot_memory_clear_fault(OotGuestMemory *memory)
{
    AcquireSRWLockExclusive(&transfer_lock);
    if (memory != NULL)
        memory->fault = (OotMemoryFault){0};
    ReleaseSRWLockExclusive(&transfer_lock);
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

static int check_limit(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned access, unsigned limit)
{
    unsigned index;
    if (memory != NULL) memory->fault = (OotMemoryFault){0};
    if (memory == NULL || !memory->valid || size == 0 || size > limit)
        return fail(memory, address, size, access, OOT_MEMORY_CONFIGURATION, address);
    if ((uint64_t)(size - 1) > UINT64_MAX - address)
        return fail(memory, address, size, access, OOT_MEMORY_ADDRESS_WRAP, address);
    for (index = 0; index < size; ++index) {
        const OotGuestRegion *region = find_region(memory, address + index);
        if (region == NULL)
            return fail(memory, address, size, access, OOT_MEMORY_UNMAPPED, address + index);
        if ((region->permissions & access) != access)
            return fail(memory, address, size, access, OOT_MEMORY_PERMISSION, address + index);
    }
    return 1;
}

static int check(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned access)
{
    return check_limit(memory,address,size,access,16);
}

int oot_memory_probe(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned access)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = access == OOT_MEMORY_READ || access == OOT_MEMORY_WRITE ? check(memory,address,size,access) :
        fail(memory,address,size,access,OOT_MEMORY_CONFIGURATION,address);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

static uint64_t read_bytes(OotGuestMemory *memory, uint64_t address, unsigned size)
{
    unsigned index;
    uint64_t result = 0;
    for (index = 0; index < size; ++index) {
        const OotGuestRegion *region = find_region(memory, address + index);
        result |= (uint64_t)region->data[(size_t)(address + index - region->base)] << (index * 8);
    }
    return result;
}

static void write_bytes(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t value)
{
    unsigned index;
    for (index = 0; index < size; ++index) {
        const OotGuestRegion *region = find_region(memory, address + index);
        region->data[(size_t)(address + index - region->base)] = (uint8_t)(value >> (index * 8));
    }
}

static int load(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t *value)
{
    if (value == NULL || (size != 1 && size != 2 && size != 4 && size != 8))
        return fail(memory, address, size, OOT_MEMORY_READ, OOT_MEMORY_CONFIGURATION, address);
    if (!check(memory, address, size, OOT_MEMORY_READ))
        return 0;
    *value = read_bytes(memory, address, size);
    return 1;
}

static int store(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t value)
{
    if (size != 1 && size != 2 && size != 4 && size != 8)
        return fail(memory, address, size, OOT_MEMORY_WRITE, OOT_MEMORY_CONFIGURATION, address);
    if (!check(memory, address, size, OOT_MEMORY_WRITE))
        return 0;
    write_bytes(memory, address, size, value);
    return 1;
}

static int load_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size,
                         uint64_t *first, uint64_t *second)
{
    uint64_t first_value, second_value;
    if ((element_size != 4 && element_size != 8) || first == NULL || second == NULL || first == second)
        return fail(memory, address, 0, OOT_MEMORY_READ, OOT_MEMORY_CONFIGURATION, address);
    if (!check(memory, address, element_size * 2, OOT_MEMORY_READ))
        return 0;
    first_value = read_bytes(memory, address, element_size);
    second_value = read_bytes(memory, address + element_size, element_size);
    *first = first_value;
    *second = second_value;
    return 1;
}

static int store_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size,
                          uint64_t first, uint64_t second)
{
    if (element_size != 4 && element_size != 8)
        return fail(memory, address, 0, OOT_MEMORY_WRITE, OOT_MEMORY_CONFIGURATION, address);
    if (!check(memory, address, element_size * 2, OOT_MEMORY_WRITE))
        return 0;
    write_bytes(memory, address, element_size, first);
    write_bytes(memory, address + element_size, element_size, second);
    return 1;
}

int oot_memory_load(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t *value)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = load(memory, address, size, value);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_store(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t value)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = store(memory, address, size, value);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_load_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size, uint64_t *first, uint64_t *second)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = load_pair(memory, address, element_size, first, second);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_store_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size, uint64_t first, uint64_t second)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = store_pair(memory, address, element_size, first, second);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_load_rcpc(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned sp_base, uint64_t *value)
{
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    if (!memory || !memory->valid || !value || sp_base > 1 || (size != 1 && size != 2 && size != 4 && size != 8))
        ok = fail(memory, address, size, OOT_MEMORY_READ, OOT_MEMORY_CONFIGURATION, address);
    else if (address % size || (sp_base && address % 16))
        ok = fail(memory, address, size, OOT_MEMORY_READ, OOT_MEMORY_ALIGNMENT, address);
    else ok = load(memory, address, size, value);
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_compare_exchange(OotGuestMemory *memory, uint64_t address,
    unsigned size, unsigned sp_base, uint64_t expected, uint64_t desired, uint64_t *observed)
{
    int ok;
    uint64_t value, mask = size == 4 ? UINT64_C(0xffffffff) : UINT64_MAX;
    const unsigned access = OOT_MEMORY_READ | OOT_MEMORY_WRITE;
    AcquireSRWLockExclusive(&transfer_lock);
    if (!memory || !memory->valid || !observed || sp_base > 1 || (size != 4 && size != 8))
        ok = fail(memory,address,size,access,OOT_MEMORY_CONFIGURATION,address);
    else if (address % size || (sp_base && address % 16))
        ok = fail(memory,address,size,access,OOT_MEMORY_ALIGNMENT,address);
    else {
        ok = check(memory,address,size,access);
        if (ok) {
            value = read_bytes(memory,address,size);
            if (value == (expected & mask)) write_bytes(memory,address,size,desired);
            *observed = value;
        }
    }
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_load_record(OotGuestMemory *memory, uint64_t address, uint8_t *bytes, unsigned size)
{
    uint8_t captured[OOT_MEMORY_RECORD_LIMIT];
    unsigned i;
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = bytes ? check_limit(memory,address,size,OOT_MEMORY_READ,OOT_MEMORY_RECORD_LIMIT) :
        fail(memory,address,size,OOT_MEMORY_READ,OOT_MEMORY_CONFIGURATION,address);
    if (ok) {
        for (i = 0; i < size; ++i) {
            const OotGuestRegion *r = find_region(memory,address+i);
            captured[i] = r->data[(size_t)(address+i-r->base)];
        }
        memcpy(bytes,captured,size);
    }
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}

int oot_memory_store_record(OotGuestMemory *memory, uint64_t address, const uint8_t *bytes, unsigned size)
{
    uint8_t captured[OOT_MEMORY_RECORD_LIMIT];
    unsigned i;
    int ok;
    AcquireSRWLockExclusive(&transfer_lock);
    ok = bytes ? check_limit(memory,address,size,OOT_MEMORY_WRITE,OOT_MEMORY_RECORD_LIMIT) :
        fail(memory,address,size,OOT_MEMORY_WRITE,OOT_MEMORY_CONFIGURATION,address);
    if (ok) {
        memcpy(captured,bytes,size);
        for (i = 0; i < size; ++i) {
            const OotGuestRegion *r = find_region(memory,address+i);
            r->data[(size_t)(address+i-r->base)] = captured[i];
        }
    }
    ReleaseSRWLockExclusive(&transfer_lock);
    return ok;
}
