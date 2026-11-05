#ifndef OOT_GUEST_MEMORY_H
#define OOT_GUEST_MEMORY_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(OOT_MEMORY_SHARED_EXPORTS)
#define OOT_MEMORY_API __declspec(dllexport)
#else
#define OOT_MEMORY_API
#endif

enum OotMemoryAccess { OOT_MEMORY_READ = 1, OOT_MEMORY_WRITE = 2 };
enum OotMemoryReason {
    OOT_MEMORY_OK = 0,
    OOT_MEMORY_UNMAPPED = 1,
    OOT_MEMORY_PERMISSION = 2,
    OOT_MEMORY_ADDRESS_WRAP = 3,
    OOT_MEMORY_CONFIGURATION = 4
};

/* Caller-owned, sorted, disjoint guest regions backed by live native buffers.
 * The table and buffers must outlive the memory object. Table metadata is immutable.
 * Permissions apply to data access only; instruction dispatch is separate. */
typedef struct OotGuestRegion {
    uint64_t base;
    uint64_t size;
    uint8_t *data;
    uint32_t permissions;
} OotGuestRegion;

typedef struct OotMemoryFault {
    uint64_t address;         /* Start of the requested transfer. */
    uint64_t failing_address; /* First rejected byte, or address for wrap/config. */
    uint32_t size;
    uint32_t access;
    uint32_t reason;
} OotMemoryFault;

typedef struct OotGuestMemory {
    const OotGuestRegion *regions;
    size_t count;
    OotMemoryFault fault;
    uint32_t valid;
} OotGuestMemory;

OOT_MEMORY_API int oot_memory_init(OotGuestMemory *memory, const OotGuestRegion *regions, size_t count);
OOT_MEMORY_API void oot_memory_clear_fault(OotGuestMemory *memory);
/* Little-endian scalar transfers of 1, 2, 4, or 8 bytes. Unaligned is allowed.
 * Every byte is checked before mutation; failures leave output/backing unchanged.
 * This deterministic fault policy is not a model of partial hardware stores. */
OOT_MEMORY_API int oot_memory_load(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t *value);
OOT_MEMORY_API int oot_memory_store(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t value);
/* Paired 4/8-byte elements use whole-pair preflight; outputs must be distinct.
 * No element, register output, or writeback is committed on a rejected pair. */
OOT_MEMORY_API int oot_memory_load_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size,
                                       uint64_t *first, uint64_t *second);
OOT_MEMORY_API int oot_memory_store_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size,
                                        uint64_t first, uint64_t second);

#endif
