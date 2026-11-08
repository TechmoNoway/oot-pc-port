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
    OOT_MEMORY_CONFIGURATION = 4,
    OOT_MEMORY_ALIGNMENT = 5
};

/* Caller-owned, sorted, disjoint guest regions backed by live native buffers.
 * The table and buffers must outlive the memory object. Table metadata is immutable.
 * Permissions apply to data access only; instruction dispatch is separate.
 * A view/fault record has one owner thread. Concurrent views may share backing
 * only through APIs in the SAME linked backend instance. Region tables and
 * buffer lifetimes must be immutable while in use; no concurrent raw byte access.
 * Backend transfers are serialized, including scalar/pair loads and stores. */
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
/* Nonmutating whole-transfer preflight, 1-16 bytes, one data access kind.
 * This is not a reservation; the transfer checks again at commit. */
OOT_MEMORY_API int oot_memory_probe(OotGuestMemory *memory, uint64_t address, unsigned size, unsigned access);
/* Little-endian scalar transfers of 1, 2, 4, or 8 bytes. Unaligned is allowed.
 * Every byte is checked before mutation; failures leave output/backing unchanged.
 * This deterministic fault policy is not a model of partial hardware stores. */
OOT_MEMORY_API int oot_memory_load(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t *value);
OOT_MEMORY_API int oot_memory_store(OotGuestMemory *memory, uint64_t address, unsigned size, uint64_t value);
/* No-offset LDAPR/B/H subset: aligned Normal-memory accesses, no tagging/MMIO.
 * Whole access plus ordering is serialized with ALL other backend transfers.
 * This conservative total order is stronger than RCpc; it does not model every
 * allowed weak-memory outcome. Natural alignment is a supported-domain rule;
 * SP bases additionally require 16-byte alignment. Rejection preserves output.
 * No guest SCTLR/alignment-control registers or guest scheduling ABI are implied. */
OOT_MEMORY_API int oot_memory_load_rcpc(OotGuestMemory *memory, uint64_t address, unsigned size,
                                      unsigned sp_base, uint64_t *value);
/* Startup SDK CAS32/64 uses the same serialized Normal-memory order as every
 * other backend transfer. Require natural alignment (and SP16 for an SP base)
 * and complete READ|WRITE permission even when comparison fails. A successful
 * call returns the original little-endian value, zero-extended for CAS32, and
 * stores the low desired bits only when the low expected bits match. A rejected
 * call changes neither output nor backing. The native output must be private,
 * stable and nonaliasing with guest backing/metadata. This conservative total
 * order does not model every permitted weak-memory outcome or guest threads. */
OOT_MEMORY_API int oot_memory_compare_exchange(OotGuestMemory *memory, uint64_t address,
    unsigned size, unsigned sp_base, uint64_t expected, uint64_t desired, uint64_t *observed);
/* Paired 4/8-byte elements use whole-pair preflight; outputs must be distinct.
 * No element, register output, or writeback is committed on a rejected pair. */
OOT_MEMORY_API int oot_memory_load_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size,
                                       uint64_t *first, uint64_t *second);
OOT_MEMORY_API int oot_memory_store_pair(OotGuestMemory *memory, uint64_t address, unsigned element_size,
                                        uint64_t first, uint64_t second);

#define OOT_MEMORY_RECORD_LIMIT 64u
/* Separate bounded service-record transfers; scalar/pair/probe limits remain
 * unchanged. The complete 1-64-byte record shares the same backend lock and
 * whole-transfer preflight. Failure preserves every destination byte, including
 * a native load output. Native buffers must be private, stable and nonaliasing
 * with guest backing/metadata for the call. */
OOT_MEMORY_API int oot_memory_load_record(OotGuestMemory *memory, uint64_t address,
    uint8_t *bytes, unsigned size);
OOT_MEMORY_API int oot_memory_store_record(OotGuestMemory *memory, uint64_t address,
    const uint8_t *bytes, unsigned size);

#define OOT_MEMORY_NATIVE_INPUT_LIMIT 4096u
/* A separate read-only native-SDK input operand. Capture the entire bounded
 * record/payload under the same transfer lock. Failure preserves all output;
 * native output must be private/nonaliasing. Earlier transfer limits remain. */
OOT_MEMORY_API int oot_memory_load_native_input(OotGuestMemory *memory, uint64_t address,
    uint8_t *bytes, unsigned size);
/* Native-SDK named DMB options 1/2/3,5/6/7,9/10/11,13/14/15 participate in
 * the same backend transfer lock as every scalar/pair/record/CAS operation.
 * This Normal-memory total order is stronger than the selected Arm barriers;
 * it does not model device/MMIO effects, DSB completion or every weak-memory
 * outcome. No guest bytes or mapping metadata change. Failure records a
 * zero-sized configuration fault; success clears the caller's fault view. */
OOT_MEMORY_API int oot_memory_barrier(OotGuestMemory *memory, uint32_t option);

#endif
