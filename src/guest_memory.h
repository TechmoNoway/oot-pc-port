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
/* Application byte/halfword CAS uses the same transaction and lock. This
 * separate entry accepts only size1/2; the old API still accepts only size4/8.
 * Return zero-extended old bytes and compare/store only low source bits. All
 * alignment, complete RW, fault and private-output preconditions above apply. */
OOT_MEMORY_API int oot_memory_compare_exchange_narrow(OotGuestMemory *memory,uint64_t address,
    unsigned size,unsigned sp_base,uint64_t expected,uint64_t desired,uint64_t *observed);
/* Initialization-only LDADD W/X backend: one naturally aligned complete
 * READ|WRITE transfer under the same lock as every other backend access.
 * Return the old zero-extended value and add modulo the selected width.
 * Failure preserves output and all bytes. The stronger serialized Normal-
 * memory order covers admitted relaxed/acquire-release variants, without a
 * claim of exhaustive weak-memory equivalence. observed must be private and
 * nonaliasing with backing/metadata; SP bases require 16-byte alignment. */
OOT_MEMORY_API int oot_memory_fetch_add(OotGuestMemory *memory, uint64_t address,
    unsigned size, unsigned sp_base, uint64_t addend, uint64_t *observed);
/* Same W/X preflight, serialization and fault isolation, with old|operand. */
OOT_MEMORY_API int oot_memory_fetch_or(OotGuestMemory *memory,uint64_t address,
    unsigned size,unsigned sp_base,uint64_t operand,uint64_t *observed);
OOT_MEMORY_API int oot_memory_fetch_clear(OotGuestMemory *memory,uint64_t address,
    unsigned size,unsigned sp_base,uint64_t operand,uint64_t *observed);
/* Separate naturally aligned STLR B/H/W/X backend. No read permission is
 * needed; the complete little-endian write is serialized with all transfers.
 * All bytes remain unchanged on faults. Earlier scalar limits are unchanged. */
OOT_MEMORY_API int oot_memory_store_release(OotGuestMemory *memory, uint64_t address,
    unsigned size, unsigned sp_base, uint64_t value);
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
#define OOT_MEMORY_SERVICE_WRITE_LIMIT (8u*1024u*1024u)
#define OOT_MEMORY_SERVICE_PATH_LIMIT 4096u
typedef struct OotServiceWrite {
    uint64_t address;
    const uint8_t *bytes;
    uint32_t size;
} OotServiceWrite;
/* Separate application-service transfers, never instruction/probe grants.
 * At most two disjoint guest outputs, each <=8 MiB, total <=8 MiB+64.
 * Whole-range preflight precedes every write under the common transfer lock.
 * Descriptor/data buffers must be live, immutable, private and nonaliasing with
 * guest backing or memory metadata. A failure preserves every guest byte. */
OOT_MEMORY_API int oot_memory_store_service(OotGuestMemory *memory,const OotServiceWrite *writes,unsigned count);
/* Snapshot a NUL-terminated path under the same lock; capacity includes NUL.
 * Maximum capacity is 4097. Failure preserves both private native outputs. */
OOT_MEMORY_API int oot_memory_load_service_path(OotGuestMemory *memory,uint64_t address,
    char *bytes,unsigned capacity,unsigned *length);
/* Native-SDK named DMB options 1/2/3,5/6/7,9/10/11,13/14/15 participate in
 * the same backend transfer lock as every scalar/pair/record/CAS operation.
 * This Normal-memory total order is stronger than the selected Arm barriers;
 * it does not model device/MMIO effects, DSB completion or every weak-memory
 * outcome. No guest bytes or mapping metadata change. Failure records a
 * zero-sized configuration fault; success clears the caller's fault view. */
OOT_MEMORY_API int oot_memory_barrier(OotGuestMemory *memory, uint32_t option);

#endif
