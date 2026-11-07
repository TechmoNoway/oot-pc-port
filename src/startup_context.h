#ifndef OOT_STARTUP_CONTEXT_H
#define OOT_STARTUP_CONTEXT_H

#include "arm64_lift.h"
#include "runtime_image.h"

#define OOT_STARTUP_CONTEXT_VERSION 1u
#define OOT_STARTUP_DEBUG_LIMIT 4096u
#define OOT_STARTUP_HEAP_ALIGNMENT UINT64_C(0x200000)
#define OOT_SDK_CONTEXT_VERSION 1u
#define OOT_SDK_EXPLICIT_ENTROPY 1u
#define OOT_SDK_PROCESS_INFO 2u
#define OOT_SDK_NO_REMOTE_ARENA 4u
#define OOT_SDK_MAIN_THREAD 8u
#define OOT_SDK_NO_ALIAS_EXTRA 16u
#define OOT_SDK_PAGE_ALLOCATION 32u
#define OOT_SDK_OBSERVED_MAIN_TLR 64u

typedef struct OotStartupContext OotStartupContext;

/* Explicit experimental NSO process model, not a recovered Switch 2 ABI.
 * The image supplies a guarded stack. TLS is a zeroed private buffer without
 * invented SDK fields. Heap capacity is reserved but initially unmapped.
 * tick_frequency=0 leaves the counter service unsupported. */
typedef struct OotStartupConfig {
    uint64_t tls_base, tls_size, heap_base, heap_capacity, main_thread_handle;
    uint64_t tick_frequency;
} OotStartupConfig;

/* Separate opt-in SDK process model. Entropy is private process state: flags=0
 * requests fresh host entropy; an explicit four-word input is for synthetic or
 * reproducible private execution. Never log or embed a real entropy input.
 * PROCESS_INFO enables only declared/supported process-query fields below.
 * GetInfo 11 accepts handle 0 and entropy indices 0-3. PROCESS_INFO also
 * permits debugger query 8 at handle/subtype 0 and IDs 0-7,12-18,21-23 at
 * the current-process pseudo-handle and subtype 0. Used memory is actual
 * image/TLS backing plus mapped heap; IDs 16/17 describe no resource arena.
 * NO_REMOTE_ARENA requires PROCESS_INFO and declares that no remote arena is
 * backed: IDs 29-32 return zero at the same current-process/subtype-0 domain.
 * This option grants no remote allocation or mapping service.
 * MAIN_THREAD requires PROCESS_INFO and declares one fixed thread identity,
 * priority and core. Only read-only thread queries are implemented.
 * NO_ALIAS_EXTRA requires PROCESS_INFO: GetInfo 28 reports zero extra alias
 * reservation at the current-process/subtype-0 domain.
 * PAGE_ALLOCATION requires PROCESS_INFO and a complete 4 KiB mapping model;
 * GetInfo 33 reports that owned granule for current-process/subtype 0 only.
 * OBSERVED_MAIN_TLR requires MAIN_THREAD/PROCESS_INFO and initializes only
 * the observed four-byte logical-handle field at TLS+0x110. This lock-owner
 * identity is restricted to 1..0x3fffffff, leaving the waiter bit unoccupied.
 * No SDK thread object or unproved TLS fields are manufactured. */
typedef struct OotSdkConfig {
    uint32_t version, flags;
    uint64_t entropy[4];
    uint64_t core_mask, priority_mask;
    uint64_t aslr_base, aslr_size, alias_base, alias_size;
    uint64_t program_id, is_application, total_memory;
    uint64_t main_thread_id, main_thread_priority, main_thread_core;
} OotSdkConfig;

enum OotStartupContextError {
    OOT_STARTUP_CONTEXT_OK = 0,
    OOT_STARTUP_CONTEXT_BAD_ARGUMENT = 1,
    OOT_STARTUP_CONTEXT_ALLOCATION = 2,
    OOT_STARTUP_CONTEXT_BAD_IMAGE = 3,
    OOT_STARTUP_CONTEXT_BAD_LAYOUT = 4,
    OOT_STARTUP_CONTEXT_BAD_MEMORY = 5,
    OOT_STARTUP_CONTEXT_BAD_CLOCK = 6,
    OOT_STARTUP_CONTEXT_BAD_ENTROPY = 7
};

enum OotStartupServiceStatus {
    OOT_STARTUP_SERVICE_IMPLEMENTED = 0,
    OOT_STARTUP_SERVICE_UNSUPPORTED = 1,
    OOT_STARTUP_SERVICE_FAULT = 2
};

typedef struct OotStartupServiceReport {
    uint32_t status, id, error, text_size;
    uint64_t result;
    char text[OOT_STARTUP_DEBUG_LIMIT + 1];
} OotStartupServiceReport;

/* Single owner thread; copies config/region metadata and retains its image.
 * All transfers must use this backend instance. Borrowed views and pointers
 * expire at final destroy. No concurrent service or metadata access is allowed. */
OOT_MEMORY_API OotStartupContext *oot_startup_context_create(OotRuntimeImage *image,
    const OotStartupConfig *config, uint32_t *error);
OOT_MEMORY_API OotStartupContext *oot_startup_context_create_sdk(OotRuntimeImage *image,
    const OotStartupConfig *config, const OotSdkConfig *sdk, uint32_t *error);
OOT_MEMORY_API int oot_startup_context_sdk_enabled(const OotStartupContext *context);
OOT_MEMORY_API uint64_t oot_startup_context_tpidr_el0(const OotStartupContext *context);
OOT_MEMORY_API int oot_startup_context_retain(OotStartupContext *context);
OOT_MEMORY_API void oot_startup_context_destroy(OotStartupContext *context);
OOT_MEMORY_API OotGuestMemory *oot_startup_context_memory(OotStartupContext *context);
OOT_MEMORY_API OotRuntimeImage *oot_startup_context_image(OotStartupContext *context);
OOT_MEMORY_API uint64_t oot_startup_context_tls_pointer(const OotStartupContext *context);
OOT_MEMORY_API uint64_t oot_startup_context_heap_size(const OotStartupContext *context);
OOT_MEMORY_API int oot_startup_context_initial_state(const OotStartupContext *context,
    uint64_t entry, OotArm64State *state);

/* SVC register ABI, not C wrapper ABI. Successful services retire one SVC by
 * advancing PC by four; unsupported/faulting services change neither guest
 * state nor guest bytes nor heap mapping. Reports contain captured guest debug
 * text only; there is no direct stdout/file/network side effect. QueryMemory
 * requires an entirely page-aligned experimental mapping and writes one atomic
 * 40-byte record. SDK GetInfo is an explicit opt-in with strict query domains;
 * other GetInfo, permission changes, exceptions and scheduling stop. */
OOT_MEMORY_API int oot_startup_context_service(OotStartupContext *context,
    uint32_t id, OotArm64State *state, OotStartupServiceReport *report);
/* SDK-only TPIDRRO_EL0/TPIDR_EL0 and scalar CAS operations. CAS32/CAS64 use
 * the same serialized backend and complete read/write preflight as other
 * transfers. Supported words retire one instruction; faults retire nothing.
 * This single-threaded process model does not claim guest scheduling or an
 * exhaustive weak-memory model. */
OOT_MEMORY_API int oot_startup_context_system(OotStartupContext *context,
    uint32_t word, OotArm64State *state);

#endif
