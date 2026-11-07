#ifndef OOT_STARTUP_CONTEXT_H
#define OOT_STARTUP_CONTEXT_H

#include "arm64_lift.h"
#include "runtime_image.h"

#define OOT_STARTUP_CONTEXT_VERSION 1u
#define OOT_STARTUP_DEBUG_LIMIT 4096u
#define OOT_STARTUP_HEAP_ALIGNMENT UINT64_C(0x200000)

typedef struct OotStartupContext OotStartupContext;

/* Explicit experimental NSO process model, not a recovered Switch 2 ABI.
 * The image supplies a guarded stack. TLS is a zeroed private buffer without
 * invented SDK fields. Heap capacity is reserved but initially unmapped.
 * tick_frequency=0 leaves the counter service unsupported. */
typedef struct OotStartupConfig {
    uint64_t tls_base, tls_size, heap_base, heap_capacity, main_thread_handle;
    uint64_t tick_frequency;
} OotStartupConfig;

enum OotStartupContextError {
    OOT_STARTUP_CONTEXT_OK = 0,
    OOT_STARTUP_CONTEXT_BAD_ARGUMENT = 1,
    OOT_STARTUP_CONTEXT_ALLOCATION = 2,
    OOT_STARTUP_CONTEXT_BAD_IMAGE = 3,
    OOT_STARTUP_CONTEXT_BAD_LAYOUT = 4,
    OOT_STARTUP_CONTEXT_BAD_MEMORY = 5,
    OOT_STARTUP_CONTEXT_BAD_CLOCK = 6
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
 * 40-byte record. GetInfo, permission changes, exceptions and scheduling stop. */
OOT_MEMORY_API int oot_startup_context_service(OotStartupContext *context,
    uint32_t id, OotArm64State *state, OotStartupServiceReport *report);

#endif
