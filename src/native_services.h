#ifndef OOT_NATIVE_SERVICES_H
#define OOT_NATIVE_SERVICES_H

#include "sdk_native.h"

#define OOT_NATIVE_SERVICES_VERSION 1u
#define OOT_NATIVE_CONTEXT_LIMIT 1024u
#define OOT_NATIVE_ABORT_OBSERVERS 4u
#define OOT_NATIVE_MOUNTS 8u

enum OotNativeServicesHandler {
    OOT_NATIVE_AOC_INITIALIZE=128,
    OOT_NATIVE_AOC_FINALIZE=129,
    OOT_NATIVE_ERR_INITIALIZE_CONTEXT_WRITER=144,
    OOT_NATIVE_DIAG_INITIALIZE_ABORT_OBSERVER=160,
    OOT_NATIVE_PCTL_INITIALIZE=176,
    OOT_NATIVE_FS_INITIALIZE_FOR_APPLICATION=192,
    OOT_NATIVE_FS_SET_LOCAL_APPLICATION_ACCESS_LOG=193,
    OOT_NATIVE_FS_SET_RESULT_HANDLED=194,
    OOT_NATIVE_TIME_INITIALIZE=208,
    OOT_NATIVE_OS_GET_SYSTEM_TICK=224 /* Context-owned live QPC conversion. */
};
enum OotNativeCatalogueMode { OOT_NATIVE_CATALOGUE_EMPTY=1 };
enum OotNativeParentalPolicy {
    OOT_NATIVE_PARENTAL_BLOCKED=0, OOT_NATIVE_PARENTAL_ALLOWED=1
};
enum OotNativeFilesystemMode {
    OOT_NATIVE_FS_UNINITIALIZED=0, OOT_NATIVE_FS_APPLICATION=1
};
enum OotNativeAbortObserverKind { OOT_NATIVE_ABORT_CAPTURE=1 };

/* Launch declarations, not inferred console account/service state. An empty
 * add-on catalogue and a local parental policy must be selected explicitly.
 * A clock declaration is a pinned monotonic frequency/tick and Unix-second
 * calibration snapshot, not a live console shared-memory service. All zero
 * means absent. No host pointer is kept. */
typedef struct OotNativeServicesConfig {
    uint32_t version, aoc_catalog_mode, parental_policy, reserved;
    uint64_t clock_frequency, clock_ticks, clock_unix_seconds;
} OotNativeServicesConfig;

typedef struct OotNativeAbortObserver {
    uint32_t kind, active;
    uint64_t captures;
} OotNativeAbortObserver;

/* Empty until a real read-only provider is registered. A mount name is owned;
 * provider_id is a host registry index, never a guest object or IPC handle. */
typedef struct OotNativeReadonlyMount {
    char name[16];
    uint32_t provider_id, active;
} OotNativeReadonlyMount;

typedef struct OotNativeServices {
    uint32_t version, aoc_initialized, err_initialized, diag_initialized;
    uint32_t pctl_initialized, fs_mode, local_access_log, result_handled;
    uint32_t aoc_count, aoc_references, context_capacity, context_size, observer_count;
    uint32_t mount_count, parental_policy, clock_initialized, clock_references;
    OotNativeServicesConfig config;
    uint64_t calls, aoc_initializations, aoc_finalizations, err_initializations;
    uint64_t diag_initializations, pctl_initializations, fs_initializations;
    uint64_t access_log_updates, result_handled_updates, clock_initializations;
    uint8_t context[OOT_NATIVE_CONTEXT_LIMIT];
    OotNativeAbortObserver observers[OOT_NATIVE_ABORT_OBSERVERS];
    OotNativeReadonlyMount mounts[OOT_NATIVE_MOUNTS];
} OotNativeServices;

/* A prepared effect is committed by the enclosing dispatcher after checking
 * its complete ABI result. A zero size means no guest write. This provider
 * never writes guest memory while preparing a candidate. */
typedef struct OotNativeServicesWrite {
    uint64_t address;
    uint32_t size;
    uint8_t bytes[OOT_MEMORY_RECORD_LIMIT];
} OotNativeServicesWrite;

OOT_MEMORY_API int oot_native_services_init(OotNativeServices *state,
    const OotNativeServicesConfig *config);
OOT_MEMORY_API int oot_native_services_handler_valid(uint32_t id);
OOT_MEMORY_API int oot_native_services_returns_value(uint32_t id);
/* All arguments and results are private, stable and pairwise nonaliasing.
 * On failure next/result/write are unchanged. The report may change.
 * Unsupported exported consumers must be bound to an explicit guard; these
 * providers do not initialize the original SDK's guest objects or sessions. */
OOT_MEMORY_API int oot_native_services_prepare(const OotNativeServices *state,
    uint32_t id, const OotArm64State *registers, OotGuestMemory *memory,
    OotNativeServices *next, OotArm64State *result,
    OotNativeServicesWrite *write, OotNativeReport *report);

#endif
