#ifndef OOT_SDK_NATIVE_H
#define OOT_SDK_NATIVE_H

#include "arm64_lift.h"
#include "guest_memory.h"

#define OOT_SDK_NATIVE_VERSION 1u
#define OOT_NATIVE_FUNCTION_VERSION 1u
#define OOT_NATIVE_LOG_LIMIT 4096u
#define OOT_NATIVE_STRING_LIMIT 256u

enum OotNativeHandlerId {
    OOT_NATIVE_LM_INITIALIZE=1,
    OOT_NATIVE_LM_FINALIZE=2,
    OOT_NATIVE_LM_SET_DESTINATION=3,
    OOT_NATIVE_LM_LOG=4,
    OOT_NATIVE_DIAG_CALL_LOG_OBSERVERS=5,
    OOT_NATIVE_DIAG_ENABLE_DEFAULT_LOG_OBSERVER=6,
    OOT_NATIVE_OE_INITIALIZE=16,
    OOT_NATIVE_OE_FINALIZE=17,
    OOT_NATIVE_OE_GET_OPERATION_MODE=18,
    OOT_NATIVE_OE_GET_PERFORMANCE_MODE=19,
    OOT_NATIVE_OE_SET_CPU_BOOST_MODE=20,
    OOT_NATIVE_GUARD_UNSUPPORTED=31
};
enum OotNativeStatus {
    OOT_NATIVE_IMPLEMENTED=0, OOT_NATIVE_UNSUPPORTED=1, OOT_NATIVE_FAULT=2
};
enum OotNativeError {
    OOT_NATIVE_OK=0, OOT_NATIVE_BAD_ARGUMENT=1, OOT_NATIVE_BAD_STATE=2,
    OOT_NATIVE_BAD_MEMORY=3, OOT_NATIVE_BAD_INPUT=4, OOT_NATIVE_LIMIT=5,
    OOT_NATIVE_UNSUPPORTED_CALLBACK=6
};
/* Original-function provenance only. No serialized host function pointer is
 * accepted. The dispatcher copies this table and validates complete read-only
 * original extents before it permits a native replacement at an entry. */
typedef struct OotNativeFunction {
    uint32_t version, id;
    uint64_t entry;
    uint32_t size;
    uint8_t sha256[32];
} OotNativeFunction;

typedef struct OotNativeConfig {
    uint32_t version, operation_mode, performance_mode;
    uint64_t process_id, main_thread_id;
} OotNativeConfig;

/* Private per-process implementation state. All captures are bounded and
 * owned; no guest/native pointer, IPC handle or external output is retained.
 * A candidate must not become live until the dispatcher accepts the complete
 * register result. This is a single-owner, nonreentrant implementation. */
typedef struct OotSdkNative {
    uint32_t version, logging_initialized, platform_initialized, destination;
    uint32_t cpu_boost_mode, last_log_size, last_metadata_size;
    OotNativeConfig config;
    uint64_t calls, logging_initializations, logging_finalizations;
    uint64_t platform_initializations, platform_finalizations;
    uint64_t destination_updates, log_records, log_bytes;
    uint8_t last_log[OOT_NATIVE_LOG_LIMIT];
    uint8_t last_metadata[64];
    uint32_t default_observer_enabled, last_log_head, last_log_tail;
    uint64_t observer_updates, log_attempts;
    char last_filename[OOT_NATIVE_STRING_LIMIT];
    char last_function[OOT_NATIVE_STRING_LIMIT];
    char last_module[OOT_NATIVE_STRING_LIMIT];
} OotSdkNative;

typedef struct OotNativeReport {
    uint32_t status, handler, error, log_size;
} OotNativeReport;
typedef OotNativeReport OotSdkNativeReport;

/* Initialization returns one on success, zero on rejected configuration. */
OOT_MEMORY_API int oot_sdk_native_init(OotSdkNative *state, const OotNativeConfig *config);
OOT_MEMORY_API int oot_sdk_native_handler_valid(uint32_t id);
OOT_MEMORY_API int oot_sdk_native_returns_value(uint32_t id);
/* Preparation performs only checked reads and changes no guest bytes. On
 * failure, next/result are unchanged; the report and memory fault may change.
 * Successful output returns to the incoming canonical LR. All registers are
 * preserved except X0 for a declared scalar getter. Void functions preserve X0.
 * Inputs/outputs/metadata must be private, stable and nonaliasing for the call. */
OOT_MEMORY_API int oot_sdk_native_prepare(const OotSdkNative *state, uint32_t id,
    const OotArm64State *registers, OotGuestMemory *memory, OotSdkNative *next,
    OotArm64State *result, OotNativeReport *report);

#endif
