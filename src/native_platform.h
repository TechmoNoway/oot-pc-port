#ifndef OOT_NATIVE_PLATFORM_H
#define OOT_NATIVE_PLATFORM_H

#include "arm64_lift.h"
#include "guest_memory.h"

#define OOT_NATIVE_PLATFORM_VERSION 1u
#define OOT_NATIVE_PLATFORM_WRITE_LIMIT 64u

enum OotNativePlatformHandlerId {
    OOT_PLATFORM_INITIALIZE=64,
    OOT_PLATFORM_FINALIZE=65,
    OOT_PLATFORM_GET_OPERATION_MODE=66,
    OOT_PLATFORM_GET_PERFORMANCE_MODE=67,
    OOT_PLATFORM_GET_CURRENT_FOCUS_STATE=68,
    OOT_PLATFORM_SET_CPU_BOOST_MODE=69,
    OOT_PLATFORM_SET_FOCUS_HANDLING_MODE=70,
    OOT_PLATFORM_SET_RESUME_NOTIFICATION_ENABLED=71,
    OOT_PLATFORM_SET_OPERATION_MODE_NOTIFICATION_ENABLED=72,
    OOT_PLATFORM_SET_PERFORMANCE_MODE_NOTIFICATION_ENABLED=73,
    OOT_PLATFORM_GET_CURRENT_GRAPHICS_SCALE=74
};

enum OotNativePlatformStatus {
    OOT_PLATFORM_IMPLEMENTED=0, OOT_PLATFORM_UNSUPPORTED=1, OOT_PLATFORM_FAULT=2
};
enum OotNativePlatformError {
    OOT_PLATFORM_OK=0, OOT_PLATFORM_BAD_ARGUMENT=1, OOT_PLATFORM_BAD_STATE=2,
    OOT_PLATFORM_BAD_MEMORY=3, OOT_PLATFORM_BAD_INPUT=4, OOT_PLATFORM_LIMIT=5
};

/* An explicitly selected host model, not recovered console service values.
 * operation/performance are 0..1, focus is 1..3, graphics_scale is 0..2.
 * Process/thread identities must come from the enclosing process declaration.
 * No host power-plan, applet service, event or guest SDK object is created. */
typedef struct OotNativePlatformConfig {
    uint32_t version, operation_mode, performance_mode, focus_state;
    uint32_t graphics_scale, reserved;
    uint64_t process_id, main_thread_id;
} OotNativePlatformConfig;

/* Copyable per-process state with no borrowed pointers or opaque handles.
 * Boost and focus/notification settings are owned advisory settings. The
 * read-only model does not generate focus or operation-change notifications. */
typedef struct OotNativePlatform {
    uint32_t version, initialized, cpu_boost_mode, focus_handling_mode;
    uint32_t resume_notification_enabled, operation_notification_enabled;
    uint32_t performance_notification_enabled, reserved;
    OotNativePlatformConfig config;
    uint64_t calls, initialization_calls, finalization_calls, generations;
    uint64_t boost_updates, focus_updates, notification_updates, queries;
} OotNativePlatform;

/* One bounded output record staged for the enclosing transaction. The current
 * scalar/void platform family always produces size zero. No guest bytes are
 * changed by prepare; a future typed output requires an explicit handler. */
typedef struct OotNativePlatformWrite {
    uint64_t address;
    uint32_t size;
    uint8_t bytes[OOT_NATIVE_PLATFORM_WRITE_LIMIT];
} OotNativePlatformWrite;

typedef struct OotNativePlatformReport {
    uint32_t status, handler, error, size;
} OotNativePlatformReport;

/* Configuration rejection leaves state unchanged. Initialization prepares the
 * provider; OOT_PLATFORM_INITIALIZE separately starts its platform lifetime. */
OOT_MEMORY_API int oot_native_platform_init(OotNativePlatform *state,
    const OotNativePlatformConfig *config);
OOT_MEMORY_API int oot_native_platform_valid(const OotNativePlatform *state);
OOT_MEMORY_API int oot_native_platform_handler_valid(uint32_t id);
OOT_MEMORY_API int oot_native_platform_returns_value(uint32_t id);

/* Pure candidate preparation, using the same 0/1/2 status convention as the
 * native SDK dispatcher. On failure next/result/write are unchanged. A valid
 * private report may change. Successful void calls preserve all registers;
 * typed 32-bit getters change only X0 and zero-extend it. PC returns to LR.
 * All inputs, output records and guest backing/metadata must be live, stable,
 * private and mutually nonaliasing. No guest SDK global is read or initialized.
 * Unimplemented event/object/callback consumers must be bound to an explicit
 * unsupported guard by the enclosing provenance-checked registry. */
OOT_MEMORY_API int oot_native_platform_prepare(const OotNativePlatform *state,
    uint32_t id, const OotArm64State *registers, OotGuestMemory *memory,
    OotNativePlatform *next, OotArm64State *result,
    OotNativePlatformWrite *write, OotNativePlatformReport *report);

#endif
