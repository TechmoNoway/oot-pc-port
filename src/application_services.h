#ifndef OOT_APPLICATION_SERVICES_H
#define OOT_APPLICATION_SERVICES_H
#include "arm64_lift.h"
#include "guest_memory.h"
#define OOT_APPLICATION_GRAPHICS_NOTIFICATIONS 320u
#define OOT_APPLICATION_DESIRED_LANGUAGE 321u
/* Explicit application preference, zero-padded LanguageCode bytes "en-US".
 * This is project configuration, not an inferred Windows/Switch setting. */
#define OOT_APPLICATION_DEFAULT_LANGUAGE UINT64_C(0x53552d6e65)
typedef struct OotApplicationServices {
    uint32_t version,graphics_notifications,reserved[2];
    uint64_t policy_calls,language_code,language_calls;
} OotApplicationServices;
/* Application-only notification policy and explicit language preference.
 * This creates no applet session,
 * event handle, guest object or notification. Unsupported consumers stay guarded.
 * All four state/register objects must be live, private and nonaliasing.
 * Returns 0 implemented, 1 unsupported, 2 fault; failures preserve both outputs. */
OOT_MEMORY_API int oot_application_services_prepare(const OotApplicationServices *state,
    uint32_t id,uint32_t platform_initialized,const OotArm64State *registers,
    OotApplicationServices *next,OotArm64State *result);
#endif
