#ifndef OOT_NATIVE_GRAPHICS_H
#define OOT_NATIVE_GRAPHICS_H
#include "arm64_lift.h"

#define OOT_GRAPHICS_BOOT 448u
#define OOT_GRAPHICS_CHECK 449u
typedef struct OotGraphics OotGraphics;
typedef struct OotGraphicsReport {
    uint32_t version,ready,api_version,driver_version,vendor_id,device_id,queue_family,reserved;
    uint64_t calls,boots,checks,working_memory,working_size;
    char device_name[256];
} OotGraphicsReport;

/* A private owner, not a guest handle or an SDK object. Creation allocates no
 * GPU resource. The first successful boot owns a real Vulkan device/queue.
 * Calls are externally serialized by the enclosing native dispatcher. */
OotGraphics *oot_graphics_create(void);
void oot_graphics_destroy(OotGraphics *graphics);
int oot_graphics_snapshot(const OotGraphics *graphics,OotGraphicsReport *report);
/* 0 implemented, 1 unsupported, 2 fault. Void ABI: preserve every GPR, SP and
 * NZCV, change only PC to LR. Inputs/output/owner must be live and disjoint.
 * Failure publishes neither GPU readiness, counters nor output registers. */
int oot_graphics_call(OotGraphics *graphics,uint32_t id,
    const OotArm64State *registers,OotArm64State *result);
#endif
