#ifndef OOT_NATIVE_GRAPHICS_H
#define OOT_NATIVE_GRAPHICS_H
#include "arm64_lift.h"

#define OOT_GRAPHICS_BOOT 448u
#define OOT_GRAPHICS_CHECK 449u
#define OOT_DISPLAY_INITIALIZE 450u
typedef struct OotGraphics OotGraphics;
typedef struct OotGraphicsDisplayPeer OotGraphicsDisplayPeer;
typedef struct OotGraphicsLayerPeer OotGraphicsLayerPeer;
typedef struct OotGraphicsPeerReport {
    uint32_t width,height,refresh,dpi,visible,presentation_supported;
} OotGraphicsPeerReport;
typedef struct OotGraphicsReport {
    uint32_t version,ready,api_version,driver_version,vendor_id,device_id,queue_family,reserved;
    uint64_t calls,boots,checks,working_memory,working_size;
    char device_name[256];
} OotGraphicsReport;
typedef struct OotDisplayReport {
    uint32_t version,ready,presentation_supported,reserved;
    uint64_t calls,initializations;
} OotDisplayReport;

/* A private owner, not a guest handle or an SDK object. Creation allocates no
 * GPU resource. The first successful boot owns a real Vulkan device/queue.
 * Calls are externally serialized by the enclosing native dispatcher. */
OotGraphics *oot_graphics_create(void);
void oot_graphics_destroy(OotGraphics *graphics);
int oot_graphics_snapshot(const OotGraphics *graphics,OotGraphicsReport *report);
int oot_graphics_display_snapshot(const OotGraphics *graphics,OotDisplayReport *report);
/* Display initialization owns a hidden Win32 window and actual Vulkan surface.
 * Calls and final owner destruction must run on the window's creator thread.
 * These host resources are not guest Display/Layer handles or rendered frames. */
/* 0 implemented, 1 unsupported, 2 fault. Void ABI: preserve every GPR, SP and
 * NZCV, change only PC to LR. Inputs/output/owner must be live and disjoint.
 * Failure publishes neither GPU readiness, counters nor output registers. */
int oot_graphics_call(OotGraphics *graphics,uint32_t id,
    const OotArm64State *registers,OotArm64State *result);
/* Private host peers. No pointer returned here is a guest object/handle. Each
 * child retains its parent; calls and destruction use the display creator
 * thread and externally serialized lifetimes. Layer creation owns a separate
 * real visible window/surface, never changes the initializer's hidden probe. */
OotGraphicsDisplayPeer *oot_graphics_display_peer_open(OotGraphics *graphics);
int oot_graphics_display_peer_live(const OotGraphicsDisplayPeer *display);
int oot_graphics_display_peer_report(const OotGraphicsDisplayPeer *display,OotGraphicsPeerReport *report);
void *oot_graphics_display_peer_monitor(const OotGraphicsDisplayPeer *display);
void oot_graphics_display_peer_close(OotGraphicsDisplayPeer *display);
OotGraphicsLayerPeer *oot_graphics_layer_peer_open(OotGraphicsDisplayPeer *display,uint32_t width,uint32_t height);
int oot_graphics_layer_peer_live(const OotGraphicsLayerPeer *layer);
int oot_graphics_layer_peer_report(const OotGraphicsLayerPeer *layer,OotGraphicsPeerReport *report);
void oot_graphics_layer_peer_close(OotGraphicsLayerPeer *layer);
#endif
