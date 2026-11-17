#ifndef OOT_NATIVE_OBJECTS_H
#define OOT_NATIVE_OBJECTS_H
#include "native_graphics.h"
#include "runtime_image.h"
#include "native_nvn_resources.h"
#define OOT_OBJECT_DECLARATION_VERSION 1u
#define OOT_OBJECT_VSYNC 1u
#define OOT_OBJECT_REFRESH 2u
#define OOT_OBJECT_NVN 4u
#define OOT_OBJECT_NVN_LAYOUT 8u
#define OOT_OBJECT_NVN_RESOURCES 16u
#define OOT_OBJECT_OPEN_DISPLAY 451u
#define OOT_OBJECT_CLOSE_DISPLAY 452u
#define OOT_OBJECT_CREATE_LAYER 453u
#define OOT_OBJECT_DESTROY_LAYER 454u
#define OOT_OBJECT_NATIVE_WINDOW 455u
#define OOT_OBJECT_VSYNC_EVENT 456u
#define OOT_OBJECT_REFRESH_CAPABILITY 457u
#define OOT_NVN_GET_PROC 458u
#define OOT_NVN_DEVICE_INITIALIZE 459u
#define OOT_NVN_DEVICE_FINALIZE 460u
#define OOT_NVN_DEVICE_GET_INTEGER 461u
#define OOT_NVN_DEVICE_SET_ORIGIN 462u
#define OOT_NVN_DEVICE_GET_ORIGIN 463u
#define OOT_NVN_DEVICE_SET_DEPTH 464u
#define OOT_NVN_DEVICE_GET_DEPTH 465u
#define OOT_OBJECT_TABLES 8u
#define OOT_OBJECT_VPTRS 5u
typedef struct OotObjectTable {
    uint64_t address;
    uint32_t size,reserved;
    uint8_t sha256[32];
} OotObjectTable;
/* Trusted generated declaration, never populated from guest CLI options.
 * The immutable package/code anchor and complete relocated table hashes bind
 * static identities. Live original constructor vptrs are checked on every call.
 * vptr order: Display, LayerWithHistory, listener, native window, recorder pool. */
typedef struct OotObjectDeclaration {
    uint32_t version,flags,width,height;
    uint64_t display,display_size,layer,layer_size;
    uint64_t vptr_address[OOT_OBJECT_VPTRS],vptr_value[OOT_OBJECT_VPTRS];
    uint64_t native_window,anchor;
    uint32_t anchor_size,reserved;
    uint8_t image_sha256[32],anchor_sha256[32];
    OotObjectTable tables[OOT_OBJECT_TABLES];
} OotObjectDeclaration;
typedef struct OotObjects OotObjects;
typedef struct OotObjectsReport {
    uint32_t version,display_open,layer_open,event_open;
    uint64_t references,calls,opens,closes,creates,destroys,window_getters,vsync_events;
    uint64_t waits,resets,clears,handle_closes;
} OotObjectsReport;
/* A process-owned capability declaration, not the physical refresh rate. */
typedef struct OotRefreshReport {
    uint32_t version,reserved;
    uint64_t capability_bits,update_mask,updates,ignored;
} OotRefreshReport;
typedef struct OotNvnProc { char name[128];uint64_t entry; } OotNvnProc;
typedef struct OotNvnDeclaration {
    uint32_t version,count;
    uint64_t table;
    uint8_t table_sha256[32];
    const OotNvnProc *procedures;
} OotNvnDeclaration;
typedef struct OotNvnReport {
    uint64_t lookups,initializations,finalizations,device,integer_queries;
    uint64_t state_updates,state_queries;
    uint32_t window_origin,depth_mode;
} OotNvnReport;
/* Borrows image/memory/graphics until destruction. All calls and destruction
 * run serially on the creator thread; destroy this owner before those borrows.
 * OOT_OBJECT_VSYNC requires the separate source-audited event opt-in. Ordinary
 * object profiles keep that flag zero and do not publish guest events. */
OotObjects *oot_objects_create(OotRuntimeImage *image,OotGuestMemory *memory,OotGraphics *graphics,
    const OotObjectDeclaration *declaration);
void oot_objects_destroy(OotObjects *objects);
int oot_objects_handler_valid(const OotObjects *objects,uint32_t id);
int oot_objects_returns_value(uint32_t id);
int oot_objects_snapshot(const OotObjects *objects,OotObjectsReport *out);
int oot_objects_refresh_snapshot(const OotObjects *objects,OotRefreshReport *out);
int oot_objects_bind_nvn(OotObjects *objects,const OotNvnDeclaration *declaration);
int oot_objects_resources_snapshot(const OotObjects*,OotNvnResourcesReport*);
int oot_objects_nvn_snapshot(const OotObjects *objects,OotNvnReport *out);
/* Whole public API replacements. 0 implemented, 1 unsupported, 2 fault.
 * Only W0 Result (where declared) and PC=LR change. Failure preserves all
 * guest bytes/registers/owner counters except the ordinary memory fault view. */
int oot_objects_call(OotObjects *objects,uint32_t id,OotArm64State *state);
/* Source-specific registered event tokens only; no generic kernel emulation.
 * A handled SVC advances PC by four. Unknown handles/modes remain unsupported. */
int oot_objects_service(OotObjects *objects,uint32_t id,OotArm64State *state);
#endif
