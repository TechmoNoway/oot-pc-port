#ifndef OOT_NATIVE_OBJECTS_H
#define OOT_NATIVE_OBJECTS_H
#include "native_graphics.h"
#include "runtime_image.h"
#define OOT_OBJECT_DECLARATION_VERSION 1u
#define OOT_OBJECT_VSYNC 1u
#define OOT_OBJECT_OPEN_DISPLAY 451u
#define OOT_OBJECT_CLOSE_DISPLAY 452u
#define OOT_OBJECT_CREATE_LAYER 453u
#define OOT_OBJECT_DESTROY_LAYER 454u
#define OOT_OBJECT_NATIVE_WINDOW 455u
#define OOT_OBJECT_VSYNC_EVENT 456u
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
/* Borrows image/memory/graphics until destruction. All calls and destruction
 * run serially on the creator thread; destroy this owner before those borrows.
 * Production source generation currently leaves OOT_OBJECT_VSYNC disabled:
 * its producer and OS consumer proof is a separate required capability gate. */
OotObjects *oot_objects_create(OotRuntimeImage *image,OotGuestMemory *memory,OotGraphics *graphics,
    const OotObjectDeclaration *declaration);
void oot_objects_destroy(OotObjects *objects);
int oot_objects_handler_valid(const OotObjects *objects,uint32_t id);
int oot_objects_returns_value(uint32_t id);
int oot_objects_snapshot(const OotObjects *objects,OotObjectsReport *out);
/* Whole public API replacements. 0 implemented, 1 unsupported, 2 fault.
 * Only W0 Result (where declared) and PC=LR change. Failure preserves all
 * guest bytes/registers/owner counters except the ordinary memory fault view. */
int oot_objects_call(OotObjects *objects,uint32_t id,OotArm64State *state);
/* Source-specific registered event tokens only; no generic kernel emulation.
 * A handled SVC advances PC by four. Unknown handles/modes remain unsupported. */
int oot_objects_service(OotObjects *objects,uint32_t id,OotArm64State *state);
#endif
