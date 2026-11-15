/* Host-only monitor timing owner. No guest ABI, handle namespace or API binding. */
#ifndef OOT_NATIVE_VBLANK_H
#define OOT_NATIVE_VBLANK_H
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
typedef struct OotVblankSource OotVblankSource;
typedef struct OotVblankSnapshot {
    uint64_t ticks;
    uint32_t ready,failed,signaled,reserved;
} OotVblankSnapshot;
enum { OOT_VBLANK_CLEARED=0,OOT_VBLANK_ALREADY_RESET=1,OOT_VBLANK_UNAVAILABLE=2 };
/* The caller serializes API lifetimes and closes all returned duplicates before
 * destroy. A worker owns its DXGI interfaces exclusively. Creation becomes ready
 * only after the first observed edge; reset and publication share one lock.
 * Driver WaitForVBlank is synchronous: shutdown joins it without forcibly killing
 * the worker, and can wait for the driver call to return. A subprocess watchdog
 * is required when testing a potentially unresponsive physical display driver.
 * Snapshot counters/signals describe host timing, never guest SDK readiness. */
OotVblankSource *oot_vblank_create(HMONITOR monitor);
void oot_vblank_destroy(OotVblankSource *source);
int oot_vblank_snapshot(OotVblankSource *source,OotVblankSnapshot *out);
/* Caller owns the returned real SYNCHRONIZE-only duplicate. */
int oot_vblank_duplicate_read(OotVblankSource *source,HANDLE *out);
int oot_vblank_duplicate_wait_handles(OotVblankSource *source,HANDLE *data,HANDLE *failure);
int oot_vblank_reset(OotVblankSource *source,int require_signal);
#endif

