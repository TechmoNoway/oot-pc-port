#ifndef OOT_STARTUP_INIT_ATOMIC_H
#define OOT_STARTUP_INIT_ATOMIC_H

#include "arm64_lift.h"
#include "guest_memory.h"

enum OotStartupInitAtomicKind {
    OOT_STARTUP_INIT_ATOMIC_NONE=0, OOT_STARTUP_INIT_LDADD=1,
    OOT_STARTUP_INIT_LDADDAL=2, OOT_STARTUP_INIT_STLR=3, OOT_STARTUP_INIT_LDSET=4,
    OOT_STARTUP_INIT_LDCLR=5, OOT_STARTUP_APP_LDADDA=6, OOT_STARTUP_APP_LDADDL=7
};

/* Exact LDADD/LDADDAL W/X, LDSET/LDCLR W/X in all A/R variants and STLR B/H/W/X.
 * Other LSE, exclusive,
 * acquire-only and release-only additions are not implicitly admitted. */
OOT_MEMORY_API int oot_startup_init_atomic_kind(uint32_t word);
/* Additional A/R additions belong only to the separate application profile. */
OOT_MEMORY_API int oot_startup_application_atomic_kind(uint32_t word);
OOT_MEMORY_API int oot_startup_application_atomic_step(uint32_t word,OotArm64State *registers,OotGuestMemory *memory);
/* Returns 0 implemented, 1 unsupported, 2 fault. The enclosing context must
 * require its separate initialization opt-in. One successful backend transfer
 * commits before the private register result. Failures retire nothing and
 * preserve all registers/backing. Source and base are captured before changing
 * an aliased destination; register31 is ZR except an address base is SP.
 * All input/state/backing/metadata must be stable; the register state must be
 * private and nonaliasing with guest bytes and memory metadata. */
OOT_MEMORY_API int oot_startup_init_atomic_step(uint32_t word,
    OotArm64State *registers, OotGuestMemory *memory);

#endif
