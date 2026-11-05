#ifndef OOT_PAUTH_H
#define OOT_PAUTH_H

#include "arm64_lift.h"

/* Explicit opt-in model; unrelated to the existing lift/registry ABIs. */
#define OOT_PAUTH_ABI_VERSION 1
#define OOT_PAUTH_QARMA5_VA39 1
#define OOT_PAUTH_LIFT_CONFIGURATION 3

typedef struct OotPauth OotPauth;
typedef struct OotPauthKeys {
    uint64_t ia_lo, ia_hi, ib_lo, ib_hi;
} OotPauthKeys;

enum OotPauthResult {
    OOT_PAUTH_REJECTED = -1, /* Configuration/encoding error: nothing retires. */
    OOT_PAUTH_SIGNED = 0,
    OOT_PAUTH_AUTHENTICATED = 1,
    OOT_PAUTH_POISONED = 2 /* Basic PAuth failure retires with a corrupt pointer. */
};

/* NULL keys requests fresh process-local keys from the Windows system RNG.
 * Explicit keys are for synthetic validation or an eventual specified guest ABI.
 * The context copies keys, is immutable, and must outlive all its calls/yields.
 * Do not serialize it, log keys, use a destroyed pointer, or destroy during a call. */
OOT_MEMORY_API OotPauth *oot_pauth_create(uint32_t model, const OotPauthKeys *keys);
OOT_MEMORY_API void oot_pauth_destroy(OotPauth *context);
OOT_MEMORY_API uint32_t oot_pauth_model(const OotPauth *context);

/* Only PACIASP/PACIBSP/AUTIASP/AUTIBSP/RETAA/RETAB. Keys always enabled,
 * 39-bit T0/T1 VA, no TBI, basic QARMA5 PAuth (no EPAC/PAuth2/FPAC/GCS/BTI).
 * Signing requires an initially canonical VA39 pointer; noncanonical signing is
 * rejected (including re-signing a PAC-bearing LR). AUT/RET accept any 64-bit LR.
 * A successful step advances PC or writes a guest branch target. It never fetches
 * that target or calls a native pointer. RETAA/B leave the signed X30 unchanged.
 * REJECTED leaves every state byte unchanged; all other results retire one step. */
OOT_MEMORY_API int oot_pauth_step(const OotPauth *context, OotArm64State *state, uint32_t word);

#endif
