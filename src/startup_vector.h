#ifndef OOT_STARTUP_VECTOR_H
#define OOT_STARTUP_VECTOR_H

#include "arm64_lift.h"
#include "guest_memory.h"

/* Separate initialization-only register bank. The public integer state ABI
 * stays unchanged. This finite initialization subset has no general SIMD FP,
 * SVE, system feature-trap or guest scheduling semantics. FPCR permits zero/FZ;
 * scalar comparison/arithmetic owns cumulative FPSR exception bits. */
typedef struct OotStartupVectorState {
    uint8_t q[32][16];
    uint32_t fpcr, fpsr;
} OotStartupVectorState;

typedef struct OotStartupVectorWrite {
    uint64_t address;
    uint32_t size;
    uint8_t bytes[64];
} OotStartupVectorWrite;

enum OotStartupVectorStatus {
    OOT_STARTUP_VECTOR_IMPLEMENTED=0,
    OOT_STARTUP_VECTOR_UNSUPPORTED=1,
    OOT_STARTUP_VECTOR_FAULT=2
};

OOT_MEMORY_API void oot_startup_vector_init(OotStartupVectorState *state);
/* SIMD pair S/D/Q signed-offset/pre/post, single S/D/Q immediate transfers,
 * integer MOVI, scalar S/D FMOV immediate/general and DUP from a general register.
 * No-offset LD1/ST1 single B/H/S/D lanes preserve all other vector bits.
 * Scalar S/D comparison/conditional comparison, select, move, sign operations,
 * conversion, square root and finite-input MUL/DIV/ADD/SUB/fused variants use
 * nearest rounding and cumulative FPSR. Other arithmetic/control modes, non-temporal
 * pairs and repeated-destination pair loads remain excluded. */
OOT_MEMORY_API int oot_startup_vector_kind(uint32_t word);
/* Application-only non-scaled conversions; earlier kind/prepare reject.
 * Kind 1: SCVTF/UCVTF S/D from W/X. Kind 2: FCVTZS/FCVTZU back to W/X.
 * Kind 3: SCVTF/UCVTF from the low S/D integer lane to same-width float,
 * including ordinary Q31 and aliases; clear the full scalar destination.
 * Kinds 4..8: vector ORR, scalar DUP element, INS element, vector CMEQ, BIF.
 * Q=0 clears the upper half; INS alone preserves unrelated destination lanes.
 * INS low source-index bits are ignored. All inputs use original vector state. */
OOT_MEMORY_API int oot_startup_application_vector_kind(uint32_t word);
/* Prepare a private copy and at most one 1/2/4/8/16/32-byte store record. No guest
 * bytes change here. Load operands use one serialized whole-record capture;
 * store probes are preflight only, with an atomic whole-record commit required
 * by the enclosing transaction before installing next/result. On any failure
 * all three outputs remain unchanged. Inputs, outputs and guest storage must
 * remain live, private and mutually nonaliasing for the call. Scalar S/D loads
 * clear the remaining bits of their complete 128-bit destination registers.
 * SP bases and resulting SP writeback require 16-byte alignment in this model.
 * The deterministic complete-fault policy does not model partial HW stores. */
OOT_MEMORY_API int oot_startup_vector_prepare(const OotStartupVectorState *state,
    uint32_t word, const OotArm64State *registers, OotGuestMemory *memory,
    OotStartupVectorState *next, OotArm64State *result,
    OotStartupVectorWrite *write);
OOT_MEMORY_API int oot_startup_application_vector_prepare(const OotStartupVectorState *state,
    uint32_t word,const OotArm64State *registers,OotGuestMemory *memory,
    OotStartupVectorState *next,OotArm64State *result,OotStartupVectorWrite *write);

#endif
