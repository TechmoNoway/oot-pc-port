#ifndef OOT_STACK_DISPATCH_H
#define OOT_STACK_DISPATCH_H
#include "leaf_dispatch.h"
#include "pauth.h"

#define OOT_STACK_POLICY_VERSION 1u
#define OOT_STACK_CFG_POLICY_VERSION 2u
#define OOT_STACK_LAYOUT_POLICY_VERSION 3u
#define OOT_STACK_PAUTH_POLICY_VERSION 4u
#define OOT_STACK_READ_POLICY_VERSION 5u
#define OOT_STACK_CALL_POLICY_VERSION 6u
#define OOT_STACK_PLT_POLICY_VERSION 7u
#define OOT_STACK_MAX_PLT 256u
#define OOT_STACK_MAX_READ_RANGES 128u
#define OOT_STACK_MAX_FUNCTIONS 32u
#define OOT_STACK_MAX_WORDS 128u
#define OOT_STACK_MAX_FRAME 256u
#define OOT_STACK_MAX_DEPTH 16u
#define OOT_STACK_MAX_STEPS 1000000u
enum OotStackKind { OOT_STACK_OPEN, OOT_STACK_FP, OOT_STACK_NORMAL, OOT_STACK_CALL,
    OOT_STACK_CLOSE, OOT_STACK_RETURN, OOT_STACK_LOAD, OOT_STACK_STORE,
    OOT_STACK_SAVE, OOT_STACK_RESTORE, OOT_STACK_BRANCH, OOT_STACK_ALLOC,
    OOT_STACK_RECORD_SAVE, OOT_STACK_RECORD_RESTORE, OOT_STACK_DEALLOC,
    OOT_STACK_SIGN, OOT_STACK_AUTH, OOT_STACK_READ, OOT_STACK_OPEN_LR, OOT_STACK_CLOSE_LR };
enum OotStackError { OOT_STACK_BAD_REGISTRY = 48, OOT_STACK_CHANGED = 49,
    OOT_STACK_BAD_MEMORY = 50, OOT_STACK_DEPTH = 51,
    OOT_STACK_BAD_READ_RANGE = 52, OOT_STACK_BAD_READ_EFFECT = 53,
    OOT_STACK_BAD_PLT_TARGET = 54, OOT_STACK_BAD_PLT_EFFECT = 55 };
typedef struct OotStackStep { uint32_t kind, offset, size, reserved; uint64_t callee; } OotStackStep;
typedef struct OotStackFunction {
    uint64_t entry;
    uint32_t instruction_count, max_steps, abi_version, policy_version, frame_size, max_depth;
    OotLeafRun run;
    const OotStackStep *steps;
    OotCodeHash hash;
} OotStackFunction;
typedef struct OotStackCfgStep {
    uint16_t next_a, next_b, saved_a, saved_b;
    uint32_t max_steps, writable_mask;
} OotStackCfgStep;
typedef struct OotStackCfgFunction {
    OotStackFunction info;
    const OotStackCfgStep *flow;
    uint32_t saved_mask, locals_begin;
} OotStackCfgFunction;
/* Post-instruction state: SP 0=frame base,1=entry; FP 0=entry,1=record;
 * LR 0=unchanged,1=entry,2=BL continuation (3 is reserved for PAC policy);
 * owner 0=keep,1=claim,2=release. */
typedef struct OotStackLayoutStep { uint8_t sp, fp, lr, owner; } OotStackLayoutStep;
typedef struct OotStackLayoutFunction {
    OotStackCfgFunction cfg;
    const OotStackLayoutStep *states;
    uint32_t record_offset, reserved;
} OotStackLayoutFunction;

typedef int (*OotPauthRun)(OotArm64State *, OotGuestMemory *, const OotPauth *, uint64_t, uint64_t *);
/* Policy 4 keeps the old descriptor prefixes intact. info.run must be NULL;
 * run has the separate PAC callback ABI. LR state 3 means this frame's signed LR. */
typedef struct OotStackPauthFunction {
    OotStackLayoutFunction layout;
    OotPauthRun run;
    uint32_t sign_word, auth_word;
} OotStackPauthFunction;

typedef struct OotReadRange { uint64_t base, size; } OotReadRange;
typedef struct OotStackReadFunction {
    OotStackPauthFunction pauth;
    const uint32_t *read_words; /* Exact opcode at READ steps; zero elsewhere. */
} OotStackReadFunction;
/* Policy 6 additionally permits pre-index LR/callee-save pairs without FP setup.
 * Both words are zero for the existing FP layouts, exact opcodes otherwise. */
typedef struct OotStackCallFunction {
    OotStackReadFunction reads;
    uint32_t open_word, close_word;
} OotStackCallFunction;
/* Exact ADRP X16 / LDR X17 / ADD X16 / BR X17 bridge. The sole target is a
 * registered ordinary leaf; run is trusted compiled code with the raw ABI. */
typedef struct OotPltFunction {
    uint64_t entry, slot, target;
    OotLeafRun run;
    uint32_t words[4];
    OotCodeHash hash;
} OotPltFunction;
typedef struct OotStackDispatcher OotStackDispatcher;

/* Separate single-threaded bounded DAG profile. Copies trusted compiled metadata,
 * retains image, stages frame-local accesses, and uses an explicit guest stack. */
OOT_MEMORY_API OotStackDispatcher *oot_stack_create(OotRuntimeImage *image,
    const OotStackFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, uint32_t *error);
/* Separate policy v2: closed acyclic CFG and explicit contiguous X19-X28 save
 * slots. The policy-v1 entry point and descriptor layout remain unchanged. */
OOT_MEMORY_API OotStackDispatcher *oot_stack_create_cfg(OotRuntimeImage *image,
    const OotStackCfgFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, uint32_t *error);
OOT_MEMORY_API OotStackDispatcher *oot_stack_create_layout(OotRuntimeImage *image,
    const OotStackLayoutFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, uint32_t *error);
/* Retains both image and immutable PAC context through every activation/yield. */
OOT_MEMORY_API OotStackDispatcher *oot_stack_create_pauth(OotRuntimeImage *image,
    const OotStackPauthFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, uint32_t *error);
/* Policy 5: reads from unreserved current-frame locals or copied explicit ranges
 * within retained image regions. Entire remaining stack is excluded. Callbacks
 * receive a read-only snapshot of exactly one checked load, never the full image. */
OOT_MEMORY_API OotStackDispatcher *oot_stack_create_reads(OotRuntimeImage *image,
    const OotStackReadFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, const OotReadRange *ranges, size_t range_count, uint32_t *error);
OOT_MEMORY_API OotStackDispatcher *oot_stack_create_calls(OotRuntimeImage *image,
    const OotStackCallFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, const OotReadRange *ranges, size_t range_count, uint32_t *error);
OOT_MEMORY_API OotStackDispatcher *oot_stack_create_plt(OotRuntimeImage *image,
    const OotStackCallFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count,
    OotPauth *pauth, const OotReadRange *ranges, size_t range_count,
    const OotPltFunction *plts, size_t plt_count, uint32_t *error);
OOT_MEMORY_API int oot_stack_destroy(OotStackDispatcher *dispatcher);
OOT_MEMORY_API int oot_stack_begin(OotStackDispatcher *dispatcher, const OotArm64State *state,
    uint64_t expected_return, OotLeafReport *report);
OOT_MEMORY_API int oot_stack_run(OotStackDispatcher *dispatcher, OotArm64State *state, uint64_t budget, OotLeafReport *report);
OOT_MEMORY_API int oot_stack_abort(OotStackDispatcher *dispatcher, OotLeafReport *report);
#endif
