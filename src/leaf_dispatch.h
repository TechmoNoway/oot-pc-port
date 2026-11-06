#ifndef OOT_LEAF_DISPATCH_H
#define OOT_LEAF_DISPATCH_H

#include "arm64_lift.h"
#include "runtime_image.h"

#define OOT_LEAF_POLICY_VERSION 1u
#define OOT_LEAF_MEMORY_POLICY_VERSION 2u
#define OOT_LEAF_MAX_RANGES 128u
#define OOT_LEAF_MAX_WORDS 256u
#define OOT_LEAF_MAX_FUNCTIONS 256u
#define OOT_LEAF_MAX_RETURNS 4096u
#define OOT_LEAF_RETURN UINT16_MAX

typedef int (*OotLeafRun)(OotArm64State *, OotGuestMemory *, uint64_t, uint64_t *);

typedef struct OotLeafStep {
    uint16_t next_a, next_b; /* Instruction indices, or both OOT_LEAF_RETURN. */
    uint16_t max_steps;
    uint16_t reserved;
} OotLeafStep;

/* Trusted native code and generated metadata; never deserialize a code pointer.
 * The code module must remain loaded until its dispatchers have been destroyed. */
typedef struct OotLeafFunction {
    uint64_t entry;
    uint32_t instruction_count, max_steps;
    uint32_t abi_version, policy_version;
    OotLeafRun run;
    const OotLeafStep *steps;
} OotLeafFunction;
typedef struct OotCodeHash { uint8_t bytes[32]; } OotCodeHash;
typedef struct OotReadRange { uint64_t base, size; } OotReadRange;
/* Separate bound-only policy. Ordinary entries keep policy 1 and NULL words;
 * policy 2 binds exact read/store words, zero elsewhere. Entire stack excluded. */
typedef struct OotMemoryLeafFunction {
    OotLeafFunction info;
    const uint32_t *effect_words;
} OotMemoryLeafFunction;

enum OotLeafStatus {
    OOT_LEAF_READY = 0,
    OOT_LEAF_YIELDED = 1,
    OOT_LEAF_RETURNED = 2,
    OOT_LEAF_REJECTED = 3,
    OOT_LEAF_CONTRACT_FAULT = 4
};

enum OotLeafError {
    OOT_LEAF_OK = 0,
    OOT_LEAF_BAD_ARGUMENT = 1,
    OOT_LEAF_BAD_REGISTRY = 2,
    OOT_LEAF_BUSY = 3,
    OOT_LEAF_NO_ACTIVE_CALL = 4,
    OOT_LEAF_BAD_ENTRY = 5,
    OOT_LEAF_BAD_RETURN = 6,
    OOT_LEAF_BAD_STATE = 7,
    OOT_LEAF_BAD_STACK = 8,
    OOT_LEAF_BAD_NZCV = 9,
    OOT_LEAF_BAD_COUNT = 10,
    OOT_LEAF_BAD_EDGE = 11,
    OOT_LEAF_PROTECTED_REGISTER = 12,
    OOT_LEAF_BAD_LIFT_STATUS = 13,
    OOT_LEAF_REENTRY = 14,
    OOT_LEAF_ALLOCATION_FAILED = 15,
    OOT_LEAF_BAD_IMAGE = 16,
    OOT_LEAF_BAD_CODE = 17,
    OOT_LEAF_BAD_MEMORY_RANGE = 18,
    OOT_LEAF_BAD_MEMORY_EFFECT = 19,
    OOT_LEAF_BAD_MEMORY = 20
};

typedef struct OotLeafReport {
    uint32_t status, error;
    uint64_t entry, pc, expected_return;
    uint64_t retired_this_call, total_retired;
} OotLeafReport;

typedef struct OotLeafDispatcher OotLeafDispatcher;

/* Single-threaded. The executing flag guards reentry; it is not a lock. */
/* Copies bounded registry/CFG/return-site metadata. Return sites must be sorted,
 * unique, aligned, and outside all registered leaf ranges. Stack bounds are
 * an explicit caller contract, not an allocation or an execute-permission map. */
OOT_MEMORY_API OotLeafDispatcher *oot_leaf_dispatcher_create(const OotLeafFunction *functions, size_t count,
    const uint64_t *return_sites, size_t return_count, uint64_t stack_low, uint64_t stack_high, uint32_t *error);
/* Copies hashes, retains image, derives stack bounds, and verifies exact current
 * text bytes against the compiled registry's expected initial snapshot. */
OOT_MEMORY_API OotLeafDispatcher *oot_leaf_dispatcher_create_bound(OotRuntimeImage *image,
    const OotLeafFunction *functions, size_t count, const OotCodeHash *code_hashes, const uint8_t body_sha256[32],
    const uint64_t *return_sites, size_t return_count, uint32_t *error);
OOT_MEMORY_API OotLeafDispatcher *oot_leaf_dispatcher_create_memory_bound(OotRuntimeImage *image,
    const OotMemoryLeafFunction *functions, size_t count, const OotCodeHash *hashes, const uint8_t body_hash[32],
    const uint64_t *returns, size_t return_count,
    const OotReadRange *reads, size_t read_count, const OotReadRange *writes, size_t write_count, uint32_t *error);
OOT_MEMORY_API int oot_leaf_dispatcher_destroy(OotLeafDispatcher *dispatcher); /* Refuses reentrant destruction. */
OOT_MEMORY_API int oot_leaf_begin(OotLeafDispatcher *dispatcher, const OotArm64State *state,
    uint64_t entry, uint64_t expected_return, OotLeafReport *report);
OOT_MEMORY_API int oot_leaf_run(OotLeafDispatcher *dispatcher, OotArm64State *state,
    uint64_t budget, OotLeafReport *report);
OOT_MEMORY_API int oot_leaf_abort(OotLeafDispatcher *dispatcher, OotLeafReport *report);

#endif
