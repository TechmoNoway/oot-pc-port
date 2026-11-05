#ifndef OOT_STACK_DISPATCH_H
#define OOT_STACK_DISPATCH_H
#include "leaf_dispatch.h"

#define OOT_STACK_POLICY_VERSION 1u
#define OOT_STACK_MAX_FUNCTIONS 32u
#define OOT_STACK_MAX_WORDS 128u
#define OOT_STACK_MAX_FRAME 256u
#define OOT_STACK_MAX_DEPTH 16u
#define OOT_STACK_MAX_STEPS 1000000u
enum OotStackKind { OOT_STACK_OPEN, OOT_STACK_FP, OOT_STACK_NORMAL, OOT_STACK_CALL,
    OOT_STACK_CLOSE, OOT_STACK_RETURN, OOT_STACK_LOAD, OOT_STACK_STORE };
enum OotStackError { OOT_STACK_BAD_REGISTRY = 48, OOT_STACK_CHANGED = 49,
    OOT_STACK_BAD_MEMORY = 50, OOT_STACK_DEPTH = 51 };
typedef struct OotStackStep { uint32_t kind, offset, size, reserved; uint64_t callee; } OotStackStep;
typedef struct OotStackFunction {
    uint64_t entry;
    uint32_t instruction_count, max_steps, abi_version, policy_version, frame_size, max_depth;
    OotLeafRun run;
    const OotStackStep *steps;
    OotCodeHash hash;
} OotStackFunction;
typedef struct OotStackDispatcher OotStackDispatcher;

/* Separate single-threaded bounded DAG profile. Copies trusted compiled metadata,
 * retains image, stages frame-local accesses, and uses an explicit guest stack. */
OOT_MEMORY_API OotStackDispatcher *oot_stack_create(OotRuntimeImage *image,
    const OotStackFunction *functions, size_t count, uint64_t root,
    const OotLeafFunction *leaves, size_t leaf_count, const OotCodeHash *hashes,
    const uint8_t body_hash[32], const uint64_t *returns, size_t return_count, uint32_t *error);
OOT_MEMORY_API int oot_stack_destroy(OotStackDispatcher *dispatcher);
OOT_MEMORY_API int oot_stack_begin(OotStackDispatcher *dispatcher, const OotArm64State *state,
    uint64_t expected_return, OotLeafReport *report);
OOT_MEMORY_API int oot_stack_run(OotStackDispatcher *dispatcher, OotArm64State *state, uint64_t budget, OotLeafReport *report);
OOT_MEMORY_API int oot_stack_abort(OotStackDispatcher *dispatcher, OotLeafReport *report);
#endif
