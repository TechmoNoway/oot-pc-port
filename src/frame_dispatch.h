#ifndef OOT_FRAME_DISPATCH_H
#define OOT_FRAME_DISPATCH_H
#include "leaf_dispatch.h"

#define OOT_FRAME_POLICY_VERSION 1u
#define OOT_FRAME_MAX_WORDS 64u
#define OOT_FRAME_MAX_RETURNS 256u
enum OotFrameKind { OOT_FRAME_OPEN, OOT_FRAME_FP, OOT_FRAME_NORMAL, OOT_FRAME_CALL, OOT_FRAME_CLOSE, OOT_FRAME_RETURN };
enum OotFrameError { OOT_FRAME_BAD_REGISTRY = 32, OOT_FRAME_STACK_CHANGED = 33, OOT_FRAME_BAD_MEMORY = 34 };
typedef struct OotFrameStep { uint32_t kind, reserved; uint64_t callee; } OotFrameStep;
typedef struct OotFrameFunction {
    uint64_t entry;
    uint32_t instruction_count, max_steps, abi_version, policy_version;
    OotLeafRun run;
    const OotFrameStep *steps;
    OotCodeHash hash;
} OotFrameFunction;
typedef struct OotFrameDispatcher OotFrameDispatcher;

/* One linear FP/LR caller -> bound register-only leaves. No recursion, arbitrary
 * memory access, or implicit expansion of the leaf profile. Image is retained. */
OOT_MEMORY_API OotFrameDispatcher *oot_frame_create(OotRuntimeImage *image, const OotFrameFunction *root,
    const OotLeafFunction *leaves, size_t count, const OotCodeHash *hashes, const uint8_t body_sha256[32],
    const uint64_t *return_sites, size_t return_count, uint32_t *error);
OOT_MEMORY_API int oot_frame_destroy(OotFrameDispatcher *dispatcher);
OOT_MEMORY_API int oot_frame_begin(OotFrameDispatcher *dispatcher, const OotArm64State *state,
    uint64_t expected_return, OotLeafReport *report);
OOT_MEMORY_API int oot_frame_run(OotFrameDispatcher *dispatcher, OotArm64State *state, uint64_t budget, OotLeafReport *report);
OOT_MEMORY_API int oot_frame_abort(OotFrameDispatcher *dispatcher, OotLeafReport *report);
#endif
