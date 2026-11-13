#ifndef OOT_STARTUP_DISPATCH_H
#define OOT_STARTUP_DISPATCH_H

#include "startup_context.h"
#include "pauth.h"
#include "sdk_native.h"

#define OOT_STARTUP_DISPATCH_VERSION 1u
#define OOT_STARTUP_RAW_IMAGE 1u
#define OOT_STARTUP_SDK_RUNTIME 2u
#define OOT_STARTUP_NATIVE_RUNTIME 4u
#define OOT_STARTUP_INIT_RUNTIME 8u
#define OOT_STARTUP_HOST_LINKED 16u
#define OOT_STARTUP_APPLICATION 32u
#define OOT_STARTUP_GRAPHICS 64u
#define OOT_STARTUP_MAX_NATIVE_FUNCTIONS 64u
#define OOT_STARTUP_INIT_MAX_NATIVE_FUNCTIONS 4096u
#define OOT_STARTUP_MAX_INSTRUCTIONS 16384u
#define OOT_STARTUP_MAX_SPANS 256u
#define OOT_STARTUP_MAX_RETIRED UINT64_C(100000000)
#define OOT_STARTUP_SDK_MAX_INSTRUCTIONS 65536u
#define OOT_STARTUP_SDK_MAX_SPANS 1024u
#define OOT_STARTUP_INIT_MAX_INSTRUCTIONS 524288u
#define OOT_STARTUP_INIT_MAX_SPANS 8192u
#define OOT_STARTUP_SDK_MAX_RETIRED UINT64_C(1000000000)
#define OOT_STARTUP_SDK_GOAL_VERSION 1u
#define OOT_STARTUP_SDK_MAX_STAGES 32u

typedef int (*OotStartupRun)(OotArm64State *, OotGuestMemory *, const OotPauth *, uint64_t, uint64_t *);
enum OotStartupInstructionKind {
    OOT_STARTUP_NORMAL = 0, OOT_STARTUP_BRANCH = 1, OOT_STARTUP_INDIRECT = 2,
    OOT_STARTUP_SVC = 3, OOT_STARTUP_UNSUPPORTED = 4, OOT_STARTUP_SYSTEM = 5, OOT_STARTUP_VECTOR = 6
};
/* Direct branches use next_a=target and next_b=fallthrough (both target for
 * unconditional branches). Indirect targets use two zero fields. Normal/SVC
 * and SDK system-register instructions use pc+4 twice; explicit unsupported
 * stops use pc twice. SVC/system rows have no native callback. */
typedef struct OotStartupInstruction {
    uint64_t pc;
    uint32_t word, kind;
    uint64_t next_a, next_b;
    OotStartupRun run;
} OotStartupInstruction;
typedef struct OotStartupFastFunction {
    uint64_t entry;
    uint32_t size;
    uint8_t sha256[32];
    OotStartupRun run;
} OotStartupFastFunction;

typedef struct OotStartupSpan {
    uint64_t entry;
    uint32_t size;
    uint8_t sha256[32];
} OotStartupSpan;
typedef struct OotStartupProgram {
    uint32_t version, flags;
    uint64_t entry;
    uint8_t body_sha256[32];
    const OotStartupInstruction *instructions;
    size_t instruction_count;
    const OotStartupSpan *spans;
    size_t span_count;
} OotStartupProgram;

enum OotStartupStatus {
    OOT_STARTUP_READY = 0, OOT_STARTUP_YIELDED = 1, OOT_STARTUP_STOPPED = 2,
    OOT_STARTUP_REJECTED = 3, OOT_STARTUP_CONTRACT_FAULT = 4
};
enum OotStartupError {
    OOT_STARTUP_OK = 0, OOT_STARTUP_BAD_ARGUMENT = 1, OOT_STARTUP_BAD_PROGRAM = 2,
    OOT_STARTUP_BAD_IMAGE = 3, OOT_STARTUP_BAD_CODE = 4, OOT_STARTUP_BAD_STATE = 5,
    OOT_STARTUP_REENTRY = 6, OOT_STARTUP_NO_ACTIVE = 7,
    OOT_STARTUP_UNSUPPORTED_WORD = 8, OOT_STARTUP_UNSUPPORTED_SERVICE = 9,
    OOT_STARTUP_UNREGISTERED_TARGET = 10, OOT_STARTUP_MEMORY_FAULT = 11,
    OOT_STARTUP_RETIREMENT_LIMIT = 12, OOT_STARTUP_BAD_CALLBACK = 13,
    OOT_STARTUP_BAD_SERVICE = 14, OOT_STARTUP_SDK_INITIALIZED = 15,
    OOT_STARTUP_BAD_SDK_GOAL = 16, OOT_STARTUP_BAD_NATIVE_FUNCTION = 17,
    OOT_STARTUP_NATIVE_INTERIOR = 18, OOT_STARTUP_NATIVE_FAULT = 19
};
enum OotStartupEvent { OOT_STARTUP_TRACE_STEP = 0, OOT_STARTUP_TRACE_SERVICE = 1, OOT_STARTUP_TRACE_STOP = 2,
    OOT_STARTUP_TRACE_NATIVE = 3 };
typedef struct OotStartupTrace {
    uint64_t pc, next_pc, retired;
    uint32_t word, event, error, service;
} OotStartupTrace;
typedef void (*OotStartupTraceSink)(const OotStartupTrace *, void *);
typedef struct OotStartupReport {
    uint64_t pc, retired;
    uint32_t status, error, word, service;
} OotStartupReport;
typedef struct OotStartupDispatcher OotStartupDispatcher;

/* Private diagnostic completion requirement, not an executable callback. The
 * original unconditional B thunk must retire to entry after the ordered stage
 * entries have each retired an instruction. Execution stops before entry's
 * first instruction. All PCs must belong to the copied, hash-bound program. */
typedef struct OotSdkGoal {
    uint32_t version, stage_count;
    uint64_t thunk, entry;
    uint32_t thunk_word;
    const uint64_t *stages;
} OotSdkGoal;

/* Host boot requires complete original DT_INIT bodies, not registration flags.
 * Source-bound body entry and authenticated return delimit actual completion. */
typedef struct OotStartupConstructor {
    uint64_t entry, body_entry, return_pc;
    uint32_t size;
    uint8_t sha256[32];
} OotStartupConstructor;
OOT_MEMORY_API int oot_startup_dispatch_set_constructors(OotStartupDispatcher *dispatcher,
    const OotStartupConstructor *constructors, size_t count);
OOT_MEMORY_API uint32_t oot_startup_dispatch_constructors_completed(const OotStartupDispatcher *dispatcher);

/* Separate trusted-native startup prefix contract. The raw-image flag is an
 * explicit compilation/provenance declaration, bound to the package body hash;
 * it does not infer a startup ABI from arbitrary image bytes. All code metadata
 * is copied. Image, context and PAC lifetimes are retained. Single-threaded;
 * callbacks and trace sinks may not reenter or destroy an executing session. */
OOT_MEMORY_API OotStartupDispatcher *oot_startup_dispatch_create(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *program,
    uint64_t retirement_limit, uint32_t *error);
/* SDK opt-in requires RAW_IMAGE|SDK_RUNTIME flags and an SDK-enabled context.
 * The original constructor rejects that context/profile and system operations. */
OOT_MEMORY_API OotStartupDispatcher *oot_startup_dispatch_create_sdk(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *program,
    uint64_t retirement_limit, uint32_t *error);
/* Separate hybrid profile: flags RAW_IMAGE|SDK_RUNTIME|NATIVE_RUNTIME and a
 * native-enabled SDK context. Descriptors select trusted built-in handler IDs,
 * never guest-address casts or serialized native pointers. */
OOT_MEMORY_API OotStartupDispatcher *oot_startup_dispatch_create_native(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *program,
    uint64_t work_limit, uint32_t *error);
/* Separate initialization profile: flags 15 and an initialization-enabled
 * native SDK context. Up to 4096 copied function bindings may intercept exact
 * entries outside the selected instruction table. Each complete body is
 * checked at registration and again before its actual call. Program spans
 * retain their per-quantum checks; the earlier native profile still requires
 * selected entries, its 64-function cap and all-body checks across yields. */
OOT_MEMORY_API OotStartupDispatcher *oot_startup_dispatch_create_init(OotRuntimeImage *image,
    OotStartupContext *context, OotPauth *pauth, const OotStartupProgram *program,
    uint64_t work_limit, uint32_t *error);
OOT_MEMORY_API int oot_startup_dispatch_set_fast_functions(OotStartupDispatcher *dispatcher,
    const OotStartupFastFunction *functions, size_t count);
OOT_MEMORY_API uint64_t oot_startup_dispatch_host_steps(const OotStartupDispatcher *dispatcher);
OOT_MEMORY_API uint64_t oot_startup_dispatch_fast_calls(const OotStartupDispatcher *dispatcher);
OOT_MEMORY_API OotStartupDispatcher *oot_startup_dispatch_create_host(OotRuntimeImage *image,
    OotStartupContext *context,OotPauth *pauth,const OotStartupProgram *program,
    uint64_t limit,uint32_t *error);
/* Separate flags-62 application prefix: retain the complete initialization
 * goal, then continue through its original entry instead of stopping there. */
OOT_MEMORY_API OotStartupDispatcher *oot_startup_dispatch_create_graphics(OotRuntimeImage *image,
    OotStartupContext *context,OotPauth *pauth,const OotStartupProgram *program,
    uint64_t limit,uint32_t *error);
OOT_MEMORY_API OotStartupDispatcher *oot_startup_dispatch_create_application(OotRuntimeImage *image,
    OotStartupContext *context,OotPauth *pauth,const OotStartupProgram *program,
    uint64_t limit,uint32_t *error);
OOT_MEMORY_API int oot_startup_dispatch_initialization_reached(const OotStartupDispatcher *dispatcher);
OOT_MEMORY_API int oot_startup_dispatch_application_entry_retired(const OotStartupDispatcher *dispatcher);
OOT_MEMORY_API uint64_t oot_startup_dispatch_post_entry_retired(const OotStartupDispatcher *dispatcher);
/* Install copied, sorted, disjoint original-body bindings before begin. Body
 * hashes follow the profile's checks above. Goal/stage entries may not be covered.
 * Calls intercept only canonical entries, before PAC or original retirement;
 * entering an interior stops. Both original instructions and native calls
 * consume work/quantum, but native calls never increment retired or stages. */
/* The incoming LR must be a distinct, canonical, selected return entry; its
 * exact original word and the replacement body are checked before effects. */
OOT_MEMORY_API int oot_startup_dispatch_set_native_functions(OotStartupDispatcher *dispatcher,
    const OotNativeFunction *functions, size_t count, uint32_t *error);
OOT_MEMORY_API uint64_t oot_startup_dispatch_native_calls(const OotStartupDispatcher *dispatcher);
/* Install a copied goal only before begin on an idle SDK dispatcher. Without a
 * goal SDK execution remains a diagnostic prefix, never completed startup. */
OOT_MEMORY_API int oot_startup_dispatch_set_sdk_goal(OotStartupDispatcher *dispatcher,
    const OotSdkGoal *goal, uint32_t *error);
OOT_MEMORY_API uint32_t oot_startup_dispatch_sdk_stages_completed(const OotStartupDispatcher *dispatcher);
OOT_MEMORY_API int oot_startup_dispatch_destroy(OotStartupDispatcher *dispatcher);
OOT_MEMORY_API int oot_startup_dispatch_begin(OotStartupDispatcher *dispatcher,
    const OotArm64State *state, OotStartupReport *report);
OOT_MEMORY_API int oot_startup_dispatch_run(OotStartupDispatcher *dispatcher,
    OotArm64State *state, uint64_t budget, OotStartupTraceSink trace, void *user,
    OotStartupReport *report);
/* Abort discards the session checkpoint, not retired effects or the image's
 * one-shot startup claim. A new startup requires a freshly reopened image. */
OOT_MEMORY_API int oot_startup_dispatch_abort(OotStartupDispatcher *dispatcher);

#endif
