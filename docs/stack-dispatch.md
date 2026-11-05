# Local stack frames and direct-call graphs

`linear-local-stack-dag-v1` is a separate verified function profile and native dispatcher. It supports fixed local storage and direct calls between framed functions or to register-only leaves. The earlier leaf and 16-byte framed-caller profiles retain their existing rules. Only synthetic functions are executed in validation; registry preparation does not launch the game.

## Verified function shape

Each selected framed function contains 4-128 instructions with the following shape:

```text
stp x29, x30, [sp, #-N]!
mov x29, sp
... linear integer operations, frame-local loads/stores, direct BL ...
ldp x29, x30, [sp], #N
ret x30
```

`N` is a fixed multiple of 16 from 16 through 256 bytes. The first 16 bytes hold the original FP/LR pair. Body accesses must lie wholly in `[frame_base + 16, frame_base + N)`, using the unchanged SP or FP as base and a fixed offset. Supported accesses are checked scalar transfers of 1/2/4/8 bytes, including signed loads, and offset-only paired W/X or LDPSW transfers. Local loads cannot write X18-X30. Stores may read those registers. Scalar unscaled offsets are permitted when the complete access still lies inside locals. Body writeback, register-offset addressing, literal loads, other bases, saved-frame accesses, and accesses to ancestor frames are rejected.

Integer computations use the existing leaf value forms/NOPs and preserve X18-X30/SP; canonical direct BL is the only body operation allowed to update LR. Body branches and indirect calls are excluded. Callees may be another selected framed function or an existing verified register-only leaf; leaf internal control flow remains acyclic and may branch. A framed function need not contain a call.

The registry contains 1-32 framed functions and 0-256 leaves. Framed ranges are sorted, disjoint from each other and all leaves, and reachable from the selected root. The complete call graph must have no cycles/recursion and a maximum framed depth of 16. Verification computes each function's depth, maximum stack demand, and retirement bound, including every repeated call site and each leaf's longest path. Bounds above 1,000,000 instructions are rejected. Native registration independently validates metadata shape, targets, reachability, depth, and retirement ranks; trusted generated metadata is still required, not an arbitrary serialized callback table.

## Registry generation

The existing `tools/prepare_registry.py` accepts schema version 2 for this profile. `frames` lists explicit records with `name`, `module`, `offset`, and `size`; `root` names one of those records. `leaves` is an explicit list that may be empty. Return sites and optional stack bounds follow the same rules as [hash-bound registries](bound-dispatch.md). Schema version 1 keeps its earlier leaf/single-caller behavior.

For example, the tests prepare a synthetic NSO with the following selections (these are artificial fixture offsets, not game function identities):

```json
{
  "schema_version": 2,
  "root": "stack_caller",
  "frames": [
    {"name": "stack_caller", "module": "main", "offset": 16, "size": 40},
    {"name": "stack_child", "module": "main", "offset": 64, "size": 32}
  ],
  "leaves": [{"name": "stack_remainder", "module": "main", "offset": 96, "size": 12}],
  "return_sites": [536870912],
  "stack_size": 4096
}
```

Generation performs a fresh verified complete offline link, verifies every selected range, and writes a matching `image.ootmem`, `registry.c`, and `manifest.json` to a fresh directory under `build/`. The emitted `oot_create_bound_registry` returns an `OotStackDispatcher *`. Compile its source with `src/` includes and link the CMake `oot-stack-dispatch` target, which carries the required leaf/image/memory/host/BCrypt dependencies. The host application's mapping command remains data-only.

## Execution, ownership, and commit

`oot_stack_create` copies descriptors, step tables, hashes, and approved external return tokens; it retains the image and validates each current text range against its compiled hash and the expected initial package body identity. Native code pointers come only from trusted compiled symbols. Keep that code module loaded until its contexts are destroyed. Writable stack/data can evolve without changing the initial identity tag.

`oot_stack_begin` requires the selected root entry, matching approved X30/return token, canonical NZCV, and aligned SP with room for the root frame inside the image's stack. A direct call checks the target's current code and the callee's stack space before retiring BL. Root entry does not reserve the complete maximum stack demand: a tighter stack may execute a valid prefix and reject a deeper call. Internal continuations are derived from verified BL sites and are never external entry permissions.

The dispatcher holds an explicit activation array of at most 16 frames. Each records entry state, expected return, frame base, and owned frame bytes. Calls and returns push/pop this array without recursively invoking native dispatcher functions. A separate bound leaf context handles register-only callees. One shared guest instruction budget covers all root, framed-child, and leaf instructions; call/return transitions themselves add no extra retirement.

Every framed instruction runs on a private integer state and a shadow copy of only its current frame. Before commit the dispatcher checks exactly one retirement, the expected status and PC, canonical NZCV, preserved X18-X28, the precise FP/LR/SP transition, and absence of ignored memory faults. An opening store may change only the saved pair and must save the original FP/LR. A local store may change only its declared byte span. Other steps must not change shadow bytes. Passing stores commit through the checked whole-access scalar/pair backend; rejected steps leave native backing and the last architectural checkpoint unchanged.

All owned bytes, including locals and saved registers, are checkpointed after a valid store. Before execution/resume the dispatcher checks every active ancestor/current frame; host edits to any owned byte are rejected. Active framed code is rehashed on resume, callee code before entry, and leaf code by the bound leaf dispatcher. The canonical restore releases ownership of that frame, preserving its old bytes in memory. Child activations cannot access parent locals or pass stack pointers to memory-using callees under this profile.

Input/state/hash/stack-space rejections retire no affected instruction and allow repair/retry. Native callback contract failures latch until `oot_stack_abort`. Abort discards dispatcher ownership without undoing an already retired prefix. Completed calls are idempotent and reusable through begin. Begin/run/abort/destruction reject reentry while executing a callback. Image references, metadata, and contexts are single-threaded; the flag is not a lock. These checks do not sandbox hostile C or prove arithmetic equivalence for every input.

## Validation and next boundaries

```powershell
.\.venv\Scripts\python.exe -B tools/stack_validation.py
.\.venv\Scripts\python.exe -B tools/stack_validation.py --compiler gcc
```

The deterministic suite validates 128 complete three-level call cases, including repeated child calls, scalar/pair local transfers, signed loads, and leaf calls. It compares all integer registers, SP/PC/NZCV, retirement, complete stack bytes, and an independent arithmetic result with Unicorn 2.1.4. Four cases also compare all 296 individual retired prefixes. Zero, single, short, and unlimited budgets are exercised. A separate 16-level graph with 256-byte frames consumes exactly the synthetic 4096-byte stack and matches reference execution.

Negative cases cover current/ancestor frame edits, local-byte edits, active/ancestor/leaf code changes, checkpoints, a callee that would cross the stack lower bound, cyclic/unregistered call metadata, invalid store scopes, nine intentionally faulty callbacks, reentry, failure latching, image lifetime, and abort behavior. Synthetic NSO bundle tests compile and execute the actual schema-2 factory, including a registry with no leaves, reject another initial snapshot, and verify source/hash/output preservation. Reports and generated artifacts stay under ignored `build/stack-validation/` and `build/lifter-validation/`.

The separate [framed CFG policy](stack-cfg.md) adds acyclic branches and explicit scalar/pair X19-X28 saves without changing this linear profile. Loops, other prologues, dynamic stack allocation, shared/global/heap memory effects, pointer arguments, recursion, indirect calls, PAC/system/SIMD semantics, startup, host services, and rendering remain separate boundaries. These profiles are structural evidence for deliberately bounded subsets, not a recovered process ABI or a playable game port.
