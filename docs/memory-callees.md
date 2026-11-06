# Memory leaves and checked callee closures

Leaf policy 2 (`acyclic-memory-leaf-v2`) and stack policy 9/schema 10 add direct and exact-PLT calls to verified unframed integer memory helpers. Earlier ordinary leaf and stack policies keep their original constructors and permissions. The milestone uses original linked bytes, actual callee proofs and synthetic native execution only; game callbacks remain ungenerated and unexecuted.

## Leaf contract

A memory leaf contains 1-256 original instruction words, at least one supported memory effect, a closed acyclic CFG and standard `RET X30` exits. Every declared instruction must be reachable. It preserves X18-X30 and SP, including across every yielded prefix. It cannot call another function, allocate a frame, sign/authenticate LR, use memory writeback, or use SP/FP as a memory base. Existing register computations and conditional/direct branches retain the ordinary leaf restrictions. A GPR computed from SP still cannot authorize a stack access.

The supported memory forms are the no-writeback integer forms from [checked memory](checked-memory.md): scalar unsigned/unscaled/register-offset loads and stores, sign-extending loads, offset W/X pairs and LDPSW, literal loads, and aligned no-offset LDAPR/B/H. Load destinations are X0-X17 or ZR; stores may read protected registers without changing them. Vector/FP, atomics/RMW, other ordering, tagged/device memory, loops and nonlocal/indirect returns remain excluded.

`OotMemoryLeafFunction` wraps an unchanged `OotLeafFunction` with an exact `effect_words` table. Policy-2 entries contain original memory opcodes at effect steps and zero elsewhere. The native constructor validates effect/CFG shape and destination restrictions, copies words/CFG/hashes, and binds every effect word to the exact retained read-only text. A mixed table may include ordinary policy-1 leaves with a NULL effect table. Old bound/unbound leaf constructors reject policy 2; the new leaf constructor is bound-only. Native callback addresses are trusted compiled symbols, never casts of guest PCs or deserialized pointers. Their code module must outlive the dispatcher.

## Memory effects and ownership

`oot_leaf_dispatcher_create_memory_bound` copies separate 0-128 read and write grant lists. Each nonempty range must fit wholly inside one appropriately permitted retained image region below the synthetic stack. Lists are sorted and disjoint within each access kind. An empty list grants no external access; a read grant never implies write permission and vice versa. One complete operand must fit in one grant, so adjacent grants cannot be joined.

The entire stack is excluded, including the current caller's unreserved locals, saved registers, signed LR and all ancestor frames. The framed caller's own policy-9 instructions retain the policy-8 local-frame access rules; its memory-leaf callees receive only explicit image grants. Heap/external buffers and a guest process ABI are not supplied by these capabilities.

For a load, the dispatcher captures the complete operand once through the real scalar/pair/RCpc backend, computes the exact expected state and gives the callback only a private read-only operand snapshot. For a store, it probes whole-operand write permission without reading backing, computes bytes from pre-instruction register values, and supplies a private write-only window initialized to the complement of the expected bytes. It checks the full state, window metadata, bytes, status, edge and retirement before committing through the real serialized scalar/pair backend. Normal steps get an empty window in policy 2; ordinary policy-1 callbacks keep their NULL memory argument.

Range rejection (leaf error 18) and backend rejection (20) retire nothing for that instruction and preserve its CPU checkpoint/backing. They do not latch a callback fault. Grant tables and checkpoint ownership remain immutable; changing a guest register requires aborting/restarting the call. Bad effects/window metadata (19), illegal accesses, status/count/edge or protected-register changes latch a contract fault. Earlier retired stores retain their effects. Whole-operand commit follows the project's deterministic fault policy, not hardware partial-store behavior. RCpc uses the existing naturally aligned serialized Normal-memory subset.

The standalone leaf dispatcher retains its image. The enclosing stack dispatcher retains its image and immutable PAC key context as before. All descriptors, effects, CFG and grants are copied across caller-storage changes and handle releases. Runtime/dispatcher APIs remain single-threaded; operand windows constrain the callback protocol and are not a native-code security sandbox.

## Framed and PLT integration

`oot_stack_create_memory_callees` accepts policy-9 frames using the unchanged copied call-descriptor layout, and a mixed table of ordinary and memory leaves. Schema 10 adds an explicit `memory_leaves` selection list beside `leaves`; combined terminal selections are limited to 256. Frames remain bounded to 32 functions, 128 words, 16-256 bytes and 16 simultaneous activations. A memory leaf does not consume another frame or depth slot. Weighted instruction bounds include the real leaf and all four PLT instructions.

An explicit `verify_memory_plt_stub` proves the unchanged relocation-backed ADRP X16 / LDR X17 / ADD X16 / BR X17 pattern with exactly one registered ordinary or memory-leaf target. Old PLT verifiers still require ordinary leaves. Native code binds stub/target hashes and exact words, verifies the current eight-byte GOT target before BL and throughout bridge/leaf yields, and preserves caller LR/SP/FP, PAC and frame checkpoints. Schema 10 rejects any write grant overlapping any registered eight-byte GOT slot, so guest instructions cannot change a binding through their own grants. External changes between yields remain detected by the live binding checks. No lazy binding, general indirect call, nonlocal continuation or service ABI is inferred.

## Delivery and evidence

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config config/milestones/memory-callees.json `
  --output build/milestones/memory-callees-v3
```

The runner builds the host/helper and performs complete MSVC CTest/Python validation, GCC common comparisons and both new/preceding memory factory suites. It runs fresh default/PLT surveys, the new `--memory-callees` survey and the policy-6 callee audit. Default/PLT per-module outcomes must match the preceding milestone; the new survey's shared policy-8 results must reproduce the prior memory baseline on identical source/text, metadata denominator, limits, decoder and model. Its classification must reproduce all three prior missing-frontier counts before reporting newly eligible targets. Source changes or stale/failed/skipped checks prevent completion.

The new synthetic suite exercises 60 store and 49 load fixtures, sign/zero extension, aliases and ZR, branches, RCpc values/alignment, independent bytes/results, changing data, separate/empty/adjacent grants, full operand bounds and pair isolation, 24 bad read/store callback modes, hash/effect metadata errors, GOT-overlapping grant rejection, old constructor rejection, retry, caller-stack denial and retained lifetimes. Mixed direct/ordinary/PLT execution and a 16-frame/4096-byte chain compare every CPU and stack/RW/BSS prefix with the pinned enabled QARMA5 reference. It checks 589 complete calls and 6,828 yielded prefixes per compiler. Two actual schema-10 factories add 160 calls and 4,320 prefixes per compiler with both PAC keys and return styles.

The game survey only proves structural regions with runtime obligations. Its cohort separates the global memory-leaf catalog, actual direct targets, exact eligible PLT snapshots, upgraded root closures, unique frame/leaf/edge unions, and overlapping root references. The prior and remaining missing frontiers distinguish unique targets, caller-region/target edges and discovery failure windows. Full addresses and reports remain private under `build/`; no runtime grants, live GOT guarantee, game compilation or execution is supplied. See [aggregate profile results](function-profile-survey.md).
