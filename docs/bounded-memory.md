# Bounded memory loops and writeback

Leaf policy 3 (`bounded-memory-leaf-v3`) and stack policy 10/schema 11 add scalar/pair writeback and one conservative counter-loop shape to the bound memory-callee model. Ordinary leaf policy 1, memory-leaf policy 2 and stack policies 1-9 keep their original constructors and permissions. Game surveys use unchanged linked bytes and real callee proofs; validation executes synthetic code only.

## Effects and loop shape

A policy-3 leaf contains 1-256 original words, at least one implemented integer memory effect, standard `RET X30` exits and no function calls. It preserves X18-X30 and SP. Load destinations and writeback bases must be X0-X17, with ZR allowed as a transferred value. SP/FP memory bases, constrained-unpredictable base/transfer overlap, vector/FP, atomics/RMW, device/tagged memory and nonlocal returns remain excluded.

The new effect helpers admit the implemented scalar immediate pre/post-index and W/X paired pre/post-index forms, including signed loads and LDPSW where the encoding permits them. Offset, unsigned/unscaled/register-offset, literal and aligned no-offset RCpc forms retain their existing semantics. The old checked-read/write decoders still reject writeback. Every operand uses pre-instruction source values; pre-index uses the updated address, while post-index accesses the old address. A rejected scalar/pair access publishes neither destinations nor base writeback.

Acyclic policy-3 helpers use the existing closed-DAG proof, including acyclic backward layout edges. A cyclic helper must have exactly one backward edge, from a conditional latch to the loop header. The contiguous header-to-latch body otherwise falls through one instruction at a time. All other edges point forward, no outside edge enters the body interior, and the body contains a memory effect. Prefixes may initialize the counter and suffixes may change it after the loop.

The counter is a W/X register in X0-X17. The sole body writer is `SUB`/`SUBS counter,counter,#positive-immediate`, including the shifted-immediate form. The latch is matching-width `CBNZ counter` or `B.NE` driven by `SUBS`. For B.NE, no later body instruction may write NZCV; flag-preserving loads, stores and computations may occur between the decrement and latch. Multiple loops, internal body branches, other counter writers, side entries and unproved cycles remain rejected.

## Admission, bounds and yielded state

At the first loop header, before its instruction or memory effect, runtime reads the current width-masked counter and decrement amount. The count must be positive, divisible by the decrement, and represent at most 1,024 iterations. This permits a prefix to compute or load the count before admission. A matching preceding CBZ may bypass the loop for zero; zero is never admitted at the header. For W counters, admission uses the low 32 bits, ordinary body steps preserve the full X value, and the declared W decrement clears its upper bits exactly.

The dispatcher checks the counter on every body step. Only the bound decrement may change it, and that instruction's full expected state is calculated independently. The latch and recognized zero guard must produce the exact expected branch and unchanged remaining state. Every post-decrement B.NE step must preserve NZCV. These checks precede any real store commit, so a callback cannot reset a counter or alter flags to commit extra iterations.

`OotLeafStep.max_steps` remains a 16-bit rank for the DAG obtained by cutting the sole declared backward edge. `OotLeafFunction.max_steps` carries a separate 32-bit retirement bound: `N + (1024 - 1) * loop_span`, where N is the declared instruction count. Acyclic helpers use the ordinary DAG bound. A global retirement ceiling is checked before another callback and survives every yield. Zero and single-instruction budgets preserve the same checkpoint and ownership rules as the preceding policies.

Header admission failure (leaf error 21) retires no header instruction and does not latch a callback fault. Earlier retired prefix effects remain present. The checkpoint cannot be edited to repair the count; abort/restart is required to supply different register state. A loop/control violation (22) or exhausted retirement ceiling (23) latches a contract fault before another store can commit. Existing memory range/backend failures retain their nonmutating per-instruction behavior. The project models deterministic whole-transfer faults rather than hardware partial stores.

## Binding and integration

`OotBoundedLeafFunction` wraps the unchanged memory-leaf descriptor with the full original word table and copied `OotLeafLoop` metadata. The native constructor checks bounded indices, loop/CFG/rank shape and original decrement/guard/latch words, binds every word and effect to exact retained read-only text, and copies all metadata. A mixed registry may also contain ordinary and policy-2 leaves through their unchanged descriptor prefixes. Old leaf constructors reject policy 3; `oot_leaf_dispatcher_create_bounded_bound` is an explicit bound-only entry point.

`oot_stack_create_bounded_callees` and schema 11 add explicit `bounded_leaves` selections beside `leaves` and `memory_leaves`. Combined terminals remain limited to 256. Framed caller CFGs stay acyclic with the existing 32-function, 128-word, 16-256-byte and 16-activation limits. A bounded leaf adds no frame/depth slot; its conservative bound and all four original PLT instructions contribute to caller retirement bounds.

The existing copied image read/write grants remain separate and bounded. Each complete operand must fit inside a single grant; grants may serve repeated transfers, but adjacent grants are never combined for one transfer. All caller and ancestor stack bytes remain excluded from leaves, including unreserved locals. Schema-11 write grants cannot overlap any registered PLT GOT slot. Exact stub/target hashes, live single-target GOT binding, signed LR, PAC keys, frame ownership and checkpoints remain checked through direct/PLT calls and every yield. Images/keys and copied descriptor lifetimes follow the previous contracts. Native callbacks are trusted compiled symbols; no guest PC is cast to a native pointer and the operand protocol is not a security sandbox.

## Evidence pipeline and static scope

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config config/milestones/bounded-memory.json `
  --output build/milestones/bounded-memory-v1
```

The runner selects complete MSVC CTest/Python validation and GCC common/new/preceding memory suites, fresh default/PLT surveys, the `--bounded-memory` survey and the policy-6 callee audit. Old per-module default/PLT outcomes must stay unchanged. Shared policy-9 profile outcomes, including retained accepted/rejected samples, must match the passed callee baseline on input/text hashes, metadata denominator, limits, decoder and PAC model. Prior-frontier comparison checks only its three exhaustive aggregate counts: blocked roots, unique targets and caller-region/target edges. It does not compare frontier target samples or establish identity-by-identity equality. Zero lost previous memory candidates/accepted roots is checked from the actual current production maps. A final source fingerprint must match `run.json`; source changes or failed/skipped/stale evidence prevent completion.

Synthetic fixtures cover 72 scalar/pair writeback combinations and 20 loop variants, W/X counters, CBNZ/B.NE, zero guards, prefix initialization, shifted/strided decrements, post-decrement stores, boundary counts, single-instruction yields, full-depth mixed callees, malformed metadata/callbacks, permission/range faults, retained lifetimes and actual schema-11 factories with both PAC keys and return styles.

The full `build/milestones/bounded-memory-v1/run.json` reports all stages passed with an unchanged source fingerprint. Native validation passes 357 Python tests without skips, six CTest groups and 283,401 common native/reference comparisons per compiler. On each of MSVC and GCC, the bounded-memory suite checks 865 whole calls and 17,145 instruction prefixes; actual schema-11 factories add 128 whole calls and 6,496 prefixes. Fresh default/PLT/bounded-memory surveys, the policy-6 audit and baseline comparisons also pass. Native reports, surveys, comparison data and summaries remain private in that run directory.

The fresh original-byte survey preserves all 16,805 policy-2 memory-leaf candidates and finds 554 additional regions: 251 acyclic writeback helpers and 303 bounded loops. Of the new regions, 364 use writeback, including 113 loops. Framed acceptance rises from 2,858 to 2,868 roots; upgraded closures use 12 distinct new leaves and 20 unique call edges. Five used leaves contain bounded loops, reached by two upgraded roots; the other seven are acyclic writeback helpers. These are structural proofs with header-count, image-grant and live-GOT obligations. They do not establish original function identity, heap support, process startup or gameplay readiness. Full addresses/reports remain private under `build/`; surveys generate no game C, register no callbacks and supply no runtime capabilities. See [aggregate profile results](function-profile-survey.md).
