# Framed control flow and saved registers

`acyclic-saved-stack-dag-v2` adds closed acyclic control flow and explicit X19-X28 save slots to the framed-function dispatcher. Registry schema 3 opts into this profile through `oot_stack_create_cfg`. The existing leaf, single-caller, and linear-stack policies, descriptor layouts, and entry points retain their rules. Only independently generated synthetic functions are executed in validation.

## Shape and register ownership

Functions retain the fixed 16-256-byte aligned FP/LR frame and a single shared epilogue. Immediately after `mov x29,sp`, the verifier recognizes zero or more contiguous 64-bit scalar or paired saves of distinct X19-X28 registers, starting at frame offset 16. Pairs may use either register order. Saves use SP/FP and fixed offsets without writeback. The epilogue must restore the same groups, offsets, and register order in reverse group order before restoring FP/LR and returning through X30.

For example:

```text
stp x29, x30, [sp, #-80]!
mov x29, sp
stp x19, x20, [sp, #16]
str x21, [sp, #32]
... body, with locals beginning at offset 40 ...
ldr x21, [x29, #32]
ldp x19, x20, [x29, #16]
ldp x29, x30, [sp], #80
ret x30
```

All X19-X28 values must remain equal to entry state during the save prefix. The body may modify only the declared saved subset; X18, unsaved X19-X28, FP, and SP remain protected. Each restore removes its destination registers from the writable set and must recover their original full-width entry values. All saved registers are protected again at FP/LR restore and return. A child's entry snapshot captures its caller's current values, so nested calls restore those values before the caller resumes.

Save slots are separate from ordinary locals. Body loads/stores cannot read or overwrite saved slots, including through FP. Local transfers retain the previous checked scalar/pair rules and may load into a declared saved register. The shadow-window commit contract additionally checks that each save stores the exact original register values; other stores may change only their declared local span. Restores do not change memory. Current and ancestor frame-byte checkpoints include save slots and locals.

This is a conservative recognized layout. Gaps, arbitrary save order relative to computations, alternative FP/LR placements, multiple epilogues, dynamic allocation, and other prologues are not inferred.

## Closed acyclic CFG

Body control flow supports direct `B`, `B.cond`, `CBZ/CBNZ`, and `TBZ/TBNZ` with their existing lifted semantics. Targets must be aligned inside the body or at the first instruction of the shared epilogue. Branching into the save prefix, into the middle of the restore sequence, directly to RET, or outside the declared region is rejected. Every declared word must be reachable in the conservative CFG. Control-flow cycles and recursive call graphs are rejected. Architectural always/never conditions still use conservative structural successor sets; CFG verification does not prove branch-predicate arithmetic semantics.

Direct BL targets remain explicit selected framed functions or verified register-only leaves. An internal call's CFG successor is its continuation after the callee returns. The verifier computes a weighted longest path: one instruction plus the maximum successor rank, adding the callee's maximum retirement at a call site. Mutually exclusive paths use a maximum rather than summing their calls. All paths converge on the verified restore sequence. Registry limits remain 32 framed functions, 256 leaves, 128 words per frame function, 16 framed activations, and a maximum weighted bound of 1,000,000 instructions.

Native registration copies the common steps, new CFG steps, masks, and layout metadata. It independently validates ranges, successors, reachability, register-save/restore pairing, exact writable masks by phase, weighted descending ranks, and the acyclic call graph. Per-instruction execution accepts only the current step's declared successor(s), while preserving the existing private-state/shadow-memory commit, code hashes, explicit activation stack, instruction budgets, checkpoint ownership, and reentry rules. No guest address is cast to a native function pointer. These checks require trusted compiled callbacks and are not a sandbox or proof of universal semantic equivalence.

## Registry schema 3

Use the same explicit `frames`, `leaves`, named `root`, return-site, and optional stack fields as [schema 2](stack-dispatch.md), with `"schema_version": 3`. Preparation reads fresh verified prepared inputs, performs complete offline linking, verifies every selection under the new policy, and writes a matching image, C registry, and manifest to a fresh ignored `build/` directory. It does not execute selected game code.

The generated factory returns `OotStackDispatcher *` and calls `oot_stack_create_cfg`. `OotStackCfgFunction` contains the unchanged common descriptor plus a CFG table, saved-register mask, and local-area start. The policy-v1 constructor rejects these policy-v2 descriptors. Compile generated source with `src/` includes and link `oot-stack-dispatch`; retain the compiled code module until all contexts are destroyed.

Each `OotStackCfgStep` records up to two instruction-index successors, saved-register indices for save/restore steps, the weighted remaining-step bound, and the permitted post-instruction register mask. The return sentinel is `UINT16_MAX`. Metadata is compiled C, not a serialized format for native pointers. Image/range identity and retained-image ownership follow [bound dispatch](bound-dispatch.md).

Abort still preserves the retired prefix. In particular, it does not unwind a partially executed save sequence or restore already modified callee-saved registers automatically. A controller must establish a valid new entry state before beginning another call.

## Validation and next boundaries

```powershell
.\.venv\Scripts\python.exe -B tools/stack_cfg_validation.py
.\.venv\Scripts\python.exe -B tools/stack_cfg_validation.py --compiler gcc
```

Both native compilers validate 128 nested branch/call cases against Unicorn 2.1.4 and independent arithmetic results, with complete integer/flag state, retirement, and full stack comparisons. Paths retire 26, 34, 47, 48, 52, or 53 instructions and attain the verified weighted bound of 53. Another 272 cases exercise all 16 B.cond encodings with all 16 canonical NZCV states, plus a 256-byte frame saving/modifying/restoring all ten X19-X28 registers. In total 527 individual instruction prefixes are compared, alongside zero/single/short/unlimited budgets.

Negative tests cover branches into forbidden regions or cycles, unreachable words, bad save/restore pairs, unsaved-register writes, saved-slot accesses, call recursion/depth, malformed native CFG metadata, copied metadata ownership, changed saved/local bytes, active/ancestor/leaf code hashes, and 13 faulty native callback modes. The callbacks test staged saves/stores, wrong edges/count/status/flags, protected registers before saves and after restores, and ignored memory faults. Faults preserve the last committed state/stack and latch until abort. Schema-3 synthetic NSO tests compile and execute the actual factory across both paths, validate input/output/hash preservation, retain the image after its original handle is closed, and verify schema-2 rejection of the same selections.

Reports and generated artifacts remain under ignored `build/stack-cfg-validation/` and `build/lifter-validation/`. No game callbacks are registered. The separate [fixed-layout policy](stack-layouts.md) now supports split allocation, offset records, and sparse slots without broadening this policy. Further layouts, loop verification, nonlocal/indirect calls, general memory effects, PAC/system/SIMD semantics, process startup, services, and graphics remain separate milestones.
