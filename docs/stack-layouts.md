# Fixed stack allocation and offset frame records

Registry schema 4 opts into `fixed-layout-stack-dag-v3`, a separate function policy for split stack allocation, offset FP/LR records, and sparse callee-save slots. It uses the existing explicit activation stack, acyclic CFG/call graph, checked shadow-memory commits, hashes, and instruction budgets. Earlier schemas and descriptor layouts retain their existing policies. Validation executes only synthetic code.

## Recognized shapes

The split shape allocates the complete fixed frame first, then saves the original FP/LR at an aligned offset:

```text
sub sp, sp, #N
stp x29, x30, [sp, #R]
... fixed SP-based X19-X28 saves may precede FP setup ...
add x29, sp, #R
... remaining fixed saves, then the body ...
... reverse callee-save restores ...
ldp x29, x30, [sp, #R]
add sp, sp, #N
ret x30
```

`N` is a fixed multiple of 16 from 16 through 256 bytes. `R` is a nonnegative multiple of 8 whose complete 16-byte record lies inside that frame. Save groups may appear before or after the single FP setup, but the FP/LR save must precede it. FP-relative addressing before FP setup is rejected.

The profile also recognizes a combined opening `stp x29,x30,[sp,#-N]!` and closing `ldp x29,x30,[sp],#N`, with record offset zero. Its X19-X28 saves can precede or follow FP setup and use sparse slots. Mixing split and combined functions in one bounded call graph is supported.

Callee saves use fixed 64-bit scalar or paired transfers of distinct X19-X28 registers. Each slot must be 8-byte aligned, inside the frame, and disjoint from FP/LR and all other save slots. Restores match the same groups/offsets/register order in reverse group order. Gaps between slots are allowed. All registers remain protected through the save prefix; the body may change only the saved subset, and restores must recover the original entry values.

The body retains closed acyclic `B`, `B.cond`, `CBZ/CBNZ`, `TBZ/TBNZ`, and explicit direct calls to selected framed functions or register-only leaves. Every declared word must be conservatively reachable. Branches can reach the body or the first shared-epilogue instruction; they cannot skip restores or jump directly to stack deallocation/RET. Limits remain 32 framed functions, 256 leaves, 128 words per framed function, 16 framed activations, and a weighted longest-path bound of 1,000,000 retired instructions.

## Local addressing and reserved slots

Memory metadata normalizes every supported access to an offset from the allocated frame base. SP refers to that base; FP refers to `frame_base + R`. Supported scalar/pair local transfers may therefore use negative FP-relative offsets, including unscaled scalar addressing, while remaining inside the current frame. Other bases, dynamic offsets, and body writeback remain excluded.

Locals can occupy any frame bytes outside the reserved FP/LR and callee-save slots. An access must fit completely within the frame and overlap no reserved byte. Save-slot reads by ordinary body loads are rejected as well as writes. `locals_begin` is zero in this profile and does not describe a contiguous unprotected area; the manifest records `reserved_ranges` explicitly.

For example, a 96-byte frame can place FP/LR at `[80,96)`, X19/X20 at `[48,64)`, and X21 at `[72,80)`. Body locals can then use `[0,48)` and `[64,72)`. An access through `[x29,#-16]` reaches frame offset 64. Nested callees preserve the caller's actual current FP value, including its nonzero record offset.

## Per-instruction state and ownership

`OotStackLayoutFunction` extends the unchanged CFG descriptor with copied post-instruction state metadata, the record offset, and a zero reserved field. `oot_stack_create_layout` checks the layout, all normalized access spans, disjoint slots, save/restore pairs, CFG edges/ranks, and exact post-state/ownership transitions before accepting trusted compiled callbacks. The older constructors reject policy-v3 descriptors.

The state table declares SP as frame-base or entry SP, FP as frame-record address or original FP, LR as unchanged/original/call continuation, and frame ownership as unchanged/claim/release. Native registration independently derives and validates these states from the declared step shape; they are not arbitrary permissions supplied by a file. As with other profiles, code pointers come from compiled symbols only and the compiled module must remain loaded while a context exists.

The complete frame becomes owned after a successful `SUB SP` or combined opening store, even before FP/LR is saved. Uninitialized local bytes are preserved and checkpointed, not zeroed per call. Each instruction runs on private integer state and a shadow frame. Saves must store exact original values, ordinary stores may change only their declared local span, and all other instructions must leave shadow bytes unchanged. Passing writes use whole-access checked scalar/pair commits.

After split `LDP FP/LR`, SP still refers to the allocated frame base. The entire frame remains owned and checked across yields until the following `ADD SP` succeeds. Only that deallocation releases ownership. A failing save, restore, allocation, or deallocation instruction leaves the last committed state/backing unchanged and latches a callback-contract fault. Abort discards dispatcher ownership without undoing the already retired prefix or performing an implicit unwind.

Image/range hashes, current/ancestor frame checkpoints, retained image lifetime, exact resume state, approved returns, shared budgets, and single-threaded reentry rules remain in force. This is a structural policy for trusted generated C, not a sandbox or universal proof of instruction semantics.

## Preparation and validation

Use the same explicit frame/leaf selections, named root, returns, and optional stack fields as [schema 3](stack-cfg.md), changing `schema_version` to 4. Preparation freshly verifies and links inputs, then emits matching `image.ootmem`, `registry.c`, and `manifest.json` in a fresh ignored `build/` directory. The generated factory calls `oot_stack_create_layout`; link its source with `oot-stack-dispatch`. Generation and the host's image-mapping command do not execute game selections.

```powershell
.\.venv\Scripts\python.exe -B tools/stack_layout_validation.py
.\.venv\Scripts\python.exe -B tools/stack_layout_validation.py --compiler gcc
```

Both native compilers compare 128 three-level mixed-layout calls, 72 cases across nine layout variants, and a 16-frame mixed chain consuming exactly 4096 stack bytes against Unicorn 2.1.4. Independent formulas, full integer/flag state, retired counts, and whole-stack bytes are checked. The main branch paths retire 26 or 61 instructions and attain the computed bound of 61. Another 696 individual instruction prefixes cover allocation, offset saves, delayed FP setup, negative FP-relative accesses, sparse slots, all ten saved registers, restores, and deallocation.

Negative checks cover mismatched allocation/deallocation, invalid record/FP setup, overlap and bounds, FP use before setup, forbidden body/save accesses, branch entry/cycles, malformed native state/slot/CFG metadata, copied metadata ownership, old-constructor rejection, and 12 deliberately faulty callbacks. Ownership is tested immediately after allocation and after record restore before deallocation. Schema-4 synthetic NSO tests compile the actual split/combined factories, exercise both paths, close the controller's original image reference before execution, and verify source/output/hash preservation.

Reports and generated artifacts stay under ignored `build/stack-layout-validation/` and `build/lifter-validation/`. Game callbacks remain unregistered. The next work is a static survey of function/layout coverage to guide further layouts, loop verification, wider memory/call support, remaining instruction semantics, process startup, services, and graphics.
