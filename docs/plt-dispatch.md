# Checked PLT dispatch to verified leaves

Policy `plt-leaf-stack-dag-v7`, selected by registry schema 8, extends the [LR-pair policy](lr-pair-frames.md) with exact four-instruction PLT bridges to existing verified register-only leaves. Earlier constructors, descriptor layouts, state ABI 2, PAC ABI 1, and policies 1-6 retain their rules. This adds a bounded transfer contract; it does not provide a general indirect dispatcher, host-service ABI, process startup, or nonlocal returns.

## Exact original bridge and target

The only accepted stub is `ADRP X16; LDR X17, [X16, #low]; ADD X16, X16, #low; BR X17`. Both offsets must identify the same naturally aligned eight-byte GOT slot. Production preparation requires the existing relocation-backed stub recognition, a matching linked GOT snapshot, an explicitly selected verified register-only leaf, and a symbol outside the nonlocal-return set. The original 16 bytes are preserved, hashed, translated to C and registered as trusted compiled code. The stub is never replaced with a direct call or a fabricated leaf.

Native `OotPltFunction` metadata declares entry, slot, the single approved leaf target, callback, four exact words, and source hash. `oot_stack_create_plt` accepts policy-7 frames through the unchanged `OotStackCallFunction` layout plus a separate bounded PLT table. It independently checks the pattern/address calculation, sorted disjoint stub ranges, frame/leaf overlap, approved returns, registered target, and complete readable retained-image slot below the stack. Stub words must match the hash-bound read-only text. The original target leaf has its own pinned code hash. No guest address or serialized pointer is cast to native code.

Each registry permits 1-256 selected bridges, each targeting exactly one registered ordinary leaf. Several stubs may share a slot or target. There are still at most 32 framed functions, 256 leaves, 16 frame activations, and the existing weighted instruction bound. A bridge has no guest frame or additional activation; its call weight is four original stub instructions plus the real leaf's bound. Caller frames may use existing FP/LR layouts or preserve FP through an LR/callee-save pair.

## Running and suspending the bridge

BL retires normally, sets LR to the caller continuation, and enters the registered stub. Each of the four stub instructions then retires separately under the same instruction budget. ADRP/LDR/ADD effects on X16/X17 are preserved, and BR changes only PC. SP, FP, LR, NZCV, all other registers, signed frame records, and current/ancestor frame ownership retain their contracts. The final BR begins the approved leaf with the original BL continuation as its return site. The leaf's RET returns directly to the caller, without a synthetic extra return instruction.

Before committing the caller's BL, while the bridge is active, and across yields during its leaf, the dispatcher rechecks current stub/leaf text hashes and reads the GOT through the checked backend. The current slot must still equal the declared target, even if a different value names another registered leaf. The active bridge leases this exact binding until the leaf returns. Host updates may be observed between API calls, but changing an active binding rejects the next step until repaired. Runtime image, dispatcher and key APIs remain single-threaded; this does not establish guest threading or lazy-binding support.

The stub callback receives an empty checked memory view for ADRP/ADD/BR and a private read-only eight-byte operand snapshot for LDR. The GOT slot is a dedicated bridge capability, not a grant of general frame-read access to that address. The real source observation uses the existing serialized little-endian Normal-memory backend. Full expected state, status, edge, retired count, snapshot bytes and memory-view metadata are checked before commit. Native callbacks remain trusted code, not a security sandbox.

Wrong GOT contents return REJECTED with `OOT_STACK_BAD_PLT_TARGET` (54); inaccessible source memory uses `OOT_STACK_BAD_MEMORY` (50). Changed source/target code uses the existing image/code errors. Preflight failures leave that instruction and guest state uncommitted, while earlier successful steps remain retired; a repaired binding/permission can resume at the same PC. These conservative preconditions are a dispatcher boundary, not a claim about hardware fault timing for a broken binding. Bad callback effects latch a contract fault, normally `OOT_STACK_BAD_PLT_EFFECT` (55); existing count, edge, status and memory errors retain their codes.

The dispatcher copies PLT descriptors and retains the image and immutable PAC context. A caller may release its own image/key handles after construction. Compiled callback modules must remain loaded for the dispatcher's lifetime. `setjmp`, `_setjmp`, related signal variants and `longjmp` are excluded during preparation; their activation/continuation contract remains separate.

## Explicit schema-8 bundle

Use the existing prepared-input/complete-link workflow with `schema_version: 8`, the explicit PAC model, frame/leaf selections, approved returns, stack bounds and nonempty `read_ranges`. Add a `plts` array whose records select an exact stub and name its selected leaf:

```json
{
  "name": "helper_bridge",
  "module": "main",
  "offset": 192,
  "leaf": "verified_helper"
}
```

These illustrative synthetic values are not a game selection. Each stub is exactly 16 bytes; a supplied `size` must equal 16. The selected leaf must exist in `leaves` and match the relocation-backed GOT snapshot. `tools/prepare_registry.py` emits separate frame/stub descriptors, original-byte hashes, and `oot_create_bound_registry(image, pauth, error)`. The manifest records PLT selections and runtime GOT checks, never keys or native callback pointers. Use a fresh ignored output directory. Current validation generates and executes synthetic selections only.

## Validation and measured survey

```powershell
.venv\Scripts\python.exe -B tools/plt_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools/plt_validation.py --compiler gcc
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --plt --report build/function-profiles/oot111-plt-v7.json
```

Both compilers pass 114 whole-call cases and 2,145 register/stack prefix comparisons with pinned Unicorn 2.1.4 and enabled QARMA5. Independent formulas check results. Sixteen layouts exercise LR/FP frames, both PAC keys and return styles, negative ADRP deltas, stubs crossing a page boundary, low and end-of-region GOT offsets, and read-only/writable slots. Tests include nested calls, shared stubs with different caller continuations, direct leaves alongside bridges, zero/partial/large budgets, and 16 frames filling a 4,096-byte stack before a PLT call.

Sixteen bad callback modes check full state, X16/X17, SP/LR/NZCV, operand writes, empty-window access, memory metadata, counts, status and edges. Seven pause points cover the caller BL, all four stub instructions, and execution inside the target leaf. GOT edits, permission failures and repair, code/hash/word mismatches, alternate structurally valid metadata, forbidden targets/overlap/returns, old-constructor rejection, ancestor edits and copied/retained ownership are covered. Actual schema-8 factories run mixed frames and both return styles on MSVC/GCC. Executed inputs, code and keys are synthetic.

Fresh local 1.1.1 analysis preserves all module source/text hashes, 284,396 metadata candidates, 127,551 discovered regions and 156,845 discovery blockers. The global relocation-backed catalog contains **386 eligible leaf-directed stubs**; this is separate from a single registry's 256-bridge limit. All **72 stubs in the earlier missing-callee frontier** satisfy the new original-byte bridge verifier. The other catalog entries were outside that measured frontier; these counts must not be added or treated as functions unlocked.

The same static pass retains **1,688 policy-6 candidates** and accepts **1,703 policy-7 structural candidates**, containing 13,645 declared root words. The gain is 15 SDK candidates: main stays at 1,686 and SDK rises from two to 17. First call-dependency failures fall from 16,458 to 16,405, exposing additional memory-policy and registry/bounds failures. Static analysis supplies no runtime ranges or live GOT guarantees and generates/registers/executes no game callbacks. Private full reports stay under `build/function-profiles/`; see the [profile survey](function-profile-survey.md).

The later [CCMP/CCMN milestone](conditional-compare.md) adds flag-only semantics and validates their propagation through actual schema-8 PAC/PLT factories on both compilers. Its fresh static discovery reaches 130,808 regions and the global eligible catalog grows to 404, while policy-6/7 accepted counts remain 1,688/1,703. The preceding paragraphs record the original PLT milestone; current aggregate comparisons are in the [profile survey](function-profile-survey.md#after-conditional-comparisons).

The subsequent [widening-multiply milestone](long-multiply.md) exercises W-source/X-destination arithmetic and saved-register writes through actual schema-8 factories on MSVC/GCC. Its static survey reaches 133,760 regions, a 423-entry global eligible catalog and 1,710 accepted policy-7 candidates; policy 6 remains 1,688. These instruction additions preserve the original bridge/GOT, memory and ownership contracts.

The [reversal/leading-count milestone](bit-operations.md) additionally validates all scalar W/X variants through four actual schema-8 bundles, including full X19 restoration after W19 writes. Fresh static discovery reaches 135,020 regions and the global eligible catalog reaches 430; policy-6/7 acceptance stays at 1,688/1,710. Game callbacks remain ungenerated and unexecuted.

The [high-multiply milestone](high-multiply.md) validates signed/unsigned full-X products and ignored Ra fields through actual schema-8 factories on both compilers. Its static discovery reaches 135,390 regions and the eligible global catalog grows to 433, while policy-6/7 acceptance remains 1,688/1,710. The original bridge/GOT, memory, hash and ownership contracts are unchanged.
