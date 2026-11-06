# Checked reads from retained images

Policy `checked-read-pauth-stack-dag-v5`, selected by registry schema 6, extends the [PAC frame policy](pauth-stack-dispatch.md) with explicit checked reads. Policies 1-4, their constructors and descriptor layouts, state ABI 2, and the separate PAC callback ABI remain unchanged. Stores still use the existing frame-local staged-write contract. This milestone does not enable process startup or game callbacks.

## Structural proof and runtime obligations

The verifier accepts implemented integer scalar loads with unsigned, unscaled, or register offsets, PC-relative LDR/LDRSW literals, offset LDP/LDPSW, and no-offset LDAPR/B/H. Loads must have no writeback. Destinations may be X0-X17, explicitly saved X19-X28, or ZR. They cannot overwrite SP, FP, LR, X18, or an unsaved protected register. Constant SP/FP accesses must stay within unreserved current-frame locals. Dynamic addresses remain runtime obligations; accepting a region structurally does not prove a pointer's value, alignment, or readable lifetime.

`OotStackReadFunction` wraps the PAC descriptor and supplies one exact opcode for each READ step, with zero at other steps. Native registration validates the decoded effect and register mask and compares each read word with the original hash-bound image text. It copies this metadata and the read ranges. Trusted compiled symbols supply callbacks; no guest address becomes a native function pointer.

Every complete operand must lie in either:

- Unreserved bytes of the currently owned frame, including an alias through a general register. Saved registers and the FP/LR record remain inaccessible to ordinary loads.
- One explicitly granted read range contained in one readable retained-image region. Text/literals, rodata, data, and BSS are eligible; adjacent capabilities cannot be joined for a single access.

All other stack bytes, including ancestor locals, are excluded. SP/FP-based reads cannot escape the current frame. There are 1-128 sorted, disjoint, nonempty external ranges; each must lie below the image's stack and entirely within one mapped readable region. The dispatcher retains the image and immutable PAC context across yields. Heap allocations, external buffers, MMIO, external stores, and guest threading are outside this ownership model.

## Capturing and committing a read

Before invoking the callback, the dispatcher decodes the effective address from the private working state, checks the complete range and ownership, and performs one actual image read through the checked backend. Pair loads use one paired transfer. RCpc loads use the real acquire API and retain its natural-alignment and SP-alignment preconditions. Ordinary scalar and pair loads retain their existing unaligned-access rules.

The dispatcher copies only the 1-16 operand bytes into a private read-only memory window and independently computes the expected register result, sign/zero extension, and next PC. The callback receives this window rather than the image or an ancestor frame. Before commit, the dispatcher validates the entire resulting register/SP/PC/NZCV state, retirement and edge contract, snapshot bytes, and window metadata, in addition to existing frame checkpoints. Stores continue to use a separate private frame window and existing transactional commit checks.

The actual source capture is the read's observation point. The callback's backend read touches only its private snapshot. All real scalar/pair/acquire transfers share the [serialized Normal-memory backend](ordered-loads.md); this preserves its stronger ordering contract without claiming every Arm weak-memory outcome. These APIs and image ownership remain single-threaded. Native callbacks are trusted code, and the checks are not an isolation mechanism against arbitrary native writes.

A capability/ownership failure returns REJECTED with `OOT_STACK_BAD_READ_RANGE` (52) before calling the callback. An underlying alignment/access fault returns REJECTED with `OOT_STACK_BAD_MEMORY` (50). Neither retires the failed instruction or changes its guest state/frame. Incorrect callback results or snapshot edits latch a contract fault, normally `OOT_STACK_BAD_READ_EFFECT` (53); existing count, status, edge, and memory errors keep their codes. Earlier successful instructions remain retired. Writable image data may evolve between yields: the next read captures current bytes, without comparing them with the initial snapshot or reusing an old capture.

## Explicit schema-6 bundle

Schema 6 uses the existing prepared-input/complete-link path, explicit framed/leaf selections, and the same `oot_create_bound_registry(image, pauth, error)` factory signature as schema 5. It additionally requires `read_ranges`, selected by module-relative byte offsets:

```json
{
  "schema_version": 6,
  "pauth_model": "qarma5-va39-tbi0-basic",
  "root": "root",
  "frames": [{"name": "root", "module": "main", "offset": 16, "size": 40}],
  "leaves": [],
  "return_sites": [4297097216],
  "stack_size": 4096,
  "read_ranges": [{"module": "main", "offset": 8448, "size": 8}]
}
```

These are illustrative synthetic selections, not game addresses. `tools/prepare_registry.py` validates ranges against exact linked segment/BSS regions, sorts and rejects overlaps, and emits the capability table, descriptors, original-byte hashes, and a manifest recording runtime address checks. It supplies no keys and grants no permissions merely because a function passed the verifier. Output remains in a fresh ignored build directory. The native constructor is `oot_stack_create_reads`.

## Validation and static survey

```powershell
.venv\Scripts\python.exe -B tools/read_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools/read_validation.py --compiler gcc
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --reads --report build/function-profiles/oot111-checked-reads-v5.json
```

MSVC and GCC pass 205 whole-call cases and 2,620 instruction-prefix comparisons with pinned Unicorn 2.1.4 using enabled QARMA5 and FEAT_LRCPC. Independent expected results also check arithmetic and load values. Forty-nine load programs cover addressing forms, signed widths, aliases, discarded results, register extensions/scaling, pairs, literals, unaligned ordinary loads, and BSS. Nested calls, all 16 frames filling a 4,096-byte stack, 11 malformed callback modes, reserved/ancestor stack reads, capability boundaries, alignment faults, metadata/text mismatches, evolving data, and copied/retained ownership are covered. Actual schema-6 ordinary and RCpc factories pass on both compilers. Executed bytes, data, and keys are synthetic.

The fresh local 1.1.1 survey retains all source/text hashes and discovers 127,551 semantic regions from 284,396 metadata entries. Policy 4 still accepts 1,686 candidates; policy 5 structurally accepts 1,688, containing 13,519 declared words. These results use unchanged bytes and real verified callee closures. No runtime read ranges are supplied by the survey, so its accepted read regions remain conditional on runtime checks. It generates no C, registers no native callbacks, and executes no game code. See the [aggregate survey](function-profile-survey.md).

The separate [LR-pair policy 6/schema 7](lr-pair-frames.md) reuses this read contract for mixed calls with FP-preserving frames. Policy 5, its descriptor/constructor, and its allowed frame shapes remain unchanged.
