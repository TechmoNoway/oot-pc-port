# Register-only leaf verification

This milestone establishes a conservative structural boundary for small code regions and validates complete synthetic functions. It does not establish the identity of original game functions, discover a process startup ABI, or execute game code.

## Policy and preconditions

`leaf_verifier.verify_leaf` accepts an explicitly bounded raw region of at most 256 aligned ARM64 instructions. Every declared word must decode to an implemented instruction, belong to the permitted register-only subset, and be reachable in the conservative direct control-flow graph. Every path must stay inside the declared region until a standard `RET X30`; calls, other indirect branches/returns, data accesses, external edges, fallthrough beyond the range, and cycles are rejected.

The allowed value-producing forms are the implemented moves, integer arithmetic/logic, extended/carry arithmetic, conditional selects, shifts, bitfields, multiply/divide, and PC-relative addresses. NOP and direct branches are allowed. X18-X30 and SP must not be written; source reads of those registers are permitted. NZCV and scratch registers X0-X17 may change. These restrictions deliberately exclude normal stack frames, pointer authentication, and functions that save/restore protected registers. A rejected region is outside this policy, not necessarily invalid ARM64 or a broken game function.

The reported instruction bound assumes entry PC equals the declared base, canonical NZCV, and X30 outside the declared range. The raw lifted function remains a budgeted loop. `--verify-leaf` now also emits a compiled-symbol descriptor for the [controlled dispatcher](leaf-dispatch.md), which enforces runtime guards when the descriptor is registered and invoked through that API. Direct calls to the raw lifted symbol still require the caller to enforce preconditions. A return token is not proof of a future executable target or a complete process startup ABI.

The verifier records SHA-256 of the exact range, form counts, return count, longest conservative path, per-instruction successor/rank metadata, policy name, and preconditions. It rejects unreachable padding/data instead of silently trimming it. Branch-condition correlations are not solved; both conditional successors are considered conservatively.

## Verify before emitting C

```powershell
.\.venv\Scripts\python.exe -B tools/lift_arm64.py build/synthetic-leaf.raw `
  --base 0x1000000 --verify-leaf `
  --output build/leaf/synthetic.c --report build/leaf/synthetic.json
```

All existing raw-range/output rules still apply. A policy failure leaves no partially emitted C file. The report embeds `leaf_verification` and names the descriptor getter. The generated C includes that getter, a pointer to its compiled lifted symbol, and constant CFG metadata; it does not cast the guest entry to a native pointer. ABI/policy mismatches fail compilation or registration. This structural result is separate from proving mathematical behavior for all inputs or proving that the selected range matches one original source function.

## Complete synthetic functions

The native validation suite includes six artificial leaves:

| Function | Independent expected result |
| --- | --- |
| Arithmetic mix | Wrapped addition, XOR mask, variable rotate |
| Signed minimum | Signed W comparison and conditional selection with W zero extension |
| Extract/insert | Extract a field and insert it while retaining the destination's other bits |
| Signed remainder | Signed divide and multiply-subtract, including zero divisor and overflow boundary |
| Wide addition | Carry propagation from a low-word sum into a high-word sum |
| Conditional diamond | Both paths and both returns of a small branch graph |

Each is structurally checked before C emission, then compiled with MSVC or GCC. There are 768 complete mathematical result trials across boundary values and deterministic random operands, plus zero/partial-budget trials. All integer state, flags, PC, and retired counts are also compared with Unicorn ARM64. Together with individual-instruction and memory tests, the milestone has 72,764 comparisons across 27 programs. Only synthetic instructions execute in validation.

## Static survey of prepared images

```powershell
.\.venv\Scripts\python.exe -B tools/survey_leaf_functions.py build/prepared/oot111 `
  --report build/leaf-survey.json --samples 64
```

The survey verifies prepared inputs and requires a complete offline link. Roots come from the module entry, supported unwind lookup entries, and defined function symbols. Each candidate is bounded by the next metadata root, text end, any declared symbol size, and the policy word limit. It follows permitted direct edges, determines the visited span, and runs the same verifier on that exact span. Reports include accepted/rejected counts and bounded samples with range hashes. No C is emitted and no game instructions execute.

The local 1.1.1 survey finds 40,038 candidate regions meeting this structural policy: rtld 5, main 38,511, subsdk0 29, sdk 1,493. These counts include trivial return stubs and other metadata candidates. Metadata is not proof of original function ownership; conservative windows can reject otherwise valid leaves or identify a closed subregion. Counts do not measure gameplay progress or universal semantic correctness.

The [controlled leaf dispatcher](leaf-dispatch.md) now enforces these contracts and passes synthetic caller/callee tests. Binding registry provenance to mapped image hashes and handling broader function profiles remain separate boundaries before game candidates can be considered for execution.
