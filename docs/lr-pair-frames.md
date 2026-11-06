# PAC calls with a preserved frame pointer

Policy `lr-pair-read-stack-dag-v6`, selected by registry schema 7, adds frames that save signed LR together with one X19-X28 register while preserving the caller's FP. A new `OotStackCallFunction` descriptor and `oot_stack_create_calls` constructor keep policies 1-5 and their descriptor layouts unchanged. This extends the [checked-read policy](checked-reads.md); it does not add external stores, arbitrary stack access, indirect calls, loops, or process startup.

## Frame and call contract

The new layout requires PACIASP/PACIBSP at entry, then a 64-bit pre-index STP of X30 and one X19-X28 register at `[SP, -frame_size]!`, in either register order. The frame is 16-256 bytes and 16-byte aligned. Optional additional X19-X28 saves use disjoint aligned SP-relative slots. No FP setup occurs: X29 retains its exact entry value throughout this activation. FP-based memory accesses are excluded in this layout. Local accesses use SP or checked general-register aliases under the existing read rules.

The epilogue restores additional saves in reverse order, then uses a matching 64-bit post-index LDP of the same LR/partner pair with the exact positive frame size. Authentication uses the entry key through RETAA/RETAB or matching AUTIASP/AUTIBSP followed by RET X30. Branches remain confined to the acyclic body or its first restore; they cannot enter signing, allocation, authentication, or the middle of the restore tail. An empty body is valid.

The initial pair reserves the first 16 bytes. Its callee-save partner joins the body's writable mask only after its original value has been saved. Ordinary loads/stores cannot touch those bytes or any additional saved slot. The closing pair must restore the original partner, this activation's exact signed LR, and entry SP while leaving FP unchanged. Caller-approved canonical returns and immutable PAC context ownership retain their earlier contracts.

Policy-6 closures may mix these frames with the existing split/combined FP/LR layouts and verified register-only leaves. Every framed member explicitly uses a policy-6 descriptor. There are no fabricated callees or cross-policy descriptor casts. The same real CFG/call proof limits registries to 32 framed functions, 16 activations, and finite weighted instruction bounds. While a leaf is active, the outer dispatcher checks SP/FP/LR against its actual suspended checkpoint, allowing a caller that preserves FP as well as one that establishes it.

## Native registration and retirement

`OotStackCallFunction` wraps the policy-5 descriptor and adds `open_word` and `close_word`. Both are zero for FP/LR layouts; LR-pair layouts declare the exact original opcodes. Registration independently checks pair width, addressing, SP base, register order, implicit partner, frame size, masks, ownership phases, and restore metadata. Both pair words must match the hash-bound mapped text. Descriptors, pair words, and explicit read ranges are copied; the image and immutable keys are retained across yields.

Opening saves run on the private frame window. Only after the exact original partner and signed LR have been validated does the dispatcher commit the paired store and claim the frame. A failed store leaves the opening instruction unretired and the guest state/backing unchanged. A retry resumes at the opening instruction after the already completed signing step. Closing loads are checked before releasing ownership. All current and ancestor frame bytes remain protected while allocated, including across mixed calls and yields. Callback contract faults latch; guest addresses never become native code pointers.

Checked external reads, Normal-memory RCpc acquisition, snapshot validation, capability bounds, image lifetime, and single-threaded dispatcher rules remain those of policy 5. Native callbacks remain trusted code. No additional memory permissions are inferred from the new frame shape.

## Schema 7 and validation

Schema 7 uses the schema-6 fields and explicit prepared-input/complete-link workflow. Set `schema_version` to 7 and retain `pauth_model: "qarma5-va39-tbi0-basic"`, exact frame/leaf selections, approved return sites, stack bounds, and nonempty explicit `read_ranges`. The generated factory remains `oot_create_bound_registry(image, pauth, error)` and supplies no keys. It emits policy-6 descriptors for all framed selections, including FP/LR helpers. Output must use a fresh ignored build directory. Only synthetic selections are compiled or registered in current validation.

```powershell
.venv\Scripts\python.exe -B tools/call_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools/call_validation.py --compiler gcc
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --lr-calls --report build/function-profiles/oot111-lr-calls-v6.json
```

Both native compilers pass 437 whole-call cases and 3,957 state/stack prefix comparisons with pinned Unicorn 2.1.4, enabled QARMA5, and FEAT_LRCPC. Independent formulas check results. Eighty programs cover all ten partner registers, both pair orders, both keys, and both return styles. Additional cases cover an empty 16-byte frame, all ten callee-save registers in one frame, conditional mixed LR/FP/leaf calls with checked acquire reads, partial budgets, and 16 alternating frames filling a 4,096-byte stack.

Negative cases check ten malformed callback modes, wrong/restored partner/FP/LR/SP, modified pair bytes, counts/status, read effects, metadata/text mismatches, wrong FP phases, missing implicit save masks, old-constructor rejection, opening-store failure and repair, ancestor edits, and copied/retained metadata/image/key lifetimes. Actual schema-7 mixed factories pass both return styles on MSVC and GCC. Executed code, inputs, and keys are synthetic.

## Static result

The local 1.1.1 run uses unchanged source/text hashes, 284,396 metadata entries, 127,551 discovered regions, and real callee closures. Both policy 5 and policy 6 accept **1,688 structural candidates (13,519 words)**. First unsupported combined-frame rejections decrease from 1,307 to 774, exposing later failures: policy 6 reports 16,458 call-dependency failures and 11,409 memory-policy failures. This milestone enables a native frame/call contract but does not yet increase fully accepted game candidates.

The survey grants no runtime read ranges, generates no C, registers no callbacks, and executes no game code. Its counts do not prove original function identity or gameplay coverage. Private reports remain under ignored `build/function-profiles/`. Missing callee coverage and permitted write effects remain separate work; the [aggregate survey](function-profile-survey.md) records the comparison.
