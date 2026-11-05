# Static function-profile survey

`tools/survey_function_profiles.py` measures the existing function policies against freshly verified, completely linked private inputs. It discovers bounded metadata-rooted regions, applies the actual production verifiers to unchanged bytes and real callee closures, and records why candidates are blocked. It emits a JSON report only: no C translation, native callback registration, or guest execution occurs.

## Run and reproduce

```powershell
.\.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --report build/function-profiles/oot111.json --samples 12
```

Use a fresh report path under `build/`; existing reports and prepared inputs are preserved. The CLI verifies prepared file sizes/hashes and performs a fresh complete offline link before analysis. Unresolved strong symbols, invalid linking, or changed prepared inputs prevent report creation. Reports contain private addresses, hashes, and samples and remain ignored. Only aggregate observations belong in project documentation.

The tool requires the existing pinned analysis environment. Capstone supplies syntax labels for unsupported encodings and diagnostic prefix observations; semantic support is decided by the independent project decoder and verifiers, not by successful disassembly.

## Scope and method

Seeds are the module entry, unwind-header entries, and defined function symbols. Duplicate entries are merged, and the smallest nonzero size among symbol aliases constrains their shared window. A window ends at the earliest of the next metadata entry, symbol-size boundary, exact text end, or `--max-words` limit (default 256). This matches the earlier leaf survey's metadata scope. Direct-call targets, relocated pointers, and initializer targets are not added as new seeds by this tool.

Discovery follows supported encodings and direct intra-window edges in deterministic fallthrough-first order. BL records a callee and follows only its continuation. Standard `RET X30` closes a path; unsupported encodings, out-of-window edges, and indirect boundaries block discovery. A region must have a reachable standard return, and its selected bytes span through the highest visited instruction. Production verification then checks all selected words, including unreachable gaps, cycles, memory/register effects, exact frame policy, and required call bounds.

Each profile is evaluated independently. Leaf callees are accepted only from actual byte ranges that passed `verify_leaf`. Framed dependencies are collected from real discovered candidates, bounded to the existing 32-frame registry limit, and verified together using the profile's production verifier. Unknown targets remain unregistered; no synthetic RET bodies, fake addresses, or relaxed policy substitutes are supplied. Root-only checks run first so an immediate local-policy failure does not require gathering unrelated callees.

Reports distinguish discovery-blocked candidates from evaluated regions and profile rejections. For every module/profile:

```text
metadata candidates = discovery blocked + profile accepted + profile rejected
```

Accepted counts overlap across profiles and must not be summed. Instruction-word counts cover accepted root regions, not repeated callee expansions. Failure categories and original reason histograms describe the first failure in this pipeline, not every defect or missing instruction in a candidate. Size-policy rejections include regions below a profile's minimum as well as above its maximum; they do not all mean oversized functions.

Prefix observations may look past up to four leading PAC/BTI syntax hints to describe the following allocation shape. This is diagnostic only. The original bytes, including those hints, remain unchanged for discovery and verification. Neither an observed frame pattern nor an unwind entry proves original function identity. Unvisited text is not classified as proven data.

## Local 1.1.1 snapshot

The 2026-11-06 survey of the local `rtld`, `main`, `subsdk0`, and `sdk` inputs produced these aggregate results:

| Stage/profile | Candidate regions |
| --- | ---: |
| Metadata entry candidates | 284,396 |
| Bounded regions reaching standard returns with supported discovery encodings | 58,638 |
| Discovery blocked | 225,758 |
| Register-only leaf policy accepted | 40,038 |
| Single framed caller to verified leaves accepted | 0 |
| Linear local-stack policy accepted | 0 |
| Framed CFG policy accepted | 0 |
| Fixed-layout policy accepted | 0 |

The leaf result contains 100,995 instruction words and exactly matches the prior independent leaf-survey count on the same inputs. Zero accepted framed candidates means no candidate passed this complete strict pipeline in the measured metadata/windows. It does not establish that all original game functions were discovered or that the newer frame implementations are incorrect: synthetic tests explicitly accept valid framed callers, nested closures, and sparse layouts through this same survey API.

Discovery blockers were 190,368 unsupported-encoding frontiers, 31,286 window boundaries, 4,099 indirect jumps, and five regions without a standard return. The first unsupported categories were:

| Category | Candidates whose first unsupported encoding has this category |
| --- | ---: |
| Pointer authentication | 168,784 |
| Atomic/ordered memory | 11,760 |
| Integer forms | 3,712 |
| Load/store forms | 3,564 |
| SIMD/FP | 2,045 |
| Other control flow | 356 |
| System | 83 |
| Supervisor call | 64 |

`PACIBSP` was the first unsupported encoding for 168,780 candidates; 142,476 entries had it in the leading-hint observation. `LDAPRB` was the next most frequent first unsupported mnemonic at 10,837, followed by LDR forms (2,379) and CCMP (1,364). These are early-stop frontier counts, not total instruction frequencies. Adding one missing semantic family may expose additional failures later in those regions.

Diagnostic prefix observations found 74,101 FP/LR pre-index stores, 57,766 SUB-SP allocations, 3,992 other pre-index stack-pair stores, and 148,537 other starts, including observations following leading hints. These observations do not increase accepted-profile counts. They help choose future layouts after the earlier semantic frontiers are addressed.

The immediate priority is a specified and independently tested PAC/authenticated-return model, followed by ordered/atomic memory semantics and a new survey. PAC must not be removed or treated as an unverified no-op to inflate coverage. Loop/layout, indirect-target, general memory, startup, service, and renderer requirements remain separate. These counts measure policy acceptance of candidate regions, not gameplay progress or permission to execute game code.

## Verification

Synthetic tests cover positive leaf and framed cases under all profiles, real transitive closures, unavailable callees, call cycles, metadata aliases/window boundaries, multiple returns, indirect boundaries, unreachable words, samples/limits, PAC-prefix rejection, source preservation, fresh-output checks, and tampered-input rejection. The full Python suite continues to run the native/reference profile tests; the survey itself remains static and does not compile or run candidates.
