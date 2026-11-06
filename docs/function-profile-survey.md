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

The [PAC/authenticated-return model](pointer-authentication.md) is now integrated through a separate [PAC-aware policy/dispatcher](pauth-stack-dispatch.md). PAC is never removed or treated as an unverified no-op to inflate coverage. Loop/layout, indirect-target, general memory, startup, service, and renderer requirements remain separate. These counts measure policy acceptance of candidate regions, not gameplay progress or permission to execute game code.

## Separate PAC policy survey

`--pauth` opts into the six implemented PAC/AUT/authenticated-return encodings during discovery and evaluates only `pauth-layout-stack-dag-v4`. Default discovery and its five existing profiles remain unchanged. Both paths verify original linked bytes and actual callee closures.

```powershell
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --pauth --report build/function-profiles/oot111-pauth-v4.json
```

Fresh default and PAC surveys of local 1.1.1 inputs have identical module source and linked-text hashes. Their aggregate results are:

| Measurement | Default discovery | PAC discovery |
| --- | ---: | ---: |
| Metadata entry candidates | 284,396 | 284,396 |
| Bounded semantic regions | 58,638 | 115,164 |
| Discovery blocked | 225,758 | 169,232 |

Default profile acceptance remains 40,038 register-only leaf candidates and zero framed candidates under policies 1-3. The separate PAC policy accepts **1,686 framed candidate regions**, containing 13,494 declared instruction words: 1,685 candidates in main and one in sdk. It rejects the remaining 113,478 discovered regions, including unsigned entries, unsupported layouts/memory effects, size limits, and unavailable callees. These are metadata/window candidates rather than proven original functions.

PAC discovery exposes 39,893 first unsupported ordered/atomic frontiers, including 34,202 LDAPRB frontiers. This larger count reflects traversal beyond earlier PAC blockers. Six first unsupported PAC-family encodings remain outside the implemented subset. Other first unsupported families include load/store (17,981), integer (14,174), SIMD/FP (5,731), other control flow (1,219), system (1,218), and supervisor calls (64). First-failure counts are neither total instruction frequencies nor whole-game coverage.

Both surveys are static: no generated C, native callback registration, or game execution. Private reports remain under ignored `build/function-profiles/`.

## After the RCpc load milestone

The [aligned RCpc load model](ordered-loads.md) now implements no-offset LDAPR/B/H with a conservative serialized backend. Fresh surveys retain all source and linked-text hashes and the 284,396 metadata-entry denominator. Default discovery reaches 58,663 bounded regions. PAC discovery reaches **127,551**, compared with 115,164 before RCpc; 156,845 candidates remain discovery-blocked. No LDAPR/B/H first-unsupported frontier remains. The remaining PAC first unsupported categories are load/store (18,058), integer (16,020), SIMD/FP (5,759), ordered/atomic (5,144), system (1,248), other control flow (1,224), supervisor calls (64), and pointer authentication (6).

Acceptance remains 40,038 leaf candidates and 1,686 PAC framed candidates. Existing verifier profiles still reject the new memory form: raw semantic support does not broaden their permitted address effects. Discovery success also does not prove runtime alignment or valid pointer values. The separate checked-read integration below adds its own runtime obligations. No game callbacks were generated or run.

## Separate checked-read policy survey

`--reads` enables PAC discovery and evaluates both the unchanged policy 4 and the new [checked-read policy 5](checked-reads.md). It does not supply runtime read capabilities. Accepted regions have a structural proof with dynamic address, permission, ownership, and alignment obligations, rather than proof that every possible pointer is readable.

```powershell
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --reads --report build/function-profiles/oot111-checked-reads-v5.json
```

The local 1.1.1 run retains the preceding RCpc survey's exact source and linked-text hashes, 284,396 metadata entries, 127,551 discovered regions, and 156,845 discovery blockers. The same pass accepts 1,686 policy-4 candidates (13,494 words) and **1,688 policy-5 structural candidates (13,519 words)**. Policy 5 accepts 1,686 regions in main and two in sdk. Counts overlap and must not be added. Older policies keep their own memory rules; default behavior is unchanged.

Policy 5's first rejections include 49,428 general policy failures, 45,727 size limits, 16,151 unavailable call dependencies, and 11,269 memory-policy failures. These categories describe the first failure of a whole candidate/closure check; reductions in one category may expose another, so they are not independent coverage gains. Further layouts, missing callee coverage, loops, indirect targets, and instruction semantics remain separate work.

Real production verifiers check unchanged words and actual transitive callee proofs. The report explicitly records that runtime read ranges were not supplied. All reports remain private under ignored `build/`; no game C, native callback registration, or game execution occurs.

## LR-pair frame comparison

`--lr-calls` uses the same PAC discovery and compares policy 5 with the separate [LR-pair policy 6](lr-pair-frames.md), including real mixed frame/callee closures. It grants no runtime ranges and leaves default, `--pauth`, and `--reads` behavior unchanged.

The local 1.1.1 run retains the preceding source/text hashes and all discovery denominators. Both policies accept **1,688 structural candidates containing 13,519 words**. First unsupported combined-frame failures decrease from 1,307 to 774. Policy 6 then exposes additional later failures: call dependencies rise from 16,151 to 16,458 and memory-policy failures from 11,269 to 11,409. First failures can change across a whole closure; these differences cannot be counted as independently proven functions or acceptance gains.

Synthetic survey tests accept a real LR-pair caller and FP/LR helper through this same production verifier and reject an unavailable callee. The game survey itself performs no translation, registration, or execution. Broader callee coverage and explicit write-effect contracts remain separate milestones.

## Dependency-frontier audit

The separate [callee audit](callee-audit.md) reproduces these policy-6 results and traces all missing targets in the existing closures of 16,458 roots whose final first rejection is `call_dependency`. It finds 5,463 distinct frontier targets: 3,488 discovery-blocked metadata entries, 1,973 relocation-backed PLT stubs, and two unseeded text targets. It records both direct callers and transitive root references, without treating those overlapping references as predicted acceptance gains.

Bounded original-byte probes remain diagnostic and never satisfy other dependencies. PLT annotations record the linked GOT snapshot only. Seventy-two frontier PLT stubs resolve to existing verified register-only leaves, but an explicit verified transfer contract is still required before dispatch. The accepted count stays 1,688 and no game C or native callbacks are generated.

## Checked PLT-to-leaf comparison

`--plt` compares the unchanged policy 6 with [policy 7](plt-dispatch.md), using the same PAC discovery and actual framed/leaf proofs. A separate global catalog recognizes exact relocation-backed stubs whose linked targets are real verified register-only leaves. Only stubs required by a root's actual closure and their actual target leaf bytes enter that root's proof; no stub is turned into a fake register-only function or used to relax an older policy. Each call bound includes four original stub instructions plus the leaf bound.

The local 1.1.1 catalog contains 386 eligible bridges, including all 72 in the earlier missing-callee frontier. A single registry still permits at most 256 explicit bridges. Source/text hashes and all metadata/discovery denominators are unchanged. Policy 6 retains 1,688 candidates; policy 7 accepts **1,703 structural candidates (13,645 root words)**: 1,686 in main and 17 in SDK. The 15 additional candidates are SDK regions. Counts overlap and do not measure gameplay coverage.

First call-dependency failures decrease from 16,458 to 16,405. Of the 53 regions advancing past that first category, only 15 become accepted: memory-policy failures increase from 11,409 to 11,437 and bounds/registry failures from 162 to 172. Runtime GOT checks remain obligations, and the report explicitly records that it has not performed them or supplied runtime read ranges. No game C, callbacks or execution are produced by the survey.

## After conditional comparisons

The [CCMP/CCMN milestone](conditional-compare.md) adds exact flag-only register/immediate semantics to the existing value forms, without changing profile permissions, limits, models, descriptor versions or callee requirements. Fresh default and `--plt` surveys retain all module source and linked-text hashes, metadata entries and syntax-decoder settings. Discovery traverses the new instructions rather than stripping them or treating them as hints.

```powershell
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --report build/function-profiles/oot111-default-after-ccmp-v1.json
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --plt --report build/function-profiles/oot111-plt-after-ccmp-v1.json
```

| Measurement | Before CCMP/CCMN | After |
| --- | ---: | ---: |
| Metadata entry candidates | 284,396 | 284,396 |
| Default discovered regions | 58,663 | 59,525 |
| Default accepted ordinary leaves | 40,038 | 40,098 |
| PAC-enabled discovered regions | 127,551 | 130,808 |
| PAC-enabled discovery blockers | 156,845 | 153,588 |
| Eligible global PLT-to-leaf catalog | 386 | 404 |
| Policy-6 accepted structural regions | 1,688 | 1,688 |
| Policy-7 accepted structural regions | 1,703 | 1,703 |

The 60 additional ordinary leaf candidates bring their declared word count from 100,995 to 101,737. Older default framed policies still accept none. Policy 6 retains 13,519 accepted root words and policy 7 retains 13,645, with unchanged module accepted counts. No CCMP/CCMN first-unsupported frontier remains in either survey; the preceding PAC discovery had 6,778 CCMP and 251 CCMN first stops. These are early-stop diagnostics, not total instruction counts.

Discovering more regions also exposes more later failures: policy-6 call dependencies rise from 16,458 to 16,578 and memory-policy failures from 11,409 to 11,636; policy-7 call dependencies rise from 16,405 to 16,522 and memory-policy failures from 11,437 to 11,666. The larger bridge catalog does not imply that any additional framed closure now meets all requirements. The refreshed [callee audit](callee-audit.md) matches the new policy-6 baseline and identifies remaining blockers. All measurements remain static, with no game translation, callback registration, execution or supplied runtime ranges/GOT guarantees.

## After widening multiplication

The [long-multiply milestone](long-multiply.md) adds exact SMADDL/SMSUBL/UMADDL/UMSUBL semantics and their multiply/negate aliases. Fresh original-byte surveys retain all module source/text hashes, syntax-decoder settings, limits, models, policies and the 284,396 metadata-entry denominator.

```powershell
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --report build/function-profiles/oot111-default-after-long-multiply-v1.json
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --plt --report build/function-profiles/oot111-plt-after-long-multiply-v1.json
```

| Measurement | After CCMP/CCMN | After long multiply |
| --- | ---: | ---: |
| Default discovered regions | 59,525 | 60,537 |
| Default accepted ordinary leaves | 40,098 | 40,144 |
| PAC-enabled discovered regions | 130,808 | 133,760 |
| PAC-enabled discovery blockers | 153,588 | 150,636 |
| Eligible global PLT-to-leaf catalog | 404 | 423 |
| Policy-6 accepted structural regions | 1,688 | 1,688 |
| Policy-7 accepted structural regions | 1,703 | 1,710 |

The 46 additional ordinary leaves bring their declared word count to 102,509, from 101,737. Default accepted leaves are rtld 5, main 38,546, subsdk0 32 and SDK 1,561; older default framed policies still accept none. Policy 6 retains 13,519 accepted root words. Policy 7 reaches **13,763 root words**: main retains 1,686 accepted regions and SDK rises from 17 to 24. These seven additional regions have real production closure proofs; an increase in discovered regions or eligible stubs alone is not an acceptance result.

No newly supported long-multiply mnemonic or alias remains as a first unsupported discovery stop. Later barriers are still exposed: policy-6 call dependencies rise from 16,578 to 16,692 and memory-policy failures from 11,636 to 11,989; policy-7 call dependencies rise from 16,522 to 16,624 and memory-policy failures from 11,666 to 12,021. Wider discovery changes those denominators and first failures. The [callee audit](callee-audit.md) reproduces the new policy-6 baseline. Surveys grant no runtime read ranges/live GOT guarantees and generate/register/execute no game callbacks. Full reports remain private under `build/function-profiles/`.

## After reversal and leading counts

The [RBIT/REV/CLZ/CLS milestone](bit-operations.md) adds the exact scalar one-source variants, including REV16/REV32 and reserved W/opcode-3 rejection. Fresh default and `--plt` surveys preserve every module source/text hash, syntax-decoder setting, model, limit, policy and the 284,396 metadata-entry denominator.

```powershell
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --report build/function-profiles/oot111-default-after-bit-ops-v1.json
.venv\Scripts\python.exe -B tools/survey_function_profiles.py build/prepared/oot111 `
  --plt --report build/function-profiles/oot111-plt-after-bit-ops-v1.json
```

| Measurement | After long multiply | After bit operations |
| --- | ---: | ---: |
| Default discovered regions | 60,537 | 60,976 |
| Default accepted ordinary leaves | 40,144 | 40,175 |
| PAC-enabled discovered regions | 133,760 | 135,020 |
| PAC-enabled discovery blockers | 150,636 | 149,376 |
| Eligible global PLT-to-leaf catalog | 423 | 430 |
| Policy-6 accepted structural regions | 1,688 | 1,688 |
| Policy-7 accepted structural regions | 1,710 | 1,710 |

The 31 additional ordinary leaf candidates increase declared words from 102,509 to 103,046. Module accepted counts are rtld 5, main 38,553, subsdk0 38 and SDK 1,579. Older default framed policies still accept none. Policy-6/7 accepted words remain 13,519/13,763, with unchanged module accepted counts. The larger eligible-stub catalog does not imply new accepted framed closures.

None of the implemented one-source mnemonics remains as a first unsupported discovery stop. Policy-6 call-dependency failures fall from 16,692 to 16,669, while memory-policy failures rise from 11,989 to 12,118. Policy-7 call-dependency failures fall from 16,624 to 16,600 and memory-policy failures rise from 12,021 to 12,151. Such first-failure shifts across a larger discovered set are diagnostic, not independently proven functions. All proofs use the real verifier and callee bytes. No game C, callbacks, execution or runtime ranges/GOT guarantees are produced; the refreshed [callee audit](callee-audit.md) matches this policy-6 baseline.

## Verification

Synthetic tests cover positive leaf and framed cases under all profiles, real transitive closures, unavailable callees, call cycles, metadata aliases/window boundaries, multiple returns, indirect boundaries, unreachable words, samples/limits, PAC-prefix rejection, source preservation, fresh-output checks, and tampered-input rejection. The full Python suite continues to run the native/reference profile tests; the survey itself remains static and does not compile or run candidates.
