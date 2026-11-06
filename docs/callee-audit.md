# Static callee dependency audit

`tools/survey_callees.py` explains the dependencies behind policy-6 rejection without changing discovery, function policies, registries, or execution permissions. It reloads and verifies prepared inputs, requires a complete fresh offline link, and runs the same original-byte discovery and production LR-pair verifier used by the [profile survey](function-profile-survey.md). It writes a private JSON report only.

```powershell
.venv\Scripts\python.exe -B tools/survey_callees.py build/prepared/oot111 `
  --baseline build/function-profiles/oot111-lr-calls-v6.json `
  --report build/function-profiles/oot111-callee-audit-v2.json --samples 16
```

Choose a fresh report path under `build/`, outside the prepared input directory. Existing files are preserved and failures leave no partial report. The optional baseline must match module identities/source/text hashes, decoder and PAC model, discovery limits/counts, and per-module/global aggregate accepted/rejected policy outcomes. A baseline supplies comparison data; it never supplies code, proofs, or invented callees.

## Counts and dependency frontiers

The audit first evaluates every discovered metadata region with actual verified register-only leaves and real framed callee closures. Accepted counts and rejection categories remain those of the production policy. It then follows the existing discovered call graph for every root whose final first failure is `call_dependency`, collecting all unregistered targets in that closure. Known callees remain distinct from their missing descendants.

Each edge is a distinct declared caller-region/target pair. Multiple BL sites from the same region to the same target count once; these are not instruction-site counts or runtime call frequencies. A missing target records both its direct callers and the distinct dependency-blocked roots that reach it. Roots may reach several missing targets. Rankings by root references overlap and must not be interpreted as predicted acceptance gains: later instructions and other dependencies may still fail after one frontier is addressed.

Target classes distinguish verified register-only leaves, discovered metadata regions with their independent policy-6 outcome, blocked metadata entries, relocation-backed PLT stubs, unseeded text targets, mapped non-text addresses, module gaps, and unmapped/unaligned addresses. PLT classification takes precedence, so the reported primary categories are disjoint.

## Diagnostic probes and PLT snapshots

Only unseeded text targets in the missing frontier receive an additional diagnostic probe. It reads unchanged original bytes from the direct-call target and stops at the earliest next metadata entry, enclosing sized-symbol end, exact text end, or word limit. It records overlap with an existing discovered region. Discovery and production leaf/frame checks are real, but a successful probe remains a candidate rather than proof of original function identity or permission to register it. Probes never enter the production region/leaf maps and never satisfy one another's dependencies. Blocked metadata entries keep their original boundary/failure and are not retried with wider windows.

PLT recognition reuses the existing exact ADRP/LDR/ADD/BR pattern and relocation-backed GOT-slot mapping. The audit annotates the linked GOT snapshot, symbol, nonlocal-return marker, and one resolved target classification. It does not skip the stub, rewrite the call, infer a complete runtime target set, or supply a host-service ABI. Runtime GOT writes and general indirect transfer semantics remain separate requirements.

Reports contain original-byte hashes, private addresses, symbol names, all frontier/root references, bounded samples, and aggregate counts. They contain no generated game C or serialized native pointers. The audit supplies no runtime read ranges, registers no callbacks, and executes no guest code.

## Local 1.1.1 result

The fresh audit matches the policy-6 baseline on all module source/text hashes and aggregate outcomes:

| Measurement | Count |
| --- | ---: |
| Metadata entry candidates | 284,396 |
| Discovered semantic regions | 127,551 |
| Discovery blocked | 156,845 |
| Accepted policy-6 structural candidates | 1,688 |
| Roots whose first production failure is a call dependency | 16,458 |
| Distinct missing frontier targets | 5,463 |
| Distinct frontier caller-region/target edges | 28,266 |

Across all discovered regions, 145,624 distinct direct-call edges reference 34,658 distinct targets. These broader edge counts include regions rejected for other reasons and use a different denominator from the dependency frontier.

The 5,463 missing frontier targets partition as follows:

| Primary target class | Targets |
| --- | ---: |
| Metadata entry blocked during discovery | 3,488 |
| Relocation-backed PLT stub | 1,973 |
| Unseeded text target | 2 |

The 3,488 non-PLT blocked metadata entries stop at unsupported encodings (1,537), indirect calls (991), window boundaries (760), and indirect jumps (200). The most frequent first unsupported mnemonics are CCMP (243 targets), LDR forms (133), UMADDL (129), SMADDL (119), and FMOV (95). These are early-stop counts over distinct frontier targets, not total instruction frequencies. Both unseeded probes fail policy checks: one still lacks a callee and one lacks a supported matching authentication/return tail. Neither increases acceptance.

The 1,973 PLT stubs reference 1,880 distinct linked snapshot addresses. Their one-hop target classifications are:

| Resolved snapshot classification | PLT stubs |
| --- | ---: |
| Metadata entry blocked during discovery | 1,140 |
| Discovered metadata region, rejected by policy 6 | 761 |
| Existing verified register-only leaf | 72 |

This points to two concrete implementation areas: an explicit verified PLT tail-transfer boundary, initially restricted to already verified register-only leaves, and missing instruction families such as conditional compare. Adding more entry seeds alone would address little of this measured frontier. The 72 leaf-directed stubs are candidates for a future bounded bridge, not a promise that 72 functions or any fixed number of roots will become accepted. Exact stub/GOT/target checks, instruction budgets, retained ownership, and synthetic native/reference validation must precede such an extension.

The later [policy-7 PLT milestone](plt-dispatch.md) implements this bounded transfer contract and verifies all 72 original frontier stubs. Its separate static survey accepts 1,703 candidates, up 15. This historical audit remains a policy-6 baseline; its snapshot annotations still grant no runtime dispatch permissions.

## Verification

Thirteen synthetic tests cover real mixed closures, shared and transitive frontiers, repeated BL-site deduplication, unavailable targets, blocked metadata and unchanged boundaries, word/symbol limits, overlapping internal-label probes, successful probes that stay unregistered, dependencies between probes that remain unresolved, relocation-backed PLT snapshots and nonlocal symbols, lookalike-stub rejection, non-text/gap/unmapped targets, deterministic accounting, strict baseline comparisons, input integrity, fresh output, and CLI rollback. The complete regression suite remains applicable. No game callbacks are generated or executed during these checks.
