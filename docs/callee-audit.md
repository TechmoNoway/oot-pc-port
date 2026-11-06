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

## Local 1.1.1 result before conditional comparisons

The pre-CCMP/CCMN audit matches its policy-6 baseline on all module source/text hashes and aggregate outcomes:

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

## Refreshed audit after CCMP/CCMN

```powershell
.venv\Scripts\python.exe -B tools/survey_callees.py build/prepared/oot111 `
  --baseline build/function-profiles/oot111-plt-after-ccmp-v1.json `
  --report build/function-profiles/oot111-callee-after-ccmp-v1.json
```

The refreshed original-byte audit matches the new survey's policy-6 outcomes, discovery counts, module source/text hashes, decoder, limits and PAC model. Discovery now reaches 130,808 regions, while accepted policy-6 regions remain 1,688. There are 16,578 dependency-blocked roots, **5,519 distinct missing targets** and 28,545 frontier caller-region/target edges. Broader discovery accounts for changes to this frontier; these counts are not acceptance predictions.

| Primary target class | Targets |
| --- | ---: |
| Metadata entry blocked during discovery | 3,454 |
| Relocation-backed PLT stub | 2,063 |
| Unseeded text target | 2 |

The blocked metadata entries stop at unsupported encodings (1,369), indirect calls (1,037), window boundaries (839) and indirect jumps (209). CCMP and CCMN no longer appear as first unsupported mnemonics. Remaining leading stops include LDR forms (143), UMADDL (134), SMADDL (126) and FMOV (99). UMULL (52) and SMULL (44) are long-multiply aliases, bringing that combined instruction frontier to **356 distinct targets**. Long multiply/add/subtract is the next integer-semantics milestone; addressing, memory effects and broader calls still need separate work.

The 2,063 frontier PLT stubs have linked snapshots pointing to blocked metadata entries (1,124), discovered but policy-6-rejected regions (855), and verified ordinary leaves (84). This is separate from the global 404-entry eligible bridge catalog and from policy-7 acceptance, which remains 1,703. Both unseeded probes remain policy-rejected and unregistered. No game callbacks are generated or executed, and no runtime capabilities are granted.

## Refreshed audit after widening multiplication

```powershell
.venv\Scripts\python.exe -B tools/survey_callees.py build/prepared/oot111 `
  --baseline build/function-profiles/oot111-plt-after-long-multiply-v1.json `
  --report build/function-profiles/oot111-callee-after-long-multiply-v1.json
```

This audit matches the new policy-6 baseline on module source/text hashes, decoder/model/limits, discovery and per-module/global production outcomes. It reaches 133,760 semantic regions and retains 1,688 accepted policy-6 candidates. The missing frontier now covers **16,692 dependency-blocked roots, 5,620 distinct targets and 28,913 distinct caller-region/target edges**. Counts increase with discovery and are not estimated acceptance gains.

| Primary target class | Targets |
| --- | ---: |
| Metadata entry blocked during discovery | 3,501 |
| Relocation-backed PLT stub | 2,117 |
| Unseeded text target | 2 |

Blocked metadata entries stop at indirect calls (1,183), unsupported encodings (1,132), window boundaries (961) and indirect jumps (225). No implemented long-multiply mnemonic or alias remains as a first unsupported frontier. Leading remaining stops are LDR forms (161), LDADD (104), FMOV (98), STR forms (86) and REV (79). The register-only REV/REV16/RBIT/CLZ group accounts for **94 distinct first-unsupported targets** (79/3/3/9), motivating the next integer instruction milestone. Memory, atomics and SIMD/FP still require their own effects and runtime boundaries.

The frontier's 2,117 PLT snapshots point to blocked metadata entries (1,107), discovered policy-6-rejected regions (919) and verified ordinary leaves (91). The larger global eligible bridge catalog has 423 entries. Separately, the real policy-7 closure survey accepts 1,710 structural candidates, seven more than before this instruction milestone. Both unseeded probes still fail policy checks. The audit emits no C, registers no callbacks, grants no live capabilities and executes no game code; full reports remain ignored under `build/`.

## Refreshed audit after reversal and leading counts

```powershell
.venv\Scripts\python.exe -B tools/survey_callees.py build/prepared/oot111 `
  --baseline build/function-profiles/oot111-plt-after-bit-ops-v1.json `
  --report build/function-profiles/oot111-callee-after-bit-ops-v1.json
```

The fresh audit matches this policy-6 baseline on original source/text hashes, decoder/model/limits, discovery counts and per-module/global outcomes. It reaches 135,020 semantic regions and retains 1,688 accepted policy-6 candidates. The dependency frontier contains **16,669 blocked roots, 5,562 distinct missing targets and 28,817 distinct caller-region/target edges**, compared with 16,692/5,620/28,913 before the one-source milestone. These overlapping dependency measurements are not predicted acceptance gains; policy 7 remains at 1,710 accepted structural regions.

| Primary target class | Targets |
| --- | ---: |
| Metadata entry blocked during discovery | 3,435 |
| Relocation-backed PLT stub | 2,125 |
| Unseeded text target | 2 |

Blocked metadata entries stop at indirect calls (1,184), unsupported encodings (1,046), window boundaries (977) and indirect jumps (228). No implemented reversal or leading-count mnemonic remains as a first unsupported frontier. Leading remaining stops include LDR forms (161), LDADD (104), FMOV (98), STR forms (87) and STP forms (78). Of 68 integer first stops, UMULH (20) and SMULH (3) motivate the next register-only arithmetic milestone; CRC32 and EXTR/ROR forms remain separate gaps. No promise of 23 accepted functions follows from those high-multiply target counts.

The 2,125 frontier PLT snapshots resolve to blocked metadata (1,098), discovered policy-6-rejected regions (936) and verified ordinary leaves (91). The separate global eligible catalog contains 430 bridges. Both unseeded probes remain rejected and unregistered. All original-byte probes stay diagnostic; no runtime ranges or GOT guarantees, game C, native callbacks or game execution are produced. Detailed reports remain ignored under `build/`.

## Refreshed audit after high multiplication

```powershell
.venv\Scripts\python.exe -B tools/survey_callees.py build/prepared/oot111 `
  --baseline build/function-profiles/oot111-plt-after-high-multiply-v1.json `
  --report build/function-profiles/oot111-callee-after-high-multiply-v1.json
```

The audit matches the fresh policy-6 baseline on source/text hashes, decoder/model/limits, discovery and all per-module/global outcomes. Discovery reaches 135,390 semantic regions; policy 6 still accepts 1,688 structural candidates. There are **16,680 dependency-blocked roots, 5,558 distinct frontier targets and 28,848 distinct caller-region/target edges**. The preceding counts were 16,669/5,562/28,817. Larger discovery and overlapping root dependencies prevent interpreting those changes as accepted functions; policy 7 remains at 1,710.

| Primary target class | Targets |
| --- | ---: |
| Metadata entry blocked during discovery | 3,424 |
| Relocation-backed PLT stub | 2,132 |
| Unseeded text target | 2 |

Blocked metadata entries stop at indirect calls (1,188), unsupported encodings (1,026), window boundaries (982) and indirect jumps (228). UMULH/SMULH no longer appear as first unsupported mnemonics. Leading remaining stops are LDR forms (161), LDADD (104), FMOV (98), STR forms (87) and STP forms (78). Remaining integer first stops total 46: CRC32 variants account for 29 and EXTR/ROR for 17 (six EXTR, eleven ROR). EXTR and its immediate rotate alias are the next register-only milestone, while CRC32 remains a separate instruction family. These are distinct frontier targets, not instruction frequencies or predicted acceptance gains.

The 2,132 frontier PLT snapshots resolve to blocked metadata (1,092), discovered policy-6-rejected regions (949) and verified ordinary leaves (91). The separate global eligible catalog contains 433 bridges. Both unseeded probes remain rejected and unregistered. No original words, including ignored Ra fields, are normalized. Reports grant no runtime ranges or GOT guarantees and generate/register/execute no game callbacks; detailed reports remain private under `build/`.

## Verification

Thirteen synthetic tests cover real mixed closures, shared and transitive frontiers, repeated BL-site deduplication, unavailable targets, blocked metadata and unchanged boundaries, word/symbol limits, overlapping internal-label probes, successful probes that stay unregistered, dependencies between probes that remain unresolved, relocation-backed PLT snapshots and nonlocal symbols, lookalike-stub rejection, non-text/gap/unmapped targets, deterministic accounting, strict baseline comparisons, input integrity, fresh output, and CLI rollback. The complete regression suite remains applicable. No game callbacks are generated or executed during these checks.
