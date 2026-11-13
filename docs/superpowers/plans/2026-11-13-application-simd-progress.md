# Application SIMD Progress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Execute inline; do not spawn agents unless the user subsequently requests delegation.

**Goal:** Independently implement the six measured application SIMD register families, prove original execution past the current frontier, validate the full milestone and push the reviewed result to `dev`.

**Architecture:** Extend the existing application vector classifier/transaction, reusing the exact integer-to-float helper. Preserve the original boot, SDK providers, PAC, memory and dispatcher contracts. Add source-bound diagnostic/progress evidence around the existing runner; do not add a new execution engine.

**Tech Stack:** Windows x64, Python 3.14, C17, Visual Studio 2022 C++ Build Tools/MSVC, MSYS2 UCRT64 GCC, CMake >=3.20, the repository's pinned Capstone/Unicorn and ZBIC dependency.

**Design:** [2026-11-13-application-simd-progress-design.md](../specs/2026-11-13-application-simd-progress-design.md).

## Global constraints

- Continuation request (2026-11-13): the user asked to finish the remaining
  work until the game runs. This expands the overall objective beyond this
  intermediate SIMD milestone. Close and validate this cohort first; use its
  measured next boundary to design subsequent capabilities. Overall success
  requires actual original-game visual output and usable input, not only a
  diagnostic executable, more retired instructions or a notification call.
- User decision: independent implementation; references only. No Hookshot/Fritchii code, patches or tests imported.
- Root is `G:\Zelda\oot-pc-port`; baseline branch `dev`, HEAD `f8a7162`.
- All new support is application-only (flags 62). Keep ABI2, dispatcher version 1, PAC and vector-state layouts unchanged.
- Keep the existing nearest/ties-even FPCR zero/FZ domain; no new rounding modes or FP16.
- New instructions have no memory effects, preserve GPR/SP/NZCV, and retain transactional failure semantics.
- Game bytes, addresses/disassembly, executable files, traces, entropy, input manifests and reports stay under ignored `build/`. Reference clones remain outside this repo.
- Code, documentation and commit messages are English.
- Do not lower existing test requirements, skip a required native lane, patch original game instructions, return fabricated service success, strip PAC, or increase selection/retirement limits for a pass.
- All test fixtures added to Git are synthetic. Static game survey, synthetic native execution and original-code experiments are distinct evidence categories.
- Use fresh output directories; never rewrite a historical passed result or copy its pass status.
- Every production/config change invalidates final validation. Before committing implementation, require a fresh passed `run.json` matching `run_milestone.source_digest()`.
- No per-task code commits: the repository's complete-milestone gate takes precedence over generic frequent-commit advice. Keep task checkpoints in notes, then make the reviewed implementation commit after Task 7 passes.

## Scope and fixed decisions

The first milestone implements the following **six families only**. Do not add later services, general SIMD arithmetic, a scheduler, a renderer, or a launcher in this plan.

| Application kind | Python family / operation | Mask | Fixed bits |
|---:|---|---|---|
| 1, 2 | Existing GPR conversions / 23, 24 | Existing | Unchanged |
| 3 | `simd_integer_fp` / 25 | `0xdfbffc00` | `0x5e21d800` |
| 4 | `simd_orr` / 26 | `0xbfe0fc00` | `0x0ea01c00` |
| 5 | `simd_dup_element` / 27 | `0xffe0fc00` | `0x5e000400` |
| 6 | `simd_ins_element` / 28 | `0xffe08400` | `0x6e000400` |
| 7 | `simd_cmeq` / 29 | `0xbf20fc00` | `0x2e208c00` |
| 8 | `simd_bif` / 30 | `0xbfe0fc00` | `0x2ee01c00` |

`simd_integer_fp`: width from bit22, unsigned from bit29. ORR/BIF: Q from bit30. CMEQ: element size from bits23:22; size3,Q0 is reserved. DUP/INS: imm5 must have its lowest set bit in positions0..3. INS source-index low bits are ignored, not invalidated. The design gives the complete effects.

## File map

| File | Responsibility / change |
|---|---|
| `tools/sdk_init_instructions.py` | Application-only Python classification and `Instruction` metadata |
| `src/startup_vector.c`, `src/startup_vector.h` | Application classifier IDs and private candidate effects |
| `tests/test_application_simd.py` (new) | Literal encodings, complete state/reference checks and independent byte/rational oracles |
| `tests/test_application_boot.py` | Synthetic dispatcher program, yields, profile separation and published vector results |
| `tests/test_startup_decode_cache.py` | Application flag remains part of decode identity |
| `tools/prepare_startup.py` | Private source-bound selected SIMD/SVC records; never authority to bypass execution |
| `tools/application_frontier.py` (new) | Read-only static cohort summary and streaming full-trace progress proof |
| `tests/test_application_frontier.py` (new) | Synthetic provenance and trace-tampering tests |
| `tools/run_milestone.py` | Optional exact SVC endpoint, progress replay and evidence gates |
| `tests/test_application_milestone.py` | Exact stop validation, exclusivity and unchanged legacy endpoint contracts |
| `tests/test_application_selection.py` | Selected SIMD/SVC records bind original bytes and remain private |
| `config/milestones/application-simd.json` (new) | Full milestone configuration frozen from pilot measurements |
| `docs/application-startup.md`, `docs/development-workflow.md`, `README.md`, `AGENTS.md` | Final actual scope, measurements and next boundary |

No changes are planned for `src/startup_float.c`, `src/startup_dispatch.c`, public integer/PAC state structs, GPU code or existing milestone configurations. If tests expose a necessary change there, document its exact reason before modifying it; do not use those files to bypass the application gate.

## Task 0: Restore a usable validation environment and relocate private inputs

**Completed on 2026-11-13.** See [verified environment recovery](2026-11-13-build-environment-ready.md) and private `build/environment-repair/ready.json`. Both newly compiled original startup lanes matched the historical application trace and endpoint. Activate the documented session script and start Task1 after checking for subsequent drift; the procedures below are the recovery record, not an instruction to reinstall/rewrite existing outputs.

**Files:** No production-source changes. Fresh local `.venv-dev/`, `build/cmake-simd/`, `build/prepared/oot111-g/`, `build/prepared/romfs111-g/`, `build/research/simd-handoff/`.

**Consumes:** Old private evidence, the current NUP in `G:\Zelda`, existing toolchain source under `toolchain/zbic-src`.

**Produces:** Working Python3.14/MSVC/GCC lanes, freshly verified current-path inputs, and seed reports whose bundle paths resolve inside this checkout.

- [x] Read `AGENTS.md`, the design and this entire plan. Check `git status --short`, `git branch --show-current`, `git log -1 --oneline`, `git remote -v`. Planning documents are expected additions; preserve any other work. Do not reset/stash/delete caches.
- [x] Discover toolchains using `py -0p`, `Get-Command cmake,gcc`, and Microsoft's installed `vswhere.exe` with `-products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64`. A Visual Studio directory alone is not a working C++ compiler.
- [x] Provision official Python3.14, Visual Studio2022 Build Tools with the x64 C++ compiler, Windows SDK and CMake, and MSYS2 UCRT64 GCC if absent. Use official vendor installers/package managers. Do not replace required MSVC/GCC evidence with clang or reuse the broken copied venv. If provisioning is unavailable, report that prerequisite; continue only planning/static work, and do not claim/push a verified implementation.
- [x] Create a fresh venv and session-only tool PATH. The compiler directories below must be confirmed by discovery, not assumed to exist:

```powershell
Set-Location -LiteralPath 'G:\Zelda\oot-pc-port'
py -3.14 -m venv .venv-dev
$py = (Resolve-Path -LiteralPath '.venv-dev\Scripts\python.exe').Path
& $py -m pip install --only-binary=:all: -r tools/requirements-lifter.txt
& $py -B -c "import sys,capstone,unicorn; from compression import zstd; print(sys.version); print(capstone.__version__,unicorn.__version__)"
```

Expected dependency versions are exactly those in the requirements files, including Unicorn2.1.4. Do not silently substitute the copied research decoder (5.0.7) for the pinned test environment.

- [x] Put the discovered CMake and UCRT64 `bin` directories on this PowerShell process's PATH. Confirm `gcc --version`, `cmake --version`, `ctest --version`. Build the pinned helper and configure a fresh cache:

```powershell
& $py -B tools/build_zbic.py
cmake -S . -B build/cmake-simd -G 'Visual Studio 17 2022' -A x64 -DOOT_ZBIC_SOURCE="$PWD/toolchain/zbic-src" -DPython3_EXECUTABLE="$py"
cmake --build build/cmake-simd --config Release
ctest --test-dir build/cmake-simd -C Release --output-on-failure -R 'host_self_test|guest_memory_self_test'
```

- [x] Locate exactly one `*.nup` immediately under `G:\Zelda`; if more than one exists, inspect catalog/build identities rather than choosing the first. Run the existing preparation tools; do not edit the old manifest path strings:

```powershell
$inputs = @(Get-ChildItem -LiteralPath 'G:\Zelda' -File -Filter '*.nup')
if ($inputs.Count -ne 1) { throw 'Select the verified OOT 1.1.1 NUP explicitly.' }
& $py -B tools/prepare_exefs.py $inputs[0].FullName --package 0 --out build/prepared/oot111-g
& $py -B tools/prepare_romfs.py build/prepared/oot111-g --output build/prepared/romfs111-g
```

Verify normalized file/source hashes and all12 segment checks against old `oot111`. Verify title, update version, full build ID, file/directory census and content hashes. The RomFS index hash must change because its sealed source path changes; never overwrite the former hash or pretend the old index is portable. Check free disk space before building its decoded cache.

- [x] Create local seed copies with Python stdlib. For each of these source reports, copy the report and change **only** the final iteration's `bundle` locator to the existing corresponding directory under this checkout:
  - `build/host-boot-pilot-v13/run.json` -> `build/research/simd-handoff/sdk-init-seed.json`.
  - `build/milestones/application-content-v1/application-cmake/run.json` -> `build/research/simd-handoff/application-seed.json`.

Use `PureWindowsPath(old_bundle).relative_to(old_checkout_root)` to map the locator to `ROOT/relative`; reject escapes/nonexistent destinations. Preserve execution counters, hashes, entropy IDs, original roots and all other fields. Save a separate migration note with old/new paths and SHA256 of the unmodified original report. These copies are seed locators, not a newly passed run. The runner must still verify NPDM/goal/original module identity against fresh inputs.

- [x] Before production edits, reproduce the current application stop on both compilers with freshly prepared inputs (use Task5's command construction with the existing implementation and original endpoint). Obtain fresh source-bound manifests and shared private entropy under `build/research/simd-handoff/`. Generate the entropy once using `secrets.token_bytes(32)`, retain its sealed file under that ignored directory, and reuse that same input in these two baseline lanes. Never print or commit the bytes. Do not continue on a different initial stop without investigating and updating this plan's evidence. This catches environment/reference drift early; a historical JSON alone is insufficient.

## Task 1: Add precise classification and the scalar SIMD conversion

**Files:** Modify `tools/sdk_init_instructions.py`, `src/startup_vector.c`, `src/startup_vector.h`. Create `tests/test_application_simd.py`.

**Consumes:** Existing `oot_startup_float_from_integer`, vector candidate/ownership machinery, and `test_application_integer_float.ApplicationIntegerFloatTests` setup.

**Produces:** Application kind3 / Python operation25 for all four S/S,D/D signed/unsigned variants; old kinds and profiles unchanged.

- [x] Add a literal regression assertion for `0x7e21d808` and an independently assembled signed example. Verify Python rejects them in INIT and accepts them only with `application=True`; verify C application kind3 and old C kind0. Run to observe the missing capability before implementation.
- [x] Build new test setup by assigning fixture/reference methods as in the existing conversion test, and call `ApplicationIntegerFloatTests.setUpClass.__func__(cls)` to initialize the native library/reference. Do not subclass a large test suite and unintentionally execute its tests twice.
- [x] Add synthetic encoding helpers; their inputs/bit fields must be explicit:

```python
def simd_integer_fp(width, unsigned, rn, rd):
    return (0x5e21d800 | ((width == 64) << 22) |
            (unsigned << 29) | (rn << 5) | rd)
```

- [x] Test width32/64, signed/unsigned, every Rn/Rd field including31 and aliasing. Read source integer bits from Q lanes, not GPRs. Use values zero, one, unsigned maxima, signed minima, and ties around2**24 and2**53. Compare complete native GPR/vector/FPSR/memory state with pinned Unicorn and the independent `oracle` from `test_application_integer_float.py`. Run additional sign/rounding values for every variant independent of register-field loops.
- [x] Implement exact Python classification before the legacy fallback **only when `application` is true**. Decode with form `sdk_init_vector`, operation25, `width`32/64, `rn`, `rd`, `condition`=unsigned, `immediate`=width. No new fields in `Instruction`.
- [x] Extend `oot_startup_application_vector_kind` with kind3, retaining1/2. `vector_family()` and the INIT helper must not admit it. In `vector_prepare`, use the current private candidate/ownership/state checks, extract low integer bytes from `state->q[rn]`, call the existing integer helper with equal source/destination widths, zero destination16 bytes, write result and cumulative flags, then publish all outputs together.
- [x] Do not change the conversion helper or cast integer bits through host float/double. Q31 is a real source/destination. Test FPCR zero/FZ, prior FPSR bits, bad state controls, output/input aliasing and unchanged sentinels on every failure.

```powershell
& $py -B -m unittest discover -s tests -p test_application_simd.py -v
$env:OOT_LIFTER_COMPILER='gcc'
& $py -B -m unittest discover -s tests -p test_application_simd.py -v
Remove-Item Env:OOT_LIFTER_COMPILER
```

Both lanes must run the reference cases without skips; do not infer a pass from decode alone.

### Task 1 checkpoint (2026-11-13)

Implemented independently and reviewed as a scoped checkpoint requested by the
user. No Task2+ instruction families, original-code experiments or commits were
included. The complete milestone gate above still applies before commit/push.

- Red phase: literal tests failed on the missing Python family and native kind;
  see private `build/task1-simd/red-msvc.log`.
- Green phase: `test_application_simd.py` passed all 7 tests without skips on
  MSVC and GCC. Each lane checks 4,546 conversions (4,096 full register-field
  combinations, 448 boundary/tie cases and 2 literal native cases), plus
  rejection and transactional-fault cases.
- Regression phase: both compilers passed `test_application_integer_float.py`
  (3 tests) and `test_sdk_init_vectors.py` (24 tests). The rebuilt native CTest
  suite passed all 6 groups, including the host self-test.
- Reviewed unchanged INIT admission, kind1/2 mappings, state/dispatcher ABI,
  conversion helper, memory effects and complete publication on success only.
- Private logs and a source-bound checkpoint summary are under
  `build/task1-simd/`. This focused validation is not a passed full milestone.

## Task 2: Complete register moves, equality masks and BIF

**Files:** Same vector/decoder files; extend `tests/test_application_simd.py`.

**Consumes:** Task1's application-only classifier and transaction contract.

**Produces:** Kinds4..8, Python operations26..30, with no new public state layouts or native dependencies.

- [x] Add independently constructed encodings for each family before production changes:

```python
def orr(q, rm, rn, rd):
    return 0x0ea01c00 | (q << 30) | (rm << 16) | (rn << 5) | rd

def dup_element(imm5, rn, rd):
    return 0x5e000400 | (imm5 << 16) | (rn << 5) | rd

def ins_element(imm5, imm4, rn, rd):
    return 0x6e000400 | (imm5 << 16) | (imm4 << 11) | (rn << 5) | rd

def cmeq(q, size, rm, rn, rd):
    return 0x2e208c00 | (q << 30) | (size << 22) | (rm << 16) | (rn << 5) | rd

def bif(q, rm, rn, rd):
    return 0x2ee01c00 | (q << 30) | (rm << 16) | (rn << 5) | rd
```

- [x] Assert the literal observed instruction shapes and mask results before using these constructors as test generators. Check reserved neighboring forms with fixed-bit mutations; do not assert every one-bit mutation is invalid when it selects another legitimate instruction.
- [x] Implement the masks/variant guards from the scope table in Python/C identically. DUP/INS require `imm5!=0` and trailing-zero count<=3. CMEQ rejects size3,Q0. INS **does not reject ignored low imm4 bits**. Keep original words/hashes, with no normalization.
- [x] Define the Python metadata consistently: all use form `sdk_init_vector`; ORR/BIF width=64/128, rd/rn/rm; DUP width=element bits, `access_size`=element bytes, `immediate`=source lane; INS width=128, `access_size`=element bytes, `immediate`=destination lane, `condition`=source lane; CMEQ width=64/128, `access_size`=element bytes, rd/rn/rm. Operations are26..30. Runtime effects remain decoded from exact original words.
- [x] Read all inputs from `state`, never the candidate after a destination write. Implement byte operations with unsigned types; use `memcmp` for per-lane equality, not floating comparison. The independent expected byte equations are:

```python
orr_bytes = bytes(a | b for a, b in zip(n, m))
bif_bytes = bytes((d & mask) | (a & (255 ^ mask))
                  for d, a, mask in zip(old_d, n, m))
# DUP copies one original lane into a zeroed 16-byte result.
# INS begins with old_d and replaces exactly one lane from original n.
# CMEQ compares each complete integer lane and writes all-FF or all-00.
```

- [x] Publish through the existing transaction tail. Preserve FPSR/FPCR for non-conversion operations. Q0 results clear their upper64 bits; INS preserves every unrelated lane; DUP clears every unrelated byte.
- [x] Reference-test Q0/Q1, every element size/lane, all ignored INS low-immediate variants, all Rn/Rd fields, and a covering set of Rm fields/three-way aliases (all-distinct, Rd=Rn, Rd=Rm, Rn=Rm, all-equal,31). Exhaust all2,048 ORR/BIF Q/Rn/Rd combinations with Rm cycling0..31, plus explicit per-Rm and alias cases; avoid an unnecessary32**3 Cartesian multiplication for every state.
- [x] For CMEQ include equal/unequal lanes with high-bit differences and mixtures in the same vector. For BIF include zero/FF/alternating masks. Include NaN-shaped byte patterns for pure bit moves to show they do not interpret floats or alter FPSR.
- [x] Run both compiler lanes from Task1, plus `test_application_integer_float.py` and `test_sdk_init_vectors.py`. Keep the same numerical helper and legacy FP behavior.

## Task 3: Verify actual dispatcher behavior, yields and profile rejection

**Files:** `tests/test_application_boot.py`, `tests/test_startup_decode_cache.py`; production changes only if a demonstrated integration defect requires them.

**Consumes:** All six new classifier/effect families; existing `package()` synthetic boot fixture and `build_native`/`execute` helpers.

**Produces:** A synthetic complete post-entry program that retires each new family with observable outputs through the real dispatcher; no game bytes in fixtures.

- [x] Extend `package()` with a new named `simd_cohort=False` option; retain all existing options/default behavior. Encode a synthetic program that loads sentinel vector data from its own stack, performs conversion, ORR, DUP, INS, CMEQ and BIF, then exports results using existing FMOV-to-GPR or supported vector stores and reaches a synthetic BRK boundary.
- [x] Construct the expected vector/GPR results with Python bytes and the exact rational oracle. Do not derive expected results by running the helper under test.
- [x] Run through `emit_startup`, `write_sources`, `build_native` and `execute`, with application enabled/disabled. INIT must retain error15 before `nnMain`; application must retire the sequence and publish the expected values. All mandatory constructor/initialization evidence still applies.
- [x] Compare whole execution to quantum1 and quotas immediately before/after each new instruction. Check no duplicated retirement, no changed suspended state, complete Q-bank preservation, and no publication when the original word or profile metadata is crossed.
- [x] Add a cache test that decodes the same new word/PC first with `application=False`, then true, then false through `StartupDecodeCache`; results must equal uncached decoding and never leak across profiles.
- [x] Run `test_application_boot.py`, `test_startup_decode_cache.py`, `test_sdk_init_dispatch.py` on MSVC/GCC. Existing C `word_kind`/`valid_metadata` already query the application classifier; do not replace them with a second opcode implementation.

## Task 4: Add private cohort/progress evidence and exact SVC diagnostics

**Files:** `tools/prepare_startup.py`, new `tools/application_frontier.py`, new `tests/test_application_frontier.py`, `tools/run_milestone.py`, `tests/test_application_milestone.py`, `tests/test_application_selection.py`.

**Consumes:** Original selected nodes, existing `entry_audit.modules` source hashes, native audit, full trace format from `src/startup_cli.c`, and the prior application baseline.

**Produces these exact interfaces in `tools/application_frontier.py`:**

- `summarize_boundaries(manifest: dict) -> dict`.
- `verify_progress_trace(trace: Path, baseline_execution: dict, baseline_bundle: dict, current_bundle: dict) -> dict`.

Implement the algorithms and tests below; no production implementation is supplied by a reference repo.

- [x] Add `application_simd_sites` and `application_svc_sites` **only** to application bundle manifests. For each eligible original selected node, store `address`, `word`, `module`, `source_sha256`, and SHA256 of its four little-endian word bytes. SVC rows additionally store `service=(word>>5)&65535`. Derive from actual original `nodes`/module bytes; exclude native intercept boundaries and host scaffolding. A site record grants no runtime permission.
- [x] `application_simd_sites` includes successfully decoded new kinds3..8. `application_svc_sites` includes actual selected SVC instructions (`word & 0xffe0001f == 0xd4000001`). Verify exact original word at emission, just as existing word-boundary records do. Keep legacy manifest fields/outcomes intact.
- [x] `summarize_boundaries` recomputes production decode acceptance with application enabled for each historical word. Return a read-only report (`format='oot-application-frontier'`) with counts for the six new families, already-supported records, remaining unsupported syntax and total records. Do not count old error labels as current errors or report whole-game coverage.
- [x] `verify_progress_trace` compares baseline/current original module source/text hashes, locates the old frontier in `baseline_bundle.application_word_boundaries`, and matches the same source-bound word in `current_bundle.application_simd_sites`. Stream JSONL without loading the trace into RAM. Require an event0, error0, service0 STEP at that PC/word, with next_pc=pc+4 and retired=`baseline_execution.retired+1`. Return the matched row and input trace SHA256 as a private proof. Later repeats of that PC are allowed; the crossing at the expected retirement point must exist exactly once. Reject truncated lines/invalid JSON, duplicate matching crossings and absent/mutated source identities.
- [x] The runner must obtain the full trace through the existing `build_startup.execute` API, which already checks the native all-row digest. The proof helper cannot treat an arbitrary unverified trace file as runtime authority. At this point `folder` is the compiler's application experiment directory, `last` its final iteration, and `entropy`/`romfs_index` its existing validated inputs. Create the required private package before replay:

```python
full_dir = folder / 'progress-full'
full_dir.mkdir()
shutil.copyfile(Path(last['bundle']) / 'startup.ootmem', full_dir / 'startup.ootmem')
full = execute_startup(Path(last['executable']), full_dir,
    1_000_000_000, 10_000, 'full', entropy, False, romfs_index=romfs_index)
(full_dir / 'report.json').write_text(json.dumps(full, indent=2) + '\n', encoding='utf-8')
```

Compare the existing `app_keys` against the compact/accelerated result, then pass `full['trace_file']` and the verified bundle objects to `verify_progress_trace`.
- [x] Provide two CLI subcommands with exclusive input modes. The following concrete paths refer to the Task0 seed and the final run's first compiler; obtain the actual final bundle/full-trace paths from their reports if target expansion created a later iteration:

```powershell
& $py -B tools/application_frontier.py survey --manifest build/milestones/application-content-v1/application-cmake/iteration-00/manifest.json --output build/research/simd-handoff/old-boundary-survey.json
& $py -B tools/application_frontier.py progress --baseline build/research/simd-handoff/application-seed.json --run build/milestones/application-simd-v1/application-cmake/run.json --trace build/milestones/application-simd-v1/application-cmake/progress-full/trace.jsonl --output build/research/simd-handoff/new-progress.json
```

Inputs must resolve to existing files under this checkout's `build/`; output must be a fresh `build_destination`. Before calling the proof helper, the CLI must check the complete trace SHA256 against the new run's native `trace_sha256` and complete row/step accounting; a compact file cannot pass as a full trace. Reports contain private addresses and stay ignored. CLI errors exit nonzero without a partial passed report.

- [x] Add optional `expected_svc=None` at the end of `application_evidence`'s current signature. Add optional config `application_expected_svc`. Exactly one of guard/word/SVC is present for application experiments. Reject booleans, negative or >65535 SVC values and any mixed alternatives.
- [x] For SVC evidence require status2/error9, `native_handler_stop is False`, exact service number and exact SVC word, exactly one matching `application_svc_sites` record at the stop PC, original module/hash/word-hash agreement, plus **all** existing initialization/accounting/RomFS/provider checks. Do not accept a guard with the same numeric service ID as an SVC. Do not implement the SVC or manufacture its return value.
- [x] Add optional `application_progress_baseline` config path. For this new milestone it is mandatory. After each compiler's compact accelerated/single-step comparison, execute a fresh full single-step replay under a new subdirectory, verify its existing comparable fields/digest agree, and run `verify_progress_trace`. Add both proofs to summary. Use the same private entropy, image and RomFS seals. Leave old configurations' behavior unchanged.
- [x] Add synthetic negative tests: mutated stop PC/word/module/hash/service; guard-versus-SVC confusion; mixed endpoint fields; non-SVC word; old profiles gaining fields; missing/duplicate progress row; wrong retired count/next_pc/event; stale source; a stop row pretending to be a STEP; and malformed trace. Existing invalid-callback/resource/timeout errors must remain failures.

```powershell
& $py -B -m unittest discover -s tests -p test_application_frontier.py -v
& $py -B -m unittest discover -s tests -p test_application_milestone.py -v
& $py -B -m unittest discover -s tests -p test_application_selection.py -v
```

### Tasks 2-4 checkpoint (2026-11-13)

Both compiler lanes passed the 73-test focused suite (MSVC 185.093s, GCC
119.661s), with no skips. This includes all six new SIMD families, old GPR
conversions/INIT vectors, actual generated application dispatch, complete vector
bank snapshots across yields, crossed-word rejection, cache profile separation,
source-site records and endpoint/progress validation. An additional CLI proof
check passed in the six-test frontier suite after the focused suite loaded.
Full milestone validation remains required; these are focused checks only.
The historical survey redecodes all 20 new-cohort records, separately counts
5 already-supported records and retains 241 unsupported records (266 total).

## Task 5: Run bounded original-code pilots and freeze the new milestone config

**Measured execution adjustment (2026-11-13):** The first pilots passed the old
frontier, then repeatedly discovered cases of one SDK byte jump table. Each
discovery required about four minutes of repeated static preparation. Private
research bound the exact original bounds-check/ADR/LDRB/scaled-add/BR recipe,
the captured table pointer/index, a 12-byte original read-only SDK table, all
12 original text targets and the observed branch target. The first attempts
were explicitly interrupted during analysis, with their evidence preserved.
The v2 pilots then exposed a second table in the same bounded original window.
Its pointer is an exact original ADRP/ADD constant with no intervening register
writes or calls; the second 12-byte table is also original read-only SDK data.
The v2 attempts were likewise preserved and explicitly interrupted during
analysis. Fresh v3 pilots add all 24 verified case targets and the already
observed targets through the existing `application_entries` API.
No production behavior, runtime target checks, root/row/retirement limits or
original instructions changed. The private proof and orchestration scripts
remain under `build/application-simd-pilots/`. The final seed may use the fresh
pilot's source-bound root list to avoid rediscovering those same cases; the
progress baseline must still be the unmodified historical frontier seed.

**Files:** New `config/milestones/application-simd.json`; private pilot results only under `build/`.

**Consumes:** Fresh inputs/seeds from Task0; completed synthetic checks from Tasks1..4.

**Produces:** Matching MSVC/GCC original-code diagnostics beyond the old frontier; an exact config fixed before the full run.

- [x] Use `build_startup.run` rather than manually retyping roots. Read `additional_entries` and `application_entries` from the relocated seed's last iteration; validate seed provenance. Use this exact profile:

```python
report = build_startup.run(
    prepared, output, compiler=compiler, execute_code=True,
    expand_targets=64, limit=1_000_000_000, quantum=10_000,
    initial_entries=prior['additional_entries'], trace_mode='compact',
    sdk=True, entropy_file=entropy, native_sdk=True, sdk_init=True,
    host_linked=True, fast_functions=True, native_cache=native_cache,
    application=True, application_entries=prior['application_entries'],
    romfs_index=romfs_index)
```

`prepared`, `output`, `entropy`, `native_cache`, `romfs_index` are resolved fresh `build/` Paths from Task0; `compiler` is `cmake` or `gcc`. Read the function before invocation; its return is the experiment report. Use a tiny ignored orchestration script, not production API churn for this one run.

- [x] Run the production static cohort report against the old baseline and newly selected manifest. The20 historical records listed in the design must now decode through the six families (record counts may include duplicates). Log the recomputed already-supported historical records separately. No inference that all20 sites executed.
- [x] Inspect the first terminal boundary outside the frozen cohort. Stop adding semantics here: do not implement a newly encountered API/instruction in this milestone. A source-bound unsupported word, native guard or SVC is an admissible measured endpoint. Selection/resource/contract/tool/input failures are not; diagnose them without relaxing bounds. If the frozen cohort does not permit a valid progress replay, report the exact blocker and do not call the milestone complete.
- [x] Full-replay the final pilot executable on each compiler and verify the original frontier retired. This must precede choosing the expected endpoint. Require matching compact/full trace digests, initialization/RomFS evidence, and all existing cross-compiler fields.
- [x] Copy the **values** of `config/milestones/application-content.json` into a new `application-simd.json`; leave the old file unchanged. Set:

```json
{
  "name": "application-simd",
  "native_build": "build/cmake-simd",
  "prepared": "build/prepared/oot111-g",
  "sdk_init_seed_report": "build/research/simd-handoff/sdk-init-seed.json",
  "application_seed_report": "build/research/simd-handoff/application-seed.json",
  "application_progress_baseline": "build/research/simd-handoff/application-seed.json",
  "application_romfs_index": "build/prepared/romfs111-g/romfs.index",
  "application_min_post_entry": 308488
}
```

This is the override set, not the complete config: preserve the original baseline paths, surveys, factory patterns and earlier experiments. The existing `test_application_*.py` pattern already selects the new tests. Set exactly one expected endpoint by the following deterministic rule:

1. error8, genuine unsupported selected original word -> `application_expected_word` from matching pilot word.
2. error9 + native stop + source-bound GUARD_ID31 -> `application_expected_guard` from the unique guarded export name.
3. error9 + no native stop + source-bound SVC -> `application_expected_svc` from the original SVC immediate.

Remove the other expected-endpoint keys. Never set any of these from an unselected continuation, invalid state or quota stop. No guessed endpoint constants go into Git.

- [x] Preserve all earlier baseline comparison fields. Do not require the old application endpoint after implementing it; that old configuration remains historical. Raw/SDK/logging/initialization endpoint comparisons remain mandatory.

### Task 5 checkpoint

Fresh v3 pilots and native-digest-verified full single-step replays match on
both compilers: 311,527 post-entry instructions, 1,833,173 original instructions,
51 scaffold instructions, 50 native calls and the same sealed four-file/3,427-byte
content effects. Both prove the former source-bound frontier STEP at its exact
expected retirement count. The genuine next word is CASAB, frozen in the new
config. Trace SHA256: `de98f56fac8f07207ed590c11aa864a917e0169e63d2a6f8cb38353e4cf67057`.
The new private `application-simd-seed.json` is an exact copy of the fresh pilot
report, retaining its already verified selection roots. The progress baseline
continues to name the unchanged historical seed. No original-code progress or
pass status was copied into a new run. Full validation is still required.

## Task 6: Complete status docs and review before final validation

**Files:** `README.md`, `docs/application-startup.md`, `docs/development-workflow.md`, `AGENTS.md`; final config and implementation diff.

**Consumes:** Matching pilots and focused test results; no stale performance assertions.

**Produces:** A reviewable final diff and truthful status before freezing source for the full run.

- [x] Document six supported families, their application-only profile and retained FP control domain. Add the ignored INS low-bit rule and explicit Q31 behavior to prevent later regressions.
- [x] Describe actual reached boundary and actual file/thread/provider state from pilot reports. Keep `game not playable`, diagnostics and static record counts distinct. Do not claim graphics initialization unless original execution evidence actually establishes it.
- [x] Update the development-workflow current milestone section; it currently still leads with initialization. Point to the new config/command and later measured boundary.
- [x] Review `git diff --check`, all changed files and added test fixtures. Verify no copied third-party code, bytes/disassembly, absolute game addresses, generated sources, binaries, keys, entropy or reports will be staged.
- [x] Verify Task0's input migration did not modify historical evidence. Verify kind1/2, operations23/24 and legacy classifiers/ABIs are unchanged. Check C/Python masks and enum mapping together. Check test loops run meaningful alias/reference cases without multiplying the whole suite unnecessarily.
- [x] Record known pilot test totals, but reserve final test totals for the successful final runner. Do not edit semantic source or milestone config after the next task starts.

### Task 6 checkpoint

Implementation/configuration and added fixtures were reviewed inline. Protected
float/dispatch/context/PAC/memory sources have no changes. No reference code,
generated game sources, private addresses, entropy, inputs or reports are included
in the Git change set. Both compiler lanes passed the eight final review checks
(reserved variants, crossed SIMD flags and frontier CLI/proof tests). Documentation
records the measured CASAB stop and labels historical validation separately.
Source/configuration is now frozen for the required full fresh run; final totals
and the source gate must be read from that run rather than inferred here.

## Task 7: Fresh full validation, reviewed commit and normal push to dev

**Consumes:** Frozen source/config, valid tools/inputs, all focused checks already passing.

**Produces:** Fresh complete evidence with current source digest, reviewed implementation commit, and verified `origin/dev` synchronization.

- [x] Run once in a fresh final directory, allowing the full runner to rebuild/test both native lanes and all earlier static/runtime baselines:

```powershell
& $py -B tools/run_milestone.py --config config/milestones/application-simd.json --output build/milestones/application-simd-v1
```

If it fails, fix the cause and use a new output directory (`...-v2`, etc.). Never rerun over a completed directory, reuse the old recovery script, edit source fingerprints, remove failing stages or mark skipped tests passed. Do not use `--native-only` as the full milestone result.

- [x] Require every required stage passed, no skipped required tests, both real compiler identities, unchanged legacy survey outcomes/trace baselines, matching current application traces/state, both source-bound progress proofs, sealed RomFS effects and exact terminal boundary. No fixed new test count is promised before the run.
- [x] Verify the final source fingerprint with the actual function:

```powershell
& $py -B -c "import sys,json; from pathlib import Path; sys.path.insert(0,'tools'); import run_milestone as m; p=Path('build/milestones/application-simd-v1/run.json'); r=json.loads(p.read_text()); assert r['status']=='passed'; assert r['source_sha256']==m.source_digest(); assert all(s['status']=='passed' for s in r['stages'].values()); print('final evidence and source match')"
```

Use the actual successful fresh directory if a retry was needed. Documentation-only final totals may be corrected after the run because the current source digest excludes Markdown; any production/test/config change requires rerunning.

- [x] Fetch `origin` and compare `dev...origin/dev`. If the remote has advanced, inspect and integrate without force push; rerun affected validation and the full source-fingerprint gate after any code change. Preserve unrelated local work.
- [x] Stage only the explicitly reviewed source, synthetic tests, new config and documentation. Inspect `git diff --cached --stat`, `git diff --cached --check`, and the staged diff itself. Create one implementation commit, for example:

```powershell
git commit -m 'Add checked application SIMD cohort and source-bound progress evidence'
git push origin dev
git fetch origin dev
git rev-parse HEAD
git rev-parse origin/dev
git status --short
```

- [x] Verify the two commit IDs agree. If transport/authentication blocks push, preserve the local commit and report the exact blocker; do not claim remote delivery. If GitHub Actions is available, inspect the triggered Checks workflow and distinguish its synthetic checks from private local game evidence.
- [ ] Final report in Vietnamese: delivered capability, real new boundary, synthetic/static/original-run evidence, successful commit/link and push status, limitations and the next design input. Do not claim playability or use test counts as completion percentage.

### Full validation checkpoint

Fresh `build/milestones/application-simd-v1/run.json` passed all 42 stages on
2026-11-13. It records 641 Python tests with no skips, seven CTest groups and
283,401 common native/reference comparisons per compiler. All old static and
runtime baselines are retained. Both full application proofs match the native
digest, cross the old UCVTF frontier at the exact checkpoint and reach CASAB at
311,527 post-entry instructions. The validated checkpoint has source_sha256
`970180c2b5903c4acc7592cdcd36592b2d4b397072eb66e1e0b0d32fd6891810`.
A fresh fetch found dev and origin/dev unchanged at f8a7162 before integration.
Commit `dec936d3087867ac92bcbb12015f20b5108c67e3` was pushed and verified
against origin/dev. Later narrow-CAS changes require their own fresh validation;
the SIMD run certifies this historical checkpoint.

## Handoff acceptance matrix

| Requirement | Evidence |
|---|---|
| Independent implementation | Diff/provenance review; no reference source imports |
| Correct six SIMD families | Literal masks, independent oracles, pinned-reference MSVC/GCC full-state checks |
| Legacy separation | Negative INIT/profile/cache tests; unchanged previous milestone endpoints |
| Runtime integration | Synthetic real dispatcher and per-instruction quota/yield tests |
| Actual original progress | Original frontier STEP in verified full traces on both compilers |
| Valid next stop | Frozen exact original word/export/SVC contract; no fabricated success |
| Input relocation | Fresh ExeFS/RomFS verification; private seed locators only |
| Complete milestone | Fresh passed runner, no skipped lanes, current source fingerprint |
| Remote delivery | Reviewed commit and HEAD == origin/dev after push/fetch |

## When to return to higher-effort design

Continue routine fixes/tests within this plan autonomously. Escalate design only for: a necessary new SDK/thread/GPU behavior, a different architecture/ABI, reference disagreement on a specified semantic, original-byte/provenance mismatch, inability to provision required compilers/inputs, or a failure that would require weakening a preserved contract. Legitimate clock/thread nondeterminism may invalidate exact trace agreement; do not fake time, discard trace rows or relax equality to conceal it. Return exact evidence and a narrow decision; do not start an unbounded opcode/API chase.
