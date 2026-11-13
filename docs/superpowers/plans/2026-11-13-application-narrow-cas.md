# Application narrow CAS implementation plan

Execute inline after the application SIMD milestone has passed, been reviewed
and committed. Commit `dec936d` is verified on origin/dev after account selection.
Keep that validated checkpoint immutable. The overall user objective remains actual game output and
usable input; this is its next measured CPU capability, not a gameplay claim.

Design: [narrow CAS](../specs/2026-11-13-application-narrow-cas-design.md).
Keep independent implementation, ABI2, all old profile gates and complete
milestone commit rules. Never edit frozen SIMD source during its active run.

## 1. Red tests for exact application-only decoding and effects

- [x] Read AGENTS.md, the design, the passed SIMD run/summary and its final
  application bundle. Verify dev status and source drift; preserve other work.
- [x] Add `tests/test_application_cas.py`. Reuse existing atomic fixture/reference
  setup by module aliases and assigned methods; do not subclass/import a suite
  into a test module namespace. Require the pinned enabled ARM reference.
- [x] Construct words with `0x08a07c00 | (half<<30) | (acquire<<22) |
  (release<<15) | (rs<<16) | (rn<<5) | rt`. Check independent literals including
  `0x08e87d2a`, plus halfword and Rs/Rt31 examples. Assert old Python/C SDK/INIT
  rejection, app kind8 and exact sdk_atomic metadata from the design.
- [x] Observe the literal capability failure before changing production code.
- [x] Test all eight variants, every Rs/Rt pair with Rn cycling through0..31,
  explicit per-Rn aliases (Rs=Rn, Rt=Rn, Rs=Rt, all equal, all distinct,31),
  success/failure, truncation and W clearing. Compare complete native/reference
  registers/memory and independent byte/result equations. Capture address and
  source operands from the original state before resolving register aliases.
- [x] Test bad state, VA39 wrap, SP16, H misalignment, missing/RO/unmapped/split
  spans, malformed tables and unsupported encoding siblings. Preserve backing,
  registers and output sentinels on failures within the declared API domain.
  Reject malformed tables through memory_init; do not forge invalid native
  pointers in a live valid descriptor. Test the last mapped byte/halfword to
  catch implementations that incorrectly require a wider access.

## 2. Minimal backend and application helper

- [x] Factor CAS in `src/guest_memory.c` into a shared private helper. Preserve
  the old public wrapper's exact size4/8 admission and fault ordering; add the
  new size1/2 wrapper and declaration/comment in `src/guest_memory.h`.
- [x] Validate size before any width-dependent shift. Mask expected values and
  write only selected desired bytes under the same backend transfer lock.
  Require complete RW preflight even when the comparison fails.
- [x] Append enum8 and exact narrow classifier to `startup_init_atomic.{c,h}`.
  Add a dedicated step branch with original input capture, zero-extended Rs
  publication and existing PC/SP/NZCV/VA39 checks. New kind must not fall into
  fetch-add. Keep the old INIT/SDK helpers and application kind6/7 unchanged.
- [x] Add the explicit application-only Python classifier/metadata in
  `tools/sdk_init_instructions.py`; leave `tools/sdk_instructions.py` unchanged.
- [x] In `src/startup_dispatch.c`, extend the existing independent CAS expected
  state branch to new kind8. Snapshot size1/2 for the narrow family and expect
  zero-extended W(Rs), retaining the one-owner dispatcher precondition. Keep the
  old size4/8 branch and application metadata gates unchanged. Synthetic dispatch
  must catch a missing/wrong expectation as BAD_CALLBACK before this fix.
- [x] Run new tests on MSVC/GCC without skips, plus existing SDK CAS, INIT atomics
  and application atomics. Run native host/guest/ordered-memory self-tests.

## 3. Native order and real synthetic dispatcher

- [x] Add a bounded native two-thread CAS handshake over distinct guest aliases
  of the same backing. Both views/tables stay stable and every shared-byte
  access uses the backend. Check published payload before the release reset.
  Test byte and halfword; do not claim exhaustive weak-memory outcomes.
- [x] Extend the generated synthetic application boot fixture with a named
  `narrow_cas=False` option. Execute all variants with observable old-value and
  memory effects, independent expected bytes and a final synthetic BRK.
- [x] Compare whole/quantum1 execution and every quota around each new word.
  INIT still stops before nnMain, crossed flags/words reject before effects,
  and all original constructor/goal evidence remains mandatory.
- [x] Cache the same new word/PC under false/true/false application flags and
  compare uncached decoding. Run boot/cache/SDK-dispatch tests on both compilers.

## 4. Source-bound original progress and measured next endpoint

- [x] Add `application_atomic_sites` only in application bundle manifests for
  exact newly supported narrow CAS words, with original address/word/module,
  source hash and little-endian word hash. Preserve existing SIMD/SVC fields.
- [x] Extend `verify_progress_trace` to match the historical CASAB boundary to
  the new atomic site, while retaining SIMD proof behavior and exact source,
  retirement, next_pc, event/service/error, duplicate and malformed-row checks.
  Survey SIMD counts remain distinct from the newly supported atomic cohort.
- [x] Add synthetic proof/source mutation tests and legacy-manifest separation.
- [x] Create an exact private seed copy from the passed SIMD application's final
  report, not an interrupted pilot. Retain its proven code roots and seals.
  Add its exact observed CASAB frontier to application roots after checking the
  original boundary word/source record: the old INIT-only SDK root otherwise
  retains its rejected decode. Reauditing selects unchanged original code; it
  does not authorize an actual target or upgrade an older-profile bundle.
  Run both bounded original-code pilots with the same private entropy and
  current-path RomFS/ExeFS. Use native caches with source/tool/header identity.
- [x] Full single-step replay both final executables through build_startup.execute;
  require native digest/accounting, compact/accelerated and cross-compiler
  agreement, the exact old CASAB STEP and unchanged initialization/content state.
- [x] Freeze `config/milestones/application-narrow-cas.json` as a value copy of
  the SIMD config, with a fresh name, seed/progress-baseline pointing to the
  passed SIMD application report, a strictly later measured post-entry count
  and exactly one genuine new word/export/SVC endpoint. Never guess it.

## 5. Review, fresh full validation and dev delivery

- [x] Update status/design/plan/AGENTS.md for the actual measured behavior and
  limitations. Review all changed source/tests/config and no third-party imports,
  private game addresses/bytes, generated sources, reports, keys or binaries.
- [x] Freeze source and run tools/run_milestone.py with the new config and a fresh
  `build/milestones/application-narrow-cas-v1` output. Require every stage passed,
  no skipped lanes, preserved raw/SDK/INIT baselines, both progress proofs and
  a run source_sha256 equal to current run_milestone.source_digest().
- [x] Fix genuine failures with fresh outputs; never weaken endpoints, skip tests,
  edit fingerprints or recover by fabricating passed markers.
- [ ] Fetch/inspect origin/dev, integrate changes without force if necessary,
  review/stage only intended source/tests/config/docs, commit in English, push
  dev and verify HEAD equals origin/dev. Then continue from the next measured
  boundary toward actual original-game output/input.

## Selection checkpoint

The first MSVC pilot/full replay retained the old CASAB stop because its SDK
root had only been audited in the INIT profile. Its progress proof correctly
failed. The redundant GCC v1 build was stopped with a private interruption
record. A synthetic selection regression now checks the required explicit
application root and confirms that the prior INIT rows remain unchanged.
Fresh v2 pilots must prove actual progress; v1 is not passing evidence.

## Full validation checkpoint

`build/milestones/application-narrow-cas-v1/run.json` passed all 42 stages on
2026-11-13: 656 Python tests with no skips, seven CTest groups and 283,401 common
native/reference comparisons per compiler. Both native-verified full application
traces retire the old CASAB at the exact checkpoint and reach the guarded applet
resource getter at 311,535 post-entry instructions. All earlier profiles and
static baselines are retained. Current source_sha256 matches
`73babecba98a5534d153da6259332095c9b0d9ec5a14a4b221b576bfb03a523a`.
No stage was skipped or recovered by editing pass markers. A fresh fetch found
dev and origin/dev synchronized at `dec936d` before CAS integration. Git delivery
must still be verified before reporting it as complete.
