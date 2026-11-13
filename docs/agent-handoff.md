# Agent handoff

Read this file before continuing. The user requested saving a reviewable checkpoint
because their quota is nearly exhausted. Finish/check the current validation before
starting the next feature. The overall game goal is still incomplete: no original
rendered frame or usable input has been established.

Quota checkpoint: the previously active native validation stage is complete and
passed 703 Python tests without skips, seven CTest groups and 283,401 common
comparisons per compiler. Code is saved as a reviewed checkpoint; the remaining
full 50-stage original-analysis/execution run is still active. This is not a claim
that all 50 stages passed. Preserve its source and consult its manifest.

Checkpoint source verification covers all 257 source files, with canonical text
content hash `e6d44d8897a24f61f35eda364d7809379cf5ba40994832aee02fe8f5f9eba642`.
This hash accounts for configured Git text line endings; the local raw fingerprint
for the active run is recorded below. Read `git log -1` for the checkpoint SHA.

## Workspace and standing decisions

- Active workspace: `G:\Zelda\oot-pc-port`, branch `dev`, remote
  `https://github.com/TechmoNoway/oot-pc-port.git`. The older `E:` checkout and
  historical `C:\GAMES` build caches are not this workspace.
- Respond to the user in Vietnamese. Keep source, documentation and commit messages
  in English. Implementation is independent; Fritchii/Hookshot are references only.
- GitHub account `AnhTc0` / `anhtc0` was explicitly confirmed and used successfully.
  Do not ask for the username again. Use
  `git -c credential.username=AnhTc0 -c credential.interactive=false push origin HEAD:dev`.
  Never print or persist credential/token contents. Commit/push dev is authorized.
- Preserve original bytes, PAC, all existing budgets/profile gates and every
  previous proof. Unknown services/objects remain real unsupported stops. No dummy
  handles, fake sessions, no-op success, patched instructions or invented caps.

## Delivered graphics checkpoint

Commit `7434802ef157cb8f76c8185e89fa66a90f9a6fac` is verified on origin/dev.
[GitHub Windows Checks](https://github.com/TechmoNoway/oot-pc-port/actions/runs/43451205858)
passed. Its tree was clean at delivery. Local
`build/milestones/graphics-bootstrap-v1/run.json` passed all 46 stages: 687 Python
tests without skips, seven CTest groups and 283,401 common comparisons/compiler.
Both original full replays match digest
`13dbf98c07554aa03ec450ac375df72b63eba8db6b6a74ee12848edce4a1b1de`.
The real Vulkan boot/check resumes the original caller and stops in VI initialization
at the guarded GSV session getter. This is device readiness, not gameplay.

## Current VI implementation and validation

The source implements a separate flags254/contextDISPLAY2048 profile over graphics:
one real hidden Win32 window, a Vulkan surface, queried queue presentation support,
transactional rollback/counters, creator-thread lifetime and a separate report.
Only the source-proved public VI initializer is typed. All other unsupported VI/VI2
consumers remain closed; three original constructor groups/six aliases retain their
actual original execution and vtable/callee proofs. No guest Display, Layer, vsync
object or native-window handle is returned yet.

Actual-tree context RED failed for the absent API before promotion, then GREEN
passed. Actual-tree focused checks pass 14 native display/graphics cases per compiler
plus 17 pure audit/progress/configuration cases, without skips. Standalone real GPU
window/surface creation/support and window/class cleanup passed on MSVC and GCC.

The immutable source prototype is `build/application-display-candidate`, fingerprint
`0159325d1cbe68751e32258771161e0d294949c76c56b510656fa36e2ba110ce`.
Both `build/display-pilots/{cmake,gcc}-v1/` original pilots pass full native hashes,
single-step/accelerated equivalence, historical first-VI-entry prefix restoration
and original caller continuation. They reach guarded OpenDefaultDisplay, with
1,833,185 retired instructions (51 scaffold), 311,488 after entry and 52 native calls.
GS boot=1/check=0 and VI init=1; the old check lies inside the replaced parent.
Their complete digest is
`e330868f9e2bbdff0c7bf2b88258ecac138974fd33c7303b8ca2147d1a98bc21`.
Lower retirement than graphics is correct parent elision; larger counters do not
establish progress. Keep the immutable prototype unchanged.

The complete current validation is `build/milestones/display-initialization-v1/`,
configured by `config/milestones/display-initialization.json`. It retains all 46 old
stages and adds a GCC pure-test pattern, source audit and two display lanes: 50 total.
It started 2026-11-13 22:46:51 Asia/Bangkok on frozen local source
`5eada05fe79791bf3da82835ccb7960f5df2942174e23bb621f402ba3735d9ff`.
At checkpoint preparation its native-evidence stage passed and original surveys
were running; consult the actual manifest, not this prose,
for its current outcome. A full display milestone has not yet been claimed passed.

**Do not change src/tools/tests/config/vendor headers while that run is active.**
The runner rejects a changed source fingerprint. Documentation and ignored research
may be updated. Do not launch extra heavy native compilation during `msvc-suite`;
its existing 1,800-second stage budget is tight. Do not increase timeouts to hide a
failure. The source-only integration copy is `build/application-display-integration`.

## Read the live state and finish safely

```powershell
Set-Location G:\Zelda\oot-pc-port
. .\build\environment-repair\Enter-ZeldaBuild.ps1
$run = Get-Content build/milestones/display-initialization-v1/run.json -Raw | ConvertFrom-Json
$run.status
$run.stages.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value.status)" }
Get-Content build/research/display-handoff/full-milestone-v1.log -Tail 6
git status --short
git log -3 --oneline
```

The environment script supplies the working `.venv-dev` Python 3.14, MSVC19.44,
CMake3.31 and GCC16.2 paths. The older `.venv` is broken. If the run is still active,
wait/monitor its existing process; do not start a duplicate run or alter source.
In this chat its execution session was54702; a different chat may need to locate
the process by the exact `run_milestone.py` output path and read the manifest/log.

The user explicitly requested this quota checkpoint after the native stage, so a
code commit may precede the full milestone result. Do not confuse that checkpoint
with final milestone delivery. Do not restart or terminate the existing full run
merely because a checkpoint was committed; Git metadata/docs do not alter its
frozen runtime source. Wait for its result before implementing future code.

If passed, require all 50 stages, its `summary.json`, both native full display proofs
and the current source gate before calling it complete. Record measured test counts,
update README/workflow/display plan/handoff and verify the reviewed Git contents,
commit/push dev, remote SHA and CI. If failed, inspect the first failure, fix the
actual cause and use a fresh output directory for a new full run. Keep failed logs.
Do not edit a manifest into success or restore old source just to match a fingerprint.

To rerun only when justified after a failure/source change:

```powershell
& $py -u tools/run_milestone.py --config config/milestones/display-initialization.json `
  --output build/milestones/display-initialization-v2
```

Run manifests fingerprint local raw file bytes. Git normalizes text line endings;
verify committed source content equivalence rather than assuming a fresh checkout's
raw fingerprint must equal a historical Windows working tree. The graphics delivery
recorded both hashes and checked all245 source files. Do not change or falsify
historical fingerprints. Private prepared inputs/traces are intentionally ignored.

## Future task, after this checkpoint

Use the [display plan](superpowers/plans/2026-11-13-display-initialization.md) and
[next object plan](superpowers/plans/2026-11-13-display-objects-next.md). The actual
main caller calls VI Initialize, OpenDefaultDisplay, CreateLayer, GetDisplayVsyncEvent,
a refresh capability API, then nvnBootstrapLoader. GSV's reached session guard was
inside VI initialization, not initially an NVN resolver dependency.

Key discoveries: default Display and the reached Layer overload use source-derived
static original identities, and archived constructor trace proves the default Layer
was constructed. A new guest object allocation arena is not justified for that path.
The native-window member is ADD plus a proved PLT tail to an original identity RET;
do not infer its result from ADD alone. Vtables contain non-exported consumers that
need proper original extent/guard provenance before polymorphic identities are
exposed. Current code does not implement those objects.

Private evidence, available only on this machine:

- `build/research/display-handoff/original-instances-v2.log`,
  `original-vtable-census.json`, `vtable-research-v1.log`, `object-identity-design.md`.
- `build/research/graphics-supervisor/vi-object-research-v2.log`,
  `display-object-notes.md`, `nvn-procedures.json`, `nvn-fde-ranges.json`,
  `next-nvn-design.md`. NVN has735 source/FDE-proven procedure records; no new
  native NVN implementation or runtime authority is granted by that census.
- `build/research/display-handoff/actual-*.log` and `display-seed.json`;
  source-frozen pilot artifacts under the immutable candidate.

If ignored prepared inputs/historical native full traces are absent in another
checkout, state that and recover/regenerate them from the relevant historical commit
and user-owned inputs in an isolated workspace. Do not fabricate baselines or weaken
input containment. Never put ROMs, keys, entropy, original words/addresses, generated
C, traces or executables into Git. Continue until actual original frames/input only
when the user resumes development; this handoff is not a claim that the game runs.
