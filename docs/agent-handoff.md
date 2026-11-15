# Agent handoff

The latest task reviewed Hookshot, NX2navi and Fritchii for development throughput
and runtime lessons; see [the pinned reference review](reference-review-2026-11-15.md).
It changes documentation only. The earlier source/storage integration fast-forwards
dev from f8a7162 to 66a6549; no implementation conflicts were present.
The overall game goal remains incomplete: no original
rendered frame or usable input has been established. Do not start the next runtime
feature without its own capability milestone. The local integration validation
has passed all 50 stages with the current source gate matching.

## Workspace and standing decisions

- Active workspace: `C:\GAMES\Zelda Ocarina Of Time\oot-pc-port`, branch `dev`,
  remote `https://github.com/TechmoNoway/oot-pc-port.git`. The teammate's historical
  `G:\Zelda\oot-pc-port` paths are not the current workspace.
- Respond in Vietnamese. Keep source, documentation and commit messages in English.
  Implementation is independent; retain all applicable third-party notices.
- This machine's existing Git Credential Manager account is `TechmoNoway`, verified
  without exposing tokens. Commit/push dev is authorized. Use
  `git -c credential.username=TechmoNoway -c credential.interactive=false push origin HEAD:dev`.
  Never print or persist credential/token contents.
- Preserve original bytes, PAC, budgets/profile gates and every previous proof.
  Unknown services/objects remain unsupported stops. Do not fabricate handles,
  sessions or success, patch instructions or invent capabilities.
- The local `.venv\Scripts\python.exe` is healthy (Python 3.14.10). Current native
  tools are MSVC 19.44 and GCC 14.2; CMake is installed with VS2022 BuildTools.
  Do not run the archived machine-specific environment script or reuse its CMake
  cache/virtual environment. The pinned ZBIC Git checkout is `toolchain/zbic-src`.

## Completed historical display milestone

The transfer contains the final `build/milestones/display-initialization-v1/`
manifest and summary: all 50 stages passed, with 703 Python tests without skips,
seven CTest groups and 283,401 common comparisons per compiler. The quota-checkpoint
prose previously in this file preceded that final result. The exact archived raw
source fingerprint is
`5eada05fe79791bf3da82835ccb7960f5df2942174e23bb621f402ba3735d9ff`.
All 257 source files were independently verified. At integration, all 318 tracked
files matched the checkout after Git text normalization; subsequent changes are
documentation only. Do not change historical
fingerprints to match local line endings or describe historical passes as new local
validation. See [the integration record](source-integration.md).

The flags254/contextDISPLAY2048 profile owns a real hidden Win32 window and Vulkan
surface with queried presentation support, transactional rollback/counters and
creator-thread lifetime. Only the proved VI initializer is typed. Three original
constructor groups/six aliases retain original execution and vtable/callee proofs.
No guest Display, Layer, native-window or vsync object is returned yet.

Both original full display replays restore the first-VI-entry historical prefix
and retire the original caller after native return. They reach guarded
OpenDefaultDisplay, with 1,833,185 retired instructions (51 scaffold), 311,488 after
entry and 52 native calls. GS boot=1/check=0 and VI init=1; the old GS check is inside
the replaced parent. Their full digest is
`e330868f9e2bbdff0c7bf2b88258ecac138974fd33c7303b8ca2147d1a98bc21`.
Lower retirement than graphics is correct parent elision, not lost progress.

The earlier graphics milestone passed 46 stages, 687 Python tests, seven CTest
groups and 283,401 comparisons/compiler. Its full digest remains
`13dbf98c07554aa03ec450ac375df72b63eba8db6b6a74ee12848edce4a1b1de`.
Keep all earlier profiles and proofs unchanged.

## Current integration validation

The relocated reference view is private and explicitly marked historical:
`build/integration-20261115/historical-path-view/`. Original transfer bytes remain
preserved separately. Only derived JSON path strings were relocated; no historical
outcome or source fingerprint was promoted into local validation.

The fresh local full run uses `build/integration-20261115/display-local.json`,
`build/integration-20261115/native-build/` and output
`build/integration-20261115/validation-display-v1/`. Its frozen raw source SHA256 is
`073ce3db08d4fa8115a24b14ebfc14f4b0edd3e8213d48796dac4b6f0ebec0d4`.
It uses the verified local prepared inputs/RomFS index, not old G: paths. Its final
manifest passes all 50 stages, with 703 Python tests without skips, seven CTest
groups and 283,401 common comparisons per compiler. Both full display proofs match
the historical digest above, with real readiness/presentation support and original
caller continuation. The run finished 2026-11-15 09:47:53 UTC.

The original process ended after 45 recorded stages, with no failed stage or source
change. The private `build/resume_merged_validation.py` completed the same run;
its log is `build/merge-validation-resume.log`. It preserved original command
results and entropy, reexecuted every original post-command validation gate with
fresh diagnostic/full-replay directories, and executed every pending command.
The earlier manifest and narrow recovery changes are recorded under
`build/integration-20261115/`; do not treat the original log stopping at stage45
as the current process state.

```powershell
Set-Location 'C:\GAMES\Zelda Ocarina Of Time\oot-pc-port'
$run = Get-Content build/integration-20261115/validation-display-v1/run.json -Raw | ConvertFrom-Json
$run.status
$run.stages.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value.status)" }
Get-Content build/merge-validation-resume.log -Tail 8
git status --short
git log -3 --oneline
```

No validation process for this run should remain active. Preserve the passed
artifacts. Future source changes require a fresh run/output directory; do not
overwrite the sealed artifacts or use the one-off recovery wrapper for new work.
Do not launch extra heavy compilation during msvc-suite: this machine used
1,796.6 seconds of its existing 1,800-second budget. Do not increase the timeout
to hide a failure. Require a final passed manifest, all required stages, both full
display proofs and a matching current source gate before future delivery. Never
edit a result into success or weaken baseline/input checks.

## Preserved transfer and cleanup

The original Git bundle, manifests, dependency snapshots, original raw source and
metadata remain under `build/transfers/teammate-66a6549/`. Its consolidation map
records all 29,025 original files and their preserved local destinations/hashes.
Immutable duplicate artifacts share NTFS hard links; mutable reports remain
independent. Seven conflicting local build-tool reports/binaries retain both
versions. The verified sibling package was removed only after all preserved
members were checked. A local backup branch retains pre-integration dev.
Do not delete the preserved baselines, prepared inputs, source archive or current
validation output. Private generated code, original content and binaries stay out
of Git.
Post-build verification again passes all 29,025 preserved members. Cleanup removed
the duplicate outer package and recovered 57,394,421,760 bytes; the original NUP
and all historical inputs/evidence remain preserved.
The post-validation pass shared 2,561 byte-identical sealed artifacts and removed
2,898 new synthetic-test intermediate objects. It recovered another approximately
6.9 GB; tested DLLs, generated source, native caches and reports remain available.
`build/integration-20261115/cleanup-dedup.json` records its checks and exact scope.

## Next runtime milestone, after integration

The reference review recommends a measured shared-object-cache/checkpoint milestone
to reduce repeated compilation before further runtime work. Existing incremental
builds already work inside one cache; the observed waste is across separate caches.
Do not cache passed test outcomes or adopt reference zero-return fallbacks. The
Display/Layer source, ownership and lifetime requirements below remain unchanged.

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
