# Agent handoff

## Active ordered implementation

The user selected independently implemented NVN/Vulkan ownership plus an
external shader compiler tool. Both boot-to-NVN and the first genuine game frame
remain the requested milestones. Current uncommitted work adds application-only
LDAR (all four widths), `--nvn` over the refresh chain, the original 735-entry
NVN procedure table audit, original default builder execution, and owned
GetProcAddress/DeviceInitialize/Finalize bindings. A diagnostic pilot at
`build/research/display-objects-20261115/pilot-nvn-device-v1-cmake/` reached
guarded DeviceGetInteger after 1472 lookups and one initialization. Its device
identity borrows the live parent Vulkan owner; it is not a complete NVN device
implementation. Source-proved integer ABI version queries 0/1 (231/40) are now
being validated. Unknown properties remain unsupported. No game frame exists.
LDAR reference/generated-dispatch suites passed MSVC/GCC (four tests each);
the preceding NVN owner/audit/dispatcher suites passed ten tests per compiler.
The later `pilot-nvn-capabilities-v2-cmake/` reaches unsupported property 15
(texture descriptor size) at 325815 post-entry instructions: 1472 lookups, one
initialization, four implemented property queries and both mode setters.
Properties 42/90 explicitly report ASTC/debug false, not generic unknown success.
The new source audit has 3789 bindings; refresh-only now adds a separate original
NVN loader guard (3054 bindings), removed only by `--nvn` after its own proof.
The full new runner retains every preceding lane and adds NVN source/typed-stop,
original loader/caller full-prefix proofs and external shader/physical GPU probes.
Config: `config/milestones/nvn-bootstrap.json`, with a local path-adjusted copy
at `build/milestones/nvn-bootstrap-v1/local-config.json`.
The first 67-stage full validation at
`build/milestones/nvn-bootstrap-v1/validation/` is now explicitly FAILED,
after 63 passed commands/stages and 62 verified stages. Its refresh CMake runtime
correctly reached the original guarded NVN loader at 311523 post-entry retired
instructions, but `application_evidence` raised KeyError `entry_word`: the new
guard used a proved `_stage` record without normalizing its nested original
entry instruction into the flat native-binding word field. No guest crash or
passed new milestone is claimed. The controller and compiler/test children were
confirmed exited before changing source. Preserve this attempt; no commit/push.
Its frozen source was
`63943803d9dd6a581cb3b8ef2175e25f5c954336bd8b2ecfee12b3956030e711`.
That failed run passed 778 Python tests without skips, eight CTest groups,
283401 native/reference comparisons per compiler, source audits, renderer probes
and every retained lane through VSync. Its results remain historical evidence,
not new-source validation. `tools/native_binding.py` now validates/copies the
original entry word for both refresh-boundary and NVN source stages. Twenty
focused regression cases pass. The diagnostic preflight ran through
`build/preflight_nvn_boundary_fix_v1.py` at
`build/research/nvn-boundary-fix-preflight-v1/`, with stdout in
`build/preflight-nvn-boundary-v1.log`.
The preflight completed successfully: both new boundaries, native full/compact
hashes, restored original loader prefix and all 1479 typed original caller
continuations pass. Refresh hash:
`4260545ee7ad163265a8a5a26d3cb4a4d1547134d84dd918de06b08c937543c5`;
NVN hash: `b4995c838c6de21ed687a40759d3ecd6b0d26308bb2dfc51716d409b1d4d5015`.
The fresh full run completed successfully at
`build/milestones/nvn-bootstrap-v1/validation-v2/`, using
`local-config-v2.json` (also includes the extra pure NVN/shader GCC test groups)
and `validation-v2.log`. Its frozen source is
`39c931eabfa2826f650ad8c7dbd89486c71d314ed5df0fcbb992e3f23f3682e8`.
All 69 stages passed, with 780 Python tests without skips, eight CTest groups
and 283401 common native/reference comparisons per compiler. Both full NVN
replays reach property 15 at 325815 post-entry instructions and prove all 1479
original caller continuations. The final run finished at 2026-11-16 17:12:47 UTC
(2026-11-17 00:12:47 Asia/Saigon). Its source fingerprint still matches.
This run is sealed: preserve its outputs and use a fresh directory for new source.
The user authorized proceeding with delivery and descriptor/resource integration.
The next implementation must preserve this checkpoint and all older profiles;
the first genuine game frame remains incomplete.

The user additionally requested ongoing control of the checkout exceeding
100 GB. `build/storage-inventory-20261116-v1.json` measured about 225.1 GiB by
pathname versus 86.2 GiB of distinct file content (hardlinks explain the gap);
almost all is build output, while source/Git/environment/toolchain are under
150 MiB. Test-only intermediate pruning after the native stages ended removed
5160 files/about 103 MB (`build/nvn-storage-prune-v2.log`). Lossless NTFS
compression completed through `build/compress_closed_artifacts_v1.py`, with
progress/receipt at
`build/ntfs-closed-artifacts-compression-v1.log` / `.json`. It hashes every file
before/after and preserves logical size/mtime; the active validation-v2 and
original/prepared/transfer inputs excluded. All 8525 files preserve hashes,
logical sizes and mtimes; compression reclaimed 35.884 GB in addition to
15.431 GB from artifact sharing (about 51.3 GB combined). Observed drive free
space was about 64.1 GB after compression, despite the ongoing new validation.
The second allocated-space inventory completed through
`build/inventory_storage_20261116_v2.py`, with receipt
`build/storage-inventory-20261116-v2.json`: approximately 59.12 GB allocated
distinct data (55.06 GiB), versus 244.14 GB logical pathname sizes. The live
validation continued to grow during this snapshot. A later free-space check
reported 58.63 GB free. Source remains frozen at the hash above.
See docs/storage.md and the added AGENTS storage rule for future runs.

Do not resume/promote the failed first attempt. Sealed-stage byte/hash sharing through
`build/dedup_nvn_sealed_v2.py` completed: 7006 identical immutable artifacts share
storage, reclaiming 15.43 GB. It excludes mutable caches and retains all failed
evidence paths/outcomes; both known failed attempts contribute only passed and
verified stage outputs. See `build/nvn-sealed-dedup-applied-v2.json` and its
script for the exact rows (the report's short scope text names only the older
failed refresh attempt, but its rows/script also include the failed NVN run).
While validation-v2 is frozen, independent renderer prototypes were created
only under ignored `build/research/renderer-next/`; these are NOT production
changes or part of the frozen milestone source/evidence. Preserve their C
sources for the subsequent integration. `texture_roundtrip.c` includes the
frozen production owners and implements a real RGBA8 optimal image/view with
checked dimensions/format support, device-local allocation, staging, layout
transitions and fences. Eight odd-dimension 37x29 upload/readback iterations
pass MSVC/GCC; the final explicit HOST-stage barrier change was tested on GCC.
`shader_dispatch.c` creates an actual shader module/compute pipeline from the
external tool's synthetic EXIT-only SPIR-V, dispatches and completes a fence on
both compilers. This is driver acceptance of one trivial program, not general
SPIR-V validation or a game frame. Scripts/logs are `build/probe_texture_draft_v2.py`,
`build/probe_shader_dispatch_draft_v1.py`, `texture-draft-gcc-v1.log`,
`shader-dispatch-draft-{cmake-v2,gcc-v1}.log` and per-compiler results in the
prototype directory. They still require production ownership/error tests and
NVN resource/command integration; do not report these prototypes as a shipped
renderer or merge them while the full source gate remains active.

Read-only original resource research is recorded in
`build/research/graphics-supervisor/nvn-resources-research-v1.json` and
`nvn-resource-next-plan-v1.json`. Original TexturePoolRegisterTexture shifts its
signed W index by five and writes exactly eight words: direct exact-build
evidence for a 32-byte descriptor stride, not a borrowed Switch 1 constant.
This research grants no runtime authority. Implement its complete ABI/ownership
audit before changing the currently unsupported property 15 or pool providers.
`nvn-builder-cohort-v1.json` in that research directory surveys 180 original
Builder procedures: 179 decode in the existing application profile, and 166
are linear with one standard RET. This is a potential source-retention cohort,
not a proof of every memory operand/ownership contract or execution authority.
Audit those roles before selecting/unguarding any additional original builder.

The external compiler dependency is pinned under ignored
`toolchain/shader-compiler/`, with tracked `config/dependencies/` source locks.
Only shader-recompiler/Sirit/compat sources and their notices are fetched from
Hookshot commit 460b65424acf86be4c933858744e2932226f3f91; official SPIR-V
headers are pinned independently. The C runtime does not link this dependency.
The independent adapter is `tools/shader_compiler/`; its MSVC build succeeded
under `build/shader-compiler-v1/` (`tool-identity.json`, wrapper-v3 log).
Both dependency source locks, compatibility shim and binary are bound. Three
synthetic shaders translate successfully; invalid captures fail. A separate
`src/native_gpu.c` owns real Vulkan transfer buffers/pool/fence with barriers;
both physical compiler probes pass 32 copies/16 uploads/16 readbacks. Aggregate
report: `build/research/renderer-foundation-v1/report.json`. Synthetic GPU and
owner/dispatcher suites pass both compilers; final newer cases run in the full
milestone. Seven host CTest checks pass after the GPU change. No texture, game
shader, draw or present integration is established.
Captured shader inputs must be
explicit; missing cbuf/texture answers fail instead of inventing defaults.
The milestone source fingerprint now includes C++ adapter and dependency locks.
Only exited synthetic-test intermediates were pruned in this turn: 3470 files,
72.8 MB, with unchanged source gate (`build/nvn-test-prune-applied-v1.json`).
Original/prepared inputs, archived transfer, evidence and mutable caches remain.

The default Display 120 Hz capability milestone has an interrupted, failed
full validation at
`build/milestones/display-refresh-v1/validation/`, with its parent's
`local-config.json`, native build, `validation.log` and `delivery.json`.
Its frozen source is
`86b4ea66b91990560433d7c57c9bc4f9dc12b99f51efd2e68e23d9c41719248c`.
The user interrupted the preceding turn. The controller/children were confirmed
exited and its output lock free. A supported `--resume` attempt using the same
config/output rejected `resume command/environment differs` on 2026-11-16
(Asia/Saigon). `resume.log` records it. The manifest is explicitly failed with
59 stages passed/58 verified, not a completed milestone. No process remains
active, no cleanup touched these outputs, and no commit/push was made for this
milestone. Preserve this failed attempt; do not weaken its environment identity
or promote its outcomes. A fresh full run is required before delivery. The
current source has changed since that frozen hash. The separate
`--refresh` profile requires events/objects and declaration flags 3; older event
flags 1 and object flags 0 keep their guards. It implements only the public void
boolean capability declaration with private owned state, no mode change or IPC
session. Source audit checks 22 non-const named refresh consumers; the preceding
complete VI audit additionally guards both const DefaultDisplay refresh
consumers. It also closes two private backend
callbacks, with 3053 bindings in the unchanged 4096 limit. See
[display-refresh.md](display-refresh.md).
The private `refresh-inherited-const-closure-v1.json` in the research directory
below independently matches both inherited const guards to original complete
bodies/metadata; there are 24 related named consumers in total.

The full native phase has passed and verified: 759 Python tests without skips,
eight CTest groups and 283401 common native/reference comparisons per compiler.
The fresh source audits and physical display/VBlank peer probes passed. Raw,
SDK and native SDK replays passed on both compilers. This is an intermediate
checkpoint; remaining initialization/application/display/refresh replays and
the final passed source gate are still required before delivery.

Focused owner/dispatcher suites passed MSVC/GCC before the last additional owner
fault cases; the complete final owner cases then passed MSVC and will run on
both compilers in the full milestone. Eleven focused audit/progress/config cases
also pass. A diagnostic pilot under
`build/research/display-objects-20261115/pilot-refresh-v1-cmake/` passed handler
457 with the original false boolean and retired its caller. It stopped at
unsupported `LDAR X22, [X8]` after 313331 post-entry instructions, 1835028 retired
instructions and 56 native calls. Its 40 original application selection roots
are a bounded replay seed only. The full milestone must independently rebuild,
audit and verify both compiler full traces against the retained event prefix.
No NVN initialization, frame or usable input has been established.

SystemEvent/VSync integration passed a fresh full run:
`build/milestones/system-events-v1/validation-v2/`, with its parent's
`local-config.json`, native build and `validation-v2.log`. All 60 stages passed
and verified, with 750 Python tests without skips, eight CTest groups and 283401
common native/reference comparisons per compiler. It finished 2026-11-16
11:06:53 (Asia/Saigon); no validation/controller process remains active. Its
matching frozen source is
`91b670bfa34f65cd2ac83ee14be6ccd50725dd33bda6272caeb3d9379e7326ef`.
Further fingerprinted source changes require a new full run. This separate
60-stage run preserves every earlier lane, including the object run below.
See [system-events.md](system-events.md). The `--events` opt-in sets the compiled
declaration bit only after the new complete source audit; `--objects` alone keeps
its old guard. There are 256 original matching aliases/254 entries, 17 retained
original consumers and 3051 bindings, with no registry/budget increase. Delivery
commit, verified remote and subsequent CI state are recorded in the parent's
ignored `delivery.json`.

The first `validation/` attempt was interrupted during native suites when the
tool runtime changed. The exact controller/children were confirmed exited and
its output lock free with the unchanged source gate. Supported `--resume` then
rejected a command/environment identity mismatch. That manifest is preserved as
failed; do not resume/promote it. The v2 attempt starts every stage fresh and
does not reuse test outcomes from that attempt. `tool-interruption.json` and
`resume.log` in the parent record the attempted recovery.

Synthetic owner/dispatcher tests pass on MSVC/GCC, including actual SVC
wait/reset/miss/clear/close and yields. The new sparse publisher rejects a nonzero
destination tag before allocating resources. Both fresh full original compiler
replays publish one real VBlank-backed event and reach guarded
SetDisplay120HzRefreshRateCapability at 311509 post-entry instructions/55 native
calls, 1833206 retired instructions and 1833262 trace rows. Their matching full/
compact digest is `fecc545d3e7d6a089edfa396b2705603e53322c5ddae1ba61a106404178c853c`.
The new source audit rederives the default callback constructor/slots, readable
attachment, original consumer routes and four syscall sequences. Both early
CreateSystemEvent in-process calls remain original execution; a separately
proved private generic kernel creator stays guarded. No original game event wait,
NVN rendering, frame or usable input is established by publication alone.

Cleanup is explicitly user-authorized. Two passes shared 11713 byte-identical
immutable packages/traces/C artifacts, recovering about 27.2 GB. After all tests
ended, 17905 regenerable test intermediates (about 333 MB) were removed, for total
recovery about 27.5 GB and final observed free space 62.6 GB. Reports:
`build/events-sealed-dedup-applied-v1.json`, its v2 counterpart and
`build/events-test-prune-applied-v2.json` record exact scope and hashes. All
original inputs, prepared data, mutable caches and evidence paths remain. Do not
clean active compiler intermediates: an initial overlap removed a GCC object
before linking, then the affected three-test GCC suite was rerun successfully
after cleanup (`build/events-gcc-owner-dispatch-v2.log`). Future intermediate
cleanup must run only after the affected full/focused tests have all ended.

The default Display/Layer object implementation passed a fresh full run at
`build/milestones/display-objects-v1/validation-v2/`, using the parent's
`local-config.json` and native build. All 56 stages passed and verified, with
742 Python tests without skips, eight CTest groups and 283401 common native/
reference comparisons per compiler. It finished 2026-11-15 23:23:00 UTC. No full
validation/controller process remains active. Its matching frozen source gate is
`39d2d6a0a2acf170f2118aeb40ce8563a91f89e3ad6f01dafd92c0e4b73f88f1`.
Any further fingerprinted source changes require a new full run. This is distinct
from the earlier foundation below. See [display-objects.md](display-objects.md).
Delivery commit, verified remote and subsequent CI state are kept in the parent's
ignored `delivery.json`; no game input, trace or executable belongs in Git.

The first `validation/` attempt is explicitly failed and preserved. GCC exposed
the legacy display fixture including windows.h before declaring Win32 10 API
availability; `tests/native_display_test.c` now declares that version first.
The exact controller was verified and stopped, its output lock released and all
owned test children gone before the source change. Focused legacy display,
new peer and both object tests pass GCC after this fix. Do not resume or promote
that failed attempt; v2 is a complete fresh run with no reused test outcomes.

The separate flags510/context4096 profile binds five public object APIs, original
static identities, all eight VI/VI2 tables (103 slots/85 targets), and real owned
monitor/visible borderless window/Vulkan surface peers. Registry: 2833 entries,
unchanged 4096 limit. It retains original constructors and checks five live vptrs.
Both fresh full compiler replays pass OpenDefaultDisplay/CreateLayer and reach
guarded GetDisplayVsyncEvent at 311502 post-entry instructions with 54 native
calls, 1833199 retired instructions and 1833254 rows. Their matching digest is
`245009909241218c8095aad733c646bab258491881bad62fb83eaea67fc8b4e7`.
Both progress proofs restore the complete historical display prefix, observe
four original constructor/vptr-materialization steps and retire both original
caller continuations. The older display digest remains `e330868f9e2bbdff0c7bf2b88258ecac138974fd33c7303b8ca2147d1a98bc21`.
Private pilots/research are under `build/research/display-objects-20261115/`.
`physical-public-peers-v1/report.json` records both production public-API compiler
probes: actual 1920x1080 visible presentation-supported window/surface, 16 real
DXGI VBlank waits/resets each. The decorated-window candidate lost 19 client rows
to Windows tracking limits; the reviewed borderless implementation fixes actual
dimensions rather than relaxing checks. The full run independently repeats the
same production physical probe in its verified `physical-display-peers/` stage.

The compiled production declaration has event flags zero. Handler456 and its
scoped kernel token services are not enabled by the source generator. Their
native owner has synthetic sparse-publication/lifecycle tests only; complete
source producer/OS consumer closure remains necessary before a guest event is
published. The next dependency is SystemEvent, then the actually reached refresh/
NVN subset. There is still no original rendered frame or usable game input.

The following sections retain the historical foundation/integration evidence.

The Display object foundation passed fresh full validation at
`build/milestones/display-foundation-v1/validation/`, using its parent's
`local-config.json` and native build: all 52 stages passed and verified, 730 Python
tests without skips, eight CTest groups and 283,401 common native/reference
comparisons per compiler. Its frozen source is
`4a9596fac27df51d47bcd60de19cd88d63a01c32e506631d64692d54c982ad59`.
It finished 2026-11-15 17:26:26 UTC without interruption. Both fresh full display
digests are unchanged at
`e330868f9e2bbdff0c7bf2b88258ecac138974fd33c7303b8ca2147d1a98bc21`.
No full validation process remains active. The new implementation files include `unwind_provenance.py`,
`vtable_provenance.py`, `native_vblank.c/h`, their synthetic tests and the separate
CMake host timing library/test. They enable no guest capability. See
[display-object-foundation.md](display-object-foundation.md). The production static
audit proves all four original tables/53 slots/46 targets. The production host
fixture passes focused MSVC/GCC synthetic tests and separate physical 16-edge
wait/reset probes on both compilers; hardware logs are in
`build/research/display-objects-20261115/production-vblank-v1/`. A second probe
links `src/native_vblank.c` as its own translation unit, consumes only its public
header/API and passes the same physical 16-edge checks on both compilers; see
`production-vblank-linked-v1/` in that research directory.
The ignored `inspect_event_producer_chain.py` now traces both wrappers through
the actual default callback constructor to the original OS readable-handle
attachment. `event-default-producer-chain.json` retains full source/extent/slot
observations; this is source research, not a production ABI proof or callback
execution authority. Complete control-flow/argument/ownership and consumer proofs
are still required before any guest SystemEvent publication. Current startup flags,
handler registries, original selections and old full-prefix requirements remain
unchanged. This foundation is not completion of the full Display/Layer milestone.
`default-display-materializations.json` identifies the private original SDK
constructor and its source-bound static receiver. The rehashed historical full
trace confirms that constructor entry and both original vptr-store steps; see
`default-display-prefix-observations.json`. This supports retaining original
construction; verify source/relocation roles and live guest vptrs at binding too.
The static consumer merge survey finds 2,762 current bindings, 11 matching existing
guard entries and 35 additional private targets, without overlapping original
function extents. This fits the existing 4,096-entry limit. See
`consumer-merge-survey.json` and `runtime-integration-next.md` in the ignored
research directory for the concrete next profile; these do not register handlers.

The user authorized implementing the reference-review recommendations in order:
shared verified objects/checkpoint recovery, Display/Layer and the reached NVN
subset, then shader/rendering work. The first milestone has passed every gate.
`tools/object_cache.py` independently shares content-verified objects between
startup profiles and synthetic native fixtures. Every required executable/library
is linked and exercised. The full `build/milestones/build-cache-v3/validation/`
run passes 52/52 stages: 718 Python tests without skips, seven CTest groups and
283,401 common native/reference comparisons per compiler. Its frozen source is
`5f0d3cae98204560d03fc5aa8e397550a8af988d83b2c84e952229648b81c01a`.
Both full display digests remain
`e330868f9e2bbdff0c7bf2b88258ecac138974fd33c7303b8ca2147d1a98bc21`.
The run finished 2026-11-15 15:43:20 UTC, including a controlled interruption and
normal supported recovery. No validation/observer process should remain active.
No guest runtime capability changed. Commit
`09e8d4fa67493a5296b60e1feb90b15465b19d05` is verified on origin/dev. Its
GitHub Checks run `43731739688` completed successfully (verified through the public
GitHub API during the foundation slice).
The separately authorized Display/Layer milestone remains active. The foundation
pass validates its source/host dependencies, while guest object/event integration
and the reached NVN subset still need their own complete capability milestone.

The supported schema-2 checkpoint includes input/toolchain content identities,
owned artifact seals, native build binaries/rules, command/environment identity,
exclusive output ownership and gated Windows Job Object command lifetimes.
Focused checkpoint/workflow tests pass 18 cases, including actual process-tree
termination/restart and same-size/same-timestamp corruption. Object-cache tests
pass on both compilers; SDK vector tests pass 24 cases on each. Controlled
synthetic cold/warm measurements are documented in [build-cache.md](build-cache.md).
Use one full milestone at a time per checkout: synthetic report destinations are
shared. Never resume a failed run or substitute an earlier run's successful tests.

The earlier `build-cache-v1/validation/` attempt passed 714 Python tests, all seven
CTest groups, native comparisons, static audits and the first raw startup lane.
It was deliberately stopped before delivery to make direct post-command replays
use the same owned process-tree lifetime as staged commands. Its controller path,
arguments and recorded child relationship were verified before termination; its
incomplete manifest is explicitly failed and preserved. Do not resume or promote
that attempt. The v2 attempt passed 716 Python tests and seven CTest groups,
static audits, both raw compiler lanes and SDK/MSVC. An aggressive QA observer
exposed Windows read/delete sharing interference with atomic run.json publication.
The controller exited, and both its last committed and unpublished checkpoints
were preserved. That attempt is explicitly failed, not eligible for promotion.
The publication helper now retries only transient sharing/access denials within
a bounded interval; actual Windows handle tests cover release and persistent
denial. The v3 run reran every stage, then the verified controller was deliberately
terminated during the display/MSVC direct full replay (223,206 trace bytes).
`build/interrupt_display_replay_v3.py` performed the scoped interruption. The
ordinary CLI `--resume` reused only sealed commands, reexecuted all postconditions
and fresh full proofs, ran pending display/GCC and finished passed. No stage or
fingerprint was edited into success. Evidence/logs are in the v3 parent directory;
`resume_count` is 1. Earlier graphics observers timed out/missed their window and
did not interrupt the controller. They are not the successful recovery evidence.

Read-only next-milestone research is in
`build/research/display-objects-20261115/`. Its ignored extent-parser candidate
passes synthetic malformed-metadata checks and proves 46 unique original targets
across 53 vtable slots. The entire historical display trace is rehashed to the
native digest and contains zero calls to those targets before the current stop.
A host-only probe queries the real primary mode (1920x1080, refresh field 180);
it establishes no guest capability. `vblank_source.c/h` now implements a private
DXGI worker and real level-signaled events; synthetic signal/reset/ownership/
failure/overflow/cleanup tests and 16-edge physical wait/reset checks pass on both
compilers. `event_handle_candidate.c` passes synthetic atomic sparse record
publication and observed scoped SVC adapter checks on both compilers. These are
ignored candidates, not registered guest services. Complete source producer/
consumer binding, host peer integration and the new profile before promotion.
Read `next-slice.md` in that directory for the concrete remaining work and why
admitting unchecked original object member methods is not the chosen boundary.

The latest task reviewed Hookshot, NX2navi and Fritchii for development throughput
and runtime lessons; see [the pinned reference review](reference-review-2026-11-15.md).
That review changed documentation only. The earlier source/storage integration fast-forwards
dev from f8a7162 to 66a6549; no implementation conflicts were present.
The overall game goal remains incomplete: no original
rendered frame or usable input has been established. Do not start the next runtime
feature without its own capability milestone. The local integration validation
has passed all 50 stages with that checkpoint's source gate matching.

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
