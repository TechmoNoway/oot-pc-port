# Milestone workflow

Development is organized around complete capabilities and measured blocker cohorts. A milestone includes its dependent instruction/runtime changes, verifier integration, synthetic native evidence, fresh private surveys, documentation and a reviewed commit/push on `dev`. The assistant completes these substeps autonomously within the authorized scope and reports the result at the milestone boundary. Small instruction families no longer require separate user prompts or separate releases.

## Current milestone: SDK initialization and host-linked boot

The [SDK initialization profile](sdk-initialization.md) supplies owned platform and startup providers while retaining original SDK Start, application startup, module constructors and the exact nnMain transition. Its [acceleration extension](startup-acceleration.md) adds sealed split translation units, incremental native builds, checked whole-function leaves and a separate offline-linked boot scaffold. Original rtld text cannot execute on that linked package. Raw flags 1/3/7/15 remain separate diagnostics.

The final `build/milestones/sdk-initialization-v1/` run passes all 36 stages with a matching source fingerprint: 573 Python tests without skips, seven CTest groups and 283,401 common native/reference comparisons per compiler. Fresh static surveys retain all prior outcomes. The six preceding raw/SDK/logging experiments reproduce their original ordered trace digests.

Both new compiler runs complete the three original module constructor bodies exactly once, observe seven required stage entries and stop at the actual original nnMain transition before executing its body. Each retires 1,521,646 original and 51 scaffold instructions, with 15 native calls and 13 accelerated leaf calls. Accelerated and diagnostic single-step execution agree on the complete ordered trace digest for both compilers. This establishes the declared initialization experiment; graphics, filesystem mounts, other SDK consumers and gameplay remain further work.

## Preceding hybrid native SDK logging

The [native SDK boundary](native-sdk.md) retains the checked ARM64 translator and replaces a coherent logging family with owned host implementations. Four native operations cover initialization, destination, default-observer enablement and the common log-emission boundary; nine guarded APIs stop unsupported callbacks and opaque logger objects before effects. SDK functions outside this family remain original. OE initialization is observed through actual original entry retirement and is not replaced with an empty return.

The native configuration checks three separate execution modes on both MSVC and GCC: raw startup, original-SDK startup and hybrid startup. Earlier endpoints and full ordered trace digests remain required. Hybrid evidence binds the current original-export audit, NPDM, goal and private entropy; it must show native host operations, consistent separate retirement/call counters and actual original OE entry evidence. Native functions cannot overlap mandatory original goal markers. Successful logging initialization does not establish platform or application initialization.

The final `build/milestones/native-sdk-v1/` run passes every stage and the source-fingerprint gate: 444 Python tests without skips, seven CTest groups and unchanged prior survey outcomes. All six original-code experiments pass. Both hybrid executables retire 40,400,024 original instructions plus one native logging initialization, match all eight relocation probes and the complete ordered trace digest, and observe original OE entry retirement before stopping at its remaining `sm:` boundary. SDK initialization and game entry stay false. See [native SDK validation](native-sdk.md#validation-and-actual-startup-evidence) for the native/reference checks and exact scope.

## Preceding SDK runtime foundation

The [SDK runtime](sdk-runtime.md) extends the separate original-startup experiment with declared process queries, private entropy, TLS operations, read-only main-thread services and scalar atomic compare/exchange. An original-byte audit binds the observed TLS identity profile and the mandatory stage/nnMain goal. The current foundation endpoint is the real service-manager connection boundary, with SDK initialization and application entry explicitly incomplete. IPC transport, handle/session ownership and service semantics form the next dependency cluster.

The SDK configuration reruns both the preceding raw-startup endpoint and the extended SDK path from fresh raw images. Prior observed code roots are reselected against current verified originals; they never approve a live target or bypass an original instruction. Both SDK compiler runs share private process entropy and must match the complete ordered trace digest. A diagnostic endpoint cannot satisfy the nnMain goal.

The final `build/milestones/sdk-runtime-v1/run.json` passes all required stages with a matching source fingerprint: 415 Python tests without skips, seven CTest groups and 283,401 common native/reference comparisons per compiler. Both process-context C self-tests pass 7,810 checks. The preceding original-startup endpoint and its full trace digest remain unchanged, and fresh default/PLT/bounded surveys preserve their outcomes. Both extended SDK executables retire 40,399,581 original instructions, match all eight relocation probes and the complete ordered trace digest, then stop at ConnectToNamedPort for `sm:`. Five of seven required stage entries are observed; this is not five completed function bodies. SDK initialization and game entry remain explicitly false. See [SDK execution evidence](sdk-runtime.md#execution-evidence) for the additional reference/atomic checks and remaining IPC and heap dependencies.

## Preceding experimental native startup

[The startup bootstrap](startup-bootstrap.md) follows the original loader entry, audits initializer metadata/dependencies and connects selected translated instructions to a private Windows executable, explicit process context and trace diagnostics. Its raw-image/one-shot contract is separate from leaf/stack policies. It preserves the existing synthetic validation and static-survey scope while adding explicitly authorized experimental original-code execution.

The process model and Switch 2 ABI remain unproven, and an expected diagnostic stop is not completed startup. The final `build/milestones/startup-bootstrap-v1/run.json` reports every stage passed with an unchanged source fingerprint: 379 Python tests without skips, seven CTest groups and 283,401 common cases per compiler. The startup suite checks 480 complete runs/4,624 prefixes per compiler plus 36 cross-module/chunk cases; the process-context self-test checks 273 cases. Both native compilers reach SDK initialization after 40,397,142 instructions, match all eight entry-module relative probes and the complete ordered trace digest, then stop at GetInfo ID 11 (handle zero, sub-ID two).

Completion requires exact synthetic state/memory prefixes, original-word/control/PAC checks, loop/writeback and operand-window failures, invalid targets, real service effects, one-shot image ownership, copied lifetimes and trace/checkpoint/quota cases on both compilers. Fresh original-byte startup analysis and unchanged default/PLT/bounded outcomes must accompany matching experimental MSVC/GCC retired prefixes, independently checked relocation slots and the declared precise stop. A contract failure cannot satisfy that stop. The preceding [bounded-memory](bounded-memory.md), [memory-callee](memory-callees.md), [checked-memory](checked-memory.md) and [integer-frontier](integer-frontier.md) milestones remain available through separate configurations.

## One command for a complete validation run

From the repository root, with the project environment, MSVC build, GCC and pinned ZBIC dependency available:

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config config/milestones/application-content.json `
  --output build/milestones/application-content-v1
```

Choose a fresh output directory for each run. The configuration selects the native build, prepared inputs, preceding survey baselines, GCC factory test modules, expected report artifacts and an explicit startup diagnostic stop. It contains paths and check selections, never keys or captured game bytes. `--native-only` runs the synthetic portion without private game inputs or baseline files. The full startup configuration includes experimental original-code execution; the separate builder requires `--execute` when used directly.

The runner configures/builds the pinned host/helper, then runs two independent native lanes in parallel: complete MSVC CTest/Python validation, and the GCC differential suite followed by selected factory tests. It checks both compiler identities, fresh native/factory artifacts, required CTest groups and a complete Python pass without skips. Static default/PLT/bounded surveys and the policy-6 callee audit preserve source/text identities, metadata denominator, decoder/model/limits and existing outcomes. Shared policy-9 profile comparison includes retained accepted/rejected samples; prior-frontier comparison checks its three exhaustive aggregate counts, not frontier samples or every target identity. Current zero-loss candidate/root counts come from the real production maps. Static reports still supply no runtime grants or live GOT guarantees.

The startup configuration adds an entry/initializer audit and private raw-image execution with MSVC and GCC. Preparation links a separate audit copy, never the loader's runtime input. Each executable is bound to the exact raw package and original selected words/spans; every expansion iteration restarts on fresh backing. Bounded exact-PLT lookahead preselects potential original callees without approving live targets or omitting the stubs. The runner requires original-code execution to be explicitly reported, startup/ABI proof flags to remain false, matching compiler stop PC/word/service/retired count, the exact declared GetInfo request, independent relative-pointer probes and the full ordered trace SHA-256. Compact logs sample rows while hashing every row. Native contract failures, absent execution or a different diagnostic boundary reject completion.

The SDK configuration also requires a current SDK/NPDM/thread-identity audit, fresh SDK tests on both compilers and a GCC build/run of the complete process-context C self-test. Its configuration names the actual service/known port and required stage-entry count, or explicitly requires the full initialization goal. Matching audit input identities, executable goal metadata and entropy fingerprints are checked. A passed foundation run certifies its declared capability and diagnostic endpoint; the separate `sdk_initialization_completed` and `game_entry_reached` values remain authoritative.

The native configuration adds the original-function/record-layout audit and both hybrid executables. Event 3 represents a whole native operation rather than an original ARM instruction: `trace_steps = retired + native_calls` and `trace_rows = trace_steps + 1`. Both kinds count toward work quota. Host state and the guarded-operation stop kind must match across compilers. Callback/native return checks, copied registry lifetimes, interior/body tampering, incomplete goals and original/native trace equivalence are covered by synthetic tests.

`run.json` records pending/running/passed/failed stage states and log paths. Failures leave their evidence available and produce a nonzero exit. It never marks an incomplete run passed. Stale native artifacts, changed source code during the run, mismatched inputs/models or remaining selected instruction frontiers reject completion. The source fingerprint covers CMake, source, tools, tests and milestone configurations. Reusing an existing output is rejected, so earlier successful evidence cannot silently stand in for a new run.

`summary.json` and `summary.md` collect aggregate evidence; comparisons, full surveys, startup packages, generated C and detailed traces remain private under the run directory. After successful validation, the assistant updates the README/status and capability documents, reviews the source diff and verifies that the current code fingerprint still matches the passed run. It then commits and pushes `dev` and verifies a clean synchronized tree. Later code changes require a fresh run. Game content, keys and native binaries remain ignored. Regression execution is synthetic; the separately labeled opt-in startup experiment executes its selected original prefix and must never be described as a playable port.

## Subsequent capability milestones

The next work is selected from measured entry-path stops and the dependency audit. Startup services, module/import initialization and remaining semantics must be established for the actual path rather than inferred from global helper counts. Broader loops, layouts and call closures keep explicit opt-in contracts. Graphics/shaders, input, audio and other host systems require their own usable boundaries and integrated evidence before gameplay.

Each milestone should produce an assessable capability, with implementation, verification and status update completed together. Existing PAC/memory/ownership constraints and the no-game-execution scope of earlier profiles/surveys stay in force. Explicit original-code experiments keep their own declared boundaries and evidence. Ask for user input when a material scope choice, missing input or external blocker prevents sound progress; routine implementation choices stay inside the milestone.


## Application and content milestone

The separate application configuration preserves all prior raw/SDK/logging
prefixes and complete host initialization, then executes the original nnMain
body on a fresh linked image. Its original-export audit adds the owned
notification policy and read-only RomFS family. Preparation uses
`tools/prepare_romfs.py` to verify the selected NUP's content and produce a
private index/cache under `build/`; raw bytes remain in the NUP.

`--romfs-index` is application-only. The builder checks its exact original
catalog/ExeFS/NPDM provenance and compiles its full index seal into the CLI
object. Provider handles own bounded read-only views, and unsupported consumers
remain guarded. No extracted assets or generated bindings belong in Git.
The final runner checks entry-instruction retirement, the initialization
checkpoint, actual thread/mount effects, input/index/generated/executable seals,
old baselines and fast/single-step trace agreement on MSVC/GCC. A declared
post-entry diagnostic remains separate from gameplay. The configuration names
one exact unsupported export or original instruction word. An instruction
endpoint additionally requires its original selected-row/module/word-hash
provenance; an arbitrary budget stop, memory fault or missing selection cannot
substitute for the measured capability boundary.
