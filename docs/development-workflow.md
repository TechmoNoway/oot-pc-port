# Milestone workflow

Development is organized around complete capabilities and measured blocker cohorts. A milestone includes its dependent instruction/runtime changes, verifier integration, synthetic native evidence, fresh private surveys, documentation and a reviewed commit/push on `dev`. The assistant completes these substeps autonomously within the authorized scope and reports the result at the milestone boundary. Small instruction families no longer require separate user prompts or separate releases.

## Current milestone: experimental native startup

[The startup bootstrap](startup-bootstrap.md) follows the original loader entry, audits initializer metadata/dependencies and connects selected translated instructions to a private Windows executable, explicit process context and trace diagnostics. Its raw-image/one-shot contract is separate from leaf/stack policies. It preserves the existing synthetic validation and static-survey scope while adding explicitly authorized experimental original-code execution.

The process model and Switch 2 ABI remain unproven, and an expected diagnostic stop is not completed startup. The final `build/milestones/startup-bootstrap-v1/run.json` reports every stage passed with an unchanged source fingerprint: 379 Python tests without skips, seven CTest groups and 283,401 common cases per compiler. The startup suite checks 480 complete runs/4,624 prefixes per compiler plus 36 cross-module/chunk cases; the process-context self-test checks 273 cases. Both native compilers reach SDK initialization after 40,397,142 instructions, match all eight entry-module relative probes and the complete ordered trace digest, then stop at GetInfo ID 11 (handle zero, sub-ID two).

Completion requires exact synthetic state/memory prefixes, original-word/control/PAC checks, loop/writeback and operand-window failures, invalid targets, real service effects, one-shot image ownership, copied lifetimes and trace/checkpoint/quota cases on both compilers. Fresh original-byte startup analysis and unchanged default/PLT/bounded outcomes must accompany matching experimental MSVC/GCC retired prefixes, independently checked relocation slots and the declared precise stop. A contract failure cannot satisfy that stop. The preceding [bounded-memory](bounded-memory.md), [memory-callee](memory-callees.md), [checked-memory](checked-memory.md) and [integer-frontier](integer-frontier.md) milestones remain available through separate configurations.

## One command for a complete validation run

From the repository root, with the project environment, MSVC build, GCC and pinned ZBIC dependency available:

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config config/milestones/startup-bootstrap.json `
  --output build/milestones/startup-bootstrap-v1
```

Choose a fresh output directory for each run. The configuration selects the native build, prepared inputs, preceding survey baselines, GCC factory test modules, expected report artifacts and an explicit startup diagnostic stop. It contains paths and check selections, never keys or captured game bytes. `--native-only` runs the synthetic portion without private game inputs or baseline files. The full startup configuration includes experimental original-code execution; the separate builder requires `--execute` when used directly.

The runner configures/builds the pinned host/helper, then runs two independent native lanes in parallel: complete MSVC CTest/Python validation, and the GCC differential suite followed by selected factory tests. It checks both compiler identities, fresh native/factory artifacts, required CTest groups and a complete Python pass without skips. Static default/PLT/bounded surveys and the policy-6 callee audit preserve source/text identities, metadata denominator, decoder/model/limits and existing outcomes. Shared policy-9 profile comparison includes retained accepted/rejected samples; prior-frontier comparison checks its three exhaustive aggregate counts, not frontier samples or every target identity. Current zero-loss candidate/root counts come from the real production maps. Static reports still supply no runtime grants or live GOT guarantees.

The startup configuration adds an entry/initializer audit and private raw-image execution with MSVC and GCC. Preparation links a separate audit copy, never the loader's runtime input. Each executable is bound to the exact raw package and original selected words/spans; every expansion iteration restarts on fresh backing. Bounded exact-PLT lookahead preselects potential original callees without approving live targets or omitting the stubs. The runner requires original-code execution to be explicitly reported, startup/ABI proof flags to remain false, matching compiler stop PC/word/service/retired count, the exact declared GetInfo request, independent relative-pointer probes and the full ordered trace SHA-256. Compact logs sample rows while hashing every row. Native contract failures, absent execution or a different diagnostic boundary reject completion.

`run.json` records pending/running/passed/failed stage states and log paths. Failures leave their evidence available and produce a nonzero exit. It never marks an incomplete run passed. Stale native artifacts, changed source code during the run, mismatched inputs/models or remaining selected instruction frontiers reject completion. The source fingerprint covers CMake, source, tools, tests and milestone configurations. Reusing an existing output is rejected, so earlier successful evidence cannot silently stand in for a new run.

`summary.json` and `summary.md` collect aggregate evidence; comparisons, full surveys, startup packages, generated C and detailed traces remain private under the run directory. After successful validation, the assistant updates the README/status and capability documents, reviews the source diff and verifies that the current code fingerprint still matches the passed run. It then commits and pushes `dev` and verifies a clean synchronized tree. Later code changes require a fresh run. Game content, keys and native binaries remain ignored. Regression execution is synthetic; the separately labeled opt-in startup experiment executes its selected original prefix and must never be described as a playable port.

## Subsequent capability milestones

The next work is selected from measured entry-path stops and the dependency audit. Startup services, module/import initialization and remaining semantics must be established for the actual path rather than inferred from global helper counts. Broader loops, layouts and call closures keep explicit opt-in contracts. Graphics/shaders, input, audio and other host systems require their own usable boundaries and integrated evidence before gameplay.

Each milestone should produce an assessable capability, with implementation, verification and status update completed together. Existing PAC/memory/ownership constraints and the no-game-execution scope of earlier profiles/surveys stay in force. Explicit original-code experiments keep their own declared boundaries and evidence. Ask for user input when a material scope choice, missing input or external blocker prevents sound progress; routine implementation choices stay inside the milestone.
