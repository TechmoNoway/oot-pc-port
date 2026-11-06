# Milestone workflow

Development is organized around complete capabilities and measured blocker cohorts. A milestone includes its dependent instruction/runtime changes, verifier integration, synthetic native evidence, fresh private surveys, documentation and a reviewed commit/push on `dev`. The assistant completes these substeps autonomously within the authorized scope and reports the result at the milestone boundary. Small instruction families no longer require separate user prompts or separate releases.

## Current milestone: checked memory and callee clusters

[Policy 8/schema 9](checked-memory.md) adds explicit checked store capabilities to the PAC/LR-pair/PLT dispatcher, full operand/state validation before commit, and a new original-byte memory/callee survey. It preserves the preceding default and PLT policy outcomes, distinguishes newly accepted closures from later first failures, and publishes no game callbacks or runtime capabilities.

Completion requires synthetic byte/half/W/X/pair address/source matrices, staged effect isolation, independent read/write grants, current/ancestor frame protection, mixed PAC/PLT callees and maximum-depth cases, retained lifetimes, actual schema-9 factories, MSVC/GCC reference prefixes and refreshed private evidence. The completed [integer-frontier milestone](integer-frontier.md) remains available through its separate configuration.

## One command for a complete validation run

From the repository root, with the project environment, MSVC build, GCC and pinned ZBIC dependency available:

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config config/milestones/checked-memory.json `
  --output build/milestones/checked-memory-v3
```

Choose a fresh output directory for each run. The configuration selects the native build, prepared inputs, preceding default/PLT survey baselines, GCC factory test modules and expected report artifacts. It contains paths and check selections, never keys or captured game bytes. `--native-only` runs the synthetic portion without private game inputs or baseline files.

The runner configures/builds the pinned host/helper, then runs two independent native lanes in parallel: complete MSVC CTest/Python validation, and the GCC differential suite followed by the selected GCC factory tests. It checks both compiler identities, fresh native/factory artifacts, all required CTest groups and a complete Python pass without skips. Static default/PLT surveys run in parallel after native checks; the callee audit then reproduces the fresh policy-6 baseline. Previous/new surveys must match source/text identities, metadata denominator, decoder, model, policies and limits. The memory configuration also runs a policy-7/8 survey with callee-cluster/frontier evidence; both old baseline totals and per-module profile outcomes must remain unchanged, and the shared policy-7 results must match the fresh PLT survey. It verifies that no write grants were supplied by static analysis.

`run.json` records pending/running/passed/failed stage states and log paths. Failures leave their evidence available and produce a nonzero exit. It never marks an incomplete run passed. Stale native artifacts, changed source code during the run, mismatched inputs/models or remaining selected instruction frontiers reject completion. The source fingerprint covers CMake, source, tools, tests and milestone configurations. Reusing an existing output is rejected, so earlier successful evidence cannot silently stand in for a new run.

`summary.json` and `summary.md` collect aggregate evidence; `comparison.json` and full surveys remain private under the run directory. After successful validation, the assistant updates the README/status and capability documents, reviews the source diff and verifies that the current code fingerprint still matches the passed run. It then commits and pushes `dev` and verifies a clean synchronized tree. Later code changes require a fresh run. Game content, keys, generated game C, native binaries and detailed reports remain ignored. All native execution in this workflow is synthetic.

## Subsequent capability milestones

The next work is selected from the refreshed dependency audit by complete effects and real callee closures. Further memory milestones should target unframed memory helpers, address effects and actual blocked call closures under explicit ownership contracts. Loop and wider-call support should be delivered through complete opt-in contracts and mixed call graphs. Startup/services, followed by graphics and other host systems, require their own usable boundaries and integrated evidence.

Each milestone should be large enough to produce an assessable capability, with its implementation, verification and status update completed together. Existing PAC, memory, ownership and no-game-execution constraints stay in force. Ask for user input when a material scope choice, missing input or external blocker prevents sound progress; routine implementation choices stay inside the milestone.
