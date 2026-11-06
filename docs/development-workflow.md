# Milestone workflow

Development is organized around complete capabilities and measured blocker cohorts. A milestone includes its dependent instruction/runtime changes, verifier integration, synthetic native evidence, fresh private surveys, documentation and a reviewed commit/push on `dev`. The assistant completes these substeps autonomously within the authorized scope and reports the result at the milestone boundary. Small instruction families no longer require separate user prompts or separate releases.

## Current milestone: memory-leaf callee closures

[Bound memory leaves and stack policy 9/schema 10](memory-callees.md) integrate explicit image read/write effects through direct and exact-PLT calls. Ordinary leaves and stack policies 1-8 keep their earlier permissions and outcomes. The milestone includes original-byte target classification, real callee closure proofs and complete native effect/fault/yield evidence.

Completion requires full state/memory comparison for standalone/mixed/maximum-depth synthetic callees, separate operand grants/windows, protected caller stacks, live GOT/hash checks, negative callbacks and copied lifetimes, actual schema-10 factories, both native compilers, unchanged old baselines and exact reproduction of the prior missing-target frontier. The preceding [checked-memory milestone](checked-memory.md) and [integer frontier](integer-frontier.md) remain available through their separate configurations.

## One command for a complete validation run

From the repository root, with the project environment, MSVC build, GCC and pinned ZBIC dependency available:

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config config/milestones/memory-callees.json `
  --output build/milestones/memory-callees-v3
```

Choose a fresh output directory for each run. The configuration selects the native build, prepared inputs, preceding default/PLT survey baselines, GCC factory test modules and expected report artifacts. It contains paths and check selections, never keys or captured game bytes. `--native-only` runs the synthetic portion without private game inputs or baseline files.

The runner configures/builds the pinned host/helper, then runs two independent native lanes in parallel: complete MSVC CTest/Python validation, and the GCC differential suite followed by the selected GCC factory tests. It checks both compiler identities, fresh native/factory artifacts, all required CTest groups and a complete Python pass without skips. Static default/PLT surveys run in parallel after native checks; the callee audit then reproduces the fresh policy-6 baseline. Previous/new surveys must match source/text identities, metadata denominator, decoder, model, policies and limits. The memory-callee configuration also surveys policy 8/9 with the global leaf catalog, real upgraded closures and prior/remaining missing frontiers. Old default/PLT per-module outcomes remain unchanged; the shared policy-8 outcomes and complete prior frontier reproduce the preceding memory baseline on matching source/text/model/limits. Static reports supply no runtime grants or live GOT guarantees.

`run.json` records pending/running/passed/failed stage states and log paths. Failures leave their evidence available and produce a nonzero exit. It never marks an incomplete run passed. Stale native artifacts, changed source code during the run, mismatched inputs/models or remaining selected instruction frontiers reject completion. The source fingerprint covers CMake, source, tools, tests and milestone configurations. Reusing an existing output is rejected, so earlier successful evidence cannot silently stand in for a new run.

`summary.json` and `summary.md` collect aggregate evidence; `comparison.json` and full surveys remain private under the run directory. After successful validation, the assistant updates the README/status and capability documents, reviews the source diff and verifies that the current code fingerprint still matches the passed run. It then commits and pushes `dev` and verifies a clean synchronized tree. Later code changes require a fresh run. Game content, keys, generated game C, native binaries and detailed reports remain ignored. All native execution in this workflow is synthetic.

## Subsequent capability milestones

The next work is selected from the refreshed dependency audit by complete effects and real callee closures. Further milestones should target remaining address effects, layouts, loops and wider call closures under explicit ownership contracts. Loop and wider-call support should be delivered through complete opt-in contracts and mixed call graphs. Startup/services, followed by graphics and other host systems, require their own usable boundaries and integrated evidence.

Each milestone should be large enough to produce an assessable capability, with its implementation, verification and status update completed together. Existing PAC, memory, ownership and no-game-execution constraints stay in force. Ask for user input when a material scope choice, missing input or external blocker prevents sound progress; routine implementation choices stay inside the milestone.
