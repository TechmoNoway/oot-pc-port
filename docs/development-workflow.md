# Milestone workflow

Development is organized around complete capabilities and measured blocker cohorts. A milestone includes its dependent instruction/runtime changes, verifier integration, synthetic native evidence, fresh private surveys, documentation and a reviewed commit/push on `dev`. The assistant completes these substeps autonomously within the authorized scope and reports the result at the milestone boundary. Small instruction families no longer require separate user prompts or separate releases.

## Current milestone: bounded loops and writeback

[Bounded memory leaves and stack policy 10/schema 11](bounded-memory.md) integrate scalar/pair writeback and one verified linear counter loop through direct and exact-PLT calls. Admission at the first loop header requires a positive count divisible by the decrement and at most 1,024 iterations. Earlier policies retain their permissions and outcomes. The milestone includes original-byte target classification, real callee closure proofs and complete native effect/fault/yield evidence.

The full `build/milestones/bounded-memory-v1/run.json` reports all stages passed with an unchanged source fingerprint. The run includes 357 Python tests without skips, six CTest groups, both native compilers, fresh static surveys/audit and baseline comparisons. Native detail and aggregate static outcomes are recorded in [the capability document](bounded-memory.md); full reports remain private in the run directory.

Completion requires full state/memory comparison for standalone/mixed/maximum-depth synthetic callees, scalar/pair writeback, first-header admission and retired prefix effects, exact counter/NZCV/control checks, loop/rank bounds across yields, separate operand grants/windows, protected caller stacks/GOT slots, negative callbacks and copied lifetimes, actual schema-11 factories, both native compilers, unchanged shared-policy outcomes including retained samples, and reproduction of prior-frontier root/target/edge aggregate counts. The preceding [memory-callee](memory-callees.md), [checked-memory](checked-memory.md) and [integer-frontier](integer-frontier.md) milestones remain available through their separate configurations.

## One command for a complete validation run

From the repository root, with the project environment, MSVC build, GCC and pinned ZBIC dependency available:

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config config/milestones/bounded-memory.json `
  --output build/milestones/bounded-memory-v1
```

Choose a fresh output directory for each run. The configuration selects the native build, prepared inputs, preceding default/PLT survey baselines, GCC factory test modules and expected report artifacts. It contains paths and check selections, never keys or captured game bytes. `--native-only` runs the synthetic portion without private game inputs or baseline files.

The runner configures/builds the pinned host/helper, then runs two independent native lanes in parallel: complete MSVC CTest/Python validation, and the GCC differential suite followed by the selected GCC factory tests. It checks both compiler identities, fresh native/factory artifacts, all required CTest groups and a complete Python pass without skips. Static default/PLT surveys run in parallel after native checks; the callee audit then reproduces the fresh policy-6 baseline. Previous/new surveys must match source/text identities, metadata denominator, decoder, model, policies and limits. The bounded-memory configuration also compares policy 9/10 through `--bounded-memory`, with the full original memory catalog, real upgraded closures and prior/remaining missing frontiers. Old default/PLT per-module outcomes remain unchanged; shared policy-9 profile outcomes, including retained accepted/rejected samples, match the preceding memory-callee baseline. Prior-frontier comparison checks its three exhaustive aggregate counts (roots, unique targets and edges), not frontier samples or every target identity. Zero lost preceding memory candidates/accepted roots is checked from actual current production maps. Static reports supply no runtime grants or live GOT guarantees.

`run.json` records pending/running/passed/failed stage states and log paths. Failures leave their evidence available and produce a nonzero exit. It never marks an incomplete run passed. Stale native artifacts, changed source code during the run, mismatched inputs/models or remaining selected instruction frontiers reject completion. The source fingerprint covers CMake, source, tools, tests and milestone configurations. Reusing an existing output is rejected, so earlier successful evidence cannot silently stand in for a new run.

`summary.json` and `summary.md` collect aggregate evidence; `comparison.json` and full surveys remain private under the run directory. After successful validation, the assistant updates the README/status and capability documents, reviews the source diff and verifies that the current code fingerprint still matches the passed run. It then commits and pushes `dev` and verifies a clean synchronized tree. Later code changes require a fresh run. Game content, keys, generated game C, native binaries and detailed reports remain ignored. All native execution in this workflow is synthetic.

## Subsequent capability milestones

The next work is selected from the refreshed dependency audit by complete effects and real callee closures. Further milestones should target broader loop shapes, remaining address effects, layouts and wider call closures under explicit ownership contracts. Such extensions should be delivered through complete opt-in contracts and mixed call graphs. Startup/services, followed by graphics and other host systems, require their own usable boundaries and integrated evidence.

Each milestone should be large enough to produce an assessable capability, with its implementation, verification and status update completed together. Existing PAC, memory, ownership and no-game-execution constraints stay in force. Ask for user input when a material scope choice, missing input or external blocker prevents sound progress; routine implementation choices stay inside the milestone.
