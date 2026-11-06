# Milestone workflow

Development is organized around complete capabilities and measured blocker cohorts. A milestone includes its dependent instruction/runtime changes, verifier integration, synthetic native evidence, fresh private surveys, documentation and a reviewed commit/push on `dev`. The assistant completes these substeps autonomously within the authorized scope and reports the result at the milestone boundary. Small instruction families no longer require separate user prompts or separate releases.

## Current milestone: integer dependency frontier

This milestone combines EXTR and its immediate ROR alias with all eight CRC32/CRC32C B/H/W/X variants. The preceding audit contained 46 distinct integer first-unsupported targets: 17 EXTR/ROR and 29 CRC32. Those are diagnostic targets with overlapping caller dependencies, not a promise of 46 newly accepted functions.

Completion requires exact encoding/width rules, independent extraction/polynomial results, all relevant aliases/ZR/upper-bit/budget cases, unchanged NZCV and existing register/memory policies, complete artificial leaves and actual schema-8 PAC/PLT calls on MSVC/GCC. Fresh production-verifier surveys and a matching callee audit must show that the selected mnemonic frontier is cleared on unchanged input/text hashes. Later failures and unchanged acceptance must be reported honestly.

## One command for a complete validation run

From the repository root, with the project environment, MSVC build, GCC and pinned ZBIC dependency available:

```powershell
.venv\Scripts\python.exe -B tools/run_milestone.py `
  --config config/milestones/integer-frontier.json `
  --output build/milestones/integer-frontier-v1
```

Choose a fresh output directory for each run. The configuration selects the native build, prepared inputs, preceding default/PLT survey baselines, GCC factory test modules and expected report artifacts. It contains paths and check selections, never keys or captured game bytes. `--native-only` runs the synthetic portion without private game inputs or baseline files.

The runner configures/builds the pinned host/helper, then runs two independent native lanes in parallel: complete MSVC CTest/Python validation, and the GCC differential suite followed by the selected GCC factory tests. It checks both compiler identities, fresh native/factory artifacts, all required CTest groups and a complete Python pass without skips. Static default/PLT surveys run in parallel after native checks; the callee audit then reproduces the fresh policy-6 baseline. Previous/new surveys must match source/text identities, metadata denominator, decoder, model, policies and limits.

`run.json` records pending/running/passed/failed stage states and log paths. Failures leave their evidence available and produce a nonzero exit. It never marks an incomplete run passed. Stale native artifacts, changed source code during the run, mismatched inputs/models or remaining selected instruction frontiers reject completion. The source fingerprint covers CMake, source, tools, tests and milestone configurations. Reusing an existing output is rejected, so earlier successful evidence cannot silently stand in for a new run.

`summary.json` and `summary.md` collect aggregate evidence; `comparison.json` and full surveys remain private under the run directory. After successful validation, the assistant updates the README/status and capability documents, reviews the source diff and verifies that the current code fingerprint still matches the passed run. It then commits and pushes `dev` and verifies a clean synchronized tree. Later code changes require a fresh run. Game content, keys, generated game C, native binaries and detailed reports remain ignored. All native execution in this workflow is synthetic.

## Larger milestones after this cohort

The next work is selected from the refreshed dependency audit by complete effects and real callee closures. A memory milestone should cover a useful group of address/effect patterns with explicit readable/writable ownership, verifier/dispatcher integration and full fault/yield testing. Loop and wider-call support should be delivered through complete opt-in contracts and mixed call graphs. Startup/services, followed by graphics and other host systems, require their own usable boundaries and integrated evidence.

Each milestone should be large enough to produce an assessable capability, with its implementation, verification and status update completed together. Existing PAC, memory, ownership and no-game-execution constraints stay in force. Ask for user input when a material scope choice, missing input or external blocker prevents sound progress; routine implementation choices stay inside the milestone.
