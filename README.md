# OOT PC Port

An independent project exploring a native Windows x86-64 port of Ocarina of Time for Switch 2.

## Status

Early development. The Windows host scaffold builds and passes its native self-tests. The game is not playable yet.

The input pipeline provides [metadata inspection](docs/input-inspection.md), verified [LZ4/ZBIC segment preparation](docs/segment-preparation.md), complete [offline linking](docs/offline-linking.md) and data-only [native image mapping](docs/runtime-images.md) with guarded synthetic stacks.

The [ARM64 C lifter](docs/arm64-lifter.md) supports selected integer/control-flow semantics, scalar/paired memory, [RCpc loads](docs/ordered-loads.md), [conditional comparisons](docs/conditional-compare.md), [widening](docs/long-multiply.md) and [high multiplication](docs/high-multiply.md), and [bit operations](docs/bit-operations.md). The current [integer-frontier milestone](docs/integer-frontier.md) adds EXTR/immediate ROR and all CRC32/CRC32C B/H/W/X variants. Unsupported encodings remain explicit failures.

[Checked guest memory](docs/guest-memory.md), [hash-bound registries](docs/bound-dispatch.md), [verified leaves](docs/leaf-verification.md), [stack/CFG dispatch](docs/stack-cfg.md), [fixed layouts](docs/stack-layouts.md), [PAC-aware frames](docs/pauth-stack-dispatch.md), [checked reads](docs/checked-reads.md), [LR-pair frames](docs/lr-pair-frames.md) and [checked PLT bridges](docs/plt-dispatch.md) provide explicit register, memory, call, frame-ownership and resumable-budget contracts. PAC uses a separate [QARMA5/VA39 model](docs/pointer-authentication.md).

Synthetic translations and complete call graphs run natively on MSVC/GCC and are compared with pinned ARM64 reference execution and independent arithmetic/polynomial results. Game inputs are only [analyzed](docs/arm64-analysis.md), [surveyed against production verifiers](docs/function-profile-survey.md) and [audited for real callee dependencies](docs/callee-audit.md); game callbacks remain ungenerated and unexecuted. Candidate counts describe structural proofs and runtime obligations, not original function identity or gameplay coverage.

The completed integer-frontier run passes 333 Python tests, six CTest groups and 283,401 native/reference comparisons per compiler. On the unchanged local 1.1.1 inputs, the default verifier accepts 40,188 ordinary leaf candidates and policy 7 accepts 1,710 framed candidates. Integer first-unsupported targets in the measured callee frontier fall from 46 to zero; memory, SIMD/FP, atomic, service and wider-call requirements remain.

## Milestone delivery

Work proceeds through complete capability milestones. Each authorized milestone includes implementation, verifier/runtime integration, MSVC/GCC checks, fresh hash-matched surveys/audit, status documentation and a reviewed commit/push on `dev`. The assistant handles the dependent substeps without requiring another prompt for each instruction family.

The [milestone runner](docs/development-workflow.md) executes the complete evidence pipeline from one command, records stage checkpoints/logs and writes a private aggregate summary. Source changes, failed/skipped required checks, stale evidence or mismatched baselines prevent a successful final status. See [the current milestone configuration](config/milestones/integer-frontier.json).

Current work closes the previously measured integer first-stop cohort together with this repeatable delivery workflow. Subsequent milestones target useful groups of memory effects and call/loop closures, then process startup/services and graphics/other host systems. See [architecture](docs/architecture.md) and [development workflow](docs/development-workflow.md).

Game containers, keys, extracted files, generated game code, saves, shader caches, compiled executables and detailed reports stay outside version control. Build output belongs under `build/`; future generated output belongs under `generated/`.
