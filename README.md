# OOT PC Port

An independent project exploring a native Windows x86-64 port of Ocarina of Time for Switch 2.

## Status

Early development. The Windows host builds and passes its native self-tests. A separate [experimental startup bootstrap](docs/startup-bootstrap.md) compiles selected original loader instructions into a private Windows executable, executes them only with explicit opt-in, and records precise stop diagnostics. Startup is not complete and the game is not playable yet.

The input pipeline provides [metadata inspection](docs/input-inspection.md), verified [LZ4/ZBIC segment preparation](docs/segment-preparation.md), complete [offline linking](docs/offline-linking.md) and data-only [native image mapping](docs/runtime-images.md) with guarded synthetic stacks.

The [ARM64 C lifter](docs/arm64-lifter.md) supports selected integer/control-flow semantics, scalar/paired memory, [RCpc loads](docs/ordered-loads.md), [conditional comparisons](docs/conditional-compare.md), [widening](docs/long-multiply.md) and [high multiplication](docs/high-multiply.md), and [bit operations](docs/bit-operations.md). The preceding [integer-frontier milestone](docs/integer-frontier.md) adds EXTR/immediate ROR and all CRC32/CRC32C B/H/W/X variants. Unsupported encodings remain explicit failures.

[Checked guest memory](docs/guest-memory.md), [hash-bound registries](docs/bound-dispatch.md), [verified leaves](docs/leaf-verification.md), [stack/CFG dispatch](docs/stack-cfg.md), [fixed layouts](docs/stack-layouts.md), [PAC-aware frames](docs/pauth-stack-dispatch.md), [checked reads](docs/checked-reads.md), [LR-pair frames](docs/lr-pair-frames.md), [checked PLT bridges](docs/plt-dispatch.md), [checked memory effects](docs/checked-memory.md), [memory-leaf callees](docs/memory-callees.md) and [bounded loops/writeback](docs/bounded-memory.md) provide explicit register, memory, call, frame-ownership and resumable-budget contracts. PAC uses a separate [QARMA5/VA39 model](docs/pointer-authentication.md).

Synthetic translations and complete call graphs run natively on MSVC/GCC and are compared with pinned ARM64 reference execution and independent arithmetic/polynomial results. Static [analysis](docs/arm64-analysis.md), [profile surveys](docs/function-profile-survey.md) and [callee audits](docs/callee-audit.md) operate on original bytes without generating or executing game callbacks. Their candidate counts describe structural proofs and runtime obligations, not original function identity or gameplay coverage. The separate startup experiment has its own selected-code, memory, process-model and execution boundary.

The current startup work uses fresh raw 4 KiB page mappings because the original loader performs relocation itself; an independently linked copy supplies audit evidence. It supplies the verified NPDM stack size, private zeroed TLS, an initially unmapped reserved heap, checked QueryMemory/heap/debug/counter services and a one-shot pristine-image claim. Its NSO register/handle model is explicitly experimental and does not prove the Switch 2 ABI. Unsupported encodings, targets and services stop without invented successful results. Final validation passes 379 Python tests, seven CTest groups and 283,401 common native/reference cases per compiler. Startup tests add 480 complete runs/4,624 prefixes per compiler, 36 cross-module/chunk cases and 273 context checks.

Both MSVC and GCC execute 40,397,142 original instructions, reach SDK initialization and stop before unsupported GetInfo ID 11 (handle zero, sub-ID two). All eight audited entry-module relative-pointer probes match the independent linker, and full ordered trace SHA-256 values agree. Fresh audits, unchanged preceding profiles and the final source fingerprint also pass in `build/milestones/startup-bootstrap-v1/`. Initialization and gameplay remain incomplete.

The completed bounded-memory milestone adds leaf policy 3 and stack policy 10/schema 11: scalar/pair pre/post-index writeback and one verified counter-loop shape through direct and exact-PLT memory callees. A loop's first header admits only positive, decrement-divisible counts of at most 1,024 iterations. Full counter/control checks and a retirement ceiling survive yields; image grants, complete stack exclusion and live GOT protection remain enforced. Earlier policies retain their permissions.

The preceding bounded-memory validation passes 357 Python tests without skips, six CTest groups and 283,401 common native/reference comparisons per compiler. MSVC/GCC each validate 865 new whole calls/17,145 prefixes and 128 actual schema-11 factory calls/6,496 prefixes. Its surveys, audit, baseline comparisons and source fingerprint pass; private evidence is under `build/milestones/bounded-memory-v1/`.

The fresh original-byte 1.1.1 survey preserves all 16,805 preceding memory-leaf candidates and finds 554 additional regions: 251 acyclic writeback helpers and 303 bounded loops. Framed acceptance rises from 2,858 to 2,868 roots; newly closed roots use 12 distinct new helpers and 20 unique call edges. Five used helpers contain bounded loops, reached by two upgraded roots; the other seven are acyclic writeback helpers. These are static proofs with count, memory and GOT obligations. The game is not playable yet.

## Milestone delivery

Work proceeds through complete capability milestones. Each authorized milestone includes implementation, verifier/runtime integration, MSVC/GCC checks, fresh hash-matched surveys/audit, status documentation and a reviewed commit/push on `dev`. The assistant handles the dependent substeps without requiring another prompt for each instruction family.

The [milestone runner](docs/development-workflow.md) executes the complete evidence pipeline from one command, records stage checkpoints/logs and writes a private aggregate summary. Source changes, failed/skipped required checks, stale evidence or mismatched baselines prevent a successful final status. See [the current milestone configuration](config/milestones/startup-bootstrap.json).

The current milestone follows the actual loader entry and initialization dependencies, connects an explicit native process context and records its first unsupported boundary. Subsequent work must complete required services, module initialization and translation coverage, followed by graphics/shaders and other host systems. See [architecture](docs/architecture.md) and [development workflow](docs/development-workflow.md).

Game containers, keys, extracted files, generated game code, saves, shader caches, compiled executables and detailed reports stay outside version control. Build output belongs under `build/`; future generated output belongs under `generated/`.
