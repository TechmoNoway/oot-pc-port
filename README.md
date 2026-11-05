# OOT PC Port

An independent project exploring a native Windows x86-64 port of Ocarina of Time for Switch 2.

## Status

Early development. The Windows host scaffold builds successfully and passes its memory and performance-counter self-test.

An offline [input inspector](docs/input-inspection.md) reads NUP, NSO, and NPDM metadata and verifies selected ExeFS files against their NUP catalog hashes.

[Segment preparation](docs/segment-preparation.md) decodes LZ4/ZBIC NSO segments, verifies required SHA-256 hashes, and writes plain NSO modules with a manifest for the future loader.

[Offline linking](docs/offline-linking.md) reads MOD0 and dynamic tables, lays out module images with BSS, resolves supplied symbols, and applies supported AArch64 RELA/RELR relocations.

[ARM64 analysis](docs/arm64-analysis.md) surveys decoded instruction families, metadata-based entry candidates, direct control flow, unresolved indirect branches, and recognized `setjmp`/`longjmp` PLT calls. Syntax decoding is separate from C-lifter support.

A bounded [ARM64 C lifter](docs/arm64-lifter.md) translates selected integer operations, scalar and paired load/store addressing, and control flow. [Checked guest memory](docs/guest-memory.md) enforces mapped ranges and read/write permissions. Generated synthetic C runs natively on Windows and is compared with an independent ARM64 reference for registers, flags, memory contents, and selected access faults. Unsupported encodings are rejected.

[Native image mapping](docs/runtime-images.md) packages completely linked module regions, preserves BSS relocations, and loads verified data into the C memory backend with a guarded synthetic stack. Mapping does not execute game code.

[Leaf verification](docs/leaf-verification.md) checks bounded register-only regions for closed, acyclic control flow and preserved registers. Complete synthetic leaf functions are validated against both ARM64 execution and independent mathematical results. A static survey reports game-code candidates without executing them or claiming original function identity.

[Controlled leaf dispatch](docs/leaf-dispatch.md) checks registered entries, caller-approved returns, stack/NZCV state, suspended checkpoints, and each instruction's control-flow/register contract. Synthetic caller/callee chains and native image/stack integration pass validation; no game callbacks are registered.

The game is not playable yet. Process startup, broader instruction semantics, operating-system services, and graphics remain to be implemented.

## Development direction

The next milestones are binding compiled registries to image hashes, broader function/call support, remaining instruction semantics, process startup and operating-system services, and graphics. See [docs/architecture.md](docs/architecture.md).

Game containers, keys, extracted files, generated game code, saves, shader caches, and compiled executables stay outside version control. Build output belongs under `build/`; future generated output belongs under `generated/`.
