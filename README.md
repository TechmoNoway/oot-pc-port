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

[Hash-bound dispatch](docs/bound-dispatch.md) pins compiled function registries to the mapped snapshot and exact read-only text hashes. A separate linear caller profile supports a canonical FP/LR stack frame and direct calls to verified leaves, with staged stack writes and resumable budgets. Synthetic cases pass on MSVC and GCC.

[Local-stack dispatch](docs/stack-dispatch.md) adds fixed 16-256-byte frames, checked scalar/pair local storage, and direct calls between framed functions in a verified acyclic graph. An explicit bounded activation stack protects current and ancestor frame bytes across yields. Synthetic three-level and maximum-depth cases match ARM64 reference execution.

[Framed CFG dispatch](docs/stack-cfg.md) supports acyclic conditional branches and explicit scalar/pair save slots for X19-X28. It checks each branch edge, register permissions through save/restore phases, and weighted call-path bounds. Synthetic branching calls and all ten saved registers pass native/reference validation.

[Fixed frame layouts](docs/stack-layouts.md) add separate SUB/ADD stack allocation, offset FP/LR records, sparse save slots, delayed FP setup, and negative FP-relative locals. Synthetic mixed-layout calls and a full 16-frame stack boundary match ARM64 reference execution.

A [static profile survey](docs/function-profile-survey.md) measures the actual verifiers against metadata-rooted private game regions without translation or execution. The default local 1.1.1 survey accepts 40,038 leaf candidates; its older framed policies remain blocked.

An opt-in [pointer authentication model](docs/pointer-authentication.md) implements QARMA5 signing, authentication, and authenticated returns for a specified 39-bit address configuration. A separate [PAC-aware dispatcher](docs/pauth-stack-dispatch.md) retains keys across yields, tracks signed frame records, and validates approved returns through policy 4/schema 5. Native synthetic tests pass on MSVC and GCC. A separate static survey accepts 1,686 PAC framed candidates; game code remains unexecuted.

[RCpc ordered loads](docs/ordered-loads.md) support no-offset LDAPR/B/H through a backend that serializes scalar, pair, and acquire transfers. Value/fault comparisons, raw PAC frames, and native inter-thread publication tests pass on MSVC/GCC. The supported alignment and shared-memory ownership rules are explicit; function profiles retain their existing memory permissions.

The game is not playable yet. Process startup, broader instruction semantics, operating-system services, and graphics remain to be implemented.

## Development direction

The next milestones are verified memory reads beyond the current frame, remaining ordered/atomic semantics, wider call support, further frame layouts and loop verification, process startup and operating-system services, and graphics. See [docs/architecture.md](docs/architecture.md).

Game containers, keys, extracted files, generated game code, saves, shader caches, and compiled executables stay outside version control. Build output belongs under `build/`; future generated output belongs under `generated/`.
