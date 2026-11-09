# Incremental translation and host-linked boot

Initialization providers, whole-function execution and host-linked boot are
separate opt-ins. None establishes gameplay. Raw/SDK/logging diagnostics retain
their constructors, flags, limits and original-prefix baselines.

## Stable generated sources

Callbacks use original 256-byte address buckets; translation units cover fixed
64 KiB address buckets. Additional selections do not renumber unrelated callbacks.
A separate metadata unit holds all instruction/span bindings and registries.

`sources.json` seals every unit's name, length and SHA-256. The complete set is
validated before copying to stable cache paths; unchanged modification times are
preserved. MSVC uses generated dependency tracking. GCC keys individual objects
by source, compiler identity/binary, flags and project headers, publishing only
successful compilations. The linker includes precisely the current unit set.
`build.json` records elapsed time, changed units, compiled/reused objects and the
complete source-manifest hash. Timings describe the measured machine and run.

The preparation loop also shares a bounded in-memory decode memo keyed by exact
original word, PC and instruction profile. Every pass rereads original bytes and
rebuilds roots, native boundaries, edges and provenance. The memo is never
serialized as authority; cached/uncached synthetic audits must agree exactly.

## Whole-function execution

`--fast-functions` enables an initialization-only registry of exported leaves
proved by the existing verifier. The initial subset is linear, register-only,
2–256 original instructions, ending in standard RET. It excludes memory, calls,
PAC, protected-register/SP writes, native bindings, original stages and observed
module constructors. Each invocation checks its full body and canonical distinct
selected return. Its empty memory window, protected state, vector bank, return
and retirement count remain checked. Insufficient quota falls back to single
instructions. Every original trace row is retained, and the milestone compares
accelerated/diagnostic traces and both native compilers.

## Separate host-linked boot

`--host-linked` requires `--sdk --native-sdk --sdk-init`. Flags 30 select a freshly
offline-linked package and project-owned ARM64 scaffolding. Original rtld text
is excluded from the selected program and native bindings, so its self-relocator
cannot run on that package. Flags 1/3/7/15 remain separate raw-image experiments.

The scaffolding binds the original SDK Start register recipe: declared main
handle, original unmapped argument-area convention, readiness callback, module
initialization callback and an explicitly unsupported finalizer. It invokes
original SDK Start and module DT_INIT entries in reverse load order. Game
instructions and constructor registration results are never patched.

DSO registration can defer arrays, then primary-DSO registration can call those
original initializers inside the SDK. The host adds no second constructor pass.
Source-bound observers distinguish entry, the original constructor-body path and
authenticated return. Nested calls preserve entry SP/LR. Missing, repeated or
mismatched completion prevents the goal. Registration flags alone prove nothing.
Every module body must return exactly once, all mandatory original stage entries
must retire in order, and the actual nnMain branch must retire.

Reports separate original instructions, project scaffolding and native calls.
Successful initialization stops before the first nnMain body instruction.
Graphics, shaders, audio, input, service objects, filesystem mounts and gameplay
remain further work.
