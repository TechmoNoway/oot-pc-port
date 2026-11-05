# Native port architecture

## Current implementation

The executable is a Windows host scaffold written in C17. It queries the system, allocates and releases memory using Win32, and checks those operations with a self-test. It does not load or execute game code.

The offline Python [input inspector](input-inspection.md) reads NUP, NSO, NPDM, and extracted ExeFS metadata. It verifies the NUP catalog and selected ExeFS file hashes without extracting the game tree.

[Segment preparation](segment-preparation.md) decodes NSO LZ4 blocks or ZBIC frames and checks hashes over the decoded bytes. It writes plain NSO files and a manifest under `build/`. LZ4 decoding is implemented in the project; the ZBIC helper links a pinned external dependency stored under `toolchain/`.

The [offline linker](offline-linking.md) reads MOD0, dynamic tables, and symbols, establishes guest addresses for private module images, zero-initializes BSS, and applies supported AArch64 relocations. Images can be exported only after a complete link. This does not yet map native host memory or execute guest code.

## Planned boundaries

1. Input inspection: identify the game build, inspect module metadata, and validate user-provided inputs.
2. Segment preparation: decode and verify NSO segments while preserving memory offsets and BSS metadata.
3. Module loading: establish the guest memory layout, apply relocations, and resolve module references without executing guest code.
4. Offline translation: translate supported ARM64 instructions to C while recording unsupported instructions and unresolved control flow.
5. Host services: provide the threading, synchronization, files, saves, input, audio, and timing behavior the game uses, then run translated module initialization.
6. Graphics: establish the graphics API boundary, translate required shaders, and connect it to a native renderer.

Each boundary needs a verifiable milestone before work advances to gameplay. A successful compilation is not evidence of correct game execution.

## Repository boundaries

Only project source and documentation belong in Git. Local configuration, user inputs, extracted content, translated game code, compiled output, and runtime caches belong in ignored directories.
