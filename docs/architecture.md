# Native port architecture

## Current implementation

The executable is a Windows host scaffold written in C17. It queries the system, allocates and releases memory using Win32, and checks those operations with a self-test. It does not load or execute game code.

## Planned boundaries

1. Input inspection: identify the game build, inspect module metadata, and validate user-provided inputs.
2. Offline translation: translate supported ARM64 instructions to C while recording unsupported instructions and unresolved control flow.
3. Module loading: establish the guest memory layout, apply relocations, resolve calls, and run module initialization.
4. Host services: provide the threading, synchronization, files, saves, input, audio, and timing behavior the game uses.
5. Graphics: establish the graphics API boundary, translate required shaders, and connect it to a native renderer.

Each boundary needs a verifiable milestone before work advances to gameplay. A successful compilation is not evidence of correct game execution.

## Repository boundaries

Only project source and documentation belong in Git. Local configuration, user inputs, extracted content, translated game code, compiled output, and runtime caches belong in ignored directories.
