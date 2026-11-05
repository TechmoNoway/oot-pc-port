# Native port architecture

## Current implementation

The executable is a Windows host scaffold written in C17. It queries the system, allocates and releases memory using Win32, and checks those operations with a self-test. It does not load or execute game code.

The offline Python [input inspector](input-inspection.md) reads NUP, NSO, NPDM, and extracted ExeFS metadata. It verifies the NUP catalog and selected ExeFS file hashes without extracting the game tree.

[Segment preparation](segment-preparation.md) decodes NSO LZ4 blocks or ZBIC frames and checks hashes over the decoded bytes. It writes plain NSO files and a manifest under `build/`. LZ4 decoding is implemented in the project; the ZBIC helper links a pinned external dependency stored under `toolchain/`.

The [offline linker](offline-linking.md) reads MOD0, dynamic tables, and symbols, establishes guest addresses for private module images, zero-initializes BSS, and applies supported AArch64 relocations. Images can be exported only after a complete link. A [native image bridge](runtime-images.md) now packages exact linked segment and BSS ranges and maps them into caller-owned native backing through checked guest addresses, with a guarded synthetic stack. This does not execute guest code or establish process startup.

[ARM64 analysis](arm64-analysis.md) uses a separate disassembly backend and project control-flow logic to survey prepared code. It reports evidence-based entry candidates and follows direct edges; indirect targets and nonlocal-return semantics remain explicit gaps. Optional semantic coverage classifies exact encodings using the lifter's decoder without executing game code.

The [ARM64 lifter](arm64-lifter.md) emits C17 for a bounded raw code range. It maintains explicit X registers, SP, PC, and NZCV, returns to a dispatcher when PC leaves the translated range, and enforces an instruction budget. Scalar and paired transfers use [checked guest memory](guest-memory.md) with read/write permissions and whole-access preflight. Generated synthetic programs compile to native Windows code and are compared with Unicorn ARM64 for state, memory, and selected access faults. A synthetic translated stack frame also runs on stack backing supplied by the native image bridge. Game functions, native module dispatch, and host services are not connected for execution yet.

[Leaf verification](leaf-verification.md) adds a conservative structural boundary for short, acyclic register-only regions with standard returns and preserved X18-X30/SP. Six complete synthetic functions cover arithmetic mixing, signed minimum, bitfield insertion, signed remainder, carry propagation, and a two-return diamond. Native results are checked against independent formulas as well as ARM64 execution. Metadata-rooted game candidates are surveyed statically and remain unexecuted.

The [controlled leaf dispatcher](leaf-dispatch.md) copies and validates generated entry/CFG metadata, binds entries to trusted compiled C symbols, and checks entry, return, stack alignment/bounds, NZCV, and paused state. It executes one lifted instruction at a time on a private state copy and commits only after the step satisfies its CFG, retirement, and register contract. Synthetic native caller/callee chains match ARM64 reference execution, and a synthetic mapped image can supply its stack. Production game callbacks are not registered or executed.

## Planned boundaries

1. Input inspection: identify the game build, inspect module metadata, and validate user-provided inputs.
2. Segment preparation: decode and verify NSO segments while preserving memory offsets and BSS metadata.
3. Module loading: establish the guest memory layout, apply relocations, and resolve module references without executing guest code.
4. Offline translation: translate supported ARM64 instructions to C while recording unsupported instructions and unresolved control flow.
5. Host services: provide the threading, synchronization, files, saves, input, audio, and timing behavior the game uses, then run translated module initialization.
6. Graphics: establish the graphics API boundary, translate required shaders, and connect it to a native renderer.

Each boundary needs a verifiable milestone before work advances to gameplay. A successful compilation is not evidence of correct game execution.

The [hash-bound registry](bound-dispatch.md) now pins compiled symbols to the initial runtime snapshot and exact current text ranges. A separate verified linear FP/LR caller supports direct calls to register-only leaves, stages its stack save before commit, and preserves state/stack ownership across yields. Only synthetic functions have been registered and executed.

A separate [local-stack dispatcher](stack-dispatch.md) supports fixed 16-256-byte frames, checked local scalar/pair memory effects, and direct framed-to-framed calls in bounded acyclic graphs. It uses explicit activations, one instruction budget, staged store commits, and checks all owned ancestor/current frame bytes and active code on resume. Synthetic three-level calls, individual instruction prefixes, and a full 16-frame stack boundary match independent reference execution.

A separate [framed CFG policy](stack-cfg.md) now adds acyclic conditional control flow and explicit scalar/pair X19-X28 saves with matching restores. The dispatcher validates CFG edges, per-phase writable masks, save-slot isolation, and weighted longest paths through nested calls. Schema 3 selects this policy; earlier profiles retain their rules.

A separate [fixed-layout policy](stack-layouts.md) now supports SUB/ADD allocation, offset FP/LR records, sparse save slots, delayed FP setup, and normalized negative FP-relative accesses. Per-instruction SP/FP/LR/ownership metadata protects allocated frames until actual deallocation, including yields after restoring the frame record. Mixed-layout nested calls and a 16-frame/full-stack boundary match the reference. Schema 4 opts into this policy.

The [static profile survey](function-profile-survey.md) evaluates unchanged metadata-rooted game regions with actual production verifiers and real dependency closures, without generating C or executing candidates. The default local 1.1.1 results match the earlier 40,038 leaf candidates and accept no framed candidates under the older policies. Diagnostic observations do not bypass semantics or establish original function identity.

A separate [pointer authentication model](pointer-authentication.md) now provides QARMA5/VA39 instruction-key A/B signing, AUT, and RETAA/RETAB semantics through an explicit PAC context and separate callback ABI. Native synthetic tests compare actual signed bits, poisoned pointers, nested frames, budgets, and faults against a PAuth-enabled reference. Canonical signing is a required precondition; the older profiles and surveys keep their original policies.

A separate [PAC-aware policy/dispatcher](pauth-stack-dispatch.md) integrates the model through policy 4/schema 5. It retains the image and immutable key context, validates signed-LR phase transitions, and protects approved returns and owned frames across yields. Synthetic nested calls and 16-frame/full-stack cases match the enabled reference on MSVC and GCC. Its separate static 1.1.1 survey accepts 1,686 PAC framed candidates without generating callbacks or running game code.

The next implementation milestones are ordered/atomic memory semantics, wider memory/call support, further layouts, and loop verification. Process startup still needs a guest ABI, TLS, module initialization, scheduling, and service dispatch. Remaining integer/system forms, SIMD/FP, atomics/exclusives, nonlocal returns, and indirect-target discovery remain separate requirements. Game code must remain unexecuted until complete function coverage and required runtime boundaries are established.

## Repository boundaries

Only project source and documentation belong in Git. Local configuration, user inputs, extracted content, translated game code, compiled output, and runtime caches belong in ignored directories.
