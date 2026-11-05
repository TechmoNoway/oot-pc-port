# Hash-bound registries and linear framed callers

The compiled registry now pins the identity of its runtime snapshot and the exact linked bytes of each selected function. A separate framed-caller profile supports one canonical 16-byte FP/LR frame and direct calls to verified register-only leaves. These are library boundaries validated with synthetic code; the host CLI still only maps data, and no game callbacks are registered or executed.

## Registry preparation

`tools/prepare_registry.py` reads verified prepared ExeFS, performs a fresh complete offline link, and accepts explicit function selections. It emits a fresh directory under `build/` containing `image.ootmem`, `registry.c`, and `manifest.json`. Generation does not execute the selections. Metadata candidates are not automatically approved or treated as recovered function identities.

The JSON configuration uses schema version 1. `leaves` is a list of 1-256 records with `name`, `module`, `offset`, and `size`; offsets and sizes are integer byte counts relative to the module image. Each range must be aligned, wholly inside `.text`, non-overlapping, and pass the existing acyclic register-leaf verifier. Names use lowercase ASCII letters, digits, and underscores, starting with a letter. `return_sites` lists sorted, unique, aligned guest continuation tokens outside all selected ranges. Optional integer `stack_base` and `stack_size` override the runtime package defaults.

An optional `root` record uses the same fields and selects the framed caller. Omitting it produces a bound leaf registry. Selection is explicit and bounded; this tool is not an automatic game translation or launch command.

```powershell
.\.venv\Scripts\python.exe -B tools/prepare_registry.py build/prepared/oot111 `
  --config build/selections.json --output build/registry/selected
```

Compile the generated source with the `src/` include directory and link `oot-frame-dispatch` in CMake (which carries the leaf, image, memory, host, and BCrypt dependencies). The generated `oot_create_bound_registry(image, error)` returns an opaque leaf or frame context according to the configuration. It calls compiled descriptor getters; files never contain serialized native code pointers. Keep the compiled module loaded until all its contexts have been destroyed.

## Identity and ownership

The factory embeds the expected package body SHA-256 and exact range SHA-256 values calculated from the same linked images used to emit C. The native bound constructor checks every selected leaf, and the framed constructor also checks the root. A match requires the expected initial package identity, the entire range inside one read-only text region, and the current range bytes matching the compiled hash. Merely having mapped readable data is insufficient.

Leaf begin/run recheck the selected range. A framed run checks root code before execution, and each child begin/run checks that child's code. Checkpoint mismatches and code mismatches reject execution without retiring the affected instruction. Restoring the original bytes/state allows retry; a callback contract violation instead latches a fault until abort.

The package identity is an immutable tag of the validated initial snapshot. Writable data and stack can evolve without rehashing the package. Code bytes are rehashed from their current native backing. This is version/layout consistency checking, not a signature or proof of arbitrary input provenance. Trusted host code must not alter region metadata or race execution; this API is single-threaded and is not a sandbox for hostile native callbacks.

Bound contexts retain the native image, including stack backing. `oot_runtime_open` owns one reference; `oot_runtime_retain` adds one and `oot_runtime_close` releases one. A controller can close its original reference after creating a bound context. Borrowed memory views must not outlive the final owning reference. The older unbound leaf constructor remains an explicit synthetic/development API with caller-supplied stack bounds.

## Framed profile v1

`linear-fp-lr-caller-v1` is separate from the unchanged register-leaf policy. A root contains 5-64 instructions with exactly this shape:

```text
stp x29, x30, [sp, #-16]!
mov x29, sp
... linear register operations and direct BL to registered leaves ...
ldp x29, x30, [sp], #16
ret x30
```

At least one direct leaf call is required. The body permits the leaf profile's register computations/NOPs, preserving X18-X30/SP except the canonical BL update to LR. Branches, arbitrary loads/stores, larger frames, local stack variables, calls to other framed callers, recursion, indirect calls, and pointer authentication are excluded. Callees may use their existing acyclic internal branches. The maximum retirement bound includes root instructions and the maximum path of every call site.

`oot_frame_begin` requires exact entry PC, an approved external return token equal to X30, canonical NZCV, and a 16-byte-aligned SP with room for the frame inside the image's stack. Internal continuation tokens are derived from verified call sites and added only to the child leaf registry. The controller runs `oot_frame_run` with a guest instruction budget; root and child instructions both consume it. Call/return transitions do not recurse on the host C stack. Returned calls are idempotent; abort retains all earlier retired effects.

Every root instruction executes on a private integer state and a 16-byte shadow memory window at the frame base. Counts, status, PC edge, NZCV, X18-X28, and the expected FP/LR/SP transition must match before commit. Only the opening canonical store can change that window; it must contain the original FP/LR pair. Its bytes are copied to the checked native stack only after validation. Other steps must leave shadow bytes unchanged. Callees still receive no memory view. Invalid steps preserve the previous state and native stack, then latch a fault.

The dispatcher snapshots the owned frame bytes after the save and checks them before each following instruction, including while a child is suspended. A changed saved FP/LR pair rejects resume. The canonical restore releases frame ownership; previously stored stack bytes remain present. This is a conservative transactional project policy, not a claim about hardware partial stores or complete AAPCS64/process ABI support.

## Validation and remaining boundaries

```powershell
.\.venv\Scripts\python.exe -B tools/frame_validation.py
.\.venv\Scripts\python.exe -B tools/frame_validation.py --compiler gcc
```

Both MSVC and GCC pass 128 complete synthetic framed cases against Unicorn 2.1.4, independent arithmetic results, full integer/flag state, retired counts, and whole-stack bytes. Schedules include zero, single-instruction, short, and unlimited budgets. Tests cover changed snapshot identity, code/range mismatch, register/stack tampering, image lifetime, invalid registries/entry state, staged write rollback, nine deliberately faulty native callback modes, failure latching, and abort. Bundle tests prepare synthetic NSO inputs, compile the actual emitted factory, run only synthetic selections, and verify source/output preservation. Reports and all generated artifacts stay under ignored `build/`.

Broader frames and memory effects, framed-to-framed calls, indirect targets, PAC/system/SIMD semantics, process startup, services, and rendering remain separate milestones. Hash matching and these artificial functions do not establish safe game startup or gameplay.
