# Controlled register-only leaf dispatch

`src/leaf_dispatch.c` adds a single-threaded execution boundary for the existing verified-leaf profile. It registers trusted compiled C symbols and generated control-flow metadata, enforces entry/return/state contracts, and supports bounded execution with yield/resume. This is a library component with synthetic validation; the host application's `--map-images` command still only maps data. Game callbacks are not registered or executed.

## Registration and trust

Run `tools/lift_arm64.py --verify-leaf` to generate a lifted function and its `oot_leaf_descriptor_<suffix>` getter. The descriptor binds a compiled symbol to its guest entry, instruction count, ABI/policy versions, and per-instruction CFG successors and remaining-step bounds. It is native compiled metadata, not a file format for code pointers.

`oot_leaf_dispatcher_create` accepts at most 256 functions, each at most 256 instructions, and at most 4096 explicit return sites. Functions must be sorted, non-overlapping, aligned, and non-wrapping. Every CFG node must be reachable; successors and descending step ranks must describe a finite graph ending in return nodes. ABI/policy mismatches, missing callbacks, malformed CFGs, and invalid counts are rejected. The dispatcher copies registry, CFG, and return-site metadata; changing the input tables later does not retarget an existing context.

Return sites are sorted, unique, aligned guest PC tokens outside every registered leaf range. They are approved continuations or synthetic exit tokens supplied by the host controller. Registration does not prove that arbitrary return tokens are executable memory. A guest address is only a lookup key and is never cast to a native function pointer.

The compiled code module must stay loaded until its dispatchers are destroyed. Callbacks are trusted generated/reviewed native code. CFG checks do not prove arithmetic semantics or preempt arbitrary native code, and the API is not a sandbox for hostile C callbacks. Registry provenance is not yet checked against mapped image hashes; that remains an explicit next boundary.

## Begin, yield, return, abort

The native API uses an opaque context and a caller-owned `OotArm64State`:

| Operation | Contract |
| --- | --- |
| `oot_leaf_begin` | Requires the exact registered entry PC, X30 equal to the controller's explicit expected return site, canonical NZCV, and a 16-byte-aligned SP within configured inclusive stack bounds |
| `oot_leaf_run` | Executes up to the requested guest instruction budget and reports yielded, returned, rejected input, or a latched contract fault |
| `oot_leaf_abort` | Discards the active/returned/failed frame without undoing previously retired instructions |
| `oot_leaf_dispatcher_destroy` | Releases owned metadata; refuses destruction while a callback is executing |

Begin performs no guest instruction. An active or failed frame cannot be replaced by another begin; abort it first. A returned frame can be reused by beginning a fresh call. Completed runs are idempotent and retire no additional instructions. A zero budget yields without changing architectural state.

After each valid step the dispatcher checkpoints every integer register, SP, PC, and NZCV. A resume must match that exact architectural checkpoint, including scratch registers; changing state between slices is rejected without running a callback. The caller may restore the checkpoint and retry, or abort. State struct padding is not compared.

Stack bounds are a host-supplied state contract, not an allocation or a proof of stack backing. Integration tests obtain them from the native image bridge. Leaves receive a null guest-memory argument and cannot use memory instructions under this profile. Broader functions, nested guest calls, and process/thread startup are outside this implementation.

## Per-instruction commit

Each callback receives a private working state, a null memory view, and a one-instruction budget. Before committing, the dispatcher checks:

- Exactly one instruction retired and the lifted exit status agrees with an internal successor or a return.
- The next PC belongs to the verified CFG edge set; a return must match this call's exact expected token, even if another token is globally allowed.
- X18-X30 and SP still equal their entry values and NZCV remains canonical.

Only a passing step updates the caller's state and retirement totals. A failing step leaves the last committed architectural checkpoint intact, latches an error, and cannot be retried without abort. Earlier retired steps remain effective. This rollback concerns the integer working state; trusted native callback side effects are not sandboxed. Error reports contain status, reason, entry, current PC, expected return, per-call retirement, and total frame retirement.

The executing flag rejects reentrant begin/run/abort/destruction. It is not a lock; concurrent use of a context is unsupported. Per-instruction checking prioritizes correctness and diagnostics over production performance.

## Validation

```powershell
.\.venv\Scripts\python.exe -B tools/dispatcher_validation.py
.\.venv\Scripts\python.exe -B tools/dispatcher_validation.py --compiler gcc
```

Reports remain under `build/dispatcher-validation/`. Generated code, compiler logs, and shared libraries remain under `build/lifter-validation/`. The suite compiles verified synthetic descriptors, then checks 768 complete leaf cases and 128 stack-framed ARM64 caller chains with two dispatched callees. It compares integer state, NZCV, PC, retired counts, full stack bytes, and independent mathematical results with Unicorn. Zero budgets, multiple slice schedules, return idempotence, repaired checkpoints, and rejected entry/return/SP/NZCV/state cases are covered.

`leaf_dispatch_self_test` additionally uses native test stubs that intentionally return wrong counts/status/edges, change protected state, select the wrong allowed return, and attempt reentrant operations. It verifies fault isolation, failure latching, metadata ownership, malformed registries, and explicit recovery. Native image tests also dispatch a synthetic compiled leaf over a matching synthetic mapped image and guarded stack. No captured game instructions run in these tests.

The next work is binding compiled registry/range provenance to verified image hashes, then introducing separately verified profiles for functions with stack frames and calls. Pointer authentication, service dispatch, vectors, startup, and game execution remain unimplemented boundaries.

Reference: [Arm AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst). This project profile preserves X18-X30/SP and imposes its own entry rules; it is not a complete implementation of AAPCS64 or the game's process ABI.
