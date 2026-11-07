# Experimental native startup bootstrap

The separate RAW startup-prefix contract, version 1, connects selected original ARM64 instructions to a private Windows executable and records precise execution boundaries. It is an experimental process model. It does not prove the Switch 2 startup ABI, complete module initialization, reach a menu or make the game playable. The existing leaf/stack policies and static surveys keep their original permissions and execution scope.

## Entry and initializer audit

`tools/audit_startup.py` verifies prepared inputs, performs a complete offline link for analysis and records the entry control graph, actual original words, semantic support, direct calls, indirect boundaries and SVC immediates. The audit is static: it translates no game code, registers no native callbacks and grants no runtime capabilities. Both successors of a conditional edge are observations, not a prediction of the path a process will take.

The executable entry is selected from the loader module and checked against its original entry instruction. Other module offsets zero are not automatically executable startup entries. The initializer audit records DT_INIT/DT_INIT_ARRAY metadata, null/sentinel entries, duplicate references, target ownership and import/dependency evidence. It preserves array ordering without inferring a complete inter-module invocation order or treating every slot as a distinct constructor. Detailed instructions, symbols, targets and source/text hashes remain private under `build/`.

The current input has 9,879 distinct init-array code pointers and four DT_INIT functions. Its entry-only static graph contains 1,549 instructions with 11 indirect-call, three indirect-jump and one SVC boundary. The static SVC occurs on an error branch; it is not the first service observed at runtime.

## Raw images and relocation

The loader starts from a fresh raw snapshot of the prepared NSO segments at assigned guest module bases. BSS and the guarded stack are initially zeroed. The compiler selection, exact original words and read-only text-span hashes are bound to that snapshot's complete package body hash.

The separate startup package maps zero-padded 4 KiB text/rodata pages and merges writable data/BSS into their complete pages. It rejects overlapping page-rounded segments. This is an explicit experimental NSO process model needed for page-based module discovery; the preceding data-only package builder keeps its exact segment/BSS ranges. Backend text access stays read-only, while QueryMemory reports its separate execute property.

The original loader performs its own relocation. Its RELR operation adds the module base to existing pointer bytes, so executing it on the preceding offline-linked package would add the base twice. Startup preparation therefore audits a separately linked copy and packages the unrelocated copy. `offline_link_applied_to_package` remains false; successful offline linking is audit evidence, not permission to substitute the linked bytes for the loader's input.

Independent expected values for the entry module's RELR/RELATIVE slots are obtained from the offline linker. The native diagnostic counts matching slots after the executed prefix. A match checks those pointer results; it does not establish that every relocation, import or initializer has completed.

Every new attempt requires a newly opened raw image and new process context. Abort/restart does not undo stores, clear BSS or reverse relocation. The image claim is one-shot, including across multiple dispatchers/contexts that retain the same image; creating another dispatcher cannot make a mutated image raw again.

Before the first claim, every region descriptor and all bytes, including stack, must match the initial native-open fingerprints. A changed image is rejected before execution. The claim is never released by abort or destruction. Older mutable-image APIs do not claim an image and retain their previous behavior.

## Explicit process context

`OotStartupContext` copies its configuration, retains the image and supplies one checked-memory view over image backing, the existing guarded stack, private zeroed TLS and an explicitly reserved heap arena. It validates the view's region pointer/count/permissions/backing against owned metadata. All code, context and PAC ownership is retained through yields, and the APIs remain single-threaded.

The selected initial-state model is X0=0, X1=an explicitly supplied logical main-thread handle, SP=the package stack top, PC=the selected entry and other registers/NZCV zero. The private builder takes the stack size from verified NPDM metadata when available; the current input declares a 1 MiB stack. That field establishes a requested size, not the rest of the process ABI.

The current selection reserves a 4 KiB zeroed TLS buffer and a 64 MiB heap capacity with unmapped guards. The heap starts unmapped and is exposed only by an accepted heap-size service. TLS has no fabricated SDK fields, thread-object pointer or proven Switch 2 layout. The getter supplies its guest address; unsupported system-register instructions remain explicit boundaries.

The context implements a deliberately small service subset:

| SVC | Supported behavior |
| --- | --- |
| `0x01`, SetHeapSize | X1 supplies a size within the reserved capacity, aligned to 2 MiB. Success returns W0=0 and X1=the configured heap base. Shrink removes the mapping; later growth re-exposes zeroed bytes. |
| `0x06`, QueryMemory | X0 is a checked 40-byte MemoryInfo output and X2 the queried address. For the page-aligned model, returns mapped types/permissions, actual free gaps and the terminal inaccessible interval above the 39-bit space. Success returns W0/W1=0. |
| `0x27`, OutputDebugString | Captures at most 4,096 readable guest bytes into a result buffer and returns W0=0. It performs no direct stdout, file or network output. |
| `0x1e`, GetSystemTick | Available only when an explicit counter frequency is configured. It scales elapsed host QPC time into that process model. Frequency zero leaves the service unsupported. |

A supported service advances PC by four. Unsupported calls and rejected operands leave guest state, bytes and heap mappings unchanged. A rejected operand is a diagnostic boundary, not a fabricated Horizon result code. GetInfo, memory-permission changes, exceptions, IPC and scheduling remain unsupported. Named GetInfo diagnostics use X1 as the info ID, W2 as the handle and X3 as the sub-ID, rather than logging an unrestricted register dump. The observed SDK stop requests ID 11, handle zero, sub-ID two; other GetInfo values are not fabricated to advance startup.

QueryMemory's whole 40-byte output uses separate 1-64-byte record transfers serialized by the existing backend lock. Rejected reads leave output buffers unchanged; rejected writes change no guest bytes. Scalar/pair transfers and their public probes retain their preceding 16-byte maximum. QueryMemory rejects non-page-aligned contexts. Its mapped states, zero attributes/reference counts and inaccessible terminal interval describe this process model, not recovered Switch 2 kernel state.

## Dispatch and precise stopping

The startup dispatcher is an explicit opt-in separate from leaf/stack schemas. It copies the selected instruction/CFG/span tables and retains image, context and PAC lifetimes. The current limits are 16,384 instruction addresses, 256 text spans and a configurable ceiling of at most 100,000,000 retired instructions. It translates supported original encodings through the existing C emitter; it does not reinterpret a guest PC as a native function pointer.

The emitter groups at most 64 instructions per native callback to bound compiler work. Bounded lookahead may select potential callees of exact relocation-backed PLT stubs from the independent linked snapshot. This selects original code for compilation, without proving a live binding or original function identity. All original stub instructions still execute; the actual runtime target must be registered before the transfer can retire.

Before each step it checks the owned checkpoint, exact instruction word, memory-view metadata, stack bounds/alignment and retirement limit. Control instructions are independently checked against the original encoding and complete expected state, including LR effects and PAC. An unregistered direct or indirect target is rejected before committing the transfer or BL/BLR's LR update. Other scalar value operations remain part of the trusted native emitter boundary; this API is not a security sandbox.

Loads capture a whole operand through the real backend and expose only that read-only snapshot to the compiled callback. Stores expose a write-only staging window and commit through the backend only after expected bytes, complete state and window metadata match. Scalar/pair writeback uses pre-instruction operands and publishes no base update on rejection. Existing whole-transfer fault semantics apply.

General control flow on the selected startup path uses an explicit global retirement ceiling. It is not admitted through the preceding single-counter leaf policy, and does not change that policy's limits. Unselected instructions, unsupported encodings, service requests, invalid memory, unregistered transfers and contract violations produce distinct stops. Yielded checkpoints preserve the exact retired prefix.

## Private build and execution

The static audit can be run separately:

```powershell
.venv\Scripts\python.exe -B tools/audit_startup.py build/prepared/oot111 `
  --report build/startup-audit.json
```

Build a private native selection with the current inputs and execute it explicitly:

```powershell
.venv\Scripts\python.exe -B tools/build_startup.py build/prepared/oot111 `
  --output build/startup-experiment `
  --compiler cmake --execute --expand-targets 64 `
  --limit 100000000 --quantum 10000
```

Choose a fresh output directory. Omit `--execute` to prepare/compile without running the selected original code. `--compiler gcc` selects the other compiler. Generated C, raw packages, native executables, keys and detailed reports remain ignored.

Each target-expansion iteration starts again from verified original inputs, adds the observed original address to the static selection, regenerates its proofs and builds a new executable. Observation alone does not approve an arbitrary callback or resume past a rejected transition. Expansion stops at its explicit limit, an already selected target, an invalid target or a different diagnostic boundary.

The private executable accepts:

```powershell
oot-pc-port.exe --boot-images startup.ootmem --trace NEW_TRACE.jsonl `
  --limit 100000000 --quantum 10000 --trace-mode compact
```

The ordinary repository executable contains no game selection and reports that a private startup build is required. Trace files are created exclusively and contain step/service/stop records with PC, next PC, original word, retired count and reason. A diagnostic stop returns exit code 3 and `startup_completed:false`; it is not a successful boot. File-write failures and contract failures are errors. PAC keys are process-local and never serialized or logged.

Full trace mode stores every row. Compact mode stores the first 64 rows, every service/stop and each 10,000th committed instruction. Both modes hash every original numeric-only row, including omitted rows, through incremental SHA-256. The native report supplies the full row/step counts and digest. Synthetic CLI tests require full/compact digests to match across different yield budgets. Final compiler comparisons require identical complete-prefix digests, not just matching sample files or endpoints. Intermediate full traces may be gzip-compressed losslessly; identical raw packages use hard links where available and each iteration still opens independent native backing.

## Evidence and remaining work

The complete `build/milestones/startup-bootstrap-v1/run.json` reports all stages passed with an unchanged source fingerprint. Validation includes 379 Python tests without skips, seven CTest groups and 283,401 common native/reference comparisons per compiler. The synthetic startup suite checks 480 complete runs and 4,624 instruction prefixes per compiler against enabled reference execution and independent results. An additional 36 two-module cases cross native callback chunks and compare complete state/memory. The process-context self-test checks 273 ownership, region, heap, service, clock and fault cases. Fresh static audits and preceding default/PLT/bounded outcomes reproduce unchanged.

The final MSVC and GCC experiments both reach SDK initialization after 40,397,142 original instructions and stop before unsupported GetInfo ID 11, handle zero, sub-ID two. QueryMemory succeeds on the loader path; all eight audited entry-module relative slots match the independent linker, and both complete ordered trace digests agree. Private executables and reports are under `startup-cmake/iteration-21/` and `startup-gcc/iteration-21/` in that run directory. This is a passed diagnostic milestone, not completed initialization; eight entry-module probes do not establish equivalence for every other relocation. Further work must implement the required process-query/TLS/service behavior, complete initialization and provide graphics/shader/input/audio systems before gameplay.

## Primary references

The implementation is independent. The following primary sources inform the explicitly bounded Switch NSO/service model; they do not prove the Switch 2 ABI:

- [libnx NSO entry assembly](https://github.com/switchbrew/libnx/blob/master/nx/source/runtime/switch_crt0.s) documents normal X0/X1 entry arguments and separates exception/NRO entry.
- [Atmosphere process startup](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/kern_k_process.cpp) sets main-thread arguments and the thread-local handle field.
- [libnx SVC assembly](https://github.com/switchbrew/libnx/blob/master/nx/source/kernel/svc.s) records the trap register ABI and service immediates.
- [libnx service declarations](https://github.com/switchbrew/libnx/blob/master/nx/include/switch/kernel/svc.h) specify heap sizing and debug/counter interfaces.
- [libnx TLS access](https://github.com/switchbrew/libnx/blob/master/nx/include/switch/arm/tls.h) reads TPIDRRO_EL0; it does not define this game's complete TLS layout.
- [Atmosphere QueryMemory](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/svc/kern_svc_query_memory.cpp) and [page-table queries](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/kern_k_page_table_base.cpp) inform the MemoryInfo and terminal-interval model.
- [Windows BCryptCreateHash](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash) and [BCryptHashData](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthashdata) specify incremental hashing and hash-object ownership.
