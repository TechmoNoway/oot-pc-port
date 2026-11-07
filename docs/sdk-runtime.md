# Experimental SDK runtime

The separate SDK startup mode extends the checked raw-startup diagnostic with explicit process queries, private process entropy, TLS register operations and an original-byte initialization goal. It remains an experimental Windows process model. Reaching the goal establishes a particular SDK-to-application handoff under that model; it does not establish a recovered Switch 2 kernel ABI, a rendered frame or playable gameplay. The earlier startup mode and leaf/stack verifier contracts retain their existing permissions and limits.

## Original-byte audit and goal

`tools/sdk_startup_audit.py` verifies prepared module containers, requires a complete offline link, checks unchanged original text hashes and binds each named SDK stage to its actual dynamic symbol record/string bytes, function extent and body hash. Export names, module ownership, function kind and visibility must agree. Missing, ambiguous, hidden or aliased stage definitions are rejected.

The audit records direct calls in the original SDK Start body, exact direct-branch thunks and relocation-backed PLT snapshots. A PLT snapshot selects potential original code; it does not approve a live indirect target, replace original stub instructions or grant any runtime memory access. Initializer arrays retain null/sentinel entries, duplicates, source order and ownership without inferring invocation order.

The required observed stage order is SDK Start, libc stage zero, OS initialization, libc stage one, SDK module initialization, application startup and libc stage two. The actual order is derived from original Start callsite PCs and checked against the expected distinct symbols. Loader callback calls remain original instructions; the audit does not invent their targets or claim they ran.

The application `nnMain` symbol must be an exact four-byte unconditional B thunk to a distinct decoded instruction in the main module. The initialization goal is that branch target. The dispatcher requires each mandatory stage's first instruction to retire in order and the original `nnMain` thunk branch to retire before it accepts the handoff. It stops before executing the first application-body instruction. Goal metadata is copied and bound to selected original instructions. A missing prerequisite is a rejected goal, not successful initialization.

This static audit executes and translates no guest code. Detailed symbols, addresses, words, hashes and initializer reports remain private under ignored `build/`.

## Explicit process model

The SDK constructor and dispatcher are separate opt-ins. They retain the preceding raw-before-rtld image, one-shot pristine-image claim, copied metadata, page model, precise retirement and transactional transfer contracts. The older constructor still reserves its original 64 MiB heap and does not acquire SDK services.

The private SDK builder reads the verified NPDM's ACI0 declarations for the core mask, inclusive numeric priority mask, program ID and application type. Unsupported or missing declarations remain unproven. NPDM parsing does not verify signatures or ACID limits and does not prove that a retail kernel would grant these declarations.

The declared SDK arena uses:

| Field | Experimental value or derivation |
| --- | --- |
| Address-space metadata | 39-bit range starting at zero; no backing is mapped at zero. |
| Alias arena metadata | Separate 2 GiB interval, disjoint from image, stack, TLS and heap. It is initially unmapped. |
| Heap capacity | 1 GiB reserved capacity, initially unmapped, with the existing 2 MiB heap-size alignment. |
| Stack | Verified NPDM main-thread stack size, in the guarded raw-image package. |
| TLS | Private 4 KiB backing, initially zero except the separately audited current-thread lock-identity word. Original SDK code initializes its own thread object and pointer. |
| Total-memory budget | Initial image/stack backing plus TLS backing plus full reserved heap capacity. |
| Used memory | Initial image/stack and TLS backing plus the currently mapped heap size. |
| System-resource arena | No guest kernel-resource arena is allocated. |

These values describe the owned host model, not console RAM availability or kernel accounting. The application also deducts a fixed reservation from its total-minus-used calculation. The final chosen capacity must cover that reservation and keep the requested heap within the provided arena; the current arena is provisional until that original path has run successfully.

SDK GetInfo implements the trap ABI: X1 selects the info ID, W2 supplies the handle and X3 the subtype; success returns W0=0 and X1=the value. Other registers are preserved and PC advances by four. Unsupported IDs/domains stop with unchanged state instead of manufacturing a kernel error or success.

| GetInfo IDs | Supported domain and value |
| --- | --- |
| 11 | Handle zero, subtype 0–3: stable private process-entropy words. |
| 8 | Handle/subtype zero: no guest debugger in this model. |
| 0–7 | Current-process pseudo-handle, subtype zero: declared core/priority masks, alias/heap metadata and total/used memory. |
| 12–18 | Same domain: declared address space, actual stack, zero resource-arena budget/usage and declared program ID. |
| 21–23 | Same domain: total/used memory without the absent resource arena, and declared application type. |

Resource-limit handles and unknown process fields remain unsupported. GetInfo 28–33 require the corresponding independent flags below. A named enum or another project's HLE value is not evidence for a retail service result. Existing QueryMemory, heap sizing and debug capture keep their preceding checked transfer behavior. The default tick frequency stays zero, so counter requests remain explicit unsupported boundaries.

Additional capabilities have independent flags and prerequisites:

| SDK flag | Declared behavior |
| --- | --- |
| `NO_REMOTE_ARENA` | No remote interval is backed and no remote allocation has occurred. Current-process GetInfo 29–32 return zero. Original SDK allocation code explicitly accepts an empty interval and skips zero-size forbidden regions. Remote mapping services remain unsupported. |
| `MAIN_THREAD` | One logical main thread has declared host-model ID 1, NPDM-declared priority and initial core, and the declared allowed core mask. GetThreadPriority, GetThreadCoreMask, GetCurrentProcessorNumber and GetThreadId expose those owned values with their exact trap ABIs. Only the declared logical handle and applicable current-thread pseudo-handle are accepted. |
| `NO_ALIAS_EXTRA` | The declared alias interval has no extra reservation; current-process GetInfo 28 returns zero. The original SDK subtracts this reservation from the total interval size. |
| `PAGE_ALLOCATION` | Current-process GetInfo 33 exposes the explicitly provided 4 KiB allocation granule only when the complete mapping satisfies that page model. Original consumers use it for rounding/masking and allocation size. This does not infer the retail value. |
| `OBSERVED_MAIN_TLR` | Initializes the four-byte lock-identity word at the original SDK's observed TLS offset with the declared logical main-thread handle. Production preparation requires the strict original-byte role audit described below. |

These flags require the process-query model; the observed TLS option also requires main-thread metadata. Main-thread queries do not create guest threads, change their priority or affinity, arbitrate waits, or implement a scheduler. The declared logical ID is host-model state. Unsupported IDs, handles, subtypes and services still stop without retirement or fabricated success.

The current private builder enables these six process-model flags together. Explicit entropy is a separate execution-time option; its input is never part of the generated configuration. Synthetic callers can select smaller declared capabilities, and the preceding ordinary startup constructor does not enable any of them.

## Entropy and TLS operations

The SDK context generates four entropy words once with Windows BCrypt system randomness unless a private explicit 32-byte input is supplied. Repeated queries for an index return the same word. The private execution driver can share one ignored entropy file between fresh compiler runs so their complete traces can be compared. Reports contain only that input's SHA-256 fingerprint. Generated C, traces and logs contain neither its contents nor PAC keys. PAC keys remain separate, fresh process-local state.

Only exact MRS TPIDRRO_EL0, MRS TPIDR_EL0 and MSR TPIDR_EL0 encodings are added through the SDK decoder/dispatcher. TPIDRRO_EL0 reads the owned TLS base. TPIDR_EL0 starts at zero and retains a full 64-bit software value per context. ZR operands have their architectural discard/zero behavior; SP and NZCV are unchanged. Unsupported system registers remain diagnostic boundaries. These register operations do not create guest threads or establish the SDK's complete TLS layout.

`audit_sdk_thread_identity` separately binds the exported critical-section enter/leave functions and their slow paths to original dynamic symbol records and unchanged text. It requires the TLS read's width/offset and the compare/exchange register roles to match the observed profile, checks captured input provenance, and follows the actual direct calls to exact ArbitrateLock/ArbitrateUnlock SVC wrappers. The requesting-thread argument identifies the field's role. Changed offsets, source roles, branches, clobbered captures or wrappers reject the profile. All detailed original words and hashes stay private. Absent profile symbols are reported as unavailable in a general static audit and fail strict production preparation before the field can be supplied.

The supported logical handle is nonzero and leaves the lock's waiter bit clear. A zero-filled ownership field would make an empty-lock acquisition store zero, so leaving that field unmodeled cannot establish valid SDK lock ownership. This narrow specimen-bound inference supplies one declared current-thread identity; it does not manufacture an SDK thread object or assert a general retail TLS layout. Original SDK code remains responsible for publishing its thread-object pointer.

The SDK decoder also admits only the exact scalar 32/64-bit CAS, CASA, CASL and CASAL family. The dispatcher computes the host operation directly, preserves expected/desired input values before writing the compare register and checks the complete resulting state. The backend performs comparison and conditional storage under the same serialization lock as every other memory transfer. Natural alignment, SP-base alignment and complete read/write permission are required even on comparison failure. Rejected transfers preserve guest bytes and register outputs. This conservative Normal-memory total order covers the owned single-thread startup model; it does not claim exhaustive weak-memory outcomes or working guest concurrency.

The SDK-specific selection limits are 65,536 instruction addresses and 1,024 text spans, with an absolute execution ceiling of one billion retired instructions. A configurable smaller budget remains available. Ordinary startup limits remain unchanged. All selected original words, read-only span hashes, actual transfers and target registration checks still apply.

## Private commands

Create a fresh static audit report:

```powershell
.venv\Scripts\python.exe -B tools/sdk_startup_audit.py build/prepared/oot111 `
  --report build/sdk-startup-audit.json
```

The report contains the SDK audit fields and an `npdm` declaration audit. Its printed summary contains aggregate counts, not private code addresses.

Build and explicitly execute a private SDK selection:

```powershell
.venv\Scripts\python.exe -B tools/build_startup.py build/prepared/oot111 `
  --output build/sdk-experiment --compiler cmake --sdk --execute `
  --expand-targets 64 --limit 1000000000 --quantum 10000
```

Choose a fresh output directory. `--compiler gcc` selects the other native compiler. Omit `--execute` for preparation/compilation only. An explicit `--entropy-file` must name a private 32-byte file under `build/`; otherwise execution creates one there. Each target expansion reopens a fresh verified raw image and reruns original relocation. An unsupported service or instruction is reported at its actual boundary and is not bypassed.

## Execution evidence

The final foundation run in `build/milestones/sdk-runtime-v1/` passes every required stage with a matching source fingerprint: 415 Python tests without skips, seven CTest groups and 283,401 common native/reference comparisons per compiler. The process-context self-test passes 7,810 checks on both MSVC and GCC. SDK validation adds 12,288 thread-register reference comparisons, 6,144 scalar CAS state/memory reference comparisons, 262,144 decoder combinations and 80,000 concurrent CAS increments through aliased views per compiler. Synthetic tests also check ordered goal retirement, malformed metadata, fault isolation, entropy privacy and full/compact trace equivalence. Fresh original-byte surveys preserve all preceding default, PLT and bounded-memory outcomes.

Both compilers reproduce the preceding startup endpoint after 40,397,142 original instructions with its unchanged complete trace digest. Their extended SDK runs each retire 40,399,581 original instructions, observe five of seven mandatory stage entries and stop at SVC 31, ConnectToNamedPort for the service-manager port, `sm:`. All eight entry-module relative-pointer probes match the independent linker. The complete ordered SDK trace SHA-256 agrees across compilers: `65d575b056d9fc1f66adde744b63d3079652e38270e10131a64a7535c3ee35f9`.

Stage-entry observations do not mean that five function bodies completed. The OS stage and first libc stages have returned through original code; SDK module initialization has begun. Application startup, the last libc stage and the genuine `nnMain` handoff remain unobserved. The final reports explicitly retain `sdk_initialization_completed:false` and `game_entry_reached:false`. A passed foundation validation certifies the declared runtime capability and diagnostic endpoint, not completed initialization.

The current boundary requires an IPC/service capability cluster: a real owned handle table and session lifetime, service-manager connection and protocol handling, and the concrete services requested by the original SDK module initializers. Static original-byte analysis identifies TIPC service-manager commands 0/1 for client registration and service acquisition, followed by acquisition of the log-manager service, `lm`. Its client path then queries the CMIF pointer-buffer size, converts the session to a domain and requests a logger object. These are static observations of code after the current boundary; none of those requests has executed successfully. Service names and request/response shapes must be checked before adding a handler. Returning unconditional success or bypassing original calls would leave initialization unproven. Scheduling, blocking arbitration and guest-created threads remain unsupported.

Static analysis also identifies a later heap issue before the application stage is reached: its original calculation rounds free process memory down to 2 MiB, then deducts a fixed 2,802 MiB reservation. The present 1 GiB free budget would underflow that unsigned calculation. Process-memory budget and heap virtual-address capacity are separate quantities: a 4 GiB free process budget would yield a 1,294 MiB heap request, which fits the constructor's 2 GiB limit but exceeds the current generated 1 GiB heap capacity. A later accounting update must declare and validate both quantities, the resulting bounded request and its actual backing before application startup can complete. The successful earlier SDK prefix does not validate that later allocation.

Graphics, shaders, input, audio, remaining system-service coverage and application execution remain work after a genuine initialization handoff. The current SDK runtime foundation does not complete initialization or make the game playable.

## Primary references

The implementation is independent. These sources inform the declared model without proving a Switch 2 ABI:

- [Atmosphere capability field declarations](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/include/mesosphere/kern_k_capabilities.hpp) and [inclusive mask interpretation](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/kern_k_capabilities.cpp) inform ACI0 core, priority and program-type parsing.
- [Atmosphere loader process creation](https://github.com/Atmosphere-NX/Atmosphere/blob/master/stratosphere/loader/source/ldr_process_creation.cpp) provides application-type interpretation context.
- [Atmosphere GetInfo](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/svc/kern_svc_info.cpp) informs entropy index domains and supported process-query meanings.
- [libnx SVC assembly](https://github.com/switchbrew/libnx/blob/master/nx/source/kernel/svc.s) records the trap register ABI; the C wrapper's output-pointer ABI is distinct.
- [libnx TLS access](https://github.com/switchbrew/libnx/blob/master/nx/include/switch/arm/tls.h) shows TPIDRRO_EL0 use without supplying this game's SDK thread layout.
- [Windows BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom) specifies the host entropy source.
