# Native SDK function boundary

The hybrid startup profile replaces a declared family of SDK functions with owned native implementations. It retains the original loader and game instructions and the preceding SDK process model. A native replacement is a function operation with its own trace event and work budget; it is not retirement of the original function body. This profile does not supply IPC responses or claim that SDK initialization or gameplay is complete.

## Logging family and state ownership

The first family implements `nn::lm::Initialize`, `nn::lm::SetDestination`, `nn::diag::detail::CallAllLogObserver` and `nn::diag::EnableDefaultLogObserver`. Native per-process state owns initialization, destination and default-observer enablement, counters and bounded copies of log records. It does not retain guest pointers, create SDK log-service objects or write fabricated SDK guards or vtables. No output is sent to a console, file, network service or hardware logging destination by these operations.

Replacing only the original LM initializer would be incomplete. That function constructs service-backed SDK logger objects and installs a private diagnostics observer. The native profile also owns the common diagnostics emission boundary and destination/enable consumers. Observer registration, unregistration, callback replacement/reset and opaque log-service/getter APIs have explicit unsupported guards. Those guards stop without claiming success; guest callback invocation and the separate log-getter interface require further implementations. Ordinary SDK functions outside the selected family remain subject to original startup decoding and service boundaries.

OE initialization remains original. Its applet and power-management object construction cannot be replaced with an empty successful return. A future native platform family must define owned platform state and cover the actual consumers and effects before it can replace that initialization.

## Original metadata and record evidence

`tools/native_sdk_audit.py` requires a complete offline link and unchanged original SDK text. It checks each selected export's parsed metadata against original dynamic symbol and string records, expected module, function kind, visibility, exact extent and complete body hash. Equivalent same-contract aliases may share one descriptor; conflicting or overlapping extents are rejected. Descriptors contain trusted handler IDs, not serialized host pointers or guest addresses cast to native code.

The logging record layout is bound to a concrete original-code profile. The exported `PutImpl` constructs a 24-byte `LogBody` from the incoming message pointer and length, sets head/tail flags and calls the relocation-backed emission entry. The original LM initializer's default-observer installation identifies an original bounded observer prefix whose field reads establish the metadata prefix consumed by this native family.

The observer profile uses bounded forward CFG role tracking. Input pointers must be captured before calls or dereferences; body and metadata bases stay protected until their respective final field consumption. Branch alternatives cannot combine unrelated reads into an apparent layout proof. After the final module-pointer self-load, the original register may be reused for a string. Synthetic mutations that retain every previously matched word but clobber the live bases are rejected.

| Record | Consumed layout |
| --- | --- |
| Log body | Message pointer at 0, unsigned 64-bit length at 8, head byte at 16 and tail byte at 17; 24-byte record. |
| Metadata prefix | Signed line at 0, filename/function/module pointers at 8/16/24, severity and verbosity at 32/36; 40-byte prefix. |

Head/tail are restricted to canonical Boolean values and severity to the observed 0–4 range. The host owns bounded copies of message and source strings. The audit does not infer a complete metadata structure from this consumed prefix; later extension fields and arbitrary guest observer semantics are not implemented. The independent structure reference includes additional fields, which is why a blind larger metadata read would be unjustified.

Static PLT records describe the independent linked snapshot. They do not approve a live target or bypass original stub instructions. The native dispatcher separately checks original entry words and complete read-only body bindings, rejects interior entry and returns to the incoming canonical LR without executing the replaced PAC prologue. All registers, SP, NZCV and guest bytes retain the operation's declared effect contract; original caller frames and PAC state remain the original startup dispatcher's responsibility.

## Execution and memory contract

The native constructor requires program flags 7 and an explicitly native-enabled SDK context. Earlier constructors reject that context/profile. Bindings are copied, limited to 64 nonoverlapping extents, and checked before startup and during execution. Full body and return-word checks precede each native operation. The current handlers are void functions and preserve every register, SP and NZCV while returning to the checked incoming LR. Unknown observer/object operations stop before effects.

Trace event 3 records a native function operation. Its `retired` count is unchanged; `native_calls` increments separately. The common work ceiling and yield quantum count both kinds of work. Full/compact traces hash every original and native row. Mandatory SDK stage entries, the `nnMain` thunk and its target cannot lie in a native replacement extent, so replacing a function cannot manufacture the original-path initialization goal.

A separate read-only native-input transfer captures up to 4 KiB atomically under the existing backend lock. Existing scalar/pair/probe and 64-byte record limits stay unchanged. The remaining original SDK state-copy path uses named DMB options. This native profile implements the twelve named load/store/full variants through the same serialized backend as every transfer. The model is stronger than their Normal-memory ordering requirements; it does not implement device/MMIO barriers, DSB completion or every allowed weak-memory outcome. Older startup/SDK modes still reject DMB execution.

The original OE initializer is an observation only. A generated watched entry is bound to its original symbol metadata; the CLI records it only when an original event-0 instruction retires there. A native call or a selected but unexecuted marker cannot set this evidence.

## Private audit command

```powershell
.venv\Scripts\python.exe -B tools/native_sdk_audit.py build/prepared/oot111 `
  --report build/native-sdk-audit.json
```

Choose a fresh report path under ignored `build/`. The audit executes and translates no guest code. Detailed original symbols, addresses, words, hashes and generated function selections remain private. The report's aggregate summary names only the number of bindings and native operations.

## Validation and actual startup evidence

The final `build/milestones/native-sdk-v1/` run passes every required stage with a matching source fingerprint: 444 Python tests without skips, seven CTest groups and 283,401 common native/reference comparisons per compiler. The original process-context C self-test retains its 7,810 checks on MSVC and GCC. Twenty-nine new tests cover native handler effects, copied binding lifetimes, complete body/return checks, interior/self-return rejection, guard and fault isolation, unsupported goals, native work quotas, record captures and full/compact trace equivalence. DMB validation includes 192 independent full-state reference comparisons and 12,000 alias-view publication rounds with 24,000 barriers per compiler.

Fresh default, PLT and bounded-memory surveys retain every preceding outcome. Both compilers reproduce the raw startup endpoint after 40,397,142 original instructions and the original-SDK endpoint after 40,399,581 original instructions, with their exact prior full-prefix digests. The hybrid executables each retire 40,400,024 original instructions and complete one native logging initialization. All eight relative-pointer probes match the independent linker, and the full ordered hybrid trace SHA-256 agrees: `a31bff254c22a39dbfca01c053f6742d45d5e8e796752f8b1af84730e3906c9a`.

The original OE initializer's entry instruction actually retires in both runs. Logging native initialization has returned and the original platform path reaches its next `ConnectToNamedPort` request for `sm:`. That request is not handled by this profile. Five mandatory original stage entries are observed; this does not mean five function bodies completed. OE/SDK initialization, application entry and gameplay remain incomplete. The native logging operation is not counted as an original ARM instruction or an initialization-goal marker.

The next native platform family must own its configuration/state and cover actual OE consumers, events and callbacks before replacing OE initialization. Other SDK namespaces and the later application heap budget remain measured dependencies. A previous successful trace cannot certify future handlers; source changes require a new complete milestone run.

Build and explicitly execute a fresh hybrid profile:

```powershell
.venv\Scripts\python.exe -B tools/build_startup.py build/prepared/oot111 `
  --output build/native-sdk-experiment --compiler cmake --sdk --native-sdk --execute `
  --expand-targets 64 --limit 1000000000 --quantum 10000
```

The reviewed complete validation configuration is `config/milestones/native-sdk.json`; it checks raw startup, original-SDK startup and hybrid startup on both MSVC and GCC, retaining the earlier endpoints and complete trace digests.

## Primary references

The implementation is independent. These references inform API roles while the inspected original bytes bind this specimen's field layout:

- [Atmosphere diagnostics log types](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/include/stratosphere/diag/diag_log_types.hpp).
- [Atmosphere logging initialization and destination API](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/source/lm/lm_api.cpp).
- [Atmosphere log destination values](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/include/stratosphere/lm/lm_types.hpp).
- [Arm barrier option descriptions](https://documentation-service.arm.com/static/5f3fa899428f7a6b3328fd44) inform the named DMB subset; the owned backend deliberately supplies a stronger total order.
