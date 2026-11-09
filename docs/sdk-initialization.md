# Native SDK initialization experiment

The initialization profile supplies owned host implementations for a bounded SDK
startup cohort. Original OS setup, SDK module initialization, application
startup, constructor callbacks and the final `nnMain` branch remain guest code.
This remains a startup experiment; the existence of a native provider is not proof
that initialization completed or that the game is playable.

`--native-sdk` retains the earlier logging-only model. `--sdk-init` selects the
separate initialization model and its larger, finite registry. The source audit is
available independently of either execution mode:

```powershell
.venv\Scripts\python.exe -B tools/sdk_init_audit.py build/prepared/oot111 --report build/sdk-init-audit/report.json
```

Reports must use a fresh path under ignored `build/`. They include exact original
dynamic-symbol provenance, complete function-body hashes, implementation IDs,
return-value contracts, guard aliases and required original startup entries. The
auditor does not execute original code or grant runtime capabilities.

The [acceleration extension](startup-acceleration.md) adds stable split C,
verified whole leaves and a separate host-linked entry. The raw diagnostic
retains its original loader. Host-linked execution excludes loader text and
requires actual original constructor-body returns.

## Provider responsibilities

| Family | Native responsibility | Unsupported boundary |
| --- | --- | --- |
| Logging | Existing bounded copied records, destination and default observer state | Guest callback replacement and opaque service objects |
| OE | Explicit local operation, performance, focus and graphics state; validated CPU boost and notification settings | Original applet sessions, service objects and other OE operations |
| AOC | Balanced owned initialization references and an empty local content catalogue | Original add-on-content service objects and unimplemented catalogue queries |
| ERR | Owned error-context initialization and bounded native context state | Original context-writer objects, guest callback/error-handler installation and queries |
| Abort observation | Owned native abort-observer state | Guest observer holders, callback registration and invocation |
| PCTL | Explicit local initialization/policy state | Unimplemented parental-control queries and original service objects |
| FS | Application initialization mode and the two application logging/result flags | Filesystem connections, mounts, files, directories and unknown callbacks |
| Time | Explicit declared user-clock configuration and owned initialization references | Original time service/shared-memory objects and unimplemented time queries |
| System tick | Live Windows QPC converted to the source-bound SDK frequency | Unsupported counter variants and absent frequency declarations |
| Math log | Host binary64 log for finite positive D0, preserving the remaining vector/GPR state | Nonpositive/nonfinite domains, other libm functions and guest FP exception interfaces |

The inspected FS application initializer selects application mode; it does not
connect to a filesystem service or mount content. Its native implementation must
own that bookkeeping without implying that RomFS or save data is available.
Time initialization returns a `Result` in W0. The other initializer contracts in
this cohort are void, and preserve register state according to their declared
native ABI. Return types are explicit: the mangled names alone do not encode them.

The original GetSystemTick counter-read/return body is bound separately. The
frequency comes from the original constant frequency getter's metadata and
complete body. This input specifies 31,250,000 Hz. Checked integer conversion
measures real elapsed QPC time; retirement counts do not manufacture timestamps.

The native log binding is a typed host-libm replacement, separate from ARM FP
instruction support. It changes only the low 64 bits of Q0 and preserves the
host thread's errno, rounding mode and exception flags. It uses nearest rounding
with the default host FP environment during calculation. Independent 200-digit
Decimal checks cover subnormals, exponent extremes and randomized binary64
inputs with a two-ULP test tolerance. This does not establish bit-identical
results to the original ARM libm or implement FPCR/FPSR semantics.

Replacing OE initialization also removes original applet-client construction.
Consequently the unsupported guard family includes direct `nn::applet` exports,
in addition to OE, AOC, ERR, PCTL, FS, time and diagnostic abort APIs. Const members
and detail functions are included. No original SDK object is manufactured to make
an unsupported consumer appear initialized.

## Registry and startup checks

The new audit allows at most 4,096 nonoverlapping function descriptors. Aliases
merge only when entry, complete extent, body hash, handler and return contract
agree. Parsed namespace, function kind or symbol-list changes cannot silently
remove a guard: enumeration checks original symbol names and bounded table size.
Any original function-body mismatch remains a rejection.

A narrow original-body exception admits default C1/C2 constructors containing
only zero stores through this, within 256 bytes, followed by standard RET.
There are no loads, calls, branches, writeback or provider-global accesses.
Their original stores execute with normal pointer/permission fault checks.
They acquire no service or usable handle and do not initialize skipped provider
state. Other object operations remain guarded. Each admitted constructor has
separate symbol/body evidence.

Native calls replace a whole function before its prologue. The runtime must check
the exact entry, complete bound body and canonical distinct registered return
before effects. A guarded call stops deterministically; interior entry does not
authorize original code inside a skipped provider. Native work consumes quota
and retires no original ARM64 instruction.

All seven required pre-entry stages and the original `nnMain` B thunk remain
outside every replacement extent. The thunk's distinct target must also remain
outside the registry. Ordered original stage-entry retirements, original callback
execution and the actual thunk transition are separate requirements. Visiting a
stage entry does not prove that its body returned.

`nntimeStartup` remains original. It checks the native time initializer's Result
and installs existing libc conversion callbacks through original code. The
initialization profile does not replace that wrapper with an unconditional
success. Application startup also retains its original heap calculation; the
declared process-memory model must meet its demand rather than allowing unsigned
underflow or inventing an allocation result.

## Constructor and private-state audit limits

Original module `DT_INIT` bodies invoke their constructor arrays through checked
slot trampolines. The inspected input has 9,879 potential array slots across main
and SDK. A table census does not prove that those constructors ran. In particular,
observing the SDK Start callbacks or libc stage entries cannot substitute for
following the original constructor path and its actual targets.

The initialization profile selects all original code-valued constructor slots and
module `DT_INIT` entries together from the independent verified linked snapshot.
It checks module/source/text identity, original dynamic bounds, the complete
array checksum and each slot's exact pointer before selection. Null and sentinel
slots are retained in the audit without becoming code roots. This selection adds
potential code to the compiled program; it does not invoke a constructor or
authorize an indirect target. The raw package remains unrelocated; host-linked
boot instead packages the independently verified offline link.

This profile alone permits 524,288 selected rows, 8,192 text spans and 16,384
additional roots. Earlier modes retain their existing limits. The initialization
manifest compacts the large instruction-node list to its count and ordered
address/word hash after complete rows have been emitted into private generated
source. Earlier manifests retain their previous node representation.

The original DSO registration path can defer a module's constructor pass. A later
original call can enter the same `DT_INIT` body again and run its array. The
selection covers both paths; a registration return or initialized flag does not
establish that the array completed.

The observed original RELRO path requests `SetMemoryPermission` with permission
1, then `SetMemoryAttribute` with mask and attribute both 16. The initialization
runtime applies a real read-only split to eligible original image data, and its
checked memory backend rejects subsequent writes. A supported permission-lock
operation changes the queried attribute while preserving each image data page's
existing R or RW permission. Locked RW data remains writable, and its permissions
cannot subsequently be changed. Unsupported
memory domains, permission upgrades, clearing a lock and exhausted view capacity
reject before committing the mapping or guest-register changes.

The reference meaning of attribute 16 is **PermissionLocked**; Uncached is bit 3.
Atmosphere's [memory-attribute definitions](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libvapours/include/vapours/svc/svc_types_common.hpp)
and [service validation](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/svc/kern_svc_memory.cpp)
provide independent ABI context. The runtime's admitted subset is tied to the
inspected original calls and explicit process model; these references do not
establish a recovered Switch 2 kernel ABI.

The named-vtable selection batch is confined to defined SDK libc++ `std::__1`
objects. It validates original object metadata and segment checksums, complete
object extents, exact eight-byte relocation recipes and the independent linked
pointer values. Only aligned targets in the unchanged original SDK text become
additional roots. Unrelocated integers that happen to resemble code addresses
are ignored. These original objects reside in data that the original RELRO path
can later protect; selection alone neither makes them read-only nor authorizes
a live virtual call. Original vptr loads, method-pointer loads and checked
indirect transitions remain active.

The private source review separately inspected initializer state accesses and
the surviving SDK module, application and time-startup wrappers. Those wrappers
do not directly read the skipped provider's private client state. A bounded scan
of SDK address-materialization windows found anonymous original private FS, ERR
and time consumers; shared relocated import slots were distinguished from
provider-owned mutable fields. Detailed locations and body evidence remain under
ignored `build/sdk-init-audit/`.

This is an exported-consumer guard closure and a focused original startup-path
review. It is not an exhaustive proof of arbitrary private pointer aliases or
whole-game behavior. Reports retain
`private_direct_access_closure_proven = false`. Newly reached original consumers
must be inspected and supported or guarded before extending the milestone.

## Validation

The synthetic audit tests build independent NSO symbol/string tables and check
complete-body binding, forged namespace/kind/census rejection, const/detail and
applet guards, alias conflicts, overlap and finite-registry rejection, original
stage exclusion and the exact `nnMain` thunk/target requirement. No original game
code executes in those tests. A real startup outcome must be reported separately
with both native compiler traces, original retirement counts, native provider
counts, callback evidence and the precise remaining boundary.

## Memory and instruction model

The initialization profile declares a process budget with 4 GiB available after
image, stack and TLS backing, separately from a 2 GiB heap address capacity. These
are explicit experiment declarations. The application's original fixed reservation
and alignment calculation decides the actual heap request. Windows reserves the
capacity and commits only the currently published pages; shrinking decommits pages
and subsequent growth receives zero-filled memory. Earlier SDK profiles retain
their preceding heap configuration and backing behavior.

A separate 32-register, 128-bit vector bank leaves public integer state ABI 2
unchanged. Admitted single and pair transfers move S/D/Q bits through one checked
record capture or staged whole-record commit, preserves NZCV, and validates SP
alignment and base writeback before effects. Smaller loads clear the remainder
of the 128-bit destination. Duplicate-destination pair loads, non-temporal pairs
and unimplemented vector/FP operations stop. Scalar/pair/probe limits in earlier
profiles remain unchanged. The original lazy PLT resolver uses these operations to
save and restore argument vectors around symbol lookup.

No-offset single-lane LD1/ST1 supports B/H/S/D elements while preserving all
other vector bits. General-register FMOV transfers W/S or X/D bits, with ZR
semantics and cleared upper destination bits for vector writes. These remain bit
transfers. Single-lane post-index/register-offset, multiple structures and
the upper D-lane general-register move are outside this subset.
The lane forms follow the [Arm assembler reference, ST1 single structure](https://documentation-service.arm.com/static/5f3fa899428f7a6b3328fd44)
and synthetic full-bank/memory comparisons with the pinned ARM reference.

The private bank additionally owns FPCR/FPSR without changing integer ABI 2.
FPCR permits nearest rounding with default controls or FZ; other control bits
stop before effects. Explicit scalar S/D comparisons (including conditional
comparison and signaling forms), select, moves, sign operations, S/D conversion
and square root preserve their defined bit/exception behavior. MUL/DIV/ADD/SUB
and all four fused multiply/add sign variants admit finite operands. Fused
operations round once. Unsupported operands remain explicit boundaries.
Sign operations also admit vector 2S/4S/2D forms without changing exception bits.

Each host calculation restores the thread's floating environment and errno.
Integer significand checks handle ARM tininess before rounding at the minimum
normal boundary, including fused cancellation; FZ input/output behavior is
modeled explicitly. Synthetic checks compare complete vector/integer state,
FPSR, memory and alias cases with the pinned ARM reference on MSVC/GCC.

Exact XPACLRI strips LR using the existing QARMA5/VA39/TBI0 model and bit-55
extension selector. It neither authenticates the pointer nor silently changes
prior PAC profiles. The original resolver performs its own authentication and
compares LR before and after stripping. Native/reference checks include actual
PAC-signed and poisoned pointers.

## Original module protection

The inspected RELRO path performs a page-aligned image-data downgrade to read
only, followed by the observed PermissionLocked mask/attribute value 16. The
lock can also cover remaining writable image data: it preserves R/RW access and
prevents a later permission change. The
initialization service model splits owned image views, validates complete range
coverage and publishes the complete replacement table atomically. Later guest
stores and atomic writes use that table and reject sealed bytes. QueryMemory
reports the split ranges, actual permissions and lock bit. Heap remapping retains
those protection views. Cached region records must be reacquired after mapping or
protection changes; trusted host backing pointers are not a permission grant.

This is a finite checked-memory model. Permission upgrades, cache attributes,
heap/TLS/stack/text protection and unrelated service values remain unsupported.
The permission-lock name and bit are cross-checked against the
[primary memory-type declaration](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libvapours/include/vapours/svc/svc_types_common.hpp)
and [service validation](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/svc/kern_svc_memory.cpp);
the actual path and register roles come from the inspected original bytes.

## Completed initialization evidence

The final private `build/milestones/sdk-initialization-v1/` run passes every one
of its 36 stages and the unchanged source fingerprint. It includes 573 Python
tests without skips, seven CTest groups and 283,401 common native/reference
comparisons per compiler. Fresh static surveys preserve earlier policy outcomes;
the six old raw/SDK/logging executions retain their complete prefix digests.

Both MSVC and GCC reach the same original nnMain transition after 1,521,646
original instructions and 51 project scaffold instructions, with 15 native
operations. All three original module constructor bodies return exactly once,
and all seven mandatory stage entries retire in order. The 13 accelerated leaf
calls preserve the complete ordered trace digest compared with diagnostic
single-step execution on both compilers. Heap size is 1,356,857,344 bytes; the
original protection path produces 4,927,488 read-only and 5,197,824 locked image
bytes. Every operation remains inside the declared experimental process model.

The successful report sets initialization and entry-transition evidence true,
while startup completion stays false: execution deliberately stops before the
first nnMain body instruction. This milestone does not supply graphics, shader
translation, filesystem mounts, audio, input or a playable game.
