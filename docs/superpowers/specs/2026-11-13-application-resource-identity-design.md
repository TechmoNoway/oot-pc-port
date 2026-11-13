# Application resource identity

Status: promoted source passed focused native/static checks and both bounded
original pilots with verified full traces. The fresh full milestone
`build/milestones/application-resource-identity-v2/` passes all 42 stages,
672 Python tests without skips and both compiler full-trace progress proofs,
with source SHA `31a356d994a8b0a8d287270fea0340b9f046b43de72c3dafe83a29a85d12c1ca`.
CAS commit `977149f` is verified on origin/dev. The user
requested continued independent implementation until original game output and
usable input; this is the next measured SDK dependency, not a gameplay claim.

## Evidence

The passed CAS full run stops at the guarded public applet resource-ID getter
after 311,535 original post-entry instructions. Its full traces match on both
compilers. Private static inspection resolves the original public B thunk through
a relocation-backed PLT to the am getter: a 12-byte ADRP X8 / LDR X0 / RET body.
This establishes an eight-byte return, independently of the Itanium name.

The inspected SDK defines 57 am function exports. The matching CAS full replay
retires no instruction anywhere in their exported body ranges. The next audit
must retain complete original metadata, not merely filter mutable parsed names.

Semantic reference context is [libnx applet declarations](https://github.com/switchbrew/libnx/blob/master/nx/include/switch/services/applet.h),
[its cached getter and acquisition](https://github.com/switchbrew/libnx/blob/master/nx/source/services/applet.c),
and [the NV client identity consumer](https://github.com/switchbrew/libnx/blob/master/nx/source/services/nv.c).
Fritchii's applet/window-controller ownership is reference context only; no
implementation is imported. These references do not establish a Switch 2 ABI.
The original private word/body/symbol/PLT evidence remains under build.

## Selected ownership model

Expose the existing initialized native platform's logical process identity.
Its current declaration is logical process 1, distinct from NPDM program ID and
Windows PID. Read the owning configuration; do not introduce another constant,
global ID allocator or unrelated registry. This is process metadata and does
not create an applet client, event, session or guest SDK object.

Both exact public accessors use application-only handler322. Return full X0
and preserve other GPRs, SP, NZCV and vectors, with the registered LR/PC return.
Queries have one context-owned counter, prepared and committed transactionally
with the existing aggregate native count. Invalid state/counters or unsupported
platform lifetime preserve outputs and owned state. Platform finalize disables
queries; reinitialization retains the same process identity and query count.

Executing original applet initialization instead would require genuine IPC and
object/handle ownership. The finite native metadata provider follows the existing
hybrid direction without claiming that original applet initialization occurred.
Future GPU/HID/audio consumers must validate and implement their real owned
resources; an identity value alone grants no such capability.

## Source binding and retained boundaries

The production audit requires unchanged hash-verified original text, original
symbol-table census/records, exact public B/PLT/GOT routing, getter extent,
register/width/return pattern and original data/BSS cache bounds. Bind both
getters to one typed provider and close the application-only am function-export
consumer family with unsupported guards. Preserve the original INIT registry,
all previous profiles, integer ABI2 and the prior application state layout.

Keep context integration in the existing application-services implementation.
No source-list dependency or new object hierarchy is needed. CLI resource data
is application-only and explicitly reports logical owner, active state and
successful query count. Native replacement still checks complete body binding,
interior entry and canonical distinct registered return before effects.

## Validation and actual progress

Focused evidence requires complete scalar ABI and full 64-bit owner values,
all older flags, pre-init/finalize/reinitialize behavior, counter overflow,
null/overlapping live outputs, source/GOT/symbol/ABI mutations and immutable
earlier audits. Actual generated synthetic callbacks must prove both getters,
native work quota, full/quantum1 equivalence, the whole vector bank and the old
INIT stop. The isolated candidate passed these checks on MSVC/GCC; its original
application audit passed statically with 2,275 registered functions.

After promotion, bounded original pilots must prove the former guarded public
entry becomes a successful handler322 native event at exactly the old retired
count. Native events retire no original instruction; the word-proof +1 rule
does not apply. Bind source/word/body/module identities and compare all successful
getter events with the CLI query counter in a native-digest-verified full trace.
Retain original stages, constructor returns and coherent content behavior.

Freeze the actual next endpoint, run the complete milestone with a fresh output
and current source fingerprint, review and push dev, then continue toward actual
frames/input. No unsupported success, original patch, PAC stripping, larger
bound or synthetic image may substitute for that outcome.
