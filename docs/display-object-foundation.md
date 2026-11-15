# Display object foundation

The next guest Display/Layer profile requires both complete source provenance and
owned host resources. This slice supplies the static provenance audit and the host
vertical-blank owner. It does not enable a new guest profile or return Display,
Layer, native-window, session or SystemEvent handles.

`tools/vtable_provenance.py` takes a pristine prepared module separately from its
offline-linked image. It verifies all original segment hashes, reparses MOD0,
dynamic and relocation metadata, checks the original symbol census and records,
then reconstructs every selected table byte using original ABS64/RELR records.
Tables must be primary tables in initialized data, with the declared slot count;
foreign resolution, pointer addends, partial/missing relocations and overlapping
tables are rejected. Original and linked table hashes and relocation records are
retained in the private report.

`tools/unwind_provenance.py` independently proves selected private-entry extents
using the canonical original unwind table and sequential DWARF32 record boundaries.
Only the explicitly supported CIE encodings/augmentations are admitted. It checks
table/FDE entry agreement, ranges, CIE references, body hashes and export aliases.
Anonymous targets remain private entries, without invented ELF symbols. Neither
audit registers a native handler or grants runtime execution authority.

The source audit on the verified prepared 1.1.1 input finds four related tables,
53 slots and 46 distinct targets. Captured addresses, original bodies and complete
source reports remain under ignored `build/research/display-objects-20261115/`.
The legacy unwind discovery parser and existing native registries are unchanged.
Separate source research identifies the original static DefaultDisplay constructor;
a full rehash of the historical 1,833,238-row display trace confirms its entry and
both original vptr stores. This does not replace checking live vptrs when a later
object profile binds its retained image.

`src/native_vblank.c` owns a DXGI output selected by a real `HMONITOR`. Its worker
owns all COM interfaces, observes `IDXGIOutput::WaitForVBlank`, and becomes ready
only after the first successful physical edge. A manual-reset event preserves
level signaling and coalesces edges; publication/reset/counters share a lock.
Readers receive real synchronization-only duplicates. Failure has its own wakeup
handle; reset misses, backend failure and counter overflow do not invent edges.
No timer creates a vertical-blank signal.

The caller serializes owner lifetimes and closes duplicates before destruction.
Shutdown joins the worker rather than forcibly killing it. A blocked display
driver can delay shutdown until its synchronous wait returns; physical probes run
under an owned subprocess watchdog. The backend is built as a separate CMake
library and is not linked into the current guest startup dispatcher.

Synthetic tests cover source/metadata/body tampering, absent/interior entries,
relocation/census/alias disagreements, report output ownership, level/reset
semantics, duplicate access rights and rollback, two-owner isolation, worker
failure, signal/reset failures, overflow and resource cleanup. The native fixture
runs on MSVC and GCC without requiring a physical monitor in CI. Its explicit
`--physical` mode is a separate hardware observation, never a synthetic CI result.

The fresh `build/milestones/display-foundation-v1/validation/` regression passes
all 52 stages, including 730 Python tests without skips, eight CTest groups and
283,401 common native/reference comparisons per compiler. Its source fingerprint
is `4a9596fac27df51d47bcd60de19cd88d63a01c32e506631d64692d54c982ad59`;
it finished 2026-11-15 17:26:26 UTC. Both full original display replays retain
digest `e330868f9e2bbdff0c7bf2b88258ecac138974fd33c7303b8ca2147d1a98bc21`,
1,833,185 retired instructions and 311,488 after entry. The real-input vtable audit
and linked-public-API physical probes are separate private evidence, not new
guest capability stages in that regression run.

Remaining integration includes the trusted per-context object declaration,
monitor/window/surface peers, coherent public open/create/getter/close behavior,
private consumer guards and the complete source-specific SystemEvent producer
route. The current VI2 duplication wrapper uses an initialized callback table;
the generic OS event layout alone does not establish that callback's ABI. Those
proofs must precede guest event publication. The current full startup boundary
remains guarded `OpenDefaultDisplay`; no original rendered frame or usable input
has been established.
