# Checked execution after initialization

The application profile is a separate opt-in after the initialization milestone.
Program flags 62 require an application-enabled SDK context (flag 512), fresh
host-linked backing and the unchanged original stage/constructor/nnMain goal.
Earlier flags 1/3/7/15/30 retain their endpoints. A crossed program/context or
missing goal is rejected before execution.

At the original entry transition, the dispatcher checks all ordered stages,
constructor-body returns and the retired branch. Application mode records that
initialization checkpoint and continues into original instructions. Its reports
distinguish `sdk_initialization_completed`, `application_entry_retired` and
`post_entry_retired`. Reaching an unselected entry is not retirement of its first
instruction. Quota exhaustion and later diagnostic failures preserve this
distinction; `startup_completed` remains false.

## Original-code selection

Post-entry discovery has a separate bounded selection pass, appended to the
initialization selection. It cannot redistribute the original constructor roots
or their PLT lookahead. Original reads, stubs, authentication, indirect targets,
body hashes, memory permissions and per-quantum checks remain active.

For observed main-module callbacks, independently recomputed relocation-backed
pointer neighborhoods within 128 bytes supply further potential code roots.
Complete original segment identity, relocation recipes, applied eight-byte
slots and linked pointer values are checked. An anonymous neighborhood does not
prove a vtable extent or authorize a live callback. Unrelocated code-shaped
integers and unmatched pointers are ignored. SDK libc++ selection remains its
earlier separate pass.

## Owned application services

The application audit extends a copy of the initialization registry. Each new
binding must replace its exact original guarded SDK export with the same full
body provenance. The earlier initialization registry remains unchanged; aliases,
missing exports or an unexpected prior handler reject the extension. Other
consumers remain guarded.

`SetGraphicsScaleChangedNotificationEnabled(bool)` owns the notification-enable
policy and an update counter. It requires the actual platform provider to be
initialized, accepts boolean W0 and preserves the complete void-return ABI.
It creates no applet session, event, guest object or notification. This setting
does not implement a graphics backend or a resize event queue.

The main thread has owned logical priority and affinity state initialized from
the process declaration. Application-only SetThreadPriority (SVC 13) accepts
the existing main-thread/current-thread identity and an NPDM-permitted priority.
SetThreadCoreMask (SVC 15) accepts a concrete permitted core or the observed
DontCare value (-1), with a nonempty permitted mask. The preferred core and
current logical core are distinct: DontCare preserves the current core while
it remains permitted, otherwise this model chooses the highest permitted
logical core. Queries return the requested preference and owned current state
consistently.
Earlier profiles retain immutable read-only metadata and reject both setters.
Unsupported handles, priorities, masks and other special core values stop before
effects. Counters and register results publish only after complete validation.

This is one logical guest thread; it changes neither Windows scheduling nor
physical CPU affinity and creates no new thread handles. The actual SDK SVC/RET
wrappers are bound independently. The [libnx service declarations](https://github.com/switchbrew/libnx/blob/master/nx/include/switch/kernel/svc.h)
provide independent service-number/type context. The
[Atmosphere thread services](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/svc/kern_svc_thread.cpp)
and [thread state](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libmesosphere/source/kern_k_thread.cpp)
provide independent DontCare/preferred-core context. These are semantic
references, not proof of the Switch 2 ABI, and their implementation is not
imported.
Original selected SDK code still owns its thread objects and field operations.

The application-only LDADDA/LDADDL W/X additions complete the observed atomic
ordering cohort through the shared serialized Normal-memory fetch-add backend.
They retain exact W/X/ZR/SP rules, natural alignment, complete RW preflight and
fault isolation. Earlier INIT helpers and decoders still reject these variants.
Application-aware decode memo keys prevent a cached decode from crossing that
boundary. Pinned ARM comparisons cover every register field, aliases, modular
values and ZR; native dispatcher tests verify real memory effects and unchanged
initialization endpoints. This finite serialized model does not establish
exhaustive weak-memory or guest-thread scheduling equivalence.

Application-only non-scaled SCVTF/UCVTF cover signed/unsigned W/X inputs and S/D
destinations. A pure unsigned-integer implementation rounds to nearest with ties
to even, preserves W truncation/ZR behavior, clears the scalar destination's
upper bits and accumulates only the possible Inexact FPSR bit. It never changes
the host FP environment. Old INIT decoding/preparation and crossed dispatcher
metadata reject these words. Both compilers check all 8,192 register-field,
width and signedness combinations against the pinned ARM state and an independent
exact-rational nearest-value oracle, including rounding ties, signed minima,
unsigned maxima, FZ, cumulative flags and complete state/memory preservation.
The inverse non-scaled FCVTZS/FCVTZU variants use exact truncation toward zero
and saturating signed/unsigned W/X results. NaNs, infinities, out-of-range values,
fractional inputs and FZ denormals have independently checked Invalid, Inexact
and InputDenormal flags. Their vector inputs remain unchanged and a W result
clears the upper GPR bits; destination ZR discards the result. Together both
directions cover 16,384 complete field/width/signedness reference cases per
compiler. Other fixed-point or rounding variants stay unsupported.

## Read-only game content

The application preference defaults explicitly to `en-US`. The owned
`GetDesiredLanguage` getter returns its eight zero-padded code bytes in X0 and
counts real queries. The audit recognizes the original wrapper's eight-byte
service output slot, Result check and X0 load/return before binding this ABI.
This is a declared project setting, not an inferred Windows locale or a claim
that the original applet service exists. Other settings/object consumers remain
guarded or original selected code.

`tools/prepare_romfs.py` verifies every payload in the selected NUP RomFS against
its catalog hash. It binds that catalog's ExeFS hashes and title to the already
verified prepared modules and NPDM. Raw content remains in the original NUP;
only compressed payloads enter a private decoded cache. Streaming bounds reject
overruns, truncated frames, trailing data and excessive windows. A complete
directory census preserves empty directories. Virtual UTF-8 names remain case
sensitive and are never extracted as Windows filenames.

The private version-1 index has a 160-byte header, fixed 64-byte file/directory
records, sorted canonical names, body digest and source/cache identities.
The executable's CLI object embeds the expected complete index SHA-256 through
a private build header. This header participates in incremental object identity;
other generated objects remain reusable. The builder rechecks the exact source
catalog/ExeFS binding. Loading requires the compiled seal, matching program ID,
complete directory flag and unchanged backing headers/sizes. Read-only Windows
handles deny concurrent writes and deletion. Each opened file also verifies its
actual decoded payload hash before a token is published.

Twelve original-export/body-bound operations provide cache-size query, cached
and uncached mounting, unmounting, file open/close, size, entry type and counted
or exact reads with default/zero options. The owned provider requires 64 bytes
of mount metadata containing its index seal, generation and name. Subsequent
operations validate this ticket; outputs cannot overwrite it. This is the
project provider's actual footprint, not a recovered Nintendo cache layout.
Unbound contexts cannot report a successful cache query or mount.

File tokens identify actual bounded read-only views, with finite handle slots
and generations that are never reused. They are not Windows pointers, guest SDK
objects or IPC handles. Other filesystem consumers stay guarded. Paths are
restricted to the one mounted namespace; traversal, host paths, writes and
unsupported read options stop. Real missing paths return the filesystem's
PathNotFound result; its numeric context is independently documented in
[Atmosphere's result declarations](https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libvapours/include/vapours/results/fs_results.hpp).
No third-party implementation is imported.

Reads commit at most 8 MiB plus their count through a separate joint service
transaction under the existing memory backend lock. Every output range is
preflighted before any write, preserving all bytes and provider counters on a
memory fault. A bounded path snapshot stops at the first NUL, including a
terminator at a mapped page end. Earlier scalar, pair, probe, record and native
input limits are unchanged. Synthetic backing tests cover raw, compressed and
empty files, directory/missing-path results, both read ABIs, options, stale
tokens, corrupt identities/payloads and rejected output/cache overlaps.

All assets, decoded caches, generated game C and executable bindings remain
under ignored `build/`. They are never part of the repository.

## Validation and limits

Synthetic tests check all quota boundaries around entry, exact earlier trace
prefixes, deferred/missing constructor completion, crossed profiles, owned
policy lifetimes, complete register preservation, rejected inputs, priority and
affinity query agreement, original relocation/stub binding and malformed
milestone evidence on MSVC/GCC.

The milestone pipeline retains every earlier experiment and initialization
prefix, reruns original-byte surveys and compares accelerated and diagnostic
application traces on both compilers. Source, generated-unit and executable
fingerprints must match. Native/provider work remains separately accounted.

An application diagnostic is not a completed process or a playable game.
Filesystem mounts, graphics/shaders, audio, input, broader SDK consumers and
guest thread scheduling require their own owned behavior and evidence.


## Measured original-code progress

The application/content milestone retains all three original constructor returns
and seven initialization stages, then executes 308,487 original instructions
after the checked entry transition. It performs actual main-thread priority and
DontCare-affinity updates, configures notifications, queries the owned language
preference twice and mounts the verified 186,587-file / 598-directory RomFS.
Four files are hash-verified, opened, read and closed, delivering 3,427 bytes.
The raw source remains in the NUP; the decoded cache occupies 2,991,025,900 bytes.

The measured endpoint is the original scalar-SIMD `UCVTF S8, S0` form. Its integer
operand is in a vector register; it belongs to a separate encoding family from
the completed W/X-source conversions. It remains an explicit untranslated
boundary. The original instruction/source identity and full retired trace are
recorded privately. This is an integrated startup/content diagnostic, not a
rendered frame or completed game startup.


## Final validation evidence

`build/milestones/application-content-v1/` passes all 42 required stages with
616 Python tests without skips, seven CTest groups and 283,401 common
native/reference comparisons per compiler. Existing profile outcomes and all
six raw/SDK/logging prefixes remain unchanged. Both host-initialization lanes
also reproduce the preceding completed initialization exactly.

Both application executables retire 1,830,133 original instructions plus 51
scaffold instructions, with 46 separately counted native calls and 14 accelerated
leaf calls. The complete accelerated/single-step ordered trace SHA-256 agrees on
MSVC and GCC:

`472f151e22e5d9aafb1efc05c68eca1c4f4b56bb66a33e420a3eabf8b456d0e1`

The implementation/configuration fingerprint is
`5443de62f7e37bfe0fc347ef9a9875efc5cfd96d1ba1eda7ed29bad50adac22d`.
The run metadata records interruption during GCC compilation and checkpoint
recovery on this unchanged fingerprint. Recovery verifies the original private
entropy input, re-executes the runner's original post-native evidence checks and
fresh diagnostic comparisons, then completes the unfinished GCC command and
summary. The recovery script and pre-recovery manifest hashes remain private
with the run evidence. No required stage is skipped or replaced by a marker.
