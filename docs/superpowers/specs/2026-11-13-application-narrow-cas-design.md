# Application byte/halfword compare-and-swap

Status: next measured capability design; repository implementation pending. An isolated source-only candidate under ignored build/ has focused synthetic checks.
The user requested continuation toward actual game output/input. Finish the
frozen application SIMD validation and its reviewed dev delivery first.

## Evidence and scope

The matching source-bound SIMD pilots retire 311,527 original instructions after
entry and stop at CASAB. Both native-digest-verified full replays retire the old
UCVTF frontier at the expected checkpoint. Game rendering/input remain absent.
The private exact stop and module identity are in the v3 pilot manifests; no
game addresses or disassembly are included here.

Implement one finite application-only family: CASB/CASAB/CASLB/CASALB and
CASH/CASAH/CASLH/CASALH. All eight variants share mask/fixed
`0xbfa07c00 / 0x08a07c00`. Bit30 selects byte/halfword; bit22 is acquire and
bit15 release. Rs=bits20:16, Rn=bits9:5, Rt=bits4:0.

Primary architectural references:

- [Arm A64 byte CAS](https://support.arm.com/documentation/ddi0602/2025-12/Base-Instructions/CASB--CASAB--CASALB--CASLB--Compare-and-swap-byte-in-memory-).
- [Arm A64 instruction reference](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85), byte/halfword CAS sections.

Read the low 8/16 bits of expected Rs and desired Rt. Compare atomically with
the selected memory bytes, conditionally store the low desired bits, and return
the original value zero-extended through W(Rs). Rn31 is SP; Rs31/Rt31 are ZR.
Snapshot all inputs before writing an aliased result. Preserve SP, NZCV, vectors,
other GPRs and adjacent memory. Successful retirement advances PC by four.

## Implementation choice

The selected approach factors the existing serialized CAS body into one private
backend implementation and adds a narrow-only public wrapper. It reuses the
same transfer lock, preflight and byte helpers as CAS32/64 and every other
memory operation. The old wrapper continues accepting only sizes4/8; the new
`oot_memory_compare_exchange_narrow` accepts only sizes1/2. Existing fault
ordering, outputs and backing behavior of the old API must remain identical.

A duplicated unlocked byte read/store is incorrect under concurrency. C atomic
pointer casts over guest backing would violate the existing alias/view model.
Host guest-thread scheduling is a separate dependency and is not introduced.

The admitted memory model remains serialized Normal memory, including natural
alignment, SP16 and complete RW permission even on compare failure. It is
stronger than some architectural orderings; it does not claim all weak-memory
outcomes, MMIO behavior, exclusive monitors or actual guest scheduling. Native
output/state pointers retain the existing private, stable, nonaliasing host
preconditions. Guest aliases over shared backing are supported through the
common backend instance and lock.

## Integration and retained boundaries

- Append `OOT_STARTUP_APP_CAS_NARROW=8` in `startup_init_atomic.h`.
- Recognize it only in `oot_startup_application_atomic_kind`. Add a dedicated
  CAS branch in `atomic_step`; the current fallback is fetch-add and must never
  receive the new kind. Keep all old IDs and sizes unchanged.
- Python `sdk_init_atomic_kind(...,application=True)` returns
  `compare_exchange_narrow`. Decode into the existing `sdk_atomic` form with
  width32, access_size1/2, rd=Rs, rn=Rn, rm=Rt and the existing CAS order value
  `(word>>15&1) | (word>>21&2)`. Do not change legacy `sdk_atomic_kind`.
- Existing context/dispatcher application gates already ask the application
  classifier. Keep those gates. The dispatcher's independent full-state CAS
  expectation currently recognizes only the old W/X mask: extend that existing
  branch to recognize new kind8, snapshot 1/2 bytes and expect a W(Rs) result.
  Without this change a correctly implemented narrow CAS would be reported as a
  bad callback because the expected GPR bank would remain unchanged. Reuse the
  existing CAS expectation; do not add a second effect implementation. Preserve
  ABI2, flags, PAC and actual original words.
- Earlier SDK/INIT/leaf/stack decode and helper paths must still reject these
  words. Do not generalize old CAS admission to accept them.

## Required evidence

Pinned Unicorn full register/memory comparisons on both compilers cover every
width/order, all Rs/Rt fields, a covering set of Rn fields and all register
aliases, ZR/SP, successful/failed comparisons, high source bits, high-bit old
values, and W-result clearing. Use independent expected memory/result bytes.
Faults preserve state and all backing/output bytes except declared fault detail.

Native contention tests use two private views and guest aliases to one backing.
Publish payload under release CAS and acquire it through CAS before checking
the payload; use a bounded handshake, real threads and the common backend.
This establishes the admitted backend order, not guest scheduler readiness.

Synthetic generated application dispatch must actually execute the new words,
export their memory/old-value effects, preserve original initialization and
retain the INIT stop. Compare whole execution with quantum1 and quotas around
each instruction, crossed metadata and profile-cache rejection.

Add private `application_atomic_sites` records, preserving existing SIMD/SVC
fields. Their original source/word hashes are selection evidence only. Extend
the progress proof to accept an exact new narrow-CAS site as well as the six
existing SIMD families. The next full run must prove the CASAB frontier STEP at
the SIMD baseline retirement count plus one, with unchanged original modules
and native full-trace digest. Do not relabel an atomic site as SIMD.

After focused checks, run bounded original-code pilots from the new passed SIMD
seed and its retained root list. Keep budgets, providers and previous profiles
unchanged. Freeze the genuine next unsupported word/export/SVC in a separate
config, then run the complete milestone with a fresh output directory and
current source fingerprint before commit/push. No empty-success replacement,
original patch, PAC bypass or larger limit may stand in for this evidence.


## Initial reference characterization

Before native implementation, 48 synthetic cases on the pinned, enabled Unicorn
reference passed across both sizes, all A/R choices, register aliases, ZR/SP,
low-bit source truncation and zero-extended results. The private record is
`build/application-simd-pilots/narrow-cas-reference.json`. This is reference-only
characterization, not evidence that the project already supports narrow CAS.


## Isolated candidate checkpoint

A source-only mirror at `build/cas-candidate/` passed eight narrow-CAS unit tests
and one real synthetic-dispatch/yield/vector test on each compiler. Its source
is separate from the dev tree frozen for SIMD validation. A negative control
removing the narrow CAS dispatcher expectation produced BAD_CALLBACK13 exactly;
restoring it passed. Wide-CAS/atomic regressions, native order stress, original
progress and a fresh full milestone remain mandatory before narrow-CAS delivery.
