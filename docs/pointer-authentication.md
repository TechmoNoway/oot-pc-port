# Pointer authentication model

This is an explicit opt-in semantic milestone for synthetic code. It implements QARMA5 signing/authentication with instruction keys A/B, SP as the modifier, equal 39-bit lower/upper VA ranges, and no top-byte ignore. The six exact encodings are PACIASP, PACIBSP, AUTIASP, AUTIBSP, RETAA, and RETAB. Both instruction keys are always enabled in this model. The independent C implementation uses nibble permutations, substitution, and a column diffusion matrix; it does not import another emulator's implementation. The algorithm parameters are specified in Arm's [QARMA pseudocode, DDI0553B.y, pages 1944-1945, 2050-2053, 2066, 2084-2085](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf) and the [QARMA specification](https://eprint.iacr.org/2016/444.pdf). The M-profile reference supplies the shared cryptographic algorithm only; it does not define our A64 instruction behavior.

The old integer state ABI remains version 2. The new PAC ABI is version 1 and passes an additional immutable `OotPauth` context. Its generated callback signature is deliberately different from all existing registry callbacks. The ordinary lifter, verifier policies, image packages, registry schemas, and static survey continue to reject these instructions. No game candidate is registered, translated, or executed by this validation.

## Pointer and retirement rules

Signing requires X30 to be a canonical VA39 pointer: bits 63:39 must all be zero or all one. Otherwise the step returns `OOT_PAUTH_REJECTED` without changing state. This includes a second PAC applied directly to an already signed LR. Invalid-extension signing behavior is outside this milestone: the pinned reference and current Arm pseudocode disagree on the corruption bit for that case. Do not expand this domain without resolving that difference.

For canonical signing, QARMA5 takes the extended pointer, the complete 64-bit SP modifier, and the selected 128-bit instruction key. PAC occupies bits 63:56 and 54:39; bit 55 records the address range. Authentication reconstructs the pointer using bit 55 and checks all 24 PAC bits. The architectural layout is described by Arm's [InsertPAC pseudocode](https://support.arm.com/documentation/ddi0487/maa/-Part-J-Architectural-Pseudocode/-Chapter-J1-A-profile-Architecture-Pseudocode/-J1-1-Pseudocode-for-AArch64-operation/-J1-1-364-InsertPAC).

AUT accepts any 64-bit LR. Success replaces it with the canonical pointer. Basic PAuth failure replaces bits 62:61 of that pointer with `01` for key A or `10` for key B. It retires and advances PC; it is not a checked-memory failure. RETAA/RETAB authenticate into a temporary target, leave the signed X30 intact, and retire with PC set to that guest target. The optional synchronous failure extensions FPAC/FPACCOMBINE are excluded. See Arm's [A64 instruction reference, RETAA/RETAB](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85) and [PAC failure exception conditions](https://support.arm.com/documentation/111107/2026-09/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-).

`oot_pauth_step` never fetches PC or turns it into a native pointer. Its nonnegative result retires exactly one instruction: signed, authenticated, or poisoned. Missing context, unknown instruction/model, unaligned instruction PC, or noncanonical signing rejects without retirement or state mutation. The standalone emitter returns existing dispatch/budget/memory statuses, plus `OOT_PAUTH_LIFT_CONFIGURATION` (3). A bad authenticated return therefore dispatches a poisoned **guest** PC; future controlled dispatch must reject an unapproved return target. This emitter is not a verified function dispatcher.

Checked stack accesses retain the existing whole-access preflight contract. PAC can retire before a following frame store fails; that store must leave SP, registers, and backing unchanged. A retry must not apply PAC again. Budgets count the retired PAC/AUT/RET instructions normally, including authentication failures.

## Keys and ownership

`oot_pauth_create(OOT_PAUTH_QARMA5_VA39, NULL)` obtains fresh A/B keys from the Windows system RNG. Explicit keys are copied for deterministic synthetic validation or a future specified guest ABI. No key export or serialization API exists. Destroying a context clears its allocation with `SecureZeroMemory`. Callers own their supplied key buffers and must clear sensitive buffers themselves.

Keep the same live context across a call chain and all yields. It must outlive those calls; do not destroy it concurrently, pass stale/arbitrary pointers, rotate keys with active signed frames, or log live key material. The tests intentionally change contexts to demonstrate resulting authentication failures. A production guest process/thread ownership model, key switching, TLS, initialization, and checkpoint binding remain future work. The functional QARMA implementation has not been audited for constant-time operation or side-channel resistance.

No TBI, unequal VA sizes, data keys, PACGA, XPAC, generic register PAC/AUT, authenticated loads, authenticated indirect calls, disabled-key/HINT behavior, EPAC, PAuth2, PAuth_LR, FPAC, GCS, or BTI enforcement is claimed. Host x86-64 pointer security is independent of this guest semantic model.

## Validation

Run from the repository with the pinned analysis/lifter requirements installed:

```powershell
.venv\Scripts\python.exe -B tools\pauth_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools\pauth_validation.py --compiler gcc
```

The harness uses Unicorn 2.1.4 CPU MAX with basic QARMA5 asserted through ID_AA64ISAR1. It configures SCR_EL3.API, HCR_EL2.API, SCTLR_EL1.EnIA/EnIB, T0SZ/T1SZ=25, TBI0/TBI1=0, and EL0t; MMU stays disabled. It checks the configuration and key-register writes and requires a known signing operation to change LR. PAuth is otherwise disabled by default in this reference; see the official [Unicorn FAQ](https://github.com/unicorn-engine/unicorn/blob/master/docs/FAQ.md).

Each compiler passes 124,928 primitive comparisons across 128 key sets, both canonical ranges, address boundaries, both instruction keys, all PAC/selector bit flips, changed address/SP/key, arbitrary signed values, AUT and authenticated returns. Of these, 118,784 compare failure behavior. Four nested synthetic frame programs exercise A/B keys, combined and split frames, AUT+RET and RETAA/RETAB. They pass 64 complete cases, 1,152 prefix checks, repeated single-instruction resumptions, and 16 corrupted-frame cases. Fifteen rejection checks cover configuration, encoding/domain errors, and memory-fault retirement. A native self-test also pins two public synthetic signed-LR vectors and tests fresh RNG contexts.

Reports, generated C, compiler logs, and DLLs stay under ignored `build/lifter-validation/`. No game bytes or production keys are read. This evidence supports only the stated model and synthetic cases; process startup, complete function verification, image-bound context ownership, and game readiness are not established.

The next milestone is a separate PAC-aware function policy/dispatcher with signed-LR phase tracking, return-target checks, and context ownership across yields. Only after those checks should unchanged private bytes be surveyed again.
