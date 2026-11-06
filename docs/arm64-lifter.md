# ARM64 C lifter

This milestone translates bounded raw ARM64 instruction ranges to C17. Synthetic translations run as native Windows code and are compared with an independent ARM64 reference. The game executable remains a host scaffold; building it does not automatically translate or launch the game.

## Implemented forms

| Encoding family | Semantics |
| --- | --- |
| Move wide | MOVN, MOVZ, MOVK, valid 32/64-bit forms and halfword positions |
| Add/subtract immediate | ADD, ADDS, SUB, SUBS, optional immediate shift, context-dependent SP/XZR |
| Add/subtract shifted register | ADD, ADDS, SUB, SUBS with LSL, LSR, ASR |
| Logical shifted register | AND, BIC, ORR, ORN, EOR, EON, ANDS, BICS with LSL, LSR, ASR, ROR |
| Logical immediate | AND, ORR, EOR, ANDS with independently decoded repeating bit masks |
| Bitfields | SBFM, BFM, UBFM, including immediate shift, extract, insert, and extension aliases |
| Extended arithmetic | ADD/ADDS/SUB/SUBS with unsigned/signed byte, halfword, word, X extensions and shifts 0-4 |
| Carry arithmetic | ADC, ADCS, SBC, SBCS |
| Conditional select | CSEL, CSINC, CSINV, CSNEG and their aliases, all condition codes |
| Conditional compare | CCMP/CCMN register and unsigned imm5, W/X widths, all conditions and fallback NZCV |
| Variable shift | LSLV, LSRV, ASRV, RORV with masked shift counts |
| Multiply/divide | MADD, MSUB, MUL, MNEG, UDIV, SDIV in W/X widths |
| PC-relative addresses | ADR and ADRP with signed displacements |
| Direct control flow | B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ |
| Indirect control flow | BR, BLR, RET with explicit guest PC and link-register updates |
| Hint | Exact NOP encoding |
| Scalar memory | LDR/STR byte, halfword, word, doubleword; LDRSB/LDRSH to W/X; LDRSW to X |
| Memory addressing | Unsigned scaled immediate; signed unscaled (LDUR/STUR variants); pre/post-index; UXTW/LSL/SXTW/SXTX register offset |
| Literal memory | PC-relative LDR W/X and LDRSW |
| Paired memory | LDP/STP W/X and LDPSW X, with signed offset and pre/post-index modes |
| RCpc acquire memory | Exact no-offset LDAPRB, LDAPRH, LDAPR W/X; aligned Normal-memory subset through a serialized backend |

Aliases such as CMP, CMN, TST, and register MOV inherit their underlying encoding semantics. W-register writes zero the upper X bits. Flag-setting arithmetic computes N/Z/C/V with unsigned operations; logical flag writes clear C/V. Shifts avoid signed C overflow, implementation-defined signed right shifts, and shifts by the operand width. Reserved encodings and unsupported forms fail before source emission.

EXTR, bit-reversal/counting forms, long/high multiply, non-temporal/tagged pairs, unprivileged transfers, prefetch, other ordered memory forms, system registers, SVC, pointer authentication, atomics/exclusives, SIMD/FP, and setjmp/longjmp services are not implemented. Constrained-unpredictable base/transfer overlap with writeback and identical pair-load destinations are rejected. Repeated pair-store sources are allowed. Recognizing a BR/BLR encoding does not discover its possible destinations or supply a callable native target.

The [RCpc ordered-load model](ordered-loads.md) specifies alignment, shared-backing ownership, the conservative ordering contract, and separate value/fault/concurrency validation. It does not broaden existing function-verifier memory policies.

These limits describe the ordinary lifter/registry ABI. A separate opt-in [pointer authentication model](pointer-authentication.md) implements six exact PAC/AUT/authenticated-return encodings with an extra context argument and a restricted address configuration. It cannot be registered as an ordinary lifted callback; existing profile acceptance and coverage counts are unchanged.

Division by zero returns zero. Signed division uses unsigned magnitudes, including the minimum-integer divided by -1 case, and never invokes undefined signed host division. Multiply/add and negate operations use unsigned wrapping arithmetic. Logical immediate destinations handle SP separately from source ZR; flag-setting forms discard destination 31 as ZR. Bitfield masks and sign-fill are decoded independently of mnemonic aliases. Reserved encodings remain hard translation failures.

## State and execution boundary

`src/arm64_lift.h` defines `OotArm64State` with X0-X30, SP, PC, and architectural NZCV bits 31:28. ABI version 2 adds an explicit `OotGuestMemory *` argument. Callers supply a valid state pointer, a valid executed-count pointer, canonical NZCV, and an instruction budget. Memory instructions need an initialized [guest-memory](guest-memory.md) object; a null memory argument is allowed for integer-only execution and faults on an attempted data access. Regenerate and recompile older generated translations after this ABI change.

```c
int oot_lift_run(OotArm64State *state, OotGuestMemory *memory,
                 uint64_t budget, uint64_t *executed);
```

The generated function returns:

- `OOT_LIFT_DISPATCH` when PC is outside its translated instruction set, including a misaligned target. It leaves that PC for a future dispatcher to resolve or fault. Reaching the end of a range is not proof of a guest function return.
- `OOT_LIFT_BUDGET` when PC is still translated and the budget has been consumed. A zero budget performs no instruction. The executed count is always returned.
- `OOT_LIFT_MEMORY_FAULT` when a data access fails. PC and architectural state remain at the faulting instruction, its writeback is skipped, and it is excluded from the retired instruction count. Previously retired instructions remain effective. Whole-pair preflight preserves both outputs/elements on a rejected pair. The backend records access details when a memory object is supplied.

Each translated instruction updates explicit guest state. Branches never cast guest addresses to host function pointers. Calls and returns use this same dispatch loop, so guest recursion does not grow the host C call stack in this subset. Scalar data transfers use checked regions with explicit permissions. There is no complete module runtime yet.

## Generate a bounded translation

Use a raw little-endian code range, with an explicit guest base address. The input is not parsed as an NSO container. Up to 64 KiB can be translated per invocation, and every selected word must be supported; the tool does not skip instructions or infer which bytes are code.

```powershell
.\.venv\Scripts\python.exe -B tools/lift_arm64.py build/synthetic-code.raw `
  --base 0x1000000 --offset 0 --size 16 `
  --output build/lifted/synthetic.c --report build/lifted/synthetic.json
```

Choose fresh output paths under `build/`. Include `src/` and link `src/guest_memory.c` (or the CMake `oot-guest-memory` static library) when compiling the generated source. Report schema 2 records ABI version, selected-byte SHA-256, the guest range, exact form counts, and whether memory instructions occur. Generated game-derived translations must stay outside Git and are not run by validation.

## Differential validation

Install the pinned analysis and test dependencies inside the project environment:

```powershell
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r tools/requirements-lifter.txt
.\.venv\Scripts\python.exe -B tools/lifter_validation.py
# Additional compiler check, when GCC is on PATH:
.\.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler gcc
```

The default uses CMake and a Release native compiler. Generated C is compiled as a shared test library, with warnings treated as errors, and called through Python's native FFI. Unicorn 2.1.4 executes the independently encoded synthetic ARM64 cases as the reference. It is a development dependency, not the game's runtime. Third-party packages stay in the ignored virtual environment with their own licenses.

The deterministic suite exercises every listed family, both widths, arithmetic and shift boundaries, destination/source aliases, SP/XZR, all B.cond conditions with all 16 flag states, backward branches, loops, BL/BLR/RET, BLR X30, budget exhaustion, dispatcher exits, and addresses above 4 GiB. Memory cases cover all scalar widths, signed loads, addressing/extension modes, unaligned and cross-region accesses, base/index/destination aliases, stack-like save/restore, selected faults, and successful address arithmetic wrapping to a mapped low address. It compares all integer registers, SP, PC, NZCV, retired count, exit status, mapped data bytes, and aligned missing/protected-page fault details. Additional backend-policy checks cover fault retry, stale-fault clearing, null memory, and rejected transfers across the address-space limit. Reports, generated source, compiler logs, and libraries remain under `build/lifter-validation/`. Passing these cases supplies evidence for the tested subset, not proof for every input or a playable port.

The initial integer/control-flow milestone passed 18,914 comparisons across eight synthetic programs with both MSVC and GCC. The memory milestone extends those same cases with scalar transfer and fault comparisons; the current report records counts and compiler/reference versions. A supported-encoding census does not measure complete translated functions or gameplay progress; it excludes undiscovered code and does not establish runtime services or valid memory mappings.

The scalar-memory milestone exercises 24,414 comparisons across 16 synthetic programs, including 5,500 memory cases and 133 reference fault cases. Its local static census classifies 13,088,048 of 16,956,388 discovered instruction words as supported encodings; no game instructions are executed by this census or the validation suite.

The full Python suite includes native differential validation when its dependency is installed. Windows CI installs it and runs it through CTest. A direct invocation is:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

To measure supported encodings among statically discovered game instructions without executing them:

```powershell
.\.venv\Scripts\python.exe -B tools/analyze_arm64.py build/prepared/oot111 `
  --report build/arm64-lifter-coverage.json --lifter-coverage
```

Paired-transfer validation covers W/X widths, LDPSW sign extension, positive/negative offset limits, pre/post-index writeback, SP/ZR, base/destination aliases without writeback, repeated store sources, stack frames, and cross-region accesses. Reference faults cover a missing/protected first element; the reference backend may report either element-width or combined-width callbacks, which are explicitly normalized to the native whole-pair request. Rejected second-element and wrapping-pair behavior is checked separately as a project preflight policy, not hardware partial-access equivalence.

The paired-transfer milestone extends the suite to 26,168 comparisons across 20 synthetic programs, including native stack frames and 163 reference access-fault cases. Both MSVC and GCC also pass the separate native image-bridge tests.

The extended integer milestone passes 72,764 native/reference comparisons across 27 synthetic programs, including six [verified leaf functions](leaf-verification.md) with 768 independent mathematical result checks. The leaf tests also exercise zero/partial budgets. These are entirely artificial programs; game candidates are only analyzed statically.

The [conditional-compare milestone](conditional-compare.md) extends the current combined suite to 123,627 comparisons across 35 programs on MSVC/GCC, with 47,456 independent flag checks and eight complete artificial leaves. Actual schema-8 PAC/PLT factories add 256 whole calls and 6,912 individual instruction prefixes per compiler. Existing memory permissions and ABI layouts are unchanged.

The [native image bridge](runtime-images.md) supplies mapped linked bytes and a guarded synthetic stack. Verified-leaf emission supplies CFG descriptors and exact source-byte hash getters for the [controlled dispatcher](leaf-dispatch.md). [Hash-bound registry preparation](bound-dispatch.md) freezes a matching snapshot and compiled factory and supports a separate linear framed-caller profile. Broader function profiles, remaining instruction forms, and process/runtime services are still required before executing game functions.

References: [Arm A64 instruction set](https://developer.arm.com/documentation/ddi0602/latest), [Unicorn programming API](https://www.unicorn-engine.org/docs/tutorial.html), and [pinned Unicorn package](https://pypi.org/project/unicorn/2.1.4/).
