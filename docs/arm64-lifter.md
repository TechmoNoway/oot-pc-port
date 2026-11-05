# ARM64 integer/control-flow C lifter

This milestone translates bounded raw ARM64 instruction ranges to C17. Synthetic translations run as native Windows code and are compared with an independent ARM64 reference. The game executable remains a host scaffold; building it does not automatically translate or launch the game.

## Implemented forms

| Encoding family | Semantics |
| --- | --- |
| Move wide | MOVN, MOVZ, MOVK, valid 32/64-bit forms and halfword positions |
| Add/subtract immediate | ADD, ADDS, SUB, SUBS, optional immediate shift, context-dependent SP/XZR |
| Add/subtract shifted register | ADD, ADDS, SUB, SUBS with LSL, LSR, ASR |
| Logical shifted register | AND, BIC, ORR, ORN, EOR, EON, ANDS, BICS with LSL, LSR, ASR, ROR |
| PC-relative addresses | ADR and ADRP with signed displacements |
| Direct control flow | B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ |
| Indirect control flow | BR, BLR, RET with explicit guest PC and link-register updates |
| Hint | Exact NOP encoding |

Aliases such as CMP, CMN, TST, and register MOV inherit their underlying encoding semantics. W-register writes zero the upper X bits. Flag-setting arithmetic computes N/Z/C/V with unsigned operations; logical flag writes clear C/V. Shifts avoid signed C overflow, implementation-defined signed right shifts, and shifts by the operand width. Reserved encodings and unsupported forms fail before source emission.

Memory instructions, extended-register arithmetic, logical immediates, carry arithmetic, bitfields, division, system registers, SVC, pointer authentication, atomics/exclusives, SIMD/FP, and setjmp/longjmp services are not implemented. Recognizing a BR/BLR encoding does not discover its possible destinations or supply a callable native target.

## State and execution boundary

`src/arm64_lift.h` defines `OotArm64State` with X0-X30, SP, PC, and architectural NZCV bits 31:28. Callers supply a valid state pointer, a valid executed-count pointer, canonical NZCV, and an instruction budget. The generated function returns:

- `OOT_LIFT_DISPATCH` when PC is outside its translated instruction set, including a misaligned target. It leaves that PC for a future dispatcher to resolve or fault. Reaching the end of a range is not proof of a guest function return.
- `OOT_LIFT_BUDGET` when PC is still translated and the budget has been consumed. A zero budget performs no instruction. The executed count is always returned.

Each translated instruction updates explicit guest state. Branches never cast guest addresses to host function pointers. Calls and returns use this same dispatch loop, so guest recursion does not grow the host C call stack in this subset. There is no guest-memory interface or complete module runtime yet.

## Generate a bounded translation

Use a raw little-endian code range, with an explicit guest base address. The input is not parsed as an NSO container. Up to 64 KiB can be translated per invocation, and every selected word must be supported; the tool does not skip instructions or infer which bytes are code.

```powershell
.\.venv\Scripts\python.exe -B tools/lift_arm64.py build/synthetic-code.raw `
  --base 0x1000000 --offset 0 --size 16 `
  --output build/lifted/synthetic.c --report build/lifted/synthetic.json
```

Choose fresh output paths under `build/`. Include `src/` when compiling the generated source. The report records selected-byte SHA-256, the guest range, and exact form counts. Generated game-derived translations must stay outside Git and are not run by validation.

## Differential validation

Install the pinned analysis and test dependencies inside the project environment:

```powershell
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r tools/requirements-lifter.txt
.\.venv\Scripts\python.exe -B tools/lifter_validation.py
# Additional compiler check, when GCC is on PATH:
.\.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler gcc
```

The default uses CMake and a Release native compiler. Generated C is compiled as a shared test library, with warnings treated as errors, and called through Python's native FFI. Unicorn 2.1.4 executes the independently encoded synthetic ARM64 cases as the reference. It is a development dependency, not the game's runtime. Third-party packages stay in the ignored virtual environment with their own licenses.

The deterministic suite exercises every listed family, both widths, arithmetic and shift boundaries, destination/source aliases, SP/XZR, all B.cond conditions with all 16 flag states, backward branches, loops, BL/BLR/RET, BLR X30, budget exhaustion, dispatcher exits, and addresses above 4 GiB. It compares all integer registers, SP, PC, NZCV, instruction count, and exit status. Reports, generated source, compiler logs, and libraries remain under `build/lifter-validation/`. The report records compiler and reference versions. Passing these cases supplies evidence for the tested subset, not proof for every input or a playable port.

The initial milestone passed 18,914 comparisons across eight synthetic programs with both MSVC and GCC. A static census of the locally prepared 1.1.1 inputs classified 9,021,974 of 16,956,388 discovered instruction words as supported encodings. That count does not measure complete translated functions or gameplay progress; it excludes undiscovered code and does not resolve runtime services or memory accesses.

The full Python suite includes native differential validation when its dependency is installed. Windows CI installs it and runs it through CTest. A direct invocation is:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

To measure supported encodings among statically discovered game instructions without executing them:

```powershell
.\.venv\Scripts\python.exe -B tools/analyze_arm64.py build/prepared/oot111 `
  --report build/arm64-lifter-coverage.json --lifter-coverage
```

The next milestone is checked guest-memory access and scalar load/store translation, with differential comparisons extended to memory contents and fault behavior.

References: [Arm A64 instruction set](https://developer.arm.com/documentation/ddi0602/latest), [Unicorn programming API](https://www.unicorn-engine.org/docs/tutorial.html), and [pinned Unicorn package](https://pypi.org/project/unicorn/2.1.4/).
