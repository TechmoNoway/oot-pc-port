# Widening multiply/add/subtract

The ordinary and PAC C emitters implement SMADDL, SMSUBL, UMADDL and UMSUBL, including SMULL, UMULL, SMNEGL and UMNEGL aliases. Each instruction reads two W operands, combines their full product with an X accumulator and writes an X destination. The result wraps modulo 2^64. NZCV, SP and memory remain unchanged.

## Exact encoding and arithmetic

The decoder requires `(word & 0xff600000) == 0x9b200000`: sf=1, op54=00 and the fixed long-multiply opcode bits. Bit 23 selects signed/unsigned operands and bit 15 selects addition/subtraction. Rd, Rn, Rm and Ra have separate five-bit fields. The accumulator is 64-bit even when it aliases a W source. Ra=31 produces the multiply/negate aliases; every register-31 operand is ZR and destination 31 discards the result. These instructions never select SP.

The emitter reads both multiplicands at width 32, applies sign extension for signed forms, and captures the full 64-bit accumulator before writing the destination. Every intermediate is `uint64_t`; modular unsigned multiplication of sign-extended sources produces the required signed product bits without signed C overflow or implementation-defined narrowing. Unsigned sources are zero-extended. Upper X source bits do not participate, while the accumulator's upper bits do. All source/destination aliases use their pre-instruction values. Each instruction advances PC by four and retires once; a zero budget retires nothing.

`multiply_long` is an explicitly admitted verifier value form. Existing destination restrictions remain in force: ordinary leaves preserve X18-X30/SP, and framed functions can modify callee-save destinations only in their declared saved phase. No memory capability, control-flow edge, indirect target, PAC behavior, ABI or descriptor layout changes. SMULH/UMULH and vector widening multiplication remain unsupported and are not decoded as these forms.

## Synthetic native evidence

```powershell
.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler gcc
.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_multiply_long.py -v
```

MSVC and GCC pass the combined suite of **146,219 native/reference comparisons across 38 programs** with pinned Unicorn 2.1.4. This includes **20,480 new individual multiply cases**, independent Python integer results, all 16 canonical input NZCV states, every register field, source/destination aliases, ZR with a distinct nonzero SP, signed minima/maxima, full unsigned products, accumulator wrapping, high-X-bit invariance and fixed-bit rejection. Existing ordinary MADD/MSUB semantics and unsupported high-multiply rejection remain checked.

Ten complete artificial leaves now include signed and unsigned chains using multiply, accumulate, subtract and negate aliases. The two new leaves add 352 complete mathematical result checks and every budget prefix. The full suite has 1,472 whole-leaf mathematical trials, 23,552 independently expected register-result trials including the existing ordered-load cases, and 70,048 independently expected flag trials. Reference comparisons also check every integer register, SP, PC, retirement and exit status.

Actual schema-8 factories execute mixed LR-pair/FP frames, both PAC keys and return styles, a protected X19 destination after its save, a relocation-backed four-instruction PLT bridge and an ordinary verified leaf. Each compiler passes **256 whole-call cases and 7,168 individual instruction prefixes**. Comparisons include all 4,096 stack bytes, signed frame records, every register, restored X19, unchanged NZCV, zero-budget pauses at each prefix and independent final arithmetic results. The image remains retained after the caller releases its handle. All inputs, callbacks and keys executed here are synthetic.

Generated C, native libraries and detailed reports stay under ignored `build/lifter-validation/`. Game bytes are inspected only by the [static profile survey](function-profile-survey.md) and [callee audit](callee-audit.md); no game callback is generated, registered or executed.

## Architecture references

Arm-authored encoding diagrams and instruction operation definitions: [SMADDL](https://www.scs.stanford.edu/~zyedidia/arm64/smaddl.html), [SMSUBL](https://www.scs.stanford.edu/~zyedidia/arm64/smsubl.html), [UMADDL](https://www.scs.stanford.edu/~zyedidia/arm64/umaddl.html) and [UMSUBL](https://www.scs.stanford.edu/~zyedidia/arm64/umsubl.html), 2026-03 release hosted mirror. See also the [official Arm A64 reference](https://developer.arm.com/documentation/ddi0602/latest). The project implementation is independent; no recompilation-project code is imported.
