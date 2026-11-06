# Reversal and leading-bit counts

The ordinary and PAC C emitters support scalar RBIT, REV16, REV32, REV, CLZ and CLS through exact one-source encodings. They read one register and write a register result, preserving NZCV, SP and memory. W forms read the low 32 bits and zero the destination's upper X bits. Register 31 is ZR for both operands, never SP; destination 31 discards the result.

## Encoding and effects

The decoder matches exact values of `word & 0x7ffffc00`, leaving only sf/Rn/Rd variable. S, opcode2 and every other fixed bit remain checked. The six admitted opcode values have these meanings:

| Opcode | W form | X form |
| --- | --- | --- |
| 0 | RBIT, reverse 32 bits | RBIT, reverse 64 bits |
| 1 | REV16, reverse bytes within each halfword | REV16, reverse bytes within each halfword |
| 2 | REV, reverse four bytes | REV32, reverse bytes within each word |
| 3 | Reserved and rejected | REV, reverse eight bytes; REV64 pseudo-instruction |
| 4 | CLZ, count leading zero bits | CLZ, count leading zero bits |
| 5 | CLS, count leading sign bits after the top bit | CLS, count leading sign bits after the top bit |

Byte reversal preserves the order of containers. RBIT reverses the entire selected width. CLZ on zero returns 32/64; CLS on zero or all ones returns 31/63. Source/destination aliases use the original source value. Every operation advances PC by four and retires once; zero budgets leave architectural state unchanged.

Portable C helpers use unsigned bit operations and bounded loops. Valid widths and byte containers come from the decoder, and shifts stay below 64. Leading-zero counting handles zero explicitly through its loop rather than an undefined zero-input intrinsic. CLS normalizes the sign, counts its matching prefix and excludes the original top bit. No flags are read or written by these helpers.

The three forms `bit_reverse`, `byte_reverse` and `count_leading` are explicitly added to the existing verifier value set. Ordinary leaves still preserve X18-X30/SP; frames can write callee-save destinations only after their declared saves. State ABI, descriptor layouts, memory permissions, PAC/PLT contracts and call/CFG limits are unchanged. Other one-source opcodes and SIMD operations remain unsupported.

## Native validation

```powershell
.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler gcc
.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_bit_operations.py -v
```

MSVC and GCC pass **174,745 native/reference comparisons across 42 synthetic programs**, with pinned Unicorn 2.1.4. New cases include 23,936 field/alias/budget trials and 2,484 walking-bit/prefix trials. Independent expectations use Python binary strings, byte permutations and integer bit lengths rather than the production C loops. All valid W/X variants, every register field, all 16 canonical NZCV states, ZR with a distinct nonzero SP, W upper-bit masking/clearing, one-hot/complement inputs, every leading-count boundary, container boundaries and reserved neighbors are covered.

Twelve complete artificial leaves now include a trailing-zero calculation using RBIT/CLZ and a mixed W/X normalization chain. Both new leaves have independent final formulas and every budget prefix. The combined suite includes 1,796 whole-leaf mathematical trials, 50,296 independently expected register/state trials and 98,574 independently expected flag trials. All integer registers, SP, PC, retirement and exit status are compared with the reference.

Four actual schema-8 bundles combine W/X bodies, LR-pair and FP/LR frames, both PAC keys/return styles, a saved X19/W19 destination, the original four-instruction PLT bridge and verified ordinary leaves. Each compiler passes **512 whole calls and 15,872 individual instruction prefixes**, including zero-budget pauses at every prefix, all 4,096 stack bytes, full X19 restoration after W writes, unchanged NZCV and independent final results. The registry retains its image after the caller releases the image handle. Existing fault, hash/GOT, metadata and ownership suites remain required.

All executed inputs, code and keys are synthetic. Native libraries/reports stay under ignored `build/lifter-validation/`. The [profile survey](function-profile-survey.md) and [callee audit](callee-audit.md) inspect unchanged game bytes without generating, registering or executing game callbacks.

## Architecture references

Arm-authored instruction definitions and encoding diagrams: [RBIT](https://www.scs.stanford.edu/~zyedidia/arm64/rbit_int.html), [REV16](https://www.scs.stanford.edu/~zyedidia/arm64/rev16_int.html), [REV32](https://www.scs.stanford.edu/~zyedidia/arm64/rev32_int.html), [REV](https://www.scs.stanford.edu/~zyedidia/arm64/rev.html), [CLZ](https://www.scs.stanford.edu/~zyedidia/arm64/clz_int.html) and [CLS](https://www.scs.stanford.edu/~zyedidia/arm64/cls_int.html), 2026-03 release hosted mirror. See also the [official Arm A64 reference](https://developer.arm.com/documentation/ddi0602/latest). Implementation code is independent.
