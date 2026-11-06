# High multiplication

The ordinary and PAC C emitters support UMULH and SMULH: two X sources produce bits 127:64 of their unsigned or signed 128-bit product. The result writes one X register and preserves NZCV, SP and memory. Register 31 is ZR, including discarded destination writes; there is no W variant or accumulator.

## Exact encoding and portable arithmetic

The decoder requires `(word & 0xff608000) == 0x9b400000`, checking sf=1, op54=00, the high-product opcode and o0=0. Bit 23 selects signed/unsigned interpretation. Rd/Rn/Rm are independent five-bit fields. The Ra field is ignored by the architecture operation, including values other than the canonical assembler value 31; it must never supply an addend. All 32 Ra values are explicitly decoded and validated, while the original word remains unchanged and hash-bound. Malformed o0 and W encodings remain rejected; ordinary multiply and widening multiply retain their own semantics.

The shared C17 helper uses four unsigned 32x32 products, avoiding compiler-specific 128-bit types, intrinsics, signed overflow and signed right shifts. With base B=2^32 and a=a0+B*a1, b=b0+B*b1:

```text
middle = high32(a0*b0) + low32(a1*b0) + low32(a0*b1)
unsigned_high = a1*b1 + high32(a1*b0) + high32(a0*b1) + high32(middle)
signed_high = unsigned_high - (a63 ? b : 0) - (b63 ? a : 0)  modulo 2^64
```

The middle sum is less than 3*2^32 and fits in 34 bits; its carry is retained. Every partial product fits in 64 bits. Signed correction uses unsigned modular subtraction, including INT64_MIN and negative products. The helper reads no state or flags, and destination aliases use both original source values before the write. Each instruction advances PC by four and retires once; zero budgets retire nothing.

The new `multiply_high` value form obeys the same destination/save-phase policy as other integer forms. Ordinary leaves preserve X18-X30/SP. A framed X19-X28 destination requires the existing declared save and matching restoration. Memory permissions, call/CFG limits, PAC/PLT ownership, descriptor layouts and state ABI are unchanged. SIMD high/widening multiplication remains outside this scalar subset.

## Synthetic native evidence

```powershell
.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler gcc
.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_high_multiply.py -v
```

MSVC and GCC pass **221,977 native/reference comparisons across 47 synthetic programs**, using pinned Unicorn 2.1.4. New high-product cases include 10,752 field/alias/budget trials, 1,280 ignored-Ra trials, 33,792 walking/random product trials and 1,408 complete-leaf/prefix trials. Expectations use Python arbitrary-precision signed/unsigned multiplication and division by 2^64, independently of the production limb/correction algorithm.

Cases cover all source/destination register fields, all 32 ignored Ra values, all 16 input NZCV states, ZR with a distinct nonzero SP, destination/source aliases, every pair of one-hot bit positions and their complements, 32-bit carry boundaries, full-width high bits, signed extrema and deterministic random products. Two new complete artificial leaves combine high multiplication with ordinary low multiplication and independently check both halves of a full product. The combined suite has 14 verified leaves, 2,148 whole-leaf mathematical checks, 96,472 independently expected register/state trials and 145,806 independently expected flag trials.

Actual schema-8 factories combine signed/unsigned high products, noncanonical ignored fields, a saved X19 destination, LR-pair and FP/LR frames, both PAC keys/return styles and the original four-instruction PLT bridge. Each compiler passes **256 whole calls and 7,168 instruction prefixes**, with independent final results, zero-budget pauses, all integer state, unchanged NZCV, full X19 restoration and all 4,096 stack bytes compared with enabled QARMA5 reference execution. The registry retains its image after the caller releases the image handle. The existing widening-multiply fixture uses the same reusable prefix harness and remains independently exercised.

All executed bytes and keys are synthetic. Detailed reports/libraries stay under ignored `build/lifter-validation/`. [Game profile surveys](function-profile-survey.md) and [callee audits](callee-audit.md) inspect original hash-matched bytes without generating, registering or executing game callbacks.

## Architecture references

Arm-authored instruction definitions and encoding diagrams: [UMULH](https://www.scs.stanford.edu/~zyedidia/arm64/umulh.html) and [SMULH](https://www.scs.stanford.edu/~zyedidia/arm64/smulh.html), 2026-03 release hosted mirror. See also the [official Arm A64 reference](https://developer.arm.com/documentation/ddi0602/latest). The limb implementation and validation code are independent project code.
