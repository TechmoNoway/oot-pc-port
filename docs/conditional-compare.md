# Conditional comparisons

The ordinary and PAC C emitters support exact CCMP/CCMN register and immediate encodings in W/X widths. These operations update NZCV and advance PC; they do not write a general-purpose register, SP or memory. Translation and native validation use independent project code and artificial inputs.

## Encoding and effects

The decoder requires `(word & 0x3fe00410) == 0x3a400000`. Bit 31 selects W/X, bit 30 selects CCMN/CCMP, and bit 11 selects register/unsigned five-bit immediate. The fixed S/o2/o3 bits remain checked. Conditions and fallback flags have separate four-bit fields. The internal instruction uses `rd=31` to represent a discarded destination; the low fallback nibble must never be interpreted as Rd.

The condition reads the incoming NZCV before any update. On a true condition, CCMP computes subtraction flags and CCMN computes addition flags, discarding the arithmetic result. Incoming C can affect the condition but is not an arithmetic carry input. On a false condition, all four flags are replaced by the encoded fallback nibble in bits 31:28. The lower 28 bits remain zero. AL and NV both select the arithmetic path under A64 `ConditionHolds`.

Register 31 is ZR for both sources. W comparisons ignore the upper X bits and leave those original bits intact, because there is no register write. Immediates are zero-extended values 0-31. A zero budget leaves architectural state unchanged, and a retired comparison counts as one instruction. Following comparisons, conditional selects and branches observe the resulting flags.

The two forms are explicitly admitted to the verifier's register/flag value set. Existing leaf and frame policies already permit flag changes, so this adds supported encodings without changing their register, memory, CFG, call, PAC or PLT contracts. ABI versions, descriptor layouts and policy/schema versions remain unchanged. Protected registers may be comparison sources; their values remain protected. Static acceptance can increase because discovery now traverses previously unsupported words.

## Native validation

```powershell
.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools/lifter_validation.py --compiler gcc
.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_conditional_compare.py -v
```

Both MSVC and GCC pass **123,627 native/reference comparisons across 35 synthetic programs**. The combined suite includes **47,456 independently expected flag checks**. The reference is pinned Unicorn 2.1.4, while the flag oracle uses a separate truth table and unbounded signed/unsigned integer mathematics rather than the production C formulas or decoder.

Conditional cases cover every combination of 16 incoming NZCV states, 16 conditions, 16 fallback values, both widths, both operations and both operand forms. Directed operands exercise every source register and immediate value, aliases, protected-register reads, ZR with a distinct nonzero SP, W upper bits, zero/carry/sign/overflow boundaries, and fixed-bit rejection. Zero budgets and whole-function instruction prefixes are checked. Eight complete verified artificial leaves now include a conditional range selection and a comparison chain with a V-consuming diamond; their final results have independent formulas.

Actual schema-8 factories exercise LR-pair and FP/LR frames, both PAC keys and return styles, all four comparison variants, PLT/GOT transfer, and flag consumers across calls. Each compiler passes **256 whole-call cases and 6,912 individual instruction prefixes**, comparing X0-X30, SP, PC, NZCV, retirement and all 4,096 stack bytes with enabled QARMA5 reference execution. Zero-budget checks run at every prefix, and final values/flags have independent expectations. The dispatcher retains the image after the caller releases its handle. Existing malformed-metadata, callback, GOT/hash, memory and ownership suites remain required.

Only synthetic callbacks are compiled, registered and executed. Full reports and generated native libraries stay under ignored `build/lifter-validation/`. Static game measurements are documented in the [profile survey](function-profile-survey.md).

## References

Arm-authored A64 instruction descriptions, encoding diagrams and operation pseudocode: [CCMP register](https://www.scs.stanford.edu/~zyedidia/arm64/ccmp_reg.html), [CCMP immediate](https://www.scs.stanford.edu/~zyedidia/arm64/ccmp_imm.html), [CCMN register](https://www.scs.stanford.edu/~zyedidia/arm64/ccmn_reg.html), [CCMN immediate](https://www.scs.stanford.edu/~zyedidia/arm64/ccmn_imm.html) (2026-03 release, hosted mirror). The [official Arm A64 reference](https://developer.arm.com/documentation/ddi0602/latest) supplies the architecture context. No implementation code is imported from a recompilation project.
