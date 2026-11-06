# Integer dependency-frontier milestone

This combined milestone implements EXTR/immediate ROR and every scalar CRC32/CRC32C data-size variant, integrates them with existing value-form policies and adds the [complete milestone workflow](development-workflow.md). State/descriptor ABIs, PAC/PLT ownership, register protections and memory permissions remain unchanged. Game functions remain static candidates.

## Extraction and rotation

EXTR checks `(word & 0x7fa00000) == 0x13800000`, N=sf and an immediate smaller than the selected W/X width. Rn supplies the high half of the concatenation and Rm the low half. The helper extracts the requested register-sized slice; an immediate of zero returns Rm and avoids shifting by 64. Equal source registers provide the immediate ROR alias. W sources are masked and W destinations clear the upper X half. Register 31 is ZR, and destination 31 discards the result. NZCV, SP and memory are preserved.

## CRC32 and CRC32C

The CRC decoder checks `(word & 0x7fe0e000) == 0x1ac04000`. The polynomial selector and size fields admit CRC32B/H/W/X and CRC32CB/CH/CW/CX. The sf bit must be set exactly for the 64-bit data variant. Every variant takes a W seed and writes a W result, including CRC32X/CX; data uses only its declared low 8/16/32/64 bits. All source/destination aliases capture pre-write operands, and ZR remains distinct from SP.

The portable helper processes the reflected bit stream with IEEE polynomial 0xedb88320 or Castagnoli polynomial 0x82f63b78. It applies no implicit initial/final complement. There is no dependency on host CRC instructions. This scalar lifter subset supports FEAT_CRC32; native validation explicitly selects a reference CPU advertising CRC32 and checks its ID field. The PAC-enabled reference also advertises the feature. Other system-feature discovery and guest startup remain separate boundaries.

## Independent and integrated evidence

The synthetic milestone uses arbitrary-precision concatenation/division for EXTR and normal-form polynomial long division with bit reversal for CRC. The latter is independent of the reflected C recurrence. Standard `123456789` checks yield IEEE CRC32 0xcbf43926 and CRC32C 0xe3069283 after explicit complement handling. Tests compare byte chaining with halfword/word/doubleword instructions and check dirty upper seed/data bits.

Cases exercise every valid extraction shift, walking source bits, all CRC polynomials/sizes, all source/destination fields, aliases, ZR, every canonical incoming NZCV value, zero budgets and malformed neighboring encodings. Four new artificial leaves cover W/X rotate round trips and mixed-size CRC chains. Actual schema-8 bundles combine all eight CRC variants, W/X extraction/rotation, saved X19, both PAC keys/return styles, a four-instruction PLT bridge, individual instruction prefixes, zero-budget pauses, complete stack bytes and independent final results. The reusable native call harness retains the image after the caller releases its handle.

Run the entire native/static workflow with the [milestone command](development-workflow.md#one-command-for-a-complete-validation-run). Detailed logs, native libraries, full game surveys and generated summaries stay under ignored `build/`. Compiler and final survey counts are recorded in the generated run summary and [profile survey](function-profile-survey.md). No game callbacks are generated, registered or executed.

The complete `integer-frontier-v1` run passes all stages: 333 Python tests, six CTest groups and 283,401 comparisons across 54 synthetic programs on each compiler. Eighteen artificial leaves contribute 2,660 whole-leaf mathematical checks. The new factories pass 256 whole calls and 8,960 prefixes per compiler. Static discovery reaches 135,571 PAC-enabled regions; ordinary leaf acceptance reaches 40,188 and policy-6/7 acceptance remains 1,688/1,710. The selected integer first-stop cohort falls from 46 to zero, exposing later blockers rather than proving gameplay or universal integer coverage.

## Architecture references

Arm-authored encoding and operation definitions: [EXTR](https://www.scs.stanford.edu/~zyedidia/arm64/extr.html), [CRC32](https://www.scs.stanford.edu/~zyedidia/arm64/crc32.html), [CRC32C](https://www.scs.stanford.edu/~zyedidia/arm64/crc32c.html), 2026-03 hosted release; see the [official A64 reference](https://developer.arm.com/documentation/ddi0602/latest). The implementation and validation code are independent project code.
