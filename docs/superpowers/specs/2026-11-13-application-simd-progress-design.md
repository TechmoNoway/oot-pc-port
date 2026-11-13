# Application SIMD progress: design and research

Date: 2026-11-13. Status: approved intermediate design; implementation and matching source-bound pilots complete, fresh full validation passed (42 stages, 641 Python tests, seven CTest groups). Research observations below retain their original scope.

## Decision

Deliver one independent capability milestone: complete the measured **application register-only SIMD cohort**, preserve the existing checked runtime, verify actual progress past the current application frontier, and commit/push the verified result to `dev`.

The user explicitly chose independent implementation on 2026-11-13. Hookshot and Fritchii are architecture and behavior references. Do not vendor their translator, runtime, shader sources, patches, or tests. Preserve the project's existing third-party dependency notices.

This is a plan for a coherent intermediate capability, not a commitment to graphics, gameplay, or a release date. Later milestones need their own measured input and design.

## Current owning evidence

- Checkout: `G:\Zelda\oot-pc-port`, branch `dev`, HEAD `f8a7162` (`f8a7162` is the baseline, not this proposal's implementation).
- The checkout was clean before these planning documents were created.
- Existing source: `src/startup_vector.c`, `src/startup_float.c`, `tools/sdk_init_instructions.py`, `tools/prepare_startup.py`, `tools/run_milestone.py`.
- Existing private final evidence: `build/milestones/application-content-v1/run.json`, with its application compiler reports and iteration manifests. These are historical evidence, not a fresh test pass on this machine.
- That evidence reports initialization complete, 3 constructor bodies, 7 stages, 308,487 post-entry original instructions, and four real files read/closed (3,427 bytes). It stops before scalar-SIMD `UCVTF S8, S0` (`0x7e21d808`).
- The normalized prepared `main` has build ID beginning `e0f3ccfa`, matching Hookshot's declared build-ID prefix. This comparison uses the existing prepared manifest; it does not replace revalidation against the current NUP.

### Environment findings that must precede implementation validation

The checkout and its private evidence were moved from another directory/machine configuration:

1. `.venv/pyvenv.cfg` references `C:\Program Files\Python314\python.exe`, which does not exist. Invoking that venv failed.
2. The working global Python found here is 3.13.1. It has no Capstone or Unicorn. `tools/prepare_romfs.py:copy_payload` specifically requires Python 3.14 `compression.zstd` for compressed RomFS records.
3. `build/cmake/CMakeCache.txt` still points at the former `C:\GAMES\...` source/build directories.
4. The former prepared ExeFS/RomFS manifests refer to a NUP at that old directory; the path does not exist. The current NUP is in `G:\Zelda`.
5. GCC at the former `C:\msys64\ucrt64\bin\gcc.exe` is absent, and GCC/CMake/CL are not on the observed PATH. Visual Studio 18 Community exists, but the query for the C++ workload returned no installation. Existing startup code explicitly chooses `Visual Studio 17 2022`.
6. Seed reports contain absolute `iterations[-1].bundle` paths. The runner opens those paths for provenance, so copying a config without rebinding seed paths will fail.

Use fresh environment/build/preparation directories. Never edit historical report results, seals, source fingerprints, or the old prepared manifests to make validation pass. Install/discover real required tools before claiming a native lane works. Do not redesign compiler discovery as part of this milestone; provision VS 2022 C++ Build Tools, matching the current builder.

**Recovery completed later on 2026-11-13:** Task0 has now provisioned the required tools, prepared current-path inputs and reproduced the unchanged application baseline on MSVC/GCC with matching trace hashes. See [the environment recovery record](../plans/2026-11-13-build-environment-ready.md). The numbered findings above describe the original migration failure, not the active environment after recovery. No product-code changes were made.

## Research and limits

### Fritchii

Snapshot: `Frizti/Fritchii`, branch `nx2`, commit `f66ea633db6058efe31a9611718019e5bd1667eb`, at `G:\Zelda\references\Fritchii`.

It is an emulator with Dynarmic CPU translation, HLE services, NUP/ZBIC loading, and Ampere shader lowering integrated into a GPU backend. Relevant owning files:

- `src/dynarmic/src/dynarmic/frontend/A64/decoder/a64.inc`: fixed encoding bits.
- `src/dynarmic/src/dynarmic/frontend/A64/translate/impl/simd_scalar_two_register_misc.cpp`: SIMD-source integer conversion and FPCR rounding semantics.
- `src/dynarmic/src/dynarmic/frontend/A64/translate/impl/simd_copy.cpp`: scalar element extraction and element insertion.
- `src/dynarmic/src/dynarmic/frontend/A64/translate/impl/simd_three_same.cpp`: ORR, CMEQ, BIF.
- `src/core/loader/nup.cpp`, `src/common/zbic_compression.cpp`.
- `src/shader_recompiler/frontend/ampere/lower_to_maxwell.h` and `src/video_core/shader_environment.cpp`.

Its OOT-related commit `c9ebb5c3af672a0472ca0811392f04fab10203ab` discusses `WaitIfEqual64` and shader fixes. Some services are explicitly placeholders; that is not evidence of recovered Switch 2 semantics for this project.

### Hookshot

Snapshot: `t0masz407/Hookshot`, branch `main`, commit `460b65424acf86be4c933858744e2932226f3f91`, at `G:\Zelda\references\Hookshot`.

Relevant owning files:

- `nx2/lift.py`, `nx2/image.py`: discovery, C generation, offline-linked image.
- `nx2/standalone.py`, `host/hos_main.c`: native SDK interception and boot.
- `nx2/chunks.py`, `nx2/build.py`: stable chunks and content-dependent object reuse. Our project already has its own split/incremental path; do not implement that feature again.
- `host/hos_setjmp.c`: host continuation handling beyond restoring guest registers.
- `host/nvn_native.c`, `gpu/vk/vk_shader.cpp`: NVN2 boundary and shader translation.
- `third_party/a64-kit/lift/suyu/arm64_to_c.h`: separate SIMD-source conversion handling.

The README reports Kokiri gameplay, audio, controls and saves, with limited testing. Neither reference project was built or run in this research. Hookshot's generic import stubs return zero, its missing NVN initializers can return success, and some PAC forms use an identity model. None of these policies may enter this project implicitly.

Both repositories declare GPL licensing for substantial parts. The decision for this milestone is to import **no implementation code**; this avoids changing the project's existing implementation model, not a legal conclusion about independently written code.

### Static cohort measurement

A read-only research script checked the existing normalized `main` file's SHA-256 against the historical bundle, then disassembled the frontier neighborhood. The instructions following the blocked conversion in that local function are already represented by existing scalar/GPR helpers; this does not predict the whole later runtime path.

The historical application manifest contains 266 boundary records. Twenty records fit this coherent register-only cohort:

| Family | Historical records | Meaning |
|---|---:|---|
| Scalar SIMD SCVTF/UCVTF, integer source | 4 | Observed unsigned S/S and D/D forms; support their signed siblings too |
| Vector ORR, including MOV alias | 10 | Register copies in the observed records |
| Scalar DUP element, including MOV alias | 1 | Copy one vector lane into a scalar destination |
| INS element-to-element, including MOV alias | 1 | Replace one destination lane |
| Vector CMEQ, register comparison | 3 | Per-element integer equality mask |
| Vector BIF | 1 | Insert source bits where the mask is false |

These are boundary records, not unique functions or executed sites. Some other historical boundary records already decode under current source (for example GPR-source conversions). The implementation must recompute current decoder acceptance; never treat old `semantic_error` text as current truth. No future acceptance count or graphics progress is promised.

## Alternatives considered

| Approach | Benefit | Cost / reason |
|---|---|---|
| Measured register-only SIMD cohort, retaining current checked runtime **(selected)** | Reuses exact conversion helper; small explicit state surface; testable on both compilers; addresses known game bytes | Does not implement later SDK/thread/GPU dependencies |
| Replace the translator/dispatcher architecture independently, following Hookshot's broad function model | Potentially wider execution coverage later | Large control-flow, PAC, continuation and provenance redesign; unsuitable for a low-effort implementation handoff |
| Start an independent NVN2/Vulkan renderer immediately | Directly targets visible output | No verified reached graphics boundary yet; much larger API, shader and synchronization work; would not remove the current CPU stop |

## Semantic contract

New support is **application-only**, using the existing flags-62 context and original initialization goal. Existing INIT, SDK, raw, leaf and stack profiles retain their decoding and permission domains. Integer ABI2, PAC model, native registry and vector-state layout remain unchanged.

All new operations read from the original vector bank and prepare a private candidate. Successful execution advances PC by four, changes only the declared vector destination and permitted FPSR flags, emits no memory store, and preserves all GPRs, SP and NZCV. Q31 is an ordinary vector register; it is never XZR. Existing ownership, FPCR/FPSR validation and no-partial-output rules remain in force.

| Family | Mask / fixed value | Supported variants and effect |
|---|---|---|
| SIMD integer -> float | `0xdfbffc00 / 0x5e21d800` | U=bit29, width=bit22 ? 64 : 32. Read low S/D integer bits; call existing `oot_startup_float_from_integer` with equal widths and U; zero the entire destination, write low result, OR Inexact into FPSR |
| ORR vector | `0xbfe0fc00 / 0x0ea01c00` | Q=0/1: 8/16 bytes. Bytewise OR of original Rn/Rm; zero upper 64 bits for Q=0. MOV is the Rn==Rm alias |
| DUP scalar element | `0xffe0fc00 / 0x5e000400` | `imm5=(word>>16)&31`; nonzero, lowest set bit gives log2(element bytes), at most 3. Index=`imm5>>(size+1)`. Copy that lane; zero all other destination bytes |
| INS element | `0xffe08400 / 0x6e000400` | Same imm5 size/destination index. Source index=`((word>>11)&15)>>size`. Replace only that lane; preserve all other destination bytes. Lower source-immediate bits are ignored, not rejected or normalized |
| CMEQ vector register | `0xbf20fc00 / 0x2e208c00` | Element bytes=`1<<((word>>22)&3)`; vector bytes=Q ? 16 : 8; reject size=3,Q=0. Each equal lane becomes all ones, otherwise zero; clear upper 64 bits for Q=0 |
| BIF vector | `0xbfe0fc00 / 0x2ee01c00` | For 8/16 bytes, result=`(old_Rd & Rm) | (Rn & ~Rm)`, using original operands. Clear upper 64 bits for Q=0 |

All scalar conversions keep the current nearest/ties-even, FPCR zero/FZ admission. Do not broaden rounding modes, FP16 arithmetic/conversion, fixed-point, vector conversion, scalar CMEQ, BIT/BSL, or SIMD memory support. Raw H-lane copies are bit operations, not FP16 arithmetic. Existing integer conversion helpers remain unchanged unless an independently reproduced bug is found and separately reviewed.

Application classifier result IDs 1 and 2 keep their current meaning. Allocate IDs 3..8 to the table order above; Python decoder operations 23/24 stay unchanged, with 25..30 added in that same order. Existing `sdk_init_vector` dispatch handles them; do not add a second execution engine.

## Progress evidence and terminal boundaries

The milestone succeeds only with complete synthetic verification **and actual source-bound progress** past the previous frontier. A full-trace replay of the final executable must contain a successful original STEP at the prior frontier with its original word and fallthrough, not just a larger counter. Both compilers and fast/single-step modes must agree on existing trace/state comparisons. Existing initialization, provider and RomFS effects remain required.

The final out-of-cohort stop can be one of three explicit diagnostics:

1. An exact unsupported original instruction, using the existing `application_expected_word` contract.
2. An exact guarded native export, using the existing `application_expected_guard` contract.
3. An exact unsupported original SVC, using a new mutually exclusive `application_expected_svc` integer and source-bound selected-SVC record. This adds evidence handling, not a service implementation or invented result.

Selection exhaustion, unselected targets, resource limits, missing assets/tools, provenance/hash faults, bad callbacks, memory/contract faults, and budget exhaustion are not successful terminal frontiers. Do not expand bounds or add API stubs to obtain a pass.

The final config is frozen from matching pilot evidence before the full run. Do not change expected outcomes while the final runner is executing. Source/config changes require a new run directory and source fingerprint.

## Delivery and subsequent roadmap

The implementation plan is [here](../plans/2026-11-13-application-simd-progress.md). A successful delivery includes focused native/reference checks, fresh unchanged legacy surveys, the complete milestone runner, truthful status documentation, review and a normal push to `dev`. No force push, generated content or game data.

Next design inputs are the **measured final boundary**, not a guessed service list:

1. If execution reaches thread/synchronization APIs, design one coherent native thread/synchronization family with owned lifecycle and consumers. Current main-thread logical setters are not a scheduler.
2. Once a verified NVN2 initialization boundary is reached, design API capture, resource ownership and one frame through an independent renderer. Use the references to identify protocol and shader requirements.
3. Only after a real frame: game loop input/audio, saves, stability and setup packaging. These are separate deliverables.

## External primary references

- [Arm A64 ISA reference](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85), linked by the existing decoder. The web reader could not ingest this large PDF; do not claim it was fully read in this research. Encoding patterns and semantics were additionally checked against the primary implementation files listed above.
- [Microsoft vswhere: find VC](https://github.com/microsoft/vswhere/wiki/Find-VC).
- [MSYS2 environments](https://www.msys2.org/docs/environments/) and [GCC installation](https://www.msys2.org/).

## Design review checklist

- [x] Independent implementation choice recorded.
- [x] Current source and private evidence inspected; historical results distinguished from fresh verification.
- [x] Toolchain, stale paths and seed migration failures identified.
- [x] Six families have explicit masks, semantics, profile boundaries and alias rules.
- [x] Actual runtime progress is separated from static decoder counts and gameplay.
- [x] Later thread/GPU work is bounded by new evidence rather than delegated as open-ended implementation.
- [x] No product code, toolchain installation, new guest execution, commit or push performed during planning.
