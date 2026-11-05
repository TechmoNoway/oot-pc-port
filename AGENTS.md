# Project instructions

This is an independent native Windows x86-64 port project. The current code provides a host scaffold, verified input preparation, offline linking, ARM64 analysis, checked guest memory, paired/scalar integer C lifting, and native data-only image mapping; do not describe it as a working game port.

- Keep code, documentation, and commit messages in English.
- Keep changes focused and verify behavior before reporting success.
- Keep game files, keys, extracted content, generated game code, and compiled output out of Git.
- Put build output under `build/` and generated game output under `generated/`.
- Implement project code independently. Any future imported third-party code must retain its applicable license and notices.
- Run the native host self-test when changing host code.
- Run `python -B -m unittest discover -s tests -v` when changing input inspection. Test fixtures must be synthetic.
- Build the local ZBIC helper before running segment integration tests. Keep its external dependency under ignored `toolchain/`, with its license intact.
- Linking works on private images and must not execute guest code or invent addresses for unresolved strong symbols. Keep linked images and reports under ignored `build/`.
- Install `tools/requirements-analysis.txt` in the project environment for ARM64 integration tests. Decoder success is not semantic lifter support, and unvisited text must not be called proven data.
- Install `tools/requirements-lifter.txt` for native differential validation. Compile generated synthetic C and compare with the independent reference after semantic changes. Keep generated tests, libraries, and reports under `build/`; do not execute game code in these tests.
- Run the CTest guest-memory self-test after memory changes. Preserve the explicit fault/retirement contract; preflight failures must not mutate a scalar or paired access or perform writeback. Document the distinction from hardware partial-store behavior.
- Runtime packages require a complete verified offline link. Map exact segment/BSS ranges and guarded synthetic stacks; preserve BSS relocations. Validate checksums, bounds, and permissions in the native loader. Do not execute game constructors or infer a usable process startup ABI from successful mapping.
- Leaf verification proves only the declared region's conservative control-flow/register policy. Keep its entry/LR/NZCV preconditions explicit, distinguish metadata candidates from original function identity, and use synthetic whole-function tests with independent expected results. Do not execute game candidates as part of validation.
- Leaf dispatch registers trusted compiled symbols and generated CFG metadata, never guest addresses cast to code pointers or serialized native pointers. Enforce exact entry/return, checkpoint ownership, protected-register and per-instruction edge/count checks. Run the native dispatcher self-test and generated synthetic caller/callee comparisons after dispatcher changes. Do not expand the leaf policy implicitly or register game callbacks in validation.
