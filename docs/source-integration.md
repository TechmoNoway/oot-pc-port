# Teammate source integration

On 2026-11-15, local `dev` at `f8a7162` was a direct ancestor of the teammate's
`66a6549`. The verified Git bundle and remote `origin/dev` agreed on that head.
Integration used a fast-forward, preserving all five implementation commits and
their history. The local branch `backup/dev-before-teammate-20261115` retains the
previous head. No fork or parallel source tree is needed.

The integrated work adds the application SIMD cohort, byte/halfword CAS,
application resource identity, Vulkan graphics bootstrap and VI initialization.
The current original-code frontier is `nn::vi::OpenDefaultDisplay`. A hidden
window and presentation-supported Vulkan surface are ready; guest display/layer
objects, a rendered frame and usable game input remain incomplete.

## Transfer verification and storage

The transfer manifest verified 29,025 files, totaling 62,825,085,437 bytes. Its
SHA256 is `b45c0a1799b6d679be10465df4ed40e01f7f86fb4d41b5a23f3f30da0d029420`.
The original game container was independently checked against the transfer's
external-input identity and reused in place. No second game-container copy was
created.

All transferred build evidence was consolidated under ignored `build/`. Exact
immutable duplicates share NTFS hard links; mutable JSON reports remain independent.
Seven conflicting build-tool reports/binaries preserve both versions. Original
source bytes, Git bundle, metadata, manifests and dependency/license snapshots
remain under `build/transfers/teammate-66a6549/`. Its `consolidation.json` maps every
original member to its preserved destination and SHA256. All 8,361 resulting
physical content groups were verified before deleting the duplicate sibling
package. Deletion recovered 57,394,421,760 bytes (53.45 GiB); it did not delete the
original game container, prepared inputs or historical validation evidence.

The tracked source tree is about 4 MiB. Private game inputs and build/evidence
artifacts account for the large workspace size; those are excluded from Git.

After local validation passed, 2,561 new sealed artifacts were shared with their
byte-identical preserved counterparts, reusing 6,891,092,510 bytes. Another 2,898
disposable synthetic-test intermediate files (42,051,973 bytes) were removed.
Generated source, tested DLLs, mutable native caches and all JSON reports remain.
The two cleanup passes recovered approximately 64.3 GB in total; the private
`build/integration-20261115/cleanup-dedup.json` records the final pass.

Hard links share file contents: retained immutable artifacts must never be modified
in place. New validation uses fresh output/native-cache directories. Replaced JSON
references are derived copies with their original and derived hashes recorded;
the unmodified historical reports remain preserved.

## Historical validation

The teammate's final `build/milestones/display-initialization-v1/run.json` and
`summary.json` pass all 50 stages: 703 Python tests without skips, seven CTest
groups and 283,401 common native/reference comparisons per compiler. The exact
raw source SHA256 is
`5eada05fe79791bf3da82835ccb7960f5df2942174e23bb621f402ba3735d9ff`.
The archived raw source reproduces that fingerprint. At the fast-forward, all 318
tracked files matched the integrated checkout after Git text normalization; local
raw line endings produce a different fingerprint. Subsequent integration changes
are documentation only. The historical source and result remain intact.

Both original full display replays stop at the guarded `OpenDefaultDisplay` API,
with digest `e330868f9e2bbdff0c7bf2b88258ecac138974fd33c7303b8ca2147d1a98bc21`.
They preserve the historical entry prefix and prove original caller continuation.
This completed result supersedes the earlier quota-checkpoint prose.
The integrated source commit `66a6549` also passes
[GitHub Windows Checks](https://github.com/TechmoNoway/oot-pc-port/actions/runs/43461521078).

## Local revalidation

The healthy local Python 3.14.10 environment and pinned ZBIC checkout were retained;
the teammate's machine-specific virtual environment, environment script and CMake
cache were not activated. Local MSVC 19.44 and GCC 14.2 are distinct from the
historical toolchain. Focused real Vulkan graphics and Win32 surface lifecycle
checks pass locally.

A fresh complete run uses `build/integration-20261115/display-local.json`, with
output `build/integration-20261115/validation-display-v1/` and log
`build/merge-validation-display.log`. Its frozen current source SHA256 is
`073ce3db08d4fa8115a24b14ebfc14f4b0edd3e8213d48796dac4b6f0ebec0d4`.
The configuration reuses verified local prepared inputs and the local read-only
RomFS index. A separate historical reference view relocates path strings; its
provenance explicitly states that historical passed fields are not new local
validation.

The final local manifest passes all 50 stages with its source gate matching the
working tree: 703 Python tests without skips, seven CTest groups and 283,401 common
comparisons per compiler. Both full display lanes retire 1,833,185 instructions
(51 scaffold), complete three original constructor bodies and all seven stages,
and execute 311,488 post-entry instructions with 52 native calls. Both prove real
window/surface readiness and original caller continuation, with the same full
display digest as the historical run. They stop at guarded OpenDefaultDisplay.

The process ended after 45 recorded stages without a source change or failed
stage. Recovery retained the original command results and entropy, reexecuted
every original post-command gate with fresh diagnostic/full replay directories,
and ran all pending graphics/display commands through the original runner.
`recovery-provenance.json`, `run-before-resume.json` and
`build/merge-validation-resume.log` preserve that distinction. No stage was
manually promoted into success. A post-build checksum pass again verified all
29,025 preserved transfer members across 8,361 physical file groups.

Game content, prepared images, generated game C, executables and detailed private
traces remain ignored. Retain the Vulkan headers' existing license and notices.
