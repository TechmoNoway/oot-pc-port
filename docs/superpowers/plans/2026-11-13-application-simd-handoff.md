# Execution handoff: application SIMD progress

Use this prompt after the user approves execution of the associated plan. The planning turn itself did not authorize an automatic product-code implementation or claim a completed push.

```text
Implement the approved plan in:
G:\Zelda\oot-pc-port\docs\superpowers\plans\2026-11-13-application-simd-progress.md

First read AGENTS.md, the complete plan, and its linked design. Use the
executing-plans skill and execute inline. Work on dev. Preserve any existing
changes and inspect source drift from baseline f8a7162 before editing.

The user chose independent implementation. Use the pinned Hookshot/Fritchii
snapshots as references only; do not copy their code or tests.

Deliver all six application-only register SIMD families as one milestone:
SCVTF/UCVTF from SIMD S/D, vector ORR/MOV alias, scalar DUP element/MOV alias,
INS element-to-element, vector CMEQ, and vector BIF. The plan fixes masks,
kind IDs, Python operations, semantics, variants and tests. Reuse the existing
integer-to-float helper. Do not change ABI2, PAC or older profile permissions.

Task0 was completed and independently verified on 2026-11-13. First read:
docs/superpowers/plans/2026-11-13-build-environment-ready.md
Activate build/environment-repair/Enter-ZeldaBuild.ps1, verify the private
ready.json evidence and inspect source drift, then start Task1. Python3.14,
MSVC2022, GCC UCRT64, a fresh .venv-dev, current-path sealed ExeFS/RomFS and
working seed locators already exist. Both fresh original startup runs matched
the historical trace and frontier. Do not repeat installation or use the old
copied .venv/CMake cache. Never edit old seals or passed reports to look current.
Keep all new private outputs under build/.

Finish dependent tasks without stopping after individual opcodes. Validate
literal decodes, independent byte/rational expected results, full-state pinned
Unicorn comparisons on MSVC/GCC, actual synthetic dispatcher yields and old
profile rejection. Implement the plan's source-bound progress evidence and
exact optional SVC diagnostic contract; do not implement guessed services.

Run bounded original-code pilots only after the synthetic checks. Require the
old blocked original instruction to retire in a verified full trace, not only
a larger counter. Stop capability expansion at the first genuine out-of-cohort
boundary. Freeze exactly that measured word/export/SVC in the new config.

Complete status documentation and review, run the full milestone in a fresh
directory, require every stage passed and the source fingerprint current,
review/stage only source, synthetic tests, config and docs, then commit and
push normally to origin/dev. Verify HEAD equals origin/dev. Never force push.
Do not claim delivery if a tool/input/validation/authentication blocker remains.

Do not broaden to threads, general SIMD, graphics or a launcher. Do not replace
unsupported behavior with empty success, strip PAC, bypass original code,
increase bounds for a pass, weaken equality, skip a native lane, or reuse stale
test evidence. If the plan's exact contract cannot be met, return the concrete
evidence and the narrow design question requiring higher-effort review.

Final response in Vietnamese: implemented scope, actual runtime endpoint,
verification and limitations, commit and push status. The milestone does not
promise a playable game or a first rendered frame.
```

## Read order

Tasks1-7 passed their full validation on 2026-11-13 at
`build/milestones/application-simd-v1/`; commit `dec936d` is verified on origin/dev.
Read its actual `run.json`: it certifies that implementation checkpoint, while
the later narrow-CAS work requires its own fresh full run.
The v3 pilots and native-verified full replays match on both compilers, proving
original progress to CASAB at 311,527 post-entry instructions. All 24 original
SDK jump-table selection hints remain private, and all original branches run.
Source has changed since Task0's `ready.json`; that report is historical only.
The user requested continuation until real game output/input works. The
measured byte/halfword atomic cohort now follows its
[own plan](2026-11-13-application-narrow-cas.md). Do not silently add CASAB to
the historical SIMD validation.

1. `AGENTS.md` and [verified environment recovery](2026-11-13-build-environment-ready.md).
2. [Design and research](../specs/2026-11-13-application-simd-progress-design.md).
3. [Implementation plan](2026-11-13-application-simd-progress.md), including the final acceptance matrix.

The design records the exact reference commits and owning files, historical measurements and environment findings. No additional chat-history retrieval is necessary to discover the intended scope.
