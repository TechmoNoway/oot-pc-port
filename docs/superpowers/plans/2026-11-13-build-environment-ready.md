# Build environment recovery: verified

Date: 2026-11-13. Scope: Task0 of the application SIMD plan. Product source remains at `f8a7162`; no new SIMD capability, gameplay or remote delivery is claimed.

## Start a build session

From PowerShell:

```powershell
Set-Location -LiteralPath 'G:\Zelda\oot-pc-port'
. .\build\environment-repair\Enter-ZeldaBuild.ps1
& $py --version
cmake --version
gcc --version
```

The script selects `.venv-dev`, Visual Studio2022/x64 and GCC using process-local environment variables. It does not change the system PATH. Keep using `$py` or the activated `python`, rather than the old copied `.venv`.

## Installed and verified tools

| Tool | Version | Location |
|---|---|---|
| Python x64 | 3.14.10 | `G:\Zelda\toolchains\Python314\python.exe` |
| Project environment | Python3.14 | `G:\Zelda\oot-pc-port\.venv-dev\Scripts\python.exe` |
| MSVC | 19.44.35230.0 | `G:\Zelda\toolchains\vs2022\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe` |
| CMake | 3.31.6-msvc6 | `G:\Zelda\toolchains\vs2022\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin` |
| GCC UCRT64 | 16.2.0, MSYS2 Rev6 | `G:\Zelda\toolchains\msys64\ucrt64\bin` |
| Capstone distribution | 5.0.9 | Fresh venv, pinned requirements |
| Unicorn distribution | 2.1.4 | Fresh venv, pinned requirements |

The Capstone 5.0.9 distribution's Python `__version__` constant reports 5.0.7. `importlib.metadata.version('capstone')` is 5.0.9, and the project's production decoder version check and native/reference tests passed. Do not change dependency pins or edit installed package code to reconcile that upstream constant.

The existing Visual Studio2026 installation remains installed. VS2022 Build Tools was added to match the generator explicitly selected by the current startup builder. MSYS2 was fully updated before GCC installation. Its primary mirror was moved first after the redirecting mirror stalled; the former mirror list is retained beside it as `mirrorlist.mingw.before-zelda`. Package signature/integrity checks remained enabled.

Native builds/tests were run with scoped execution outside the restricted tool sandbox. The initial sandboxed MSBuild worker communication stalled; the identical build completed outside it. If an agent encounters that same failure, use a normal developer shell or scoped tool escalation, rather than editing source or weakening tests. The session script disables MSBuild node reuse.

## Fresh private inputs and seed locators

- MSVC host/helper build: `build/cmake-simd/`.
- Verified prepared ExeFS: `build/prepared/oot111-g/`.
- Verified current-path RomFS index/cache: `build/prepared/romfs111-g/`.
- GCC decoder cross-check: `build/environment-repair/exefs-gcc-check/`.
- Seed locators: `build/research/simd-handoff/sdk-init-seed.json` and `application-seed.json`.
- Seed migration record: `build/research/simd-handoff/migration-note.json`.
- Current-path baseline configuration: `build/environment-repair/application-content-local.json`.

All 5 ExeFS source/normalized hashes match the historical input; both newly compiled ZBIC helpers agree, including 12 required segment hashes. RomFS verification covered 186,587 files and 598 directories, decoding 26,236,424,856 bytes and retaining a 2,991,025,900-byte compressed-entry cache. Its rebuilt index seal differs because the source path changed to the current NUP under `G:\Zelda`; content/catalog identities match the old preparation.

Historical prepared manifests, old CMake cache and original passed reports were not rewritten. The seed copies change only the last iteration's bundle locator. These old directories are historical evidence, not the active build environment.

## Verification performed

| Check | Result |
|---|---|
| Dependency consistency | `pip check` passed; production decoder initialized |
| Input inspection suite | 29 tests passed |
| Segment suite | 29 tests passed |
| Native MSVC CTest | 6/6 self-test groups passed |
| Existing application conversion/reference suite | 3 tests passed on each compiler, including all-field/full-state comparisons |
| Fresh original startup on MSVC | Historical application endpoint and trace reproduced |
| Fresh original startup on GCC | Same historical endpoint and trace reproduced |
| Production source fingerprint | Matches historical final evidence |

Both application runs retire 1,830,133 original instructions plus 51 scaffold instructions, execute 46 native calls and retire 308,487 original instructions after application entry. They mount the sealed RomFS and open/read/close 4 real files (3,427 bytes), with no handles left open. Both stop at the unchanged scalar-SIMD `UCVTF S8, S0` frontier.

Their full ordered trace SHA256 agrees with each other and the historical baseline:

```text
472f151e22e5d9aafb1efc05c68eca1c4f4b56bb66a33e420a3eabf8b456d0e1
```

The complete private result is `build/environment-repair/ready.json`; per-compiler evidence is in `baseline-cmake/`, `baseline-gcc/` and their `*-summary.json` files. The unchanged source fingerprint is:

```text
5443de62f7e37bfe0fc347ef9a9875efc5cfd96d1ba1eda7ed29bad50adac22d
```

The full 616-test milestone suite was **not** rerun for this environment-only repair. A future implementation still requires a fresh full milestone run after source/config changes. No implementation commit or push was made here.

## Continue implementation

Task0 is complete. Start at Task1 of [the implementation plan](2026-11-13-application-simd-progress.md), after reading `AGENTS.md` and the [design](../specs/2026-11-13-application-simd-progress-design.md). Reuse the verified active paths and seed locators above. Do not reinstall the toolchain or reprepare the input solely because the design records the earlier migration failure.
