# OOT PC Port

An independent project exploring a native Windows x86-64 port of Ocarina of Time for Switch 2.

This repository starts with a new Git history and an original Windows host scaffold. It does not contain an ARM64 recompiler, game loader, renderer, or playable game yet.

## Current baseline

- A C17 command-line executable for Windows x86-64.
- Host diagnostics for processor count, page size, and the performance counter.
- Windows memory allocation and a host self-test.
- A CMake build and a PowerShell build script for GCC.

## Build

With CMake and a C compiler installed:

```powershell
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

With MSYS2 UCRT64 GCC:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/build.ps1
.\build\oot-pc-port.exe --host-info
.\build\oot-pc-port.exe --self-test
```

The build script runs the host self-test after compiling. `--help` lists the supported commands.

## Development direction

The next milestones are input inspection, ARM64 translation, module loading, operating-system services, and graphics. See [docs/architecture.md](docs/architecture.md).

Game containers, keys, extracted files, generated game code, saves, shader caches, and compiled executables stay outside version control. Build output belongs under `build/`; future generated output belongs under `generated/`.
