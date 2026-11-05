# OOT PC Port

An independent project exploring a native Windows x86-64 port of Ocarina of Time for Switch 2.

## Status

Early development. The Windows host scaffold builds successfully and passes its memory and performance-counter self-test.

An offline [input inspector](docs/input-inspection.md) reads NUP, NSO, and NPDM metadata and verifies selected ExeFS files against their NUP catalog hashes.

The game is not playable yet. NSO segment decompression, ARM64 translation, game loading, operating-system services, and graphics are planned.

## Development direction

The next milestones are segment decompression and verification, ARM64 translation, module loading, operating-system services, and graphics. See [docs/architecture.md](docs/architecture.md).

Game containers, keys, extracted files, generated game code, saves, shader caches, and compiled executables stay outside version control. Build output belongs under `build/`; future generated output belongs under `generated/`.
