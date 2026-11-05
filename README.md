# OOT PC Port

An independent project exploring a native Windows x86-64 port of Ocarina of Time for Switch 2.

## Status

Early development. The Windows host scaffold builds successfully and passes its memory and performance-counter self-test.

An offline [input inspector](docs/input-inspection.md) reads NUP, NSO, and NPDM metadata and verifies selected ExeFS files against their NUP catalog hashes.

[Segment preparation](docs/segment-preparation.md) decodes LZ4/ZBIC NSO segments, verifies required SHA-256 hashes, and writes plain NSO modules with a manifest for the future loader.

The game is not playable yet. Module loading and relocation, ARM64 translation, operating-system services, and graphics are planned.

## Development direction

The next milestones are module layout and relocation, ARM64 translation, operating-system services, and graphics. See [docs/architecture.md](docs/architecture.md).

Game containers, keys, extracted files, generated game code, saves, shader caches, and compiled executables stay outside version control. Build output belongs under `build/`; future generated output belongs under `generated/`.
