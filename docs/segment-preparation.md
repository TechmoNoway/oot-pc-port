# NSO segment preparation

This step decodes NSO `.text`, `.rodata`, and `.data`, checks their declared decoded sizes, and verifies each SHA-256 hash required by the NSO flags. BSS remains metadata; this step does not create a guest address space, apply relocations, or execute code.

## ZBIC backend

LZ4 block decoding is implemented in Python without an extra package. ZBIC uses a separate native helper linked to the [ZBIC-capable zstd dependency](https://github.com/hexkyz/zstd/tree/491bb11b008cf57019a08fcd57beee5d3d24904d), pinned to commit `491bb11b008cf57019a08fcd57beee5d3d24904d`.

With Git and GCC available, prepare the helper locally:

```powershell
python -B tools/build_zbic.py --fetch
```

The dependency checkout stays under ignored `toolchain/zbic-src`. The original dependency source is left unmodified. The helper, its backend record, and a copy of the dependency's license are written under ignored `build/tools`. Existing dependency checkouts with a different revision or modified tracked files are rejected. Nothing is installed globally.

The helper receives compressed bytes over a binary pipe and is given an exact output size. It rejects allocations or compressed input above 256 MiB, and decoding runs in a subprocess with a 60-second timeout. This is a size and time boundary, not a process sandbox.

Alternatively, fetch only the dependency and build it with CMake/MSVC:

```powershell
python -B tools/build_zbic.py --fetch --fetch-only
cmake -S . -B build/cmake -A x64 -DOOT_ZBIC_SOURCE="$PWD/toolchain/zbic-src"
cmake --build build/cmake --config Release
```

Select that helper with `--zbic-decoder build/cmake/tools/zbic-decode.exe`, or set `OOT_ZBIC_DECODER` to its absolute path. CTest selects the CMake-built helper automatically.

## Verify without exporting modules

```powershell
python -B tools/inspect_input.py "C:\path\to\game.nup" --verify-segments --report build/segment-report.json
```

The same flag accepts a standalone NSO or an extracted ExeFS directory. Each segment reports its computed hash and whether it was compared successfully. Hash fields not required by the NSO flags are marked `null`, not verified. No segment files are written by the inspector.

## Prepare plain ExeFS modules

```powershell
python -B tools/prepare_exefs.py "C:\path\to\game.nup" --out build/prepared/oot111
```

The destination must be a fresh subdirectory of this project's `build/`. A NUP with multiple packages requires `--package INDEX`; no update merging is performed. An extracted ExeFS directory or a standalone NSO is also accepted.

The tool checks the container's ExeFS hashes before decoding. NSO outputs store decoded segments, clear compression flags, and update file extents while preserving segment memory offsets, build IDs, hash flags, and BSS size. An optional module-name field is preserved. NPDM is copied unchanged. Every required segment hash must pass before the output directory is published; failed preparation removes its temporary output and leaves existing destinations untouched.

`manifest.json` records input and output file hashes, output segment file offsets, source compression, verified hash counts, and package metadata. Container verification applies to `source_sha256`; the plain file's hash is `sha256`. Its `relocations_applied` and `bss_materialized` fields remain false. This is verified input for a future loader, not a runnable game.

## Validation

Synthetic tests cover LZ4 literal and match extensions, overlapping copies, invalid offsets, truncation, output limits, hash mismatches, ZBIC failures, plain-NSO round trips, and preparation rollback. ZBIC integration tests require the helper. Windows CI fetches the pinned dependency and builds the helper with MSVC before CTest.

Segment layouts and hash flags follow the public [NSO format](https://switchbrew.org/wiki/NSO0). LZ4 sequences follow the [LZ4 block format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md).
