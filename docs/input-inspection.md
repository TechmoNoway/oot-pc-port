# Input inspection

Run the offline inspector with Python 3.10 or later:

```powershell
python -B tools/inspect_input.py "C:\path\to\game.nup" --report build/input-report.json
```

The report is printed as JSON and optionally saved under `build/`. The input is opened for reading. No game tree is extracted, and no game code is executed.

Accepted inputs are a NUP container, a standalone NSO or NPDM file, or an extracted ExeFS directory. For a NUP with several packages, pass `--package INDEX` explicitly; the inspector does not silently merge base and update packages.

## Report contents

- Package title ID, display version, kind, and standalone-update flag when supplied by NUP metadata.
- NSO build ID, file and memory extents, BSS size, and segment compression.
- NPDM program ID, instruction width, address-space type, main-thread priority, core, and stack size.
- SHA-256 of inspected files; NUP ExeFS hashes are checked against their container records.

The NUP catalog hash is checked before its directory tables are used. Only selected ExeFS payloads are read after that. RomFS payloads are not inspected in this milestone.

## Compression and verification limits

NUP entries can use zstd compression independently of the compression inside an NSO. To inspect compressed NUP entries, use Python 3.14's `compression.zstd`, the optional `zstandard` module, or an available `zstd` command. On Windows the inspector also checks the usual MSYS2 location `C:\msys64\usr\bin\zstd.exe`. External decoding uses temporary files that are removed afterward.

The default metadata-only mode identifies LZ4 and ZBIC NSO segments without decompressing them. Pass `--verify-segments` to decode segments and compare hashes where the NSO header requires them. ZBIC decoding needs the local helper described in [segment preparation](segment-preparation.md); `--zbic-decoder PATH` or `OOT_ZBIC_DECODER` selects it.

NPDM signatures are not verified. Matching a container's own file hash confirms consistency with its catalog, not authenticity or completeness of the original game dump. Reports record these verification limits explicitly.

Catalogs are limited to 128 MiB and each inspected module to 256 MiB. Decoded ExeFS output is bounded by its declared size. Unsupported layouts, out-of-bounds ranges, repeated directory references, duplicate paths, and hash mismatches fail with exit code 1.

NSO and NPDM field layouts follow the public [NSO format](https://switchbrew.org/wiki/NSO0) and [NPDM format](https://switchbrew.org/wiki/NPDM) descriptions. NUP parsing uses the container's superblock, package, directory, file, child-index, metadata, and string tables; it does not decrypt Nintendo archive formats.

## Validation

```powershell
python -B -m unittest discover -s tests -v
```

The suite builds synthetic inputs in temporary directories. It covers ordinary and compressed payloads, metadata, integrity failures, truncation, invalid ranges, unsafe names, cycles, package selection, and command-line failures. Compression tests use the standard library, the optional module, or the local zstd command; they are skipped only when none is available. CMake registers the Python suite with CTest when Python is available.
