# Offline module linking

The offline linker reads the plain modules produced by segment preparation, builds private byte-array images, resolves symbols in an explicit module scope, and applies supported AArch64 relocations. It does not map those images into the Windows guest address space or execute instructions, constructors, finalizers, or indirect resolvers.

## Run

```powershell
python -B tools/link_exefs.py build/prepared/oot111 --report build/link-report.json
```

The prepared manifest and each file's SHA-256 are checked before use. NSO segment hashes are checked again. The input NSOs remain unchanged. The manifest must contain the canonical ExeFS names and a `main` module.

By default, supplied modules are laid out as `rtld`, `main`, `subsdk0` through `subsdk9`, then `sdk`, starting at guest address `0x100000000` with 2 MiB alignment. `--base` and `--alignment` choose a different layout. Images are page-aligned and include zero-initialized BSS. Unmapped gaps remain invalid for metadata and symbol access even though the image buffer contains zeros there. The current layout is restricted to a 39-bit guest address space and 512 MiB of total image data.

## Metadata and symbol scope

- The MOD0 pointer is read at module offset 4. Its signed relative fields locate the dynamic table, BSS, exception information, and module object.
- BSS bounds are cross-checked against the NSO header. Dynamic tables must terminate and singleton tags must not repeat.
- Symbol tables are bounded using NSO metadata, `DT_SYMTABSZ`, SysV hash counts, or GNU hash chains. Available bounds are cross-checked.
- `DT_NEEDED` names and their order are reported. No libraries are found or downloaded automatically; all modules must be supplied explicitly.
- Local, hidden, internal, and protected definitions bind within their module. `DT_SYMBOLIC` is honored. Other references use the explicit module order, preferring global definitions before weak definitions. Absolute symbols keep their absolute values.
- Unresolved weak references use zero plus their relocation addend. Unresolved strong references are reported and left unpatched. No host stubs are invented.

This explicit scope is a project linking policy, not a complete implementation of Horizon's runtime linker or a general-purpose ELF dependency loader. Symbol versioning, TLS symbols, IFUNC, and indirect relocation resolvers are unsupported.

## Relocation pass

The linker processes RELR before RELA, including the PLT RELA table. It supports `R_AARCH64_NONE`, `ABS64`, `ABS32`, `GLOB_DAT`, `JUMP_SLOT`, and `RELATIVE`. RELR address entries and 63-slot bitmaps adjust the original 64-bit values by the module base.

Writes must be aligned and remain in the module's writable data/BSS. Overlapping writes, symbol-index errors, ABS32 overflow, and unsupported relocation types fail the pass. Relocation cannot be attempted twice on the same linker instance. Failure never publishes image output.

After relocation, init/fini array entries are checked against supplied text ranges. Null and all-ones sentinel entries are permitted. These checks confirm pointer placement; they do not prove the functions are safe or correct to execute.

## Export snapshots

```powershell
python -B tools/link_exefs.py build/prepared/oot111 --report build/link-report.json --out build/linked/oot111
```

`--out` must name a fresh subdirectory under `build/`, separate from the prepared input. It receives one `<module>.image.bin` per module and a manifest containing bases, source and image hashes, relocation counts, binding counts, initializer checks, and diagnostic samples. Publication happens after all image files have been written to a temporary directory. Game-derived snapshots stay ignored by Git.

`link_complete` means the supported relocation pass completed with no unresolved strong relocation or unmapped init/fini target. It does not mean the game is bootable. The report separately records that guest code has not executed and host address space has not been mapped. Incomplete links return exit code 1, can still produce a diagnostic report, and cannot export snapshots.

## Validation

Synthetic tests exercise MOD0 bounds and signed offsets, dynamic tags, SysV/GNU symbol counts, RELA/PLT and RELR writes, cross-module and weak binding, hidden/protected symbols, BSS, pointer overflow, malformed input, and output integrity. They run in the existing Python suite and CTest.

Format references: [MOD0](https://switchbrew.org/wiki/MOD), [NSO](https://switchbrew.org/wiki/NSO0), [ELF dynamic linking](https://gabi.xinuos.com/elf/08-dynamic.html), [ELF symbols](https://gabi.xinuos.com/elf/05-symtab.html), [ELF RELA/RELR](https://gabi.xinuos.com/elf/06-reloc.html), and [AArch64 relocation operations](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst).
