# Native image mapping

The runtime image bridge connects completely linked offline module images to the C checked-memory backend. It allocates native backing buffers, copies verified region bytes, preserves BSS relocations, and creates a zeroed synthetic stack with unmapped guard pages. It does not execute constructors, game instructions, or a process entry point.

## Prepare and map

```powershell
.\.venv\Scripts\python.exe -B tools/prepare_runtime.py build/prepared/oot111 `
  --output build/runtime/oot111.ootmem --report build/runtime/oot111.json
.\build\cmake\Release\oot-pc-port.exe --map-images build/runtime/oot111.ootmem
```

Choose fresh package/report paths under `build/`. Preparation verifies the prepared manifest and segment hashes, performs a complete offline link, and refuses unresolved strong symbols or invalid initializer targets. It packages the resulting private images directly; it does not trust an edited linked-image export or execute initialization. Source files remain unchanged.

The native command emits JSON with mapped region count, backing byte count, initial SP, and an explicit false guest-execution flag. The 1.1.1 local integration check maps 17 regions with 102,872,036 backing bytes, including a 2 MiB synthetic stack, using both MSVC and GCC host builds.

## Mapped ranges and ownership

| Kind | Data permissions | Initial bytes |
| --- | --- | --- |
| `.text` | Read | Linked instruction bytes, treated as data during mapping |
| `.rodata` | Read | Linked read-only segment |
| `.data` | Read/write | Linked writable segment |
| BSS | Read/write | Zero fill, with all applied BSS relocations preserved |
| Synthetic stack | Read/write | Zero fill |

Only exact NSO segment/BSS ranges are mapped. Padding and inter-module gaps remain unmapped. Read-only permissions are enforced by the guest data-access interface. Native buffers are allocated at Windows-selected addresses and are not executable mappings; the game's guest address range is not reserved at matching host addresses. Instruction dispatch and execute-permission checks remain a separate boundary.

The stack defaults to guest base `0x7000000000`, size `0x200000`, and SP at the aligned upper end. At least one 4096-byte unmapped guard separates its lower edge from earlier regions; the upper guard is also unmapped. `--stack-base` and `--stack-size` allow a different aligned range within the 39-bit guest address limit. The stack is a test resource, not a recovered process/thread startup ABI.

`oot_runtime_open` returns an opaque object with one owning reference. `oot_runtime_retain` adds a reference and `oot_runtime_close` releases one. Bound dispatch contexts retain the image. `oot_runtime_memory` borrows its checked-memory view; region metadata must remain immutable. Backing and the borrowed view remain valid until the final reference is released. All allocated buffers are released on failure or final close. Do not retain a borrowed view beyond that lifetime. The C library is single-threaded at this stage.

## Package format v1

All integers are little-endian. Packages are limited to 512 MiB on disk, 512 MiB total backing, and 64 regions. Region tables are sorted and disjoint; payloads are contiguous with no trailing bytes. The native reader checks all bounds independently and verifies SHA-256 over the complete descriptor/payload body using Windows CNG before accepting it. This checksum detects corruption; it is not an authenticity signature or proof that arbitrary user-created contents came from a verified game input.

The 96-byte header contains:

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `OOTMEM1\0` |
| 8, 12 | uint32 version and region count |
| 16, 24 | uint64 initial SP and total backing bytes |
| 32, 40 | uint64 descriptor offset (96) and payload offset |
| 48, 56 | uint64 exact file length and zero reserved field |
| 64 | SHA-256 of all bytes starting at offset 96 |

Each 64-byte descriptor contains uint64 guest base, memory size, absolute file offset, and payload size at offsets 0/8/16/24; uint32 data permissions and kind at offsets 32/36; a zero-padded 16-byte owner label at 40; and a zero uint64 reserved field at 56. Kinds are text=1, rodata=2, data=3, BSS=4, stack=5. Owner labels use lowercase ASCII letters, digits, and underscores. Payload size equals memory size for initialized segments. BSS may omit payload only when its complete initial image is zero; nonzero relocation results require the full BSS payload. The unique final stack descriptor has no payload and owns the header SP.

The native loader validates lengths, arithmetic, region budgets, kind/permission agreement, sorted ranges, labels, zero-fill rules, stack alignment/guards, and all derived header totals. It parses bytes explicitly, without trusting native struct packing or casting file addresses to pointers.

## Validation and remaining work

Synthetic integration checks compare every native region byte with its linked image, including relocated data and BSS. They verify rejected text/rodata writes, writable data, unmapped gaps and guards, zero-filled backing, malformed packages/checksums, and source preservation. A generated paired stack-save/restore program runs on the bridge's native stack; this program is artificial and contains no extracted game code. CTest supplies the native host path, and the bridge tests also run with GCC through `OOT_LIFTER_COMPILER=gcc`.

There is no native guest startup, TLS allocation, heap, scheduler, service dispatch, constructor execution, or game-function dispatcher yet. More instruction semantics and verified function boundaries are required before executing game functions.

The [bound dispatcher and registry factory](bound-dispatch.md) check the initial package body identity and current selected code hashes inside exact read-only text ranges. Bound contexts retain the image and obtain stack bounds from it. Synthetic integration dispatches matching leaves and a canonical framed caller; game callbacks remain unregistered. Writable runtime data can change without altering the initial snapshot identity tag.

Reference: [Windows BCryptHash API](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcrypthash).
