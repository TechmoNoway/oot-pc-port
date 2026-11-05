# Checked guest memory

`src/guest_memory.c` provides little-endian data access through explicit guest regions. It never casts a guest address to a host pointer. Scalar ARM64 translations call this interface; offline game images are not yet connected to it.

## Region contract

Initialize an `OotGuestMemory` using `oot_memory_init` and a sorted array of `OotGuestRegion`. Each region supplies a guest base, byte length, live native backing buffer, and read/write permission bits. The caller owns the table and buffers and guarantees their sizes and lifetimes. Region metadata stays immutable until the next initialization. Guest regions must not overlap, have zero length, wrap the uint64 address space, or exceed native `SIZE_MAX`; a byte at `UINT64_MAX` is allowed. At most 4096 regions are accepted. An empty map is valid and rejects every access as unmapped.

Read and write permissions are independent. A region with zero permissions is a guard. Invalid initialization leaves the memory object unusable and records a configuration error instead of retaining an earlier map. The backend does not allocate buffers, reserve the game's address space, or infer permissions from NSO files.

`oot_memory_load` and `oot_memory_store` transfer 1, 2, 4, or 8 bytes. Unaligned access and transfers across adjacent permitted guest regions are supported, including regions with separate native allocations. Every byte is checked before reading or writing. No native aligned integer dereference or host-endian assumption is used.

## Fault and retirement contract

The last transfer fault records its starting address, first rejected byte, byte width, access kind, and reason: unmapped, permission, address wrap, or invalid configuration. Successful transfers clear the previous fault. The generated entry point also clears stale fault state before checking its instruction budget.

Effective address arithmetic uses modulo-64-bit addition, as required for the implemented address forms. The resulting transfer may not cross from `UINT64_MAX` to address zero. Range validation uses subtraction and checks the full byte range before indexing a native buffer.

A faulting translated scalar instruction returns `OOT_LIFT_MEMORY_FAULT`, keeps PC at that instruction, and does not count it as retired. Destination registers, base-register writeback, and backing bytes remain unchanged for that access. Earlier retired instructions retain their effects. The caller can repair the mapping and invoke the function again at the same PC. A zero budget performs no transfer.

Whole-transfer preflight is an explicit project policy. It does not reproduce possible partial writes or memory ordering effects of a hardware access that faults across a boundary. Unicorn fault comparisons deliberately cover aligned accesses wholly within a missing or protected page. Cross-boundary failure without partial mutation is verified separately as a backend contract.

## Supported execution model

This is a single-threaded, little-endian normal-memory model with unaligned data access enabled. MMU translation, address tagging/TBI, SP alignment traps, device memory/MMIO, watchpoints, ordering, atomic/exclusive behavior, and concurrent guest execution are outside this milestone. Instruction-fetch permissions and self-modifying code are not modeled by this data interface; generated instruction dispatch is separate. A dispatcher exit is not a memory fault or a verified guest function return.

Scalar translation covers byte/halfword/word/doubleword LDR/STR and signed byte/halfword/word loads, with unsigned scaled immediates, signed unscaled immediates, pre/post-index writeback, and UXTW/LSL/SXTW/SXTX register offsets. LDR/LDRSW literal forms use the same checked interface. Register 31 means SP for address bases and ZR for transferred values/index registers. Constrained-unpredictable base/transfer-register overlap with writeback is rejected. Paired, SIMD, unprivileged, prefetch, pointer-authenticated, ordered, and exclusive memory forms remain unsupported.

## Validation

The CTest `guest_memory_self_test` validates the backend independently of instruction decoding: widths, byte order, unaligned access, adjacent allocations, permissions, gaps, address limits, invalid tables, and failure without mutation. It runs in Release builds with explicit checks, rather than disabled C assertions.

The [lifter validation suite](arm64-lifter.md) compiles synthetic ARM64-to-C output using MSVC or GCC and compares all integer state and every byte of every mapped data region with Unicorn ARM64. It also compares selected access faults, verifies that failed loads preserve their old destination, checks writeback/PC/retirement, and exercises resuming after a missing page is mapped. Generated source, binaries, and reports stay under `build/`.

References: [Arm A64 instruction set](https://developer.arm.com/documentation/ddi0602/latest), [Arm register-offset addressing](https://documentation-service.arm.com/static/5f3fa899428f7a6b3328fd44), and [Unicorn 2.1.4 memory API and hooks](https://github.com/unicorn-engine/unicorn/blob/2.1.4/include/unicorn/unicorn.h).
