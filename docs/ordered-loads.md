# RCpc ordered loads

The raw C lifter implements the exact no-offset encodings of LDAPRB, LDAPRH, LDAPR W, and LDAPR X. They read 1/2/4/8 bytes from Xn or SP, zero-extend byte/halfword/word results, preserve NZCV, and perform no writeback. Rt=31 discards the result but still checks and orders the memory access. Source/destination aliases capture the address before changing the destination. Post-index, unscaled/signed forms, LDAR, STLR, barriers, exclusives, and atomic read-modify-write instructions remain unsupported.

Arm specifies acquire-PC ordering for these loads, with weaker ordering than LDAR in some store-release sequences. The value pseudocode alone does not describe that distinction. See the [Arm A64 reference, LDAPR/B/H, pages 444-448](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85) and Arm's explanation of [RCpc acquire mappings](https://developer.arm.com/community/arm-community-blogs/b/tools-software-ides-blog/posts/enabling-rcpc-in-gcc-and-llvm).

## Supported memory contract

`oot_memory_load_rcpc` uses the existing region/fault objects; their layouts and integer state ABI 2 are unchanged. Its supported domain is little-endian Normal memory, natural alignment for the transfer width, and 16-byte alignment when the base is SP. Misalignment returns `OOT_MEMORY_ALIGNMENT` (5). Invalid configuration takes priority over alignment. Translation, permissions, and complete-range checks retain the existing memory-fault/retirement contract. Failure does not modify the destination, PC, SP, backing, or retired count for that instruction. Prior retired effects remain committed; zero budgets clear stale faults without reading memory.

Alignment is an explicit supported-domain restriction, not an emulation of every SCTLR/SA/nAA configuration. The pinned reference accepts some unaligned acquire accesses under its default configuration, so only aligned architectural values/faults are compared with it. Misaligned requests are checked independently as project rejections. MMU translation, tagging/TBI, device memory/MMIO, watchpoints, and architectural alignment-trap registers are not implemented.

All scalar, paired, and RCpc backend transfers now share one exclusive Windows SRW lock **per linked backend instance**. The lock covers whole-access preflight, every backing-byte access, and output/fault update. No callback or external user code runs while it is held; internal helpers do not reacquire it. Ordinary stores participate in the same order, so acquire loads do not race with unsynchronized C byte writes. No host atomic integer pointer is fabricated over caller-supplied byte arrays. Windows documents both SRW exclusion and the associated ordering barriers: [SRW locks](https://learn.microsoft.com/en-us/windows/win32/sync/slim-reader-writer--srw--locks), [synchronization and multiprocessor issues](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-and-multiprocessor-issues).

This backend chooses a conservative total order, stronger than RCpc's minimum requirements. It supports ordered publication for the tested Normal-memory subset; it does not reproduce every allowed Arm weak-memory outcome, lock-free progress property, or cache/MMIO effect. Per-transfer serialization is not a whole-instruction/frame transaction or a guest scheduler.

Concurrent participants must obey all of these ownership rules:

- Give each executing thread its own `OotGuestMemory` view/fault record, integer state, and outputs. Transfer ownership only with external synchronization. Do not inspect a view's mutable state while its owner is running.
- Keep region metadata, permissions, backing allocation/lifetime, and initialization stable while operations can use them. Reinitialize or repair a view only while it is quiescent.
- Access shared backing exclusively through APIs from the **same** backend instance. A direct host read/write, renderer/service pointer, or second statically linked DLL copy does not participate in this lock domain. Such sharing is unsupported.
- Keep existing runtime-image, dispatcher, activation, and PAC-context APIs single-threaded. These APIs have no newly implied concurrent ownership or guest process startup contract.

The global lock intentionally serializes independent addresses and address spaces too. This favors a simple verifiable contract over throughput. Future scheduling, services, atomics, release stores, and memory-domain APIs need their own specification before changing this contract.

## Validation

```powershell
.venv\Scripts\python.exe -B tools/ordered_validation.py --compiler cmake
.venv\Scripts\python.exe -B tools/ordered_validation.py --compiler gcc
```

The decoder tests cover all 4,096 size/base/destination combinations and distinguish neighboring valid scalar encodings from unimplemented atomic/ordered forms. The generated native tests compare 1,647 cases with pinned Unicorn 2.1.4 CPU MAX, assert FEAT_LRCPC, and independently check little-endian values. Cases include W zero extension, SP/ZR, aliases, flags, budgets, unmapped/permission faults, and an acquire fault after a retired store. Twenty raw PAC frame cases include 96 reference prefixes and permission-repair resumes at the acquire rather than re-signing LR.

Twenty-nine backend policy checks cover alignment, invalid configuration, null arguments, distinct adjacent allocations, cross-region permission preflight, output preservation, and stale-fault repair. The native publication test uses two real Windows threads, separate views, and different guest aliases of shared backing. For each compiler, generated acquire callbacks pass 40,000 publication handshakes, 40,000 competing scalar read/write rounds, and 40,000 paired-transfer rounds. CTest also runs an independent direct-backend concurrency executable.

Unicorn comparisons establish values and selected synchronous faults, not a concurrent memory-model oracle. The native stress tests supply bounded evidence for the chosen synchronization contract, not exhaustive weak-memory equivalence. No game bytes or production keys are used for execution; generated C, DLLs, logs, and reports remain under ignored `build/`.

The common lifter suite now includes these 1,647 cases: 74,411 comparisons across 31 synthetic programs. Policies 1-4 keep their declared memory permissions and still reject the new form. The separate [checked-read policy 5](checked-reads.md) now admits it only with explicit runtime range, ownership, and alignment checks. A raw successful translation does not authorize execution as a registered function.

## Static survey after this milestone

Fresh local 1.1.1 surveys use the same 284,396 metadata candidates and unchanged module source/linked-text hashes. Default discovery increases from 58,638 to 58,663 bounded semantic regions. PAC discovery increases from 115,164 to 127,551; 156,845 candidates remain discovery-blocked. No LDAPR/B/H first-unsupported frontier remains in these reports. The remaining PAC-discovery first-unsupported ordered/atomic category decreases from 39,893 to 5,144, exposing other failures later in those regions.

At this milestone, function acceptance remains 40,038 ordinary leaf candidates and 1,686 PAC framed candidates. Existing profiles deliberately do not acquire new read permissions from this instruction milestone. A later separate checked-read survey accepts 1,688 structural candidates, subject to runtime obligations. The later [conditional-compare milestone](conditional-compare.md) implements CCMP/CCMN; remaining instruction frontiers include load/store addressing, long multiply, SIMD/FP and atomic read-modify-write. Neither survey generates or runs game callbacks.
