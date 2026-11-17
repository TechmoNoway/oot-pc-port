# Local build storage

Generated diagnostics dominate this checkout's storage. The 2026-11-16
inventory counted approximately 225 GiB by pathname but 86 GiB of distinct file
content, before filesystem compression. Hardlinks account for the difference.
Source, Git, the Python environment and toolchain together are under 150 MiB.
These are different measures: Explorer's summed file sizes do not show the
actual storage saved by hardlinks or NTFS compression.

The completed maintenance shared 7,006 verified identical artifacts (15.431 GB),
compressed 8,525 inactive files without changing their bytes or timestamps
(35.884 GB), and pruned approximately 103 MB of completed test intermediates.
The second inventory measured approximately 59.12 GB of allocated distinct data
(55.06 GiB), versus 244.14 GB of logical pathname sizes. This is a live-build
snapshot; new validation output continues to consume space.

A later pass over the sealed 69-stage NVN run shared another 5,089 verified
identical artifacts, reclaiming approximately 10.77 GB. Its receipt is
`nvn-sealed-dedup-applied-v3.json`; the active 72-stage texture run was excluded.
Observed drive free space afterward was approximately 56.1 GB while tests ran.

Another closed-artifact compression pass saved approximately 6.416 GB across
1,581 files, with bytes, hashes and modification times preserved. Closed synthetic
test intermediates reclaimed a further 59.8 MB. The active texture validation was
excluded from both operations; these incremental savings are not a fresh total
measurement of the checkout.

Check free space before and after large validation runs, aiming to retain at
least 30 GiB before starting another full run. Keep original/prepared game
inputs, the teammate transfer, required baseline paths and useful compiler caches.
Do not remove an active run's outputs or affected compiler intermediates.

Completed generated C, runtime packages and traces can share storage only after
exact byte/hash verification and ownership checks. Keep mutable caches separate.
Inactive text artifacts/caches can use reversible NTFS compression: preserve
logical bytes, file sizes and modification times, verify hashes after compression,
and exclude the current validation/build and original/prepared/transfer inputs.
Prune regenerable synthetic-test intermediates only after their tests exit.

Private inventory and maintenance receipts live under ignored `build/`:

- `storage-inventory-20261116-v1.json`: logical sizes and distinct NTFS file IDs.
- `storage-inventory-20261116-v2.json`: post-maintenance allocated distinct bytes.
- `nvn-sealed-dedup-applied-v2.json`: immutable byte-identical artifact sharing.
- `nvn-sealed-dedup-applied-v3.json`: additional sealed NVN artifact sharing.
- `ntfs-closed-nvn-compression-v2.json`: later verified closed-artifact compression.
- `nvn-texture-test-prune-applied-v1.json`: closed synthetic-test intermediates.
- `ntfs-compression-pilot-v1.json`: verified compression experiment.
- `ntfs-closed-artifacts-compression-v1.json`: completed bulk compression receipt.
- `nvn-storage-prune-v2.log`: completed-test intermediate pruning.

Maintenance must leave validation outcomes unchanged. A failed run stays failed
even when its already verified immutable outputs share storage with another run.
