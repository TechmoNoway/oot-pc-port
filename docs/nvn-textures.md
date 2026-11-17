# Texture ownership and fixed NVN layout

This checkpoint passes all 72 validation stages. It adds independent host texture resources and
a separate original-game layout-query diagnostic. It does not implement an NVN
memory pool, decode a game texture, submit game draws or prove a game frame.

The Vulkan owner supports bounded 2D RGBA8/BGRA8 UNORM images with one mip,
one layer and one sample. It checks the physical image-format/usage limits,
owns device-local memory and image views, and transfers tightly packed pixels
through checked staging-buffer ranges. Explicit image layouts and host/transfer
barriers precede real queue submissions and bounded fence waits. Execution
failure poisons the owner and teardown waits for pending work before releasing
resources. Failed Vulkan creation outputs are never treated as valid handles.

Private 32-byte descriptor records retain live textures. Binding, replacement,
clearing and pool teardown update references; a referenced texture cannot be
destroyed. Texture and pool identities are never reused during an owner lifetime.
There are at most 128 texture identities, 32 pool identities and 4096 live
descriptor slots per owner. These records are host metadata, not native NVIDIA
descriptor bytes or Vulkan handles to copy into guest memory. The host pool API
has no guest NVN reservation/index interpretation yet.

`--nvn-layout` requires `--nvn` and compiled object declaration flags 15. The older
flags-7 NVN profile keeps its exact property-15 boundary and trace. The new source
audit follows both original integer-query helpers and their read-only case tables
to prove the six fixed serialized ABI values: 32-byte texture/sampler records,
256 reserved texture/sampler indices, and 4/8-byte command/control alignment.
These values describe original ABI geometry, not supported hardware limits or
successful allocation. Every unsupported resource/queue/shader consumer remains
guarded. The private constant helper is guarded as well.

Eight exact original memory-pool builder setters/getters execute as translated
instructions, with complete body, instruction-role and unwind provenance. The
defaults preserve the device/prefix fields; storage updates touch only their
source-proved fields. Retaining these ordinary original instructions neither
creates a memory pool nor grants a driver object.

Focused MSVC/GCC tests cover creation rollback, layouts, nonzero staging offsets,
descriptor replacement/lifetime, malformed descriptors, ownership, thread and
range errors, failed submission/fence waits and unchanged legacy property guards.
Separate physical probes each complete 16 matching odd-dimension texture
roundtrips across the two supported formats, alongside 32 buffer copies. These
are synthetic pixels. The full run passes 789 Python tests without skips, eight
CTest groups and 283,401 common native/reference comparisons per compiler.
Both original full traces preserve the earlier profiles and match SHA-256
`c9543e23f95451f6e124cbdba95563aa09b2fe9089f8c8c8cbdb7702e1b67d5d`.
They reach guarded `nvnMemoryPoolInitialize` at 326,218 post-entry instructions,
with 1,472 procedure lookups, one device initialization and eight integer queries.
Supplemental full-body proofs verify all four executed builder setters, their
ordinary original returns and caller continuations on both compilers.

Private evidence is under `build/milestones/nvn-texture-v1/validation-v1/`.
The passed implementation/configuration fingerprint is
`694ffe37d4d9cfb9772089e283aee5944befc8b1e8a292995bb047bffb7f0c24`.

The next integration needs real guest-backed memory-pool ownership, source-bound
texture storage interpretation, game shader captures and graphics state,
descriptor/command translation, synchronization and swapchain presentation.
