# NVN resource ownership

This checkpoint passes the full 76-stage validation. It extends the separate
`--nvn-layout` diagnostic with `--nvn-resources` and object declaration flags 31.
Earlier flags 7/15 keep their original guards and complete trace baselines.
It does not establish a rendered game frame.

An independent owner implements source-bound pool/buffer initialization,
finalization, mapping, size/flag/address queries and bounded range operations.
The current pool subset accepts exactly the observed flags 0x22, page-aligned
guest storage, at most 8 MiB per pool and 64 MiB live total. Pool and buffer
identities/ranges are bounded and are not reused during an owner lifetime.
Builders, complete writable ranges, protected identities, aliases and auxiliary
fields are checked before publication. The owner retains opaque object bytes
privately and rejects later mutation; it serializes no host pointer, Vulkan
handle or invented Nintendo driver fields into guest memory.

Each pool owns a real Vulkan buffer/allocation. A logical GPU address equals its
owned guest-storage address in this explicit private model. Checked resolution
captures the requested guest bytes into its shadow immediately before use and
returns the actual owned Vulkan buffer plus offset. No native pointer into a
remappable guest heap is retained. Invalid/stale/cross-owner ranges cannot resolve.
The current shadows support transfers; vertex/index/uniform/storage binding
requires separately enabled usages and contracts. No Vulkan device-address
feature is implied by this logical address model.

The renderer-service snapshot API preflights and captures a complete operand
under the common memory-transfer lock. Its separate 8 MiB bound leaves earlier
instruction, probe, record and native-input limits unchanged. Synthetic concurrent
two-region publication verifies that a snapshot cannot contain half of each
publication. GPU execution and subsequent guest mapping changes are not a
cross-thread atomic transaction: the resource runtime remains creator-thread only.

Sampler and texture descriptor containers retain their parent pool and checked
32-byte slot ranges, reject overlapping containers, and own private metadata for
at most 65,536 slots. The three original reserved sampler recipes materialize real Vulkan samplers.
Sampler/builder registration normalizes source-proved fields into owned samplers,
shares identical states and retains references per slot. Texture registration and
shader binding consumers remain guarded. These metadata records are not
NVIDIA descriptor bytes; generic GPU-address resolution rejects their ranges
until a supported descriptor interpretation is implemented. Parent pools cannot
finalize while buffers or descriptor containers remain live.

The audit binds 29 complete original public bodies, retains seven original
buffer-builder functions plus 38 ordinary sampler methods, and guards four skipped
private driver/descriptor backends (3,741 bindings total). Original ordinary builder instructions still execute through the
checked translator. Unsupported shader, texture, command and queue APIs stop.

Synthetic tests exercise allocation rollback, complete output preservation,
builder/permission/alias rejection, original-object mutation, stale identities,
parent references, signed range rejection, shadow recapture and creator-thread
checks on MSVC/GCC. Explicit physical probes on both compilers verify 16 real
copy/readback operations and the 4,096/33,068-slot container capacities using
synthetic storage. None of these probes submits game draws.

Full delivery additionally requires every preceding lane, fresh source/input
seals, the entire old pool-init guard prefix restored from a full native trace,
typed original entries and retired original callers on both compilers.

The separate renderer owns a child Vulkan logical device over the retained parent
instance/physical device. It queries and explicitly enables `samplerAnisotropy`
and `shaderImageGatherExtended`; parent profiles keep their original feature
configuration. Resource and sampler handles all belong to the child, which dies
before the parent instance reference is released. This does not establish a game
pipeline or a presentation surface lifetime.

The sampler subset supports normalized float-color textures, nearest/linear and
mipmap filters, repeat/mirrored-repeat/edge/standard-border modes, ordinary depth
comparison and anisotropy within actual enabled limits. Non-mip filters preserve
separate minification/magnification using the Vulkan-documented 0..0.25 LOD range.
Unsupported reduction, LOD-snap, legacy/mirror-clamp and custom-border states stop.
The numeric enum reference is the pinned
[reconstructed API declaration](https://github.com/t0masz407/Hookshot/blob/460b65424acf86be4c933858744e2932226f3f91/gpu/render/nvn_api.h).
Original Switch 2 getter/body/field proofs remain authoritative for this exact
input; no foreign structure layout or runtime implementation was imported.
See the [Vulkan sampler requirements](https://docs.vulkan.org/refpages/latest/refpages/source/VkSamplerCreateInfo.html).

The completed MSVC pilot reaches guarded `nvnQueueBuilderSetDefaults` after
326,486 post-entry instructions. It owns the 1,191,936-byte pool, 37,164 descriptor
slots, four real Vulkan samplers and one game sampler registration. Its full
single-step preflight preserves the entire prior pool-init trace prefix and
verifies complete original sampler-default/device/filter/initialize bodies,
returns and original caller steps. Matching full trace SHA-256:
`44eb41e676f1f569cb3f918f8a9b2b18a45dd23c8ccd301f90bafd722204fd71`.

Private diagnostics are `build/research/nvn-resources-pilot-v5-cmake/` and
`build/research/nvn-resources-preflight-v1/`. The full milestone configuration is
`config/milestones/nvn-resources.json`. Earlier failed pilots remain private:
v1 stopped before execution at the missing flags-31 emission gate; v4 stopped
before execution at a missing LDP entry in the ordinary-method audit whitelist.
Neither failed attempt is promoted into a passed validation.

The first full run, `build/milestones/nvn-resources-v1/validation-v1/`,
failed in two legacy graphics/display fixtures whose private link source lists
omitted the new resource modules. The failure remains preserved. Both corrected
fixtures pass on MSVC/GCC; the successful fresh full run is `validation-v2/`, frozen at
`f725d7b08b4f70dc12a5317affb3d47d9aa19044f05a4fca7f24bb9a128e5cf5`.
All 76 stages passed and were verified, with 798 Python tests without skips,
eight CTest groups and 283,401 common native/reference comparisons per compiler.
Both full compiler traces match the preflight digest and prove every typed caller
and the complete original sampler bodies described above. Supplemental descriptor
and registration counters are checked in `build/nvn-resources-closeout-v1.json`.
The controller and its children have exited; the current source seal matches.
