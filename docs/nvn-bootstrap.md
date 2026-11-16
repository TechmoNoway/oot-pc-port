# NVN bootstrap and rendering foundation

The boot profile reaches original NVN startup in a private diagnostic executable;
it is not a playable port or a verified rendered game frame. The final
`build/milestones/nvn-bootstrap-v1/validation-v2/` run passes all 69 stages,
780 Python tests without skips, eight CTest groups and 283,401 common
native/reference comparisons per compiler. MSVC 19.44 and GCC 14.2 agree on
the full trace, accelerated/single-step execution and all 1,479 original caller
continuations. The checked source fingerprint matches the implementation.

`--nvn` requires the full `--refresh --events --objects` chain and uses compiled
object declaration flags 7. The preceding refresh-only profile keeps an explicit
guard at the original `nvnBootstrapLoader`. Earlier object/event flags, program
limits and source boundaries remain separate.

The exact-build source audit derives the original resolver, sorted 735-entry
procedure/name tables, RELR-backed pointers and canonical unwind bodies. Table
names are procedure records, not fabricated ELF symbols. Original default
builder setters and the public bootstrap loader execute as guest instructions.
Every remaining unsupported procedure and private skipped backend stays guarded
within the unchanged 4096-entry limit.

The independent provider owns GetProcAddress, one private device identity,
initialization/finalization, window-origin/depth modes and a finite integer-query
subset. It borrows the real parent Vulkan device without writing invented SDK
driver fields into the guest object. Lookup returns original guest code entries;
the dispatcher still checks their selected/native bodies and canonical returns.
Version queries return source-proved ABI 231.40. ASTC and debug support explicitly
report false: this provider enables neither feature. Unknown properties remain
boundaries rather than receiving generic zero or guessed hardware limits.

Both final original replays reach the texture-descriptor-size property
after 1472 procedure lookups, one initialization, four integer queries and both
mode setters, at 325,815 post-entry instructions. Implementing the descriptor/pool contract is required before that
property can honestly advertise a supported renderer representation.

Application-only LDAR/B/H support shares the serialized Normal-memory backend
used by other ordered operations. Its four widths preserve register aliases,
ZR reads, SP alignment and complete fault isolation. Earlier INIT/leaf decoders
reject these forms. Independent pinned-reference and generated-dispatch tests
pass on MSVC/GCC; this is not exhaustive ARM weak-memory or threading support.

The [external shader compiler](shader-tool.md) is a separately licensed tool.
Three synthetic native vertex/fragment/compute shaders translate to SPIR-V with
explicit captures and structural checks. This does not establish semantic
shader conformance or successful translation of the game's shaders.

`src/native_gpu.c` is an independent host renderer foundation. It retains the
real Vulkan parent, owns bounded mapped transfer buffers, command pool and fence,
and uses explicit host/transfer barriers. Source/destination ranges, overlapping
self-copies, caller thread, limits and counters are checked. A driver execution
failure poisons the owner. Synthetic tests cover resource rollback and command
failures; physical MSVC/GCC probes each complete 32 GPU copies with 16 uploads
and 16 matching readbacks. This component does not yet receive guest NVN draw
commands and does not present a game frame.

Remaining rendering work includes descriptor/pool compatibility, textures and
formats, captured game shaders and graphics state, command decoding, bindings,
GPU synchronization, swapchain presentation and validation of an actual game
frame. Controller input and beta gameplay validation remain separate work.
