# Reference review: native runtime and development throughput

Reviewed on 2026-11-15 against the local validated `9a7075f` checkout. This is an
engineering review and implementation plan; it does not add runtime capabilities.
The local frontier remains OpenDefaultDisplay, with no original game frame.

## Scope and pinned references

| Repository requested | Inspected head | Commit date (UTC) | Main relevance |
| --- | --- | --- | --- |
| [t0masz407/Hookshot](https://github.com/t0masz407/Hookshot/tree/460b65424acf86be4c933858744e2932226f3f91) | `460b65424acf86be4c933858744e2932226f3f91` | 2026-11-08 | Native SDK boundary, shared build cache, NVN replay and shader integration |
| [tangerineturtle1/NX2navi](https://github.com/tangerineturtle1/NX2navi/tree/62cc3b131264680d5d88957c53640ea31abfaa6a) | `62cc3b131264680d5d88957c53640ea31abfaa6a` | 2026-11-15 | Native runtime, scheduler, shader service, object integrity and graphics replay |
| [Frizti/Fritchii](https://github.com/Frizti/Fritchii/tree/f66ea633db6058efe31a9611718019e5bd1667eb) | `f66ea633db6058efe31a9611718019e5bd1667eb` | 2026-11-06 | Emulator-side service/graphics observations, shader lowering and synchronization |

The first entry is the exact fork requested, not an assertion about the newest
upstream Hookshot head. All three recursive trees were complete. A selective
79-file reference snapshot totals 3,403,927 source/document bytes; downloaded blobs
were verified against their Git object IDs. Snapshots, API metadata and the download
manifest stay under ignored `build/research/reference-review-20261115/`.
No reference code was executed or imported into project implementation.

Hookshot and NX2navi report gameplay in their READMEs. Their source contains
substantial rendering/runtime implementations beyond our current bootstrap. This
review did not build/run them and does not independently verify their FPS, stability
or compatibility claims. Fritchii is an emulator fork, not another static-C port.

## What explains the difference in functional progress

Hookshot's [design](https://github.com/t0masz407/Hookshot/blob/460b65424acf86be4c933858744e2932226f3f91/docs/design.md)
and [renderer provenance](https://github.com/t0masz407/Hookshot/blob/460b65424acf86be4c933858744e2932226f3f91/gpu/PROVENANCE.md)
describe reuse of an existing recompilation stack, native runtime and shader
compiler. Its native NVN interface records operations for a renderer; its Vulkan
shader implementation connects to an existing shader-recompiler IR/SPIR-V backend.
That foundation represents substantial work already done before the title-specific
port. Generating C rather than C++ does not explain our earlier frontier.

NX2navi's [architecture](https://github.com/tangerineturtle1/NX2navi/blob/62cc3b131264680d5d88957c53640ea31abfaa6a/docs/architecture.md)
likewise separates generated CPU code, native SDK services, NVN recording, shader
translation and Vulkan replay. It also models guest scheduling; our main-thread
priority/affinity state is not that scheduler. Reaching a first game frame may
therefore expose additional CPU instructions, thread services and synchronization
requirements after the current display boundary.

Our source binding, checked memory, PAC model and preserved prefixes are useful
contracts. They do not establish that the whole port is more correct or closer to
gameplay than a project with a substantially larger implemented runtime.

## Immediate throughput opportunity

Both references provide useful build organization:

- Hookshot [keeps chunk boundaries stable](https://github.com/t0masz407/Hookshot/blob/460b65424acf86be4c933858744e2932226f3f91/nx2/chunks.py)
  and [shares objects between build variants](https://github.com/t0masz407/Hookshot/blob/460b65424acf86be4c933858744e2932226f3f91/nx2/build.py).
  Its keys account for source, flags and header inputs. Compiler options also
  address expensive optimization of large generated control-flow graphs; these
  options are compiler-specific experiments, not settings to apply blindly here.
- NX2navi [preserves unchanged emitted files](https://github.com/tangerineturtle1/NX2navi/blob/62cc3b131264680d5d88957c53640ea31abfaa6a/recomp/gen.py)
  and [checks object integrity before linking](https://github.com/tangerineturtle1/NX2navi/blob/62cc3b131264680d5d88957c53640ea31abfaa6a/tools/build_game.py).
  Its documented object-sharing approach depends on replacing updated objects
  atomically, so updating a cache does not overwrite another build's hard links.

We already have stable source units, content-preserving cache copies and incremental
builds in `tools/startup_sources.py` and `tools/build_startup.py`. The missing
opportunity is sharing verified objects across the separate profile caches and
repeated synthetic-test backend builds, not replacing the generator wholesale.

Measured from the passed local run's final source manifests/build reports:

| Transition/profile | Observed local evidence |
| --- | --- |
| Application -> graphics | 299/316 C units identical; 198,732,317/271,166,427 bytes identical (73.29%) |
| Graphics -> display | 310/316 C units identical; 207,652,125/270,609,247 bytes identical (76.74%) |
| Application GCC, existing shared SDK-init cache | 59 compiled objects, 276 reused; build phase 49.2 seconds |
| Graphics GCC, separate fresh cache | 335 compiled objects, zero reused; build phase 353.4 seconds |
| Display GCC, separate fresh cache | 335 compiled objects, zero reused; build phase 338.1 seconds |
| Complete MSVC/CTest command | 1,796.7 seconds against the existing 1,800-second stage budget |

These are different profiles, not a controlled speedup benchmark. Unit counts and
byte overlap do not measure optimization cost; a few large functions may dominate.

Proposed independent cache milestone:

1. Benchmark cold/warm representative builds and distinguish generation, compilation,
   linking, reference execution and trace verification time.
2. Add a persistent immutable object store for both compilers. Keys must cover the
   compiler/toolchain, exact source, relevant dependency contents, compile flags,
   generated headers, code-generation schema and ABI. Compile-relevant profile
   differences must invalidate; independent generic units may share. Program/input
   binding objects retain all their current seals. Do not normalize paths if that
   would change include resolution or observable compiled strings.
3. Check cached object content, not just filename/existence. Rebuild missing,
   corrupt or incompatible entries and publish objects atomically. Keep mutable
   work directories independent from sealed artifacts.
4. Reuse compiled backend objects in synthetic fixtures while preserving each
   test library's own globals and lifetime. Run every required test again; this
   is not a cache of passed test results.
5. Add supported checkpoint recovery with persisted result/artifact manifests.
   A lane is complete only after its post-build verification, not just the child
   command's exit. Source/config/input/toolchain changes invalidate recovery.
   Preserve failed/interrupted evidence and original timeouts.

The current GCC path's object lookup uses existence after computing an input key;
a shared store needs an output integrity check as well. The current milestone
runner's command stages precede some lane verification; the one-off private
recovery used during integration is not a production resume interface.

## Display/Layer: learn the boundary, preserve our ownership contract

The references confirm a useful family boundary: VI initialization, default
Display, default Layer, native window, display timing/capabilities, then the NVN
resolver. Inspect them together instead of repeatedly implementing isolated calls.

Their identity policies differ from ours. Hookshot's
[VI implementation](https://github.com/t0masz407/Hookshot/blob/460b65424acf86be4c933858744e2932226f3f91/host/nn_vi.c)
allocates opaque stand-ins and signals events from a timed host loop. NX2navi's
[graphics overrides](https://github.com/tangerineturtle1/NX2navi/blob/62cc3b131264680d5d88957c53640ea31abfaa6a/runtime/ov_gfx.c)
also expose small host stand-ins consumed by its own NVN layer. These are choices
within those projects' replacement boundaries, not proof of our original SDK's
object layout or physical display timing.

For our reached path, keep the source-proved static identities and original
constructor/vtable evidence. Bind real per-context display/layer peers to the
existing window/surface, validate all outputs transactionally, implement lifetime
and close behavior, and close unsupported virtual consumers. Do not cast a host
HWND into a guest object. Vsync requires its own source/event/presentation proof;
a 60 Hz timer alone does not establish that contract.

## NVN, shaders and the first frame

The useful NVN model is a resolver plus typed implementations, an operation stream,
owned resources and a backend that executes it. Our private 735-procedure census
is a map for prioritization, not 735 functions to implement before testing progress.
Implement the source-proved subset actually reached and preserve precise stops.

Unknown-call policy needs care: Hookshot's
[NVN fallback](https://github.com/t0masz407/Hookshot/blob/460b65424acf86be4c933858744e2932226f3f91/host/nvn_native.c)
and NX2navi's [unknown-name traps](https://github.com/tangerineturtle1/NX2navi/blob/62cc3b131264680d5d88957c53640ea31abfaa6a/runtime/nvn_procs.c)
include optional strictness and zero-return paths. Known weak NVN implementations
in NX2navi stop, while dynamically trapped unknown names can return zero. Do not
generalize either repository as universally strict or universally stubbed. Our
unsupported calls remain genuine boundaries.

Shader translation is a substantial dependency. Hookshot's Vulkan shader path uses
an existing Ampere/IR/SPIR-V compiler. NX2navi's
[translator builder](https://github.com/tangerineturtle1/NX2navi/blob/62cc3b131264680d5d88957c53640ea31abfaa6a/tools/build_xlate.py)
and [shader client](https://github.com/tangerineturtle1/NX2navi/blob/62cc3b131264680d5d88957c53640ea31abfaa6a/runtime/gfx_shader.c)
separate translation into a persistent service and identify its cache by inputs,
translator identity and relevant answers. A library/dependency strategy must be
decided explicitly before assuming an independent shader compiler can be finished
quickly. Keep game-derived shader inputs/outputs private and verify our own format.

Fritchii's [Ampere lowering](https://github.com/Frizti/Fritchii/blob/f66ea633db6058efe31a9611718019e5bd1667eb/src/shader_recompiler/frontend/ampere/lower_to_maxwell.h),
image-layout helpers and synthetic shader tests offer useful research leads. Its
[GPU-thread split](https://github.com/Frizti/Fritchii/blob/f66ea633db6058efe31a9611718019e5bd1667eb/NX2_GPU_THREAD_SPLIT.md)
explains why command-data snapshots and dependency order matter. This is emulator
design evidence, not an implementation to graft into our native port. Historical
NX2 notes also describe experimental stubs and are not current ABI authority.

For the first rendering slice, specify the required pools, texture layout,
shader/reflection inputs, commands, queue synchronization and presentation together.
Capture CPU-written data when ownership requires it; preserve event order. A
working swapchain or a cleared test window is not an original game frame.

## Licensing and implementation boundary

Hookshot and Fritchii advertise GPL-3.0; their component notices carry additional
per-file details. NX2navi's root MIT license does not cover every current change:
its [LICENSE-ADDITIONS](https://github.com/tangerineturtle1/NX2navi/blob/62cc3b131264680d5d88957c53640ea31abfaa6a/LICENSE-ADDITIONS)
reserves the additions/changes after the base import, and
[third-party notices](https://github.com/tangerineturtle1/NX2navi/blob/62cc3b131264680d5d88957c53640ea31abfaa6a/THIRD_PARTY_NOTICES.md)
describe separately licensed components. Do not treat the current tree as wholly
MIT or import its implementation into ours. Independent implementation remains
the standing direction; any separately selected dependency needs its applicable
license and notices preserved.

## Recommended order

1. Shared verified build objects and supported evidence recovery, with measured
   cold/warm behavior and new test results on every required run.
2. The existing coherent Display/Layer plan, followed by the actual NVN resolver
   and startup subset reached from our own source-bound trace.
3. Shader dependency/format investigation alongside the initial NVN work, then a
   complete minimal rendering/presentation slice. Add CPU/thread/services only
   when actual execution demonstrates the dependency.

No runtime changes or speedup are claimed by this review. Keep the passed source
boundary and capability profiles unchanged until implementing a new milestone.
