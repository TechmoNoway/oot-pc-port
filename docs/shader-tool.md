# External shader compiler

The Windows C runtime and its NVN/Vulkan objects are implemented independently.
Shader translation uses a separately built executable, `oot-shader-tool.exe`.
The runtime does not link the compiler library. No game shaders or generated
SPIR-V belong in Git.

The source locks in `config/dependencies/` pin the compiler subset from
[Hookshot](https://github.com/t0masz407/Hookshot/tree/460b65424acf86be4c933858744e2932226f3f91/gpu/vk/eden/shader_recompiler)
and official [SPIR-V headers](https://github.com/KhronosGroup/SPIRV-Headers/tree/5c6004e758e0c80185ef2cee93ae5c10fa342a5b).
The selected sources include Eden/yuzu shader-recompiler, Sirit and small
compatibility headers, with their original copyright/license/provenance files.
Their applicable GPL and other notices remain intact under ignored
`toolchain/shader-compiler/`. This is an external compiler dependency, not an
import of another port's NVN implementation or renderer. Preserve its licenses
and provide corresponding dependency sources when distributing that tool.

Build from the project environment:

```powershell
.venv\Scripts\python.exe -B tools/build_shader_compiler.py
```

The fetcher verifies every selected Git blob and size before publication. The
builder writes `tool-identity.json` binding the executable, adapter and source
locks. Compiler intermediates stay under `build/` and may be pruned only after
the build exits; keep the final executable, identity, logs and dependency sources.

`tools/shader_tool.py` encodes protocol 1 requests and runs a separate private
process. Each request explicitly captures stage, complete native instructions,
queried cbuf values, texture properties, workgroup and host capabilities. Missing
answers fail translation. The tool never substitutes a zero cbuf, assumed 2D
texture or guessed workgroup. Inputs, compiler diagnostics, SPIR-V and reflection
remain in a fresh private job directory. Binary/source identity, stage and word
stream bounds are checked before a successful receipt is written.

Current scope is experimental vertex/fragment/compute translation. Reflection
lists resource descriptors and source locations. SPIR-V checks currently prove
structure only, not semantic validity or compatibility with an enabled Vulkan
pipeline. Graphics runtime state, full descriptor binding, shader conformance,
game shader capture and actual draw/compute/presentation integration remain
required. A synthetic translated shader is not a rendered game frame.

The pinned backend currently emits `ImageGatherExtended` even for trivial
programs. Vulkan requires the corresponding `shaderImageGatherExtended` feature
to be enabled before a module declares that capability. The production parent
currently enables no optional device features, so its renderer must reject such
modules until a separate supported feature declaration is queried and enabled.
Physical support and a successful driver return alone are insufficient.
See the [Vulkan feature requirements](https://docs.vulkan.org/spec/latest/chapters/features.html).

Private research translated two source-hashed packaged SceneMaterial stage
candidates under a declared offline environment, with no constant/texture query
answers supplied. A separate prototype explicitly queried/enabled the required
feature and created their graphics pipeline on both compilers. No draw commands
were submitted. These results are not original draw-state capture, a production
pipeline, shader conformance or a game frame.

The opt-in resource profile now creates a separate owned renderer device after
querying/enabling `shaderImageGatherExtended` and `samplerAnisotropy`. That child
has the required declaration for the pinned tool's gather capability; the parent
baseline still has none. Actual program capture, remaining module capabilities,
descriptor/graphics state and shader execution still need separate verification.
