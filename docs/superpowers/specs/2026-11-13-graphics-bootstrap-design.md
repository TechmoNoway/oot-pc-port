# Source-bound native graphics bootstrap

Status: independent prototype passed focused MSVC/GCC tests and both original full-trace pilots. Production integration and a fresh complete milestone remain required. No gameplay claim.

The passed resource pilot reaches the real am graphics-supervisor guard from
inside the SDK GS bootstrap. The low-level wrapper does not establish the
NativeHandle output ABI or the graphics IPC protocol. Do not implement a dummy
supervisor handle. Replace the coherent higher-level bootstrap in a separate
explicit profile, retaining the older application mode and its exact boundary.

## Original evidence

- Original nv::InitializeGraphics preserves X0/X1 and tail-calls the GS boot
  through the unchanged relocation-backed PLT. nn::gs::Initialize is a separate
  four-byte B thunk through the same original PLT/GOT.
- BootGraphicsSystem saves the full X0/X1 working-memory pair and compares both
  on every successful return; mismatched reinitialization aborts. Its successful
  path has no defined scalar return. A native void ABI preserves all GPRs,
  vector/FP state and SP/NZCV, returning only PC to the registered LR.
- CheckGraphicsSystemInitialized is a void precondition: RET when initialized,
  abort otherwise. It is not a bool query.
- The complete skipped-provider census has 233 exports across GS, GSV, NVSrv,
  syncpoint and GPU. Two boot exports and the check have typed handlers.
  Keep the original allocator initializer, its callback getter and the pure
  remote-memory query executing as original code. All three occur before boot
  in the historical full trace; the allocator constructor/callbacks were not
  skipped by replacing the later boot. Guard every other provider export.
  Finalize's original RET does not prove a native backend teardown contract.

## Real ownership

Create an opaque per-context backend lazily at the first successful boot. Load
the Windows Vulkan loader from System32 only, create an actual Vulkan instance
with surface/Win32-surface extensions, select an enumerated physical device and
graphics queue family, create a logical device with swapchain extension, and
obtain queue zero. Readiness requires all owned live handles. Preserve the full
working-memory pair for idempotent calls; never dereference or claim to have
initialized guest SDK globals. Do not expose Vulkan or arbitrary integer handles
to guest code. Destroy device then instance then unload the loader at enclosing
context teardown. No queue work is submitted by bootstrap, so there are no
pending submissions or child objects to drain in this version.

Prepare temporary backend resources and unwind failures before publishing
readiness, counters or output registers. Check counters and complete argument,
register/return and output-alias preconditions before any external allocation.
Repeated equal boot calls reuse the device; mismatched pair and pre-boot check
fail without effects. The context aggregate native-call overflow check precedes
the backend call. Keep backend pointers opaque; snapshots expose metadata only.

Use official Khronos Vulkan-Headers v1.3.296, commit
29f979ee5aa58b7b005f805ea8df7a855c39ff37, retaining unmodified headers and licenses.
The implementation remains independent of Fritchii/Hookshot.

## Validation and integration

Test real public calls against a synthetic private Vulkan function table by
including the implementation in the C test fixture; this does not add a public
fake-backend factory or fallback. Cover allocation/driver failure cleanup,
idempotency, readiness, void ABI, input/output preservation and counter limits.
Run a separately identified real hardware bootstrap/teardown smoke on this host.
Keep these two evidence categories distinct; neither establishes rendering.

Add a graphics-only context flag and program opt-in requiring application and
host-linked initialization. Retain ABI2, old flags62 and contextAPP512 and all
older baselines. Audit the complete original census/text, both thunk routes and
boot/check instruction roles before binding typed handlers and GS guard closure.
Preserve all mandatory original stages/constructor returns and original nnMain
entry. Prove progress at the earlier boot entry, before the historical internal
resource getter; do not demand the old UID event after replacing its parent.
Restore the original first boot STEP into the prefix hash and compare its
verified full original prefix. Native boot retires no original instruction.

The next original boundary must be observed using fresh source-matched pilots.
Do not change original bytes, PAC behavior, service replies or budgets. A real
VkDevice/queue is a bootstrap checkpoint; only original game frames and usable
input can complete the overall user goal.

Primary API contracts:
- https://docs.vulkan.org/refpages/latest/refpages/source/vkCreateInstance.html
- https://docs.vulkan.org/refpages/latest/refpages/source/vkEnumeratePhysicalDevices.html
- https://docs.vulkan.org/refpages/latest/refpages/source/vkCreateDevice.html
- https://docs.vulkan.org/refpages/latest/refpages/source/vkGetDeviceQueue.html
- https://docs.vulkan.org/refpages/latest/refpages/source/vkDestroyDevice.html

## Measured prototype

Both compiler pilots freeze source `e4dca0afedc9d7e998344a981f1a99f8a90d80679fda874ea43d637526cf80d2`. They retire 1,834,711 instructions (51 scaffold), reach 313,014 post-entry instructions, make 52 native calls and report one real boot plus one void check. Full single-step and compact/accelerated traces match digest `13dbf98c07554aa03ec450ac375df72b63eba8db6b6a74ee12848edce4a1b1de`. Both restore the historical first boot STEP to prefix hash `addcc32e3479d27b5f567b72bf9757902539e2606db60ee53617180cd6ae0855`. The real next guard is `nn::gsv::GetUserSession()`. Its session ABI and consumers remain unsupported; never substitute a Vulkan host pointer or arbitrary guest handle. No original game frame or usable input has been observed.

## Completed actual-tree validation

`build/milestones/graphics-bootstrap-v1/` passes all 46 stages on local source
`923350da5db72c117fa8dac40457c008879fdfd370e052c03e8e9c7128556417`:
687 Python tests without skips, seven CTest groups and 283,401 common comparisons
per compiler. Both full graphics traces reproduce the prototype's complete
ordered digest, counter state and historical first-boot prefix, while retaining
the preceding raw/SDK/logging/initialization/resource lanes. Git delivery also
checks source content equivalence under the repository's text line-ending rules.
The reached session guard is inside the original VI initializer. A subsequent
display provider needs its own real host resource ownership and source-bound ABI;
this validation does not turn a device/queue into a rendered game.
