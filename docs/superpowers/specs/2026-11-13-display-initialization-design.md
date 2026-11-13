# Independent native display initialization

The measured graphics frontier is reached inside original `nn::vi::Initialize`,
before OpenDefaultDisplay, CreateLayer and nvnBootstrapLoader in the same original
main caller. The source-bound full trace proves this ordering. GSV's low-level
session protocol is not an NVN resolver dependency at this frontier. Keep the
earlier NVN table research, but solve the reached VI API first.

The user authorized continuing the independent port until real game frames and
usable input. Routine implementation decisions proceed under that instruction.
This step initializes real host display resources; it does not yet implement a
guest Display, Layer, vsync event, swapchain, frame submission or input.

## Chosen boundary

Replacing the low-level GSV session would require its full driver/session object
and handle protocol. Returning null or a dummy success is invalid. Instead,
replace the proved public VI initializer with an owned host display initializer,
reusing the real Vulkan instance/device. This is the smallest higher-level API
whose original entry/caller/void return are already observed. Full native NVN
emulation is further work, not a substitute for the reached display dependency.

Use a separate display opt-in over graphics. Preserve every earlier profile and
the full graphics checkpoint. Bind the original VI/VI2 symbol census and exact
public initializer body before issuing a typed binding. Close unsupported VI/VI2
export consumers; do not expose guest objects or change the original init goal.
The full historical trace contains three original constructor groups (six C1/C2
export aliases) before this entry. Retain their actual vtable/stores and two
relocation-backed constructor calls. Prove the full roles, alias/body agreement
and original vtable symbol/relocation slots; they do not depend on VI boot state.
All other VI/VI2 consumers remain closed. Static discovery grants no authority.

## Resource and ABI ownership

Extend the existing private Vulkan owner with an independently reported display
state. Lazily register a private per-owner Unicode Win32 class, create a hidden
1280x720 window, create a real VkSurfaceKHR for that HWND and require the existing
physical device/queue family to support presentation to this actual surface.
The dimensions are an internal surface probe, not guest display capabilities.
Only publish readiness after all resources and the support query succeed. Do
not return HWND/VkSurfaceKHR/host addresses to the guest. A future Layer provider
must establish the actual dimensions and visibility before presentation.

Keep the current graphics report layout intact; add a separate display report.
The public initializer has no result consumed by its original caller. Preserve
the complete GPR/vector/FP state and change only PC to the registered LR. Native
calls retire no original instruction. Check both aggregate and provider counters
before resource creation. Repeated initialization is counted and reuses the same
resources; no guessed guest reference-count object is written.

Resolve destruction and query procedures before creation. Never use a failed
creation output handle. On failure destroy only newly acquired surface, window
and class, preserving the existing graphics owner, output state and counters.
Destroy the surface before HWND/class and before the instance. No queue work or
swapchain exists yet. Window creation, display calls and context destruction are
on the same native execution thread, as required by Win32; reject foreign-thread
display calls without effects. Do not create a background thread or message pump
until the first supported visible Layer/presentation operation requires one.

## Evidence and review gates

Synthetic native tests independently mock Win32/Vulkan calls, including every
failure/poisoned output, support false/error, repeat, cold state, count overflow,
full ABI preservation and destruction order. Existing graphics tests remain.
Source-audit tests use independent synthetic symbols/bodies, raw census and
mutations. Registry/profile tests reject crossed flags before execution.

An original pilot must verify the old full native trace and bind its first VI
entry STEP. Restore that STEP at the new native event to recover the entire
historical prefix, including earlier graphics boot. The old CHECK lies inside
the replaced VI body and need not run in the new profile. Require the original
caller continuation and stop honestly at the next unsupported API. Compare both
compilers, full/single-step/accelerated reports and all-row native digests.
Whole-parent replacement can reduce retired counts; continuation/prefix evidence,
not a larger instruction counter, establishes progress past that parent's caller.
No original bytes, traces, assets, generated C or binaries enter Git.

Graphics checkpoint `7434802` has passed all 46 stages and is verified on origin/dev.
The immutable display prototype passes both original compiler full replays with
real display resources, historical entry-prefix restoration and original caller
continuation. Promotion requires focused real-tree checks and a fresh complete
50-stage milestone/source gate; the prototype is not full-tree validation.

Primary API references:
- https://docs.vulkan.org/refpages/latest/refpages/source/vkCreateWin32SurfaceKHR.html
- https://docs.vulkan.org/refpages/latest/refpages/source/vkGetPhysicalDeviceSurfaceSupportKHR.html
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclassexw
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-destroywindow
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unregisterclassw

Use the unmodified Vulkan-Headers Win32 header from the same pinned upstream
revision as the existing API declarations, retaining its Apache-2.0 notices.
