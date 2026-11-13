# Next native Display/Layer task plan

This is future work. First finish/read the current 50-stage VI initialization result
in [the handoff](../../agent-handoff.md). Preserve its frozen source and all earlier
profiles. User authorization is independent implementation with Fritchii/Hookshot
as references only; no fake handles, source patches, PAC stripping or budget growth.

## Verified facts and limits

The reached OpenDefaultDisplay wrapper has an8-byte output and W0 Result. It
derives an original static Display, calls Display::Open and publishes that pointer
only on success. The reached default CreateLayer overload uses an original static
Layer, checks IsOpen/default Display identity, builds local settings and calls
Layer::Open before publishing its identity. It does not allocate a Layer through
callbacks. Archived original constructor trace proves that Layer receiver was
constructed before VI initialization. Do not invent an arena for this exact path.

Display::Open/Close are source-backed refcount/virtual operations. A proved pointer
is not a host resource. Native success requires a real per-context monitor/display/
layer peer, lifetime and output commit, with all unsupported consumers closed.

The Layer native-window member is ADD(this+offset) plus a relocation-backed PLT
tail to GS GetNativeWindowHandle, whose body is identity RET. The public getter
stores that pointer and returns W0 zero. These roles are privately observed; do
not commit addresses/words or cast HWND/VkSurfaceKHR into guest pointers.

The four related vtables have53 slots: DefaultDisplay9, Layer3, LayerNativeWindow36
and listener5. Forty-two slots lack function exports, including repeated targets;
every inspected target has a canonical observed FDE entry/range. Raw exported
consumer census alone cannot close those private virtual consumers. Confirm unique
targets, aliases, relocations and pre-frontier execution before adding guards.

## Ordered implementation tasks

1. Verify the current checkout, live/full validation, delivered SHA and private
   prepared-input identities. Read the actual native guard/caller and current
   source audit; do not assume an older note is still the frontier.
2. Audit default Display construction, both public static identity routes, the
   default Layer constructor receiver, actual vtables, exact callee PLTs and W/X
   output/return roles. Inspect default settings, visibility/fullscreen/dimensions,
   close/refcount and actual main consumers. Keep source observations private.
3. Design the smallest per-context host peer backed by the existing real window/
   surface and an actually queried Win32 monitor. The hidden1280x720 probe is not
   a guest capability. Prove actual dimensions/DPI/visibility before presentation.
   Prefer source-bound existing identities; never steal the original heap.
4. Add a narrow checked original vtable/FDE provenance path if private guards are
   needed. Preserve the old discovery/parser contracts. Validate record bounds,
   CIE version/augmentation/pointer encoding, exact table/FDE entry agreement,
   text extents, aliases, relocations and source hashes. Reject unknown forms.
   Do not label a synthetic name as an ELF export or guess a function size.
5. Before exposing polymorphic objects, close every unsupported public/private
   consumer family. Check whether new guard entries occur earlier in the verified
   trace or overlap mandatory goals/retained constructors; preserve legitimate
   original prefix execution. Keep the4096 registry limit unchanged.
6. Specify a trusted source declaration/context binding for source-derived static
   identities and exact original body/data provenance. Cold/older profiles must
   not accidentally admit object handlers. No guest option may choose arbitrary
   identities. Define live/closed/foreign input behavior and retained image lifetime.
7. TDD native OpenDefaultDisplay using independent synthetic source/memory and
   Win32 mocks. Preflight the entire8-byte output and aliases/counters, query a
   real peer, then atomically publish output/state/counters using the existing
   serialized backend. Return source-proved success only for actual behavior;
   unknown errors stay unsupported. Preserve full other GPR/vector/FP state.
8. Implement the smallest coherent default Layer/open/close/getter subset backed
   by real resources and source-proved settings. Test repeat/lifetime, wrong image,
   input/output faults, rollback, creator-thread ownership, actual dispatch/yields
   and complete state. Do not call guest callbacks through native pointer casts.
9. Inspect GetDisplayVsyncEvent through actual SystemEvent layout and duplicate/
   wait/close consumers. Research primary Windows timing/presentation contracts.
   A generic timer/event is insufficient proof of vsync; no dummy handle or
   always-success wait. Scope this as a separate dependency if needed.
10. Use a separate source candidate for bounded original compiler pilots. Require
    both native full trace hashes, exact historical native frontier/prefix crossing,
    source-bound events and original return/continuation, with unchanged inputs,
    quotas and budgets. Whole-parent elision may lower counts. Observe the real
    next unsupported API; never force a guessed endpoint.
11. Promote reviewed code only after actual-tree RED/GREEN and meaningful focused
    checks, then run a fresh full milestone/source gate. Update the handoff with
    exact status, counts, digest, commit/remote/CI and remaining work. Commit/push
    dev within the standing authorization. Hardware readiness is not a frame.

NVN follow-up: the original bootstrap routes resolve a table of735 named entries,
all with privately observed canonical FDE extents. Names alone do not prove ABI,
features, object layout or ownership. Device initialization, actual required flags/
properties, pools, shaders, commands, presentation and input remain substantial
work. Do not infer Switch2 ABI from Switch1 references or import reference-project
implementation. Use the recovered original source, owned real behavior and primary
API documentation; complete original frames/input before claiming a running game.
