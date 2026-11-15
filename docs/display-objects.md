# Default Display and Layer ownership

The separate object profile uses program flags 510 and context flag 4096 over
the existing display/application chain. It adds five whole-public-function
bindings: OpenDefaultDisplay, CloseDisplay, the reached default CreateLayer
overload, DestroyLayer and GetNativeWindow. Earlier constructors, budgets,
transfer sizes and the 4096-entry registry limit remain unchanged.

The source audit accepts one explicitly reviewed SDK build. It derives original
static identities, default dimensions, full public bodies, exact callee PLTs,
constructor materializations and the native-window member's identity return.
The final default Layer is a LayerWithHistory; its embedded recorder and VI2
native-window consumers extend the closure to eight vtables, 103 slots and 85
distinct targets. Every unsupported target has an original body/extent guard.
Anonymous targets retain private unwind provenance without invented ELF exports.
The resulting registry contains 2833 entries, including the five typed bindings.

Generated declarations bind package identity, original code, complete relocated
table hashes, bounded static spans and five vptrs. Original SDK constructors
remain guest execution. Every object call checks their live vptrs and tables;
neither source pointers nor HWND/Vulkan handles are substituted for each other.

An opened Display retains a queried real primary monitor. A Layer owns a separate
visible borderless Win32 window and Vulkan surface with actual presentation
support and verified client dimensions/DPI. The older initializer's hidden
surface remains independent. Decorated windows can be constrained by Windows'
tracking limits: the physical 1920x1080 test exposed a 1920x1061 client area.
Borderless creation supplies the requested client area without weakening the
dimension check. Creation and teardown run on the creator thread; child peers
retain parents until their own teardown.

Outputs are fully preflighted against object/table aliases, then committed
through checked memory. Resource failures roll back new candidates. Native
counters and other guest bytes/registers remain unchanged on faults. Repeated
Display opens own references; repeated default Layer creation returns its
source-proved already-open result and null output. The native-window getter
returns the original constructed interior identity. Unsupported receiver/lifetime
combinations remain diagnostic boundaries.

Synthetic MSVC/GCC fixtures cover publication, provenance/vptr mutation, ABI and
vector preservation, yields/quotas, rollback, parent lifetimes, wrong-thread
calls and actual generated factory rejection by older profiles. A separate
physical probe links production translation units through public headers,
creates a real 1920x1080 surface and observes 16 DXGI VBlank waits/resets on each
compiler. It is an explicit hardware observation, outside synthetic CI.

The production declaration leaves SystemEvent support disabled. Its per-owner
event/token implementation has synthetic lifecycle and sparse-record tests, but
the complete original producer/OS consumer proof is still required before
handler 456 or its scoped kernel services can be used by a generated game
profile. No arbitrary handle or generic timer is published to the guest.

The fresh `build/milestones/display-objects-v1/validation-v2/` run passes all 56
stages, 742 Python tests without skips, eight CTest groups and 283401 common
native/reference comparisons per compiler. It finished 2026-11-15 23:23:00 UTC.
Its current source/configuration gate matches
`39d2d6a0a2acf170f2118aeb40ce8563a91f89e3ad6f01dafd92c0e4b73f88f1`.
Both full original replays open Display and Layer, reach guarded
GetDisplayVsyncEvent after 311502 post-entry instructions and perform 54 native
calls. They agree with compact/accelerated execution at digest
`245009909241218c8095aad733c646bab258491881bad62fb83eaea67fc8b4e7`,
1833254 trace rows and 1833199 retired instructions (51 project scaffolding).
Each proof restores the historical OpenDefaultDisplay guard into the entire old
trace hash, observes four original constructor/materialization steps and retires
each original caller continuation. Both earlier full display digests remain
`e330868f9e2bbdff0c7bf2b88258ecac138974fd33c7303b8ca2147d1a98bc21`.

The first full attempt is preserved as failed after GCC exposed a legacy fixture
loading windows.h before declaring the required Win32 API version. The fixture
was fixed and the successful second attempt reran all validation. No test outcome
from the failed attempt was promoted. The parent `local-config.json` adapts the
public milestone template to this machine's preserved historical input layout;
`delivery.json` records the subsequent commit, remote and CI state.

Guest events, refresh capability queries and the reached NVN dependency remain
the next integration work. Window/surface readiness and desktop VBlank are not
original rendered game frames or usable game input.
