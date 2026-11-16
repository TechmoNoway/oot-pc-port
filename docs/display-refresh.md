# Default Display refresh capability

The separate `--refresh` opt-in requires `--events --objects` and the existing
host-linked application/display chain. Ordinary object and event profiles keep
their existing declarations and stop at the same guards. The new compiled
declaration uses flags 3; program/context flags and the 4096 binding limit stay
unchanged. Handler 457 is a whole-public-function replacement with a void ABI.

The exact-build source audit derives the public default Display identity, its
`DefaultDisplay::Get` route, W1 bit-zero conversion and the original 120 Hz
argument. It reconstructs the callback from the original VI2 constructor, checks
its complete canonical unwind extent/control targets, then reconstructs the
lower callback from the original initializer's ADR stores and table header.
That callback sends command 0x13d with the pair `(enabled ? 2 : 0, 2)`.
These are capability declaration fields; they do not request a physical Windows
mode switch. The 22 non-const named VI/VI2 refresh consumers are checked again
and remain closed except this one public API. Two const DefaultDisplay refresh
consumers remain closed by the inherited complete VI audit. Both private backend
callbacks are source-bound guards, never fake
exports or newly executable native callbacks. No SDK IPC session is created.

The owner records the logical capability for its existing live default Display.
Invalid default-display identities follow the public function's void no-op
branch and are counted separately. Valid calls require a live owned display and
the unchanged complete table/live-vptr checks. Calls preserve every GPR, SP,
NZCV, vector register and FP state, with PC returning to the checked original LR.
Thread, ownership, metadata and counter failures preserve state and counters.
The report exposes capability bits, the last update mask, accepted updates and
ignored identities separately from the existing object report. It does not
report a negotiated rate, changed desktop mode or rendered game frame.

Synthetic owner and actual generated dispatcher tests exercise both boolean
values, noncanonical upper input bits, invalid identities, absent ownership,
vptr/thread/counter faults, full vector preservation, service lifecycle and
quanta 1/2/1000. The full milestone retains every earlier lane and requires
independent MSVC/GCC full/compact and accelerated/single-step trace agreement.
Its progress proof reconstructs the entire former terminal guard prefix and
requires the next original caller instruction to retire after handler 457.

Validation and delivery results are recorded in `docs/agent-handoff.md` and the
ignored milestone delivery receipt. A successful capability declaration alone
does not establish NVN initialization, a frame or usable input.
