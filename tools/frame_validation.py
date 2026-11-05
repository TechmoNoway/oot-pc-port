"""Synthetic hash-bound framed callers, reference execution, and negative guards."""

import argparse
from ctypes import POINTER, Structure, byref, c_char_p, c_int, c_size_t, c_uint8, c_uint32, c_uint64, c_void_p, create_string_buffer, cast
from dataclasses import replace
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import random

from dispatcher_validation import CALLER, EXIT, STACK_LOW, STACK_SIZE, STACK_HIGH, CodeHash, LeafFunction, Reference, Report, bindings
from input_formats import require
from leaf_validation import leaf_programs, remainder, rotate
from lifter_validation import compile_library
from lifter_validation_types import Memory, Program, State
from prepare_registry import emit_factory
from prepare_runtime import HEADER, REGION, MAGIC

ROOT = Path(__file__).resolve().parent.parent


class FrameStep(Structure):
    _fields_ = [("kind", c_uint32), ("reserved", c_uint32), ("callee", c_uint64)]


class FrameFunction(Structure):
    _fields_ = [("entry", c_uint64), ("instruction_count", c_uint32), ("max_steps", c_uint32),
                ("abi_version", c_uint32), ("policy_version", c_uint32), ("run", c_void_p),
                ("steps", POINTER(FrameStep)), ("hash", CodeHash)]


def frame_bindings(lib):
    bindings(lib)
    lib.oot_runtime_open.argtypes, lib.oot_runtime_open.restype = [c_char_p, c_char_p, c_size_t], c_void_p
    lib.oot_runtime_close.argtypes, lib.oot_runtime_close.restype = [c_void_p], None
    lib.oot_runtime_memory.argtypes, lib.oot_runtime_memory.restype = [c_void_p], POINTER(Memory)
    lib.oot_frame_create.argtypes = [c_void_p, POINTER(FrameFunction), POINTER(LeafFunction), c_size_t,
        POINTER(CodeHash), POINTER(c_uint8), POINTER(c_uint64), c_size_t, POINTER(c_uint32)]
    lib.oot_frame_create.restype = c_void_p
    lib.oot_frame_destroy.argtypes, lib.oot_frame_destroy.restype = [c_void_p], c_int
    lib.oot_frame_begin.argtypes, lib.oot_frame_begin.restype = [c_void_p, POINTER(State), c_uint64, POINTER(Report)], c_int
    lib.oot_frame_run.argtypes, lib.oot_frame_run.restype = [c_void_p, POINTER(State), c_uint64, POINTER(Report)], c_int
    lib.oot_frame_abort.argtypes, lib.oot_frame_abort.restype = [c_void_p, POINTER(Report)], c_int
    lib.oot_create_bound_registry.argtypes, lib.oot_create_bound_registry.restype = [c_void_p, POINTER(c_uint32)], c_void_p


def synthetic_programs():
    originals = {p.name: p for p in leaf_programs()}
    leaves = [replace(originals[name], name=label, base=CALLER + (i + 1) * 4096, trials=[])
              for i, (name, label) in enumerate((("leaf_remainder", "bound_rem"), ("leaf_mix", "bound_mix")))]
    def call(index, target):
        return 0x94000000 | (((target - (CALLER + index * 4)) // 4) & 0x3FFFFFF)
    root = Program("bound_root", [0xA9BF7BFD, 0x910003FD, call(2, leaves[0].base), 0x91001C00,
        call(4, leaves[1].base), 0xA8C17BFD, 0xD65F03C0], [], base=CALLER,
        frame_leaves={p.base: p.data for p in leaves})
    return leaves, root


def package(programs, data_byte=0):
    # Independent synthetic OOTMEM1 fixture; no ExeFS or captured game bytes.
    text = bytearray(12288)
    for p in programs:
        text[p.base - CALLER:p.base - CALLER + len(p.data)] = p.data
    rows, payloads, cursor = [], [], HEADER.size + 3 * REGION.size
    for base, size, payload, permissions, kind, owner in (
        (CALLER, len(text), bytes(text), 1, 1, b"synthetic"),
        (CALLER + 0x4000, 16, bytes([data_byte]) * 16, 3, 3, b"synthetic"),
        (STACK_LOW, STACK_SIZE, b"", 3, 5, b"stack")):
        rows.append(REGION.pack(base, size, cursor, len(payload), permissions, kind, owner, 0))
        payloads.append(payload); cursor += len(payload)
    body = b"".join(rows + payloads)
    digest = hashlib.sha256(body).digest()
    return HEADER.pack(MAGIC, 1, 3, STACK_HIGH, len(text) + 16 + STACK_SIZE,
        HEADER.size, HEADER.size + 3 * REGION.size, cursor, 0, digest) + body, digest


def run_validation(mode="cmake"):
    leaves, root = synthetic_programs()
    image_bytes, body_hash = package([root, *leaves])
    extra = emit_factory([p.name for p in leaves], body_hash.hex(), [EXIT], root.name)
    extra += '''
static unsigned bad_frame_calls, bad_frame_mode;
OOT_LIFT_EXPORT unsigned oot_bad_frame_count(void) { return bad_frame_calls; }
OOT_LIFT_EXPORT void oot_bad_frame_set(unsigned mode) { bad_frame_mode = mode; }
OOT_LIFT_EXPORT int oot_bad_frame(OotArm64State *s, OotGuestMemory *m, uint64_t b, uint64_t *n)
{
    uint64_t old_pc = s->pc;
    int result;
    ++bad_frame_calls;
    result = oot_lift_bound_root(s, m, b, n);
    if (old_pc == UINT64_C(0x100200004)) {
        switch (bad_frame_mode) {
        case 1: (void)oot_memory_store(m, s->sp, 8, 0); break;
        case 2: s->x[18] ^= 1; break;
        case 3: s->sp += 16; break;
        case 4: s->pc += 4; break;
        case 5: *n = 0; break;
        case 6: result = OOT_LIFT_DISPATCH; break;
        case 7: s->nzcv |= 1; break;
        case 8: s->x[30] ^= 4; break;
        case 9: s->x[29] ^= 16; break;
        }
    }
    return result;
}
'''
    lib, build = compile_library([*leaves, root], mode, extra)
    frame_bindings(lib)
    lib.oot_bad_frame_set.argtypes, lib.oot_bad_frame_set.restype = [c_uint32], None
    lib.oot_bad_frame_count.argtypes, lib.oot_bad_frame_count.restype = [], c_uint32
    directory = ROOT / "build/frame-validation"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{mode}-synthetic.ootmem"
    path.write_bytes(image_bytes)

    def opened(data=image_bytes):
        path.write_bytes(data)
        error = create_string_buffer(192)
        image = lib.oot_runtime_open(str(path).encode(), error, len(error))
        require(image is not None, f"synthetic image rejected: {error.value}")
        return image

    error, report = c_uint32(), Report()
    image = opened()
    context = lib.oot_create_bound_registry(image, byref(error))
    require(context is not None and error.value == 0, f"valid framed registry rejected: {error.value}")
    memory = lib.oot_runtime_memory(image)
    lib.oot_runtime_close(image)  # Context and child dispatcher retain the image.
    reference = Reference([root, *leaves])
    rng = random.Random(0xF4A4E)
    edges = [0, 1, (1 << 64) - 1, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF]
    operands = [(a, b) for a in edges for b in edges] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(64)]
    completed, yields = 0, 0

    def initial(a=10, b=3):
        s = State()
        s.x[:] = [rng.getrandbits(64) for _ in range(31)]
        s.pc, s.sp, s.x[0], s.x[1], s.x[30], s.nzcv = CALLER, STACK_HIGH, a, b, EXIT, rng.randrange(16) << 28
        return s

    def finish(s, schedule):
        nonlocal yields
        for iteration in range(66):
            status = lib.oot_frame_run(context, byref(s), schedule[min(iteration, len(schedule) - 1)], byref(report))
            require(status in (1, 2) and report.error == 0, f"framed run failed: {status} {report.error}")
            if status == 2: return
            yields += 1
        raise ValueError("framed caller failed to terminate")

    try:
        # Preflight rejections must not consume state or prevent a valid begin.
        for field, value, expected_error in (("pc", CALLER + 4, 5), ("sp", STACK_LOW, 8),
                ("sp", STACK_HIGH - 8, 8), ("nzcv", 1, 9)):
            state = initial()
            setattr(state, field, value)
            before = state.values()
            require(lib.oot_frame_begin(context, byref(state), EXIT, byref(report)) == 3 and
                    report.error == expected_error and state.values() == before, "invalid framed entry accepted")
        state = initial()
        state.x[30] = EXIT + 4
        require(lib.oot_frame_begin(context, byref(state), EXIT, byref(report)) == 3 and report.error == 6,
                "wrong initial LR accepted")
        for index, (a, b) in enumerate(operands):
            # Reset all stack bytes, as the reference starts a fresh synthetic thread stack.
            stack = memory.contents.regions[2]
            for i in range(STACK_SIZE): stack.data[i] = 0
            state = initial(a, b)
            rotation = state.x[3]
            expected, count, expected_stack = reference.run(state, 64)
            require(lib.oot_frame_begin(context, byref(state), EXIT, byref(report)) == 0, "framed entry rejected")
            finish(state, ([0, 1], [1], [2], [(1 << 64) - 1])[index % 4])
            formula = rotate((((remainder(a, b) + 7 + 2 * b) & ((1 << 64) - 1)) ^ 0xFFFF), rotation)
            require(state.values() == expected and state.x[0] == formula and report.total_retired == count and
                    bytes(stack.data[:STACK_SIZE]) == expected_stack, "framed caller differs from ARM64 or mathematical result")
            require(lib.oot_frame_run(context, byref(state), 1, byref(report)) == 2 and report.retired_this_call == 0,
                    "framed return was not idempotent")
            completed += 1
        # Ownership, checkpoint, stack, root code, and child code checks across a suspended call.
        state = initial()
        require(lib.oot_frame_begin(context, byref(state), EXIT, byref(report)) == 0, "guard setup failed")
        require(lib.oot_frame_begin(context, byref(state), EXIT, byref(report)) == 3 and report.error == 3,
                "active framed call replaced")
        require(lib.oot_frame_run(context, byref(state), 3, byref(report)) == 1, "guard setup did not enter child")
        checkpoint = bytes(state)
        state.x[0] ^= 1
        require(lib.oot_frame_run(context, byref(state), 1, byref(report)) == 3 and report.error == 7, "tampered registers accepted")
        state = State.from_buffer_copy(checkpoint)
        for region_index, offset, expected_error in ((2, STACK_SIZE - 16, 33), (0, 0, 17), (0, 4096, 17)):
            pointer = memory.contents.regions[region_index].data
            saved = pointer[offset]; pointer[offset] ^= 1
            before = state.values()
            require(lib.oot_frame_run(context, byref(state), 1, byref(report)) == 3 and report.error == expected_error and
                    state.values() == before and report.retired_this_call == 0, "suspended frame accepted changed code/stack")
            pointer[offset] = saved
        finish(state, [1])
        require(report.total_retired == 14, "repaired frame repeated a retired instruction")
        state = initial()
        require(lib.oot_frame_begin(context, byref(state), EXIT, byref(report)) == 0, "abort setup failed")
        lib.oot_frame_run(context, byref(state), 1, byref(report))
        before, stack_before = state.values(), bytes(memory.contents.regions[2].data[:STACK_SIZE])
        require(lib.oot_frame_abort(context, byref(report)) == 0 and state.values() == before and
                bytes(memory.contents.regions[2].data[:STACK_SIZE]) == stack_before, "abort rolled back retired state")
        require(lib.oot_frame_run(context, byref(state), 1, byref(report)) == 3 and report.error == 4,
                "aborted frame resumed")
    finally:
        require(lib.oot_frame_destroy(context) == 1, "framed context did not close")

    # Changed snapshot data keeps code identical but must fail the compiled factory's identity pin.
    changed, _ = package([root, *leaves], data_byte=1)
    image = opened(changed)
    try:
        rejected = lib.oot_create_bound_registry(image, byref(error))
        require(rejected is None and error.value == 16, "registry accepted another image snapshot")
    finally:
        lib.oot_runtime_close(image)

    image = opened()
    try:
        getter = lib.oot_frame_descriptor_bound_root
        getter.argtypes, getter.restype = [], POINTER(FrameFunction)
        descriptor = FrameFunction.from_buffer_copy(getter().contents)
        functions, hashes = (LeafFunction * 2)(), (CodeHash * 2)()
        for i, leaf in enumerate(leaves):
            f = getattr(lib, "oot_leaf_descriptor_" + leaf.name); f.restype = POINTER(LeafFunction)
            h = getattr(lib, "oot_leaf_code_hash_" + leaf.name); h.restype = POINTER(CodeHash)
            functions[i], hashes[i] = f().contents, h().contents
        body, returns = (c_uint8 * 32).from_buffer_copy(body_hash), (c_uint64 * 1)(EXIT)
        hashes[0].bytes[0] ^= 1
        rejected = lib.oot_leaf_dispatcher_create_bound(image, functions, 2, hashes, body, returns, 1, byref(error))
        require(rejected is None and error.value == 17, "wrong code hash accepted")
        hashes[0].bytes[0] ^= 1
        original_entry = functions[1].entry
        functions[1].entry = CALLER + 0x4000  # Keep registry order while testing writable data as code.
        rejected = lib.oot_leaf_dispatcher_create_bound(image, functions, 2, hashes, body, returns, 1, byref(error))
        require(rejected is None and error.value == 17, "data region accepted as executable source")
        functions[1].entry = original_entry
        for field, value in (("abi_version", 0), ("policy_version", 0), ("max_steps", 13), ("instruction_count", 2)):
            invalid = FrameFunction.from_buffer_copy(descriptor)
            setattr(invalid, field, value)
            rejected = lib.oot_frame_create(image, byref(invalid), functions, 2, hashes, body, returns, 1, byref(error))
            require(rejected is None and error.value == 32, "invalid framed registry accepted")
        descriptor.run = cast(lib.oot_bad_frame, c_void_p).value
        for bad_mode, expected_error in enumerate((33, 12, 12, 11, 10, 13, 9, 12, 12), 1):
            lib.oot_bad_frame_set(bad_mode)
            context = lib.oot_frame_create(image, byref(descriptor), functions, 2, hashes, body, returns, 1, byref(error))
            require(context is not None, "native contract fixture could not register")
            try:
                state = initial()
                require(lib.oot_frame_begin(context, byref(state), EXIT, byref(report)) == 0, "contract setup failed")
                require(lib.oot_frame_run(context, byref(state), 1, byref(report)) == 1, "frame save failed")
                memory = lib.oot_runtime_memory(image)
                before, saved = state.values(), bytes(memory.contents.regions[2].data[:STACK_SIZE])
                require(lib.oot_frame_run(context, byref(state), 1, byref(report)) == 4 and report.error == expected_error and
                        state.values() == before and bytes(memory.contents.regions[2].data[:STACK_SIZE]) == saved,
                        f"invalid framed callback committed changes: mode {bad_mode}")
                old_calls = lib.oot_bad_frame_count()
                require(lib.oot_frame_run(context, byref(state), 10, byref(report)) == 4 and lib.oot_bad_frame_count() == old_calls,
                        "failed framed callback was executed again")
                require(lib.oot_frame_abort(context, byref(report)) == 0 and state.values() == before,
                        "failed framed callback could not be aborted")
            finally:
                lib.oot_frame_destroy(context)
    finally:
        lib.oot_runtime_close(image)
    report_data = {"schema_version": 1, "result": "passed", "synthetic_only": True, "game_code_executed": False,
        "profile": "linear-fp-lr-caller-v1", "framed_cases": completed, "budget_yields": yields,
        "identity_and_fault_guards": ["snapshot_hash", "code_hash", "text_only_range", "checkpoint", "stack_bytes",
            "root_code_resume", "callee_code_resume", "retained_image_lifetime", "staged_write_rollback", "fault_latch", "abort_prefix",
            "entry_preconditions", "registry_metadata", "protected_registers", "instruction_count", "instruction_status", "instruction_edge"],
        "native_fault_cases": 9, "body_sha256": body_hash.hex(), "reference": {"unicorn": version("unicorn")}, "native_build": build}
    destination = directory / f"{mode}-report.json"
    destination.write_text(json.dumps(report_data, indent=2) + "\n", encoding="utf-8")
    return report_data, destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", choices=("cmake", "gcc"), default="cmake")
    args = parser.parse_args()
    report, path = run_validation(args.compiler)
    print(json.dumps({"result": report["result"], "framed_cases": report["framed_cases"], "report": str(path)}))
