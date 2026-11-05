"""Synthetic multi-frame locals, direct-call DAGs, and transactional fault checks."""

import argparse
from ctypes import POINTER, Structure, byref, c_size_t, c_uint8, c_uint32, c_uint64, c_void_p, cast, create_string_buffer, memset, string_at
from dataclasses import replace
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import random

from arm64_lifter import U64
from dispatcher_validation import CALLER, EXIT, STACK_LOW, STACK_SIZE, STACK_HIGH, CodeHash, LeafFunction, Reference, Report
from frame_validation import frame_bindings
from input_formats import require
from leaf_validation import leaf_programs, remainder, rotate, signed
from lifter_validation import compile_library
from lifter_validation_types import Program, State
from pair_validation import pair
from prepare_registry import emit_stack_factory
from prepare_runtime import HEADER, REGION, MAGIC
from stack_verifier import emit_stack_descriptor, verify_stack_functions

ROOT = Path(__file__).resolve().parent.parent


class StackStep(Structure):
    _fields_ = [("kind", c_uint32), ("offset", c_uint32), ("size", c_uint32), ("reserved", c_uint32), ("callee", c_uint64)]


class StackFunction(Structure):
    _fields_ = [("entry", c_uint64), ("instruction_count", c_uint32), ("max_steps", c_uint32),
        ("abi_version", c_uint32), ("policy_version", c_uint32), ("frame_size", c_uint32), ("max_depth", c_uint32),
        ("run", c_void_p), ("steps", POINTER(StackStep)), ("hash", CodeHash)]


def stack_bindings(lib):
    frame_bindings(lib)
    lib.oot_stack_create.argtypes = [c_void_p, POINTER(StackFunction), c_size_t, c_uint64,
        POINTER(LeafFunction), c_size_t, POINTER(CodeHash), POINTER(c_uint8), POINTER(c_uint64), c_size_t, POINTER(c_uint32)]
    lib.oot_stack_create.restype = c_void_p
    for name in ("begin", "run", "abort", "destroy"):
        getattr(lib, "oot_stack_" + name).restype = c_uint32
    lib.oot_stack_begin.argtypes = [c_void_p, POINTER(State), c_uint64, POINTER(Report)]
    lib.oot_stack_run.argtypes = [c_void_p, POINTER(State), c_uint64, POINTER(Report)]
    lib.oot_stack_abort.argtypes = [c_void_p, POINTER(Report)]
    lib.oot_stack_destroy.argtypes = [c_void_p]


def scalar(size, load, rt, rn, offset, signed_load=False):
    scale = size.bit_length() - 1
    return (scale << 30) | 0x39000000 | ((2 if signed_load else int(load)) << 22) | ((offset // size) << 10) | (rn << 5) | rt


def add(rd, rn, rm):
    return 0x8B000000 | (rm << 16) | (rn << 5) | rd


def framed(name, base, size, body):
    return Program(name, [pair(2, False, 29, 30, 31, 3, -size // 8), 0x910003FD,
        *body, pair(2, True, 29, 30, 31, 1, size // 8), 0xD65F03C0], [], base=base)


def call(base, index, target):
    return 0x94000000 | (((target - (base + index * 4)) // 4) & 0x3FFFFFF)


def synthetic_programs():
    originals = {p.name: p for p in leaf_programs()}
    leaves = [replace(originals[name], name="stack_" + name, trials=[], base=CALLER + (i + 3) * 4096)
        for i, name in enumerate(("leaf_remainder", "leaf_mix"))]
    middle, deep = CALLER + 4096, CALLER + 8192
    root = framed("stack_root", CALLER, 64, [pair(2, False, 0, 1, 31, 2, 2), scalar(8, False, 3, 31, 32),
        call(CALLER, 4, middle), scalar(8, False, 0, 29, 48), pair(2, True, 0, 1, 31, 2, 2),
        call(CALLER, 7, middle), scalar(8, True, 4, 29, 48), add(0, 0, 4), pair(2, True, 4, 1, 31, 2, 2),
        scalar(8, True, 3, 29, 32), scalar(1, False, 0, 31, 40), scalar(1, True, 6, 29, 40), add(0, 0, 6),
        call(CALLER, 15, leaves[1].base), scalar(8, False, 0, 29, 48), scalar(8, True, 0, 31, 48)])
    mid = framed("stack_mid", middle, 48, [pair(2, False, 0, 1, 29, 2, 2), call(middle, 3, deep),
        pair(2, True, 4, 5, 31, 2, 2), add(0, 0, 4), scalar(4, True, 6, 29, 24), add(0, 0, 6),
        scalar(4, False, 0, 31, 40), scalar(4, True, 7, 29, 40, True)])
    inner = framed("stack_deep", deep, 32, [scalar(2, False, 0, 29, 16), call(deep, 3, leaves[0].base),
        scalar(2, True, 2, 29, 16, True), add(0, 0, 2), pair(0, False, 2, 1, 31, 2, 6), pair(1, True, 8, 9, 29, 2, 6)])
    return [root, mid, inner], leaves


def depth_programs(count=16, size=256):
    result = []
    for i in range(count):
        base = CALLER + i * 0x10000
        result.append(framed(f"depth_{i}", base, size, [call(base, 2, base + 0x10000)] if i + 1 < count else []))
    return result


def package(programs):
    extent = max(p.base - CALLER + len(p.data) for p in programs)
    text = bytearray((extent + 4095) & ~4095)
    for p in programs: text[p.base - CALLER:p.base - CALLER + len(p.data)] = p.data
    cursor = HEADER.size + 2 * REGION.size
    rows = [REGION.pack(CALLER, len(text), cursor, len(text), 1, 1, b"synthetic", 0),
        REGION.pack(STACK_LOW, STACK_SIZE, cursor + len(text), 0, 3, 5, b"stack", 0)]
    body = b"".join(rows) + text
    digest = hashlib.sha256(body).digest()
    return HEADER.pack(MAGIC, 1, 2, STACK_HIGH, len(text) + STACK_SIZE, HEADER.size, cursor,
        cursor + len(text), 0, digest) + body, digest


def run_validation(mode="cmake"):
    frames, leaves = synthetic_programs()
    chain = depth_programs()
    code = {p.base: p.data for p in frames}
    proofs = verify_stack_functions(code, {p.base: p.data for p in leaves}, CALLER)
    chain_proofs = verify_stack_functions({p.base: p.data for p in chain}, {}, CALLER)
    blob, digest = package(frames + leaves)
    deep_blob, deep_digest = package(chain)
    extra = "\n".join(emit_stack_descriptor(proofs[p.base], "oot_lift_" + p.name) for p in frames)
    extra += "\n" + "\n".join(emit_stack_descriptor(chain_proofs[p.base], "oot_lift_" + p.name) for p in chain)
    extra += emit_stack_factory([p.name for p in frames], [p.name for p in leaves], CALLER, digest.hex(), [EXIT])
    extra += emit_stack_factory([p.name for p in chain], [], CALLER, deep_digest.hex(), [EXIT]).replace(
        "oot_create_bound_registry", "oot_create_depth_registry")
    extra += '''
static unsigned bad_stack_mode, bad_stack_calls;
static OotStackDispatcher *reentry_context;
OOT_LIFT_EXPORT void oot_bad_stack_set(unsigned mode, OotStackDispatcher *context) { bad_stack_mode = mode; reentry_context = context; }
OOT_LIFT_EXPORT unsigned oot_bad_stack_count(void) { return bad_stack_calls; }
OOT_LIFT_EXPORT int oot_bad_stack(OotArm64State *s, OotGuestMemory *m, uint64_t budget, uint64_t *n)
{
    uint64_t pc = s->pc;
    int result;
    ++bad_stack_calls;
    result = oot_lift_stack_root(s, m, budget, n);
    if (pc == UINT64_C(0x100200008)) {
        switch (bad_stack_mode) {
        case 1: (void)oot_memory_store(m, s->sp + 40, 8, 1); break;
        case 2: (void)oot_memory_store(m, s->sp, 8, 0); break;
        case 3: s->x[18] ^= 1; break;
        case 4: s->pc += 4; break;
        case 5: *n = 0; break;
        case 6: result = OOT_LIFT_DISPATCH; break;
        case 7: s->sp += 16; break;
        case 8: (void)oot_memory_store(m, s->sp - 8, 8, 0); break;
        case 9: s->x[30] ^= 4; break;
        case 10: {
            OotLeafReport r;
            if (oot_stack_run(reentry_context, s, 1, &r) != OOT_LEAF_REJECTED || r.error != OOT_LEAF_REENTRY ||
                oot_stack_begin(reentry_context, s, 0, &r) != OOT_LEAF_REJECTED || r.error != OOT_LEAF_REENTRY ||
                oot_stack_abort(reentry_context, &r) != OOT_LEAF_REJECTED || r.error != OOT_LEAF_REENTRY ||
                oot_stack_destroy(reentry_context) != 0) s->x[18] ^= 1;
            break;
        }
        }
    }
    return result;
}
'''
    lib, build = compile_library(frames + leaves + chain, mode, extra)
    stack_bindings(lib)
    lib.oot_create_depth_registry.argtypes, lib.oot_create_depth_registry.restype = [c_void_p, POINTER(c_uint32)], c_void_p
    lib.oot_bad_stack_set.argtypes, lib.oot_bad_stack_set.restype = [c_uint32, c_void_p], None
    lib.oot_bad_stack_count.argtypes, lib.oot_bad_stack_count.restype = [], c_uint32
    directory = ROOT / "build/stack-validation"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{mode}-synthetic.ootmem"

    def opened(data):
        path.write_bytes(data)
        message = create_string_buffer(192)
        image = lib.oot_runtime_open(os.fsencode(path), message, len(message))
        require(image is not None, f"synthetic stack package rejected: {message.value}")
        return image

    error, report = c_uint32(), Report()
    image = opened(blob)
    context = lib.oot_create_bound_registry(image, byref(error))
    require(context is not None, f"valid stack DAG rejected: {error.value}")
    memory = lib.oot_runtime_memory(image)
    lib.oot_runtime_close(image)  # A live bound context owns the remaining references.
    stack = memory.contents.regions[1].data
    rng = random.Random(0x57ACDA6)
    reference = Reference(frames + leaves)
    edges = [0, 1, U64, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 0x8000, 0x80000000, 0xFFFFFFFF]
    operands = [(a, b) for a in edges for b in edges] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(64)]
    yields = 0
    prefix_checks = 0

    def initial(a=10, b=3):
        state = State()
        state.x[:] = [rng.getrandbits(64) for _ in range(31)]
        state.pc, state.sp, state.x[0], state.x[1], state.x[30], state.nzcv = CALLER, STACK_HIGH, a, b, EXIT, rng.randrange(16) << 28
        return state

    def finish(state, schedule=(1,)):
        nonlocal yields
        for i in range(200):
            status = lib.oot_stack_run(context, byref(state), schedule[min(i, len(schedule) - 1)], byref(report))
            require(status in (1, 2) and report.error == 0, f"valid stack run rejected: {status} {report.error} PC={state.pc:x}")
            if status == 2: return
            yields += 1
        raise ValueError("stack DAG did not terminate")

    try:
        for field, value, reason in (("pc", CALLER + 4, 5), ("sp", STACK_LOW, 8),
                ("sp", STACK_HIGH - 8, 8), ("nzcv", 1, 9)):
            state = initial(); setattr(state, field, value)
            before = state.values()
            require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 3 and
                    report.error == reason and state.values() == before, "invalid stack entry accepted")
        state = initial(); state.x[30] = EXIT + 4
        require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 3 and report.error == 6,
                "unapproved stack return accepted")
        for index, (a, b) in enumerate(operands):
            memset(stack, 0, STACK_SIZE)
            state = initial(a, b)
            start = bytes(state)
            rotation = state.x[3]
            expected, retired, expected_stack = reference.run(state, 200)
            value = (2 * (remainder(a, b) + signed(a, 16) + a + (b & 0xFFFFFFFF))) & U64
            formula = rotate((((value + (value & 255) + 2 * b) & U64) ^ 0xFFFF), rotation)
            require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "valid stack begin rejected")
            finish(state, ((0, 1), (1,), (3,), (U64,))[index % 4])
            require(state.values() == expected and bytes(stack[:STACK_SIZE]) == expected_stack and
                report.total_retired == retired == proofs[CALLER]["max_retired_instructions"] and state.x[0] == formula,
                "stack DAG differs from ARM64 or independent formula")
            require(lib.oot_stack_run(context, byref(state), 0, byref(report)) == 2 and report.retired_this_call == 0,
                    "completed stack return not idempotent")
            if index < 4:
                state = State.from_buffer_copy(start)
                memset(stack, 0, STACK_SIZE)
                for register, value in zip(reference.ids, state.x): reference.engine.reg_write(register, value)
                reference.engine.reg_write(reference.regs.UC_ARM64_REG_SP, state.sp)
                reference.engine.reg_write(reference.regs.UC_ARM64_REG_NZCV, state.nzcv)
                reference.engine.mem_write(STACK_LOW, bytes(STACK_SIZE))
                require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "prefix begin rejected")
                for step in range(retired):
                    reference.engine.emu_start(state.pc, EXIT, count=1)
                    status = lib.oot_stack_run(context, byref(state), 1, byref(report))
                    expected_prefix = (tuple(reference.engine.reg_read(r) for r in reference.ids),
                        reference.engine.reg_read(reference.regs.UC_ARM64_REG_SP),
                        reference.engine.reg_read(reference.regs.UC_ARM64_REG_PC),
                        reference.engine.reg_read(reference.regs.UC_ARM64_REG_NZCV))
                    require(status == (2 if step + 1 == retired else 1) and report.total_retired == step + 1 and
                        state.values() == expected_prefix and bytes(stack[:STACK_SIZE]) == bytes(reference.engine.mem_read(STACK_LOW, STACK_SIZE)),
                        "single-instruction frame/call prefix differs from ARM64")
                    prefix_checks += 1
        state = initial()
        require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "ownership setup rejected")
        require(lib.oot_stack_run(context, byref(state), 13, byref(report)) == 1, "nested setup did not yield")
        checkpoint, saved_stack = bytes(state), bytes(stack[:STACK_SIZE])
        for offset in (STACK_SIZE - 64, STACK_SIZE - 64 + 16, STACK_SIZE - 112 + 24, STACK_SIZE - 144 + 16):
            stack[offset] ^= 1
            require(lib.oot_stack_run(context, byref(state), 0, byref(report)) == 3 and report.error == 49 and
                    bytes(state) == checkpoint, "changed active/ancestor stack frame accepted")
            stack[offset] ^= 1
        for offset in (0, 4096, 8192, 12288):
            pointer = memory.contents.regions[0].data
            pointer[offset] ^= 1
            require(lib.oot_stack_run(context, byref(state), 1, byref(report)) == 3 and report.error == 17 and
                    bytes(state) == checkpoint and bytes(stack[:STACK_SIZE]) == saved_stack, "changed active code accepted")
            pointer[offset] ^= 1
        state.x[17] ^= 1
        require(lib.oot_stack_run(context, byref(state), 1, byref(report)) == 3 and report.error == 7, "changed checkpoint accepted")
        state = State.from_buffer_copy(checkpoint)
        finish(state)
        state = initial(); state.sp = STACK_LOW + 64
        require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "tight root stack setup rejected")
        require(lib.oot_stack_run(context, byref(state), 4, byref(report)) == 1, "tight stack prefix failed")
        before, saved = state.values(), bytes(stack[:STACK_SIZE])
        require(lib.oot_stack_run(context, byref(state), 1, byref(report)) == 3 and report.error == 51 and
                state.values() == before and bytes(stack[:STACK_SIZE]) == saved and report.retired_this_call == 0,
                "callee overflow retired its BL or mutated stack")
        require(lib.oot_stack_abort(context, byref(report)) == 0 and state.values() == before and bytes(stack[:STACK_SIZE]) == saved,
                "stack abort undid retired prefix")
    finally:
        lib.oot_stack_destroy(context)

    # Native metadata and deliberately incorrect callbacks use only synthetic code.
    image = opened(blob)
    try:
        table, hashes = (StackFunction * len(frames))(), (CodeHash * len(leaves))()
        leaf_table = (LeafFunction * len(leaves))()
        for i, p in enumerate(frames):
            getter = getattr(lib, "oot_stack_descriptor_" + p.name); getter.restype = POINTER(StackFunction)
            table[i] = getter().contents
        for i, p in enumerate(leaves):
            getter = getattr(lib, "oot_leaf_descriptor_" + p.name); getter.restype = POINTER(LeafFunction)
            leaf_table[i] = getter().contents
            getter = getattr(lib, "oot_leaf_code_hash_" + p.name); getter.restype = POINTER(CodeHash)
            hashes[i] = getter().contents
        body, returns = (c_uint8 * 32).from_buffer_copy(digest), (c_uint64 * 1)(EXIT)

        def create():
            return lib.oot_stack_create(image, table, len(table), CALLER, leaf_table, len(leaves), hashes, body, returns, 1, byref(error))

        for field, value in (("max_depth", 1), ("max_steps", 1), ("frame_size", 17), ("policy_version", 0), ("instruction_count", 129)):
            old = getattr(table[0], field); setattr(table[0], field, value)
            rejected = create()
            require(rejected is None and error.value == 48, "invalid stack metadata accepted")
            setattr(table[0], field, old)
        original_steps = table[0].steps
        owned_steps = (StackStep * table[0].instruction_count).from_buffer_copy(
            string_at(original_steps, table[0].instruction_count * 24))
        table[0].steps = owned_steps
        for index, field, value in ((4, "callee", CALLER), (4, "callee", EXIT), (2, "offset", 0),
                (2, "size", 16 + 64), (2, "reserved", 1), (2, "kind", 0)):
            old = getattr(owned_steps[index], field); setattr(owned_steps[index], field, value)
            rejected = create()
            require(rejected is None and error.value == 48, "invalid call graph/store scope accepted")
            setattr(owned_steps[index], field, old)
        table[0].steps = original_steps
        table[0].run = cast(lib.oot_bad_stack, c_void_p).value
        for bad_mode, expected_error in enumerate((49, 49, 12, 11, 10, 13, 12, 50, 12, 0), 1):
            context = create()
            require(context is not None, "native faulty-stack fixture failed to register")
            lib.oot_bad_stack_set(bad_mode, context)
            try:
                state = initial()
                require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "fault setup rejected")
                require(lib.oot_stack_run(context, byref(state), 2, byref(report)) == 1, "fault prefix rejected")
                pointer = lib.oot_runtime_memory(image).contents.regions[1].data
                before, saved = state.values(), bytes(pointer[:STACK_SIZE])
                status = lib.oot_stack_run(context, byref(state), 1, byref(report))
                if bad_mode == 10:
                    require(status == 1 and report.error == 0, "reentry guards failed")
                else:
                    require(status == 4 and report.error == expected_error and state.values() == before and bytes(pointer[:STACK_SIZE]) == saved,
                            f"faulty local-store callback committed state: mode {bad_mode}")
                    calls = lib.oot_bad_stack_count()
                    require(lib.oot_stack_run(context, byref(state), 10, byref(report)) == 4 and lib.oot_bad_stack_count() == calls,
                            "faulted stack callback was retried")
                require(lib.oot_stack_abort(context, byref(report)) == 0, "faulted stack could not abort")
            finally:
                lib.oot_stack_destroy(context)
    finally:
        lib.oot_runtime_close(image)
    image = opened(deep_blob)
    context = lib.oot_create_depth_registry(image, byref(error))
    require(context is not None, f"maximum-depth registry rejected: {error.value}")
    try:
        state = initial()
        expected, retired, expected_stack = Reference(chain).run(state, 200)
        require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "maximum-depth begin rejected")
        finish(state, (0, 1))
        pointer = lib.oot_runtime_memory(image).contents.regions[1].data
        require(state.values() == expected and bytes(pointer[:STACK_SIZE]) == expected_stack and report.total_retired == retired,
                "maximum-depth/full-stack boundary differs from reference")
    finally:
        lib.oot_stack_destroy(context); lib.oot_runtime_close(image)
    report_data = {"schema_version": 1, "result": "passed", "synthetic_only": True, "game_code_executed": False,
        "profile": "linear-local-stack-dag-v1", "whole_call_cases": len(operands), "budget_yields": yields, "prefix_step_checks": prefix_checks,
        "max_tested_depth": 16, "max_tested_frame": 256, "native_fault_modes": 9,
        "guards": ["active_frame", "ancestor_frame", "local_bytes", "active_code", "ancestor_code", "leaf_code",
            "checkpoint", "callee_stack_overflow", "abort_prefix", "staged_store_scope", "fault_latch", "metadata", "reentry", "image_lifetime"],
        "reference": {"unicorn": version("unicorn")}, "native_build": build}
    destination = directory / f"{mode}-report.json"
    destination.write_text(json.dumps(report_data, indent=2) + "\n", encoding="utf-8")
    return report_data, destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", choices=("gcc", "cmake"), default="cmake")
    args = parser.parse_args()
    report, path = run_validation(args.compiler)
    print(json.dumps({"result": report["result"], "whole_call_cases": report["whole_call_cases"], "report": str(path)}))
