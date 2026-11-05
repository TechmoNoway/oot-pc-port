"""Synthetic split/combined frames, offset records, and allocation ownership."""

import argparse
from ctypes import POINTER, Structure, byref, c_uint8, c_uint32, c_uint64, c_void_p, cast, create_string_buffer, memset, sizeof, string_at
from dataclasses import replace
from importlib.metadata import version
import json
import os
from pathlib import Path
import random

from arm64_lifter import U64
from dispatcher_validation import CALLER, EXIT, STACK_LOW, STACK_SIZE, STACK_HIGH, CodeHash, LeafFunction, Reference, Report
from input_formats import require
from leaf_validation import leaf_programs, remainder, rotate
from lifter_validation import compile_library
from lifter_validation_types import Program, State
from pair_validation import pair
from prepare_registry import emit_stack_factory
from stack_cfg_validation import Assembler, CfgFunction, CfgStep, add_immediate, bindings as cfg_bindings, immediate, mov
from stack_layout_verifier import RECORD_RESTORE, emit_layout_stack_descriptor, verify_layout_stack_functions
from stack_validation import StackStep, add, package, scalar

ROOT = Path(__file__).resolve().parent.parent


class LayoutStep(Structure):
    _fields_ = [("sp", c_uint8), ("fp", c_uint8), ("lr", c_uint8), ("owner", c_uint8)]


class LayoutFunction(Structure):
    _fields_ = [("cfg", CfgFunction), ("states", POINTER(LayoutStep)), ("record_offset", c_uint32), ("reserved", c_uint32)]


def bindings(lib):
    cfg_bindings(lib)
    args = lib.oot_stack_create.argtypes.copy(); args[1] = POINTER(LayoutFunction)
    lib.oot_stack_create_layout.argtypes, lib.oot_stack_create_layout.restype = args, c_void_p


def memory_word(size, load, rt, rn, offset):
    if offset >= 0 and offset % size == 0: return scalar(size, load, rt, rn, offset)
    return ((size.bit_length() - 1) << 30) | 0x38000000 | (int(load) << 22) | ((offset & 511) << 12) | (rn << 5) | rt


class LayoutAssembler(Assembler):
    def __init__(self, name, base, size, record=0, saves=(), split=True, fp_first=True):
        self.name, self.base, self.size = name, base, size
        self.record, self.saves, self.split = record, list(saves), split
        self.labels, self.fixups, self.words = {}, [], []
        if split:
            self.emit(0xD10003FF | (size << 10), pair(2, False, 29, 30, 31, 2, record // 8))
        else:
            self.emit(pair(2, False, 29, 30, 31, 3, -size // 8))
        if fp_first: self.emit(add_immediate(29, 31, record))
        for offset, regs in saves:
            self.emit(pair(2, False, *regs, 31, 2, offset // 8) if len(regs) == 2 else memory_word(8, False, regs[0], 31, offset))
        if not fp_first: self.emit(add_immediate(29, 31, record))

    def finish(self):
        self.label("epilogue")
        for offset, regs in reversed(self.saves):
            delta = offset - self.record
            self.emit(pair(2, True, *regs, 29, 2, delta // 8) if len(regs) == 2 else memory_word(8, True, regs[0], 29, delta))
        if self.split:
            self.emit(pair(2, True, 29, 30, 31, 2, self.record // 8), 0x910003FF | (self.size << 10))
        else:
            self.emit(pair(2, True, 29, 30, 31, 1, self.size // 8))
        self.emit(0xD65F03C0)
        for index, name, opcode, bits in self.fixups:
            delta = (self.labels[name] - index) & ((1 << bits) - 1)
            self.words[index] = opcode | (delta if bits == 26 else delta << 5)
        return Program(self.name, self.words, [], base=self.base)


def synthetic_programs():
    originals = {p.name: p for p in leaf_programs()}
    leaves = [replace(originals[name], name="layout_" + name, trials=[], base=CALLER + (i + 3) * 0x10000)
              for i, name in enumerate(("leaf_remainder", "leaf_mix"))]
    root = LayoutAssembler("layout_root", CALLER, 96, 80, ((48, (19, 20)), (72, (21,))), fp_first=False)
    root.emit(pair(2, False, 0, 1, 31, 2, 0), memory_word(8, False, 3, 29, -64), mov(19, 0), mov(20, 1), mov(21, 3))
    root.branch("zero", 0xB4000000); root.bl(CALLER + 0x10000); root.emit(add(0, 0, 19)); root.branch("join", 0x14000000, 26)
    root.label("zero"); root.emit(immediate(0, 42))
    root.label("join"); root.emit(memory_word(8, True, 1, 29, -72), memory_word(8, True, 3, 29, -64),
        memory_word(8, False, 0, 31, 64), memory_word(8, True, 0, 29, -16))
    root.bl(leaves[1].base)
    child = LayoutAssembler("layout_child", CALLER + 0x10000, 80, 0, ((48, (20, 19)), (72, (28,))))
    child.emit(mov(19, 0), mov(20, 1), mov(28, 3), memory_word(8, False, 19, 31, 16))
    child.bl(CALLER + 0x20000); child.emit(add(0, 0, 19), memory_word(8, False, 0, 31, 64), memory_word(8, True, 0, 29, 64))
    inner = LayoutAssembler("layout_combined", CALLER + 0x20000, 64, 0, ((40, (19,)),), split=False, fp_first=False)
    inner.emit(mov(19, 0), memory_word(8, False, 1, 31, 16)); inner.bl(leaves[0].base)
    inner.emit(memory_word(8, True, 1, 29, 16), add(0, 0, 1), add_immediate(19, 19, 1))
    return [root.finish(), child.finish(), inner.finish()], leaves


def matrix_programs():
    result = []
    specs = [(16, 0, (), True, True), (32, 16, (), True, False),
        (64, 16, ((0, (19,)),), True, True), (64, 32, ((0, (20, 19)), (56, (28,))), True, False),
        (80, 64, ((48, (19, 20)),), True, False), (96, 0, ((40, (19,)), (72, (20, 21))), True, True),
        (256, 240, tuple((128 + i * 16, (19 + i * 2, 20 + i * 2)) for i in range(5)), True, False),
        (64, 0, ((40, (19,)),), False, False), (64, 0, ((48, (20, 19)),), False, True)]
    for index, (size, record, saves, split, fp_first) in enumerate(specs):
        a = LayoutAssembler(f"layout_matrix_{index}", CALLER + (index + 5) * 0x10000, size, record, saves, split, fp_first)
        reserved = [(record, record + 16)] + [(offset, offset + len(regs) * 8) for offset, regs in saves]
        free = next((offset for offset in range(size - 7) if all(offset + 8 <= lo or offset >= hi for lo, hi in reserved)), None)
        if free is not None:
            a.emit(memory_word(8, False, 0, 31, free), memory_word(8, True, 2, 29, free - record))
        else: a.emit(mov(2, 0))
        regs = [r for _, group in saves for r in group]
        for r in regs: a.emit(add_immediate(r, 0, r))
        if regs:
            a.emit(mov(0, regs[0]))
            for r in regs[1:]: a.emit(add(0, 0, r))
        else: a.emit(add_immediate(0, 2, 7))
        a.branch("epilogue", 0x36000001, 14)
        a.emit(add_immediate(0, 0, 3))
        result.append((a.finish(), regs))
    return result


def depth_programs():
    result = []
    for index in range(16):
        base = CALLER + (index + 32) * 0x10000
        a = LayoutAssembler(f"layout_depth_{index}", base, 256, 240 if index % 2 == 0 else 0, split=index % 2 == 0)
        if index != 15: a.bl(base + 0x10000)
        result.append(a.finish())
    return result


def run_validation(mode="cmake"):
    frames, leaves = synthetic_programs(); matrix = matrix_programs(); chain = depth_programs()
    proofs = verify_layout_stack_functions({p.base: p.data for p in frames}, {p.base: p.data for p in leaves}, CALLER)
    singles = {p.base: verify_layout_stack_functions({p.base: p.data}, {}, p.base)[p.base] for p, _ in matrix}
    chain_proofs = verify_layout_stack_functions({p.base: p.data for p in chain}, {}, chain[0].base)
    programs = frames + leaves + [p for p, _ in matrix] + chain
    blob, digest = package(programs)
    extra = "\n".join(emit_layout_stack_descriptor(proofs[p.base], "oot_lift_" + p.name) for p in frames)
    extra += "\n" + "\n".join(emit_layout_stack_descriptor(singles[p.base], "oot_lift_" + p.name) for p, _ in matrix)
    extra += "\n" + "\n".join(emit_layout_stack_descriptor(chain_proofs[p.base], "oot_lift_" + p.name) for p in chain)
    extra += emit_stack_factory([p.name for p in frames], [p.name for p in leaves], CALLER, digest.hex(), [EXIT], layout=True)
    for p, _ in matrix:
        extra += emit_stack_factory([p.name], [], p.base, digest.hex(), [EXIT], layout=True).replace("oot_create_bound_registry", "oot_create_" + p.name)
    extra += emit_stack_factory([p.name for p in chain], [], chain[0].base, digest.hex(), [EXIT], layout=True).replace("oot_create_bound_registry", "oot_create_layout_depth")
    root_proof = proofs[CALLER]
    record_restore = next(i for i, s in enumerate(root_proof["steps"]) if s["kind"] == RECORD_RESTORE)
    modes = [(0, "s->sp += 16;", 12), (0, "uint64_t v = 0; (void)oot_memory_load(m, s->sp, 8, &v); (void)oot_memory_store(m, s->sp, 8, v ^ 1);", 49),
        (1, "(void)oot_memory_store(m, s->sp + 80, 8, 0);", 49), (1, "s->x[29] = s->sp;", 12),
        (4, "s->x[29] = s->sp;", 12), (5, "(void)oot_memory_store(m, s->sp + 80, 8, 0);", 49),
        (record_restore, "s->x[30] ^= 4;", 12), (record_restore, "s->sp += 96;", 12),
        (record_restore + 1, "s->sp -= 16;", 12), (record_restore + 1, "s->x[29] ^= 8;", 12),
        (4, "*n = 0;", 10), (4, "result = OOT_LIFT_DISPATCH;", 13)]
    extra += '''
static unsigned layout_mode, layout_calls;
OOT_LIFT_EXPORT void oot_layout_bad_set(unsigned m) { layout_mode = m; }
OOT_LIFT_EXPORT unsigned oot_layout_bad_count(void) { return layout_calls; }
OOT_LIFT_EXPORT int oot_layout_bad(OotArm64State *s, OotGuestMemory *m, uint64_t b, uint64_t *n)
{
    uint64_t pc = s->pc;
    int result;
    ++layout_calls;
    result = oot_lift_layout_root(s, m, b, n);
    switch (layout_mode) {
'''
    for i, (index, action, _) in enumerate(modes, 1): extra += f"    case {i}: if (pc == UINT64_C(0x{CALLER + 4 * index:x})) {{ {action} }} break;\n"
    extra += "    }\n    return result;\n}\n"
    lib, build = compile_library(programs, mode, extra); bindings(lib)
    lib.oot_layout_bad_set.argtypes, lib.oot_layout_bad_set.restype = [c_uint32], None
    lib.oot_layout_bad_count.argtypes, lib.oot_layout_bad_count.restype = [], c_uint32
    directory = ROOT / "build/stack-layout-validation"; directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{mode}-synthetic.ootmem"; path.write_bytes(blob)
    message, error, report = create_string_buffer(192), c_uint32(), Report()
    image = lib.oot_runtime_open(os.fsencode(path), message, len(message)); require(image is not None, f"layout image rejected: {message.value}")
    memory = lib.oot_runtime_memory(image); stack = memory.contents.regions[1].data
    reference = Reference(programs); trace = []
    from unicorn import UC_HOOK_CODE
    reference.engine.hook_add(UC_HOOK_CODE, lambda _e, pc, _s, _d: trace.append(pc))
    rng = random.Random(0x1A9007)
    prefixes, yields, counts = 0, 0, set()

    def initial(base=CALLER, a=1, b=1):
        s = State(); s.x[:] = [rng.getrandbits(64) for _ in range(31)]
        s.pc, s.sp, s.x[0], s.x[1], s.x[30], s.nzcv = base, STACK_HIGH, a, b, EXIT, rng.randrange(16) << 28
        return s

    def check(context, start, formula, schedule, prefix=False):
        nonlocal prefixes, yields
        state = State.from_buffer_copy(bytes(start)); memset(stack, 0, STACK_SIZE)
        trace.clear(); expected, retired, expected_stack = reference.run(state, 1000)
        require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "layout begin rejected")
        for iteration in range(1000):
            budget = schedule[min(iteration, len(schedule) - 1)]; before = state.values()
            status = lib.oot_stack_run(context, byref(state), budget, byref(report))
            require(status in (1, 2) and not report.error, f"layout run failed {status}/{report.error} pc={state.pc:x}")
            if not budget: require(state.values() == before and report.retired_this_call == 0, "zero layout budget changed state")
            if status == 2: break
            yields += 1
        else: raise ValueError("layout call did not terminate")
        require(state.values() == expected and state.x[0] == formula and bytes(stack[:STACK_SIZE]) == expected_stack and report.total_retired == retired,
                "layout result/state/stack differs from reference/formula")
        require(lib.oot_stack_run(context, byref(state), 1, byref(report)) == 2 and report.retired_this_call == 0, "layout return not idempotent")
        if prefix:
            state = State.from_buffer_copy(bytes(start)); memset(stack, 0, STACK_SIZE)
            for register, value in zip(reference.ids, state.x): reference.engine.reg_write(register, value)
            reference.engine.reg_write(reference.regs.UC_ARM64_REG_SP, state.sp); reference.engine.reg_write(reference.regs.UC_ARM64_REG_NZCV, state.nzcv)
            reference.engine.mem_write(STACK_LOW, bytes(STACK_SIZE))
            require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "layout prefix begin rejected")
            for step in range(retired):
                reference.engine.emu_start(state.pc, EXIT, count=1)
                status = lib.oot_stack_run(context, byref(state), 1, byref(report))
                expected_prefix = (tuple(reference.engine.reg_read(r) for r in reference.ids), reference.engine.reg_read(reference.regs.UC_ARM64_REG_SP),
                    reference.engine.reg_read(reference.regs.UC_ARM64_REG_PC), reference.engine.reg_read(reference.regs.UC_ARM64_REG_NZCV))
                require(status == (2 if step + 1 == retired else 1) and state.values() == expected_prefix and report.total_retired == step + 1 and
                    bytes(stack[:STACK_SIZE]) == bytes(reference.engine.mem_read(STACK_LOW, STACK_SIZE)), "layout prefix differs from ARM64")
                prefixes += 1
        return retired

    context = lib.oot_create_bound_registry(image, byref(error)); require(context is not None, f"layout registry rejected {error.value}")
    try:
        edges = [0, 1, U64, 1 << 63, (1 << 63) - 1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF]
        operands = [(a, b) for a in edges for b in edges] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(64)]
        for index, (a, b) in enumerate(operands):
            start = initial(a=a, b=b)
            value = 42 if not a else remainder(a, b) + b + 2 * a
            formula = rotate((((value + 2 * b) & U64) ^ 0xFFFF), start.x[3])
            counts.add(check(context, start, formula, ((0, 1), (1,), (4,), (U64,))[index % 4], index in (0, 8, 9, 16, 24, 32, 64, 127)))
        require(max(counts) == root_proof["max_retired_instructions"], "layout maximum path not exercised")
        for budget in (1, record_restore):
            state = initial(); trace.clear(); reference.run(state, 1000)
            prefix = 1 if budget == 1 else trace.index(CALLER + record_restore * 4) + 1
            require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "layout owner setup rejected")
            require(lib.oot_stack_run(context, byref(state), prefix, byref(report)) == 1, "layout owner setup did not yield")
            saved = state.values(); offset = STACK_SIZE - 96 + 80
            stack[offset] ^= 1
            require(lib.oot_stack_run(context, byref(state), 0, byref(report)) == 3 and report.error == 49 and state.values() == saved,
                    "allocated frame lost ownership before deallocation")
            stack[offset] ^= 1
            require(lib.oot_stack_abort(context, byref(report)) == 0 and state.values() == saved, "layout abort changed retired prefix")
    finally: lib.oot_stack_destroy(context)
    matrix_cases = 0
    for p, regs in matrix:
        factory = getattr(lib, "oot_create_" + p.name); factory.argtypes, factory.restype = [c_void_p, POINTER(c_uint32)], c_void_p
        context = factory(image, byref(error)); require(context is not None, f"matrix layout rejected {p.name}: {error.value}")
        try:
            for index, a in enumerate(edges):
                start = initial(p.base, a=a, b=index)
                formula = (len(regs) * a + sum(regs) if regs else a + 7) + (3 if index & 1 else 0)
                check(context, start, formula & U64, (0, 1), prefix=index == 0); matrix_cases += 1
        finally: lib.oot_stack_destroy(context)
    factory = lib.oot_create_layout_depth; factory.argtypes, factory.restype = [c_void_p, POINTER(c_uint32)], c_void_p
    context = factory(image, byref(error)); require(context is not None, f"mixed maximum-depth layout rejected {error.value}")
    try:
        start = initial(chain[0].base); check(context, start, start.x[0], (0, 1), prefix=True)
    finally: lib.oot_stack_destroy(context)

    table, leaf_table, hashes = (LayoutFunction * 3)(), (LeafFunction * 2)(), (CodeHash * 2)()
    for index, p in enumerate(frames):
        getter = getattr(lib, "oot_stack_layout_descriptor_" + p.name); getter.restype = POINTER(LayoutFunction); table[index] = getter().contents
    for index, p in enumerate(leaves):
        getter = getattr(lib, "oot_leaf_descriptor_" + p.name); getter.restype = POINTER(LeafFunction); leaf_table[index] = getter().contents
        getter = getattr(lib, "oot_leaf_code_hash_" + p.name); getter.restype = POINTER(CodeHash); hashes[index] = getter().contents
    body, returns = (c_uint8 * 32).from_buffer_copy(digest), (c_uint64 * 1)(EXIT)
    n = table[0].cfg.info.instruction_count
    states = (LayoutStep * n).from_buffer_copy(string_at(table[0].states, sizeof(LayoutStep) * n)); table[0].states = states

    def create(): return lib.oot_stack_create_layout(image, table, 3, CALLER, leaf_table, 2, hashes, body, returns, 1, byref(error))

    previous = (CfgFunction * 3)(*(table[i].cfg for i in range(3)))
    require(lib.oot_stack_create_cfg(image, previous, 3, CALLER, leaf_table, 2, hashes, body, returns, 1, byref(error)) is None and error.value == 48,
            "CFG-v2 constructor accepted layout-v3 metadata")
    owned = create(); require(owned is not None, "layout metadata ownership setup failed")
    old_fp, old_record = states[4].fp, table[0].record_offset
    states[4].fp = 0; table[0].record_offset = 0
    try:
        state = initial(); check(owned, state, rotate(5 ^ 0xFFFF, state.x[3]), (0, 1))
    finally:
        states[4].fp = old_fp; table[0].record_offset = old_record; lib.oot_stack_destroy(owned)
    for index, field, value in ((0, "owner", 0), (1, "fp", 1), (4, "fp", 0), (record_restore, "owner", 2),
            (record_restore, "sp", 1), (record_restore + 1, "sp", 0), (5, "lr", 1)):
        old = getattr(states[index], field); setattr(states[index], field, value)
        require(create() is None and error.value == 48, "invalid layout post-state metadata accepted")
        setattr(states[index], field, old)
    for field, value in (("record_offset", 48), ("record_offset", 97), ("reserved", 1)):
        old = getattr(table[0], field); setattr(table[0], field, value)
        require(create() is None and error.value == 48, "invalid layout frame-record metadata accepted")
        setattr(table[0], field, old)
    steps = (StackStep * n).from_buffer_copy(string_at(table[0].cfg.info.steps, sizeof(StackStep) * n)); table[0].cfg.info.steps = steps
    flows = (CfgStep * n).from_buffer_copy(string_at(table[0].cfg.flow, sizeof(CfgStep) * n)); table[0].cfg.flow = flows
    for index, field, value in ((2, "offset", 80), (3, "offset", 56), (5, "offset", 80), (1, "size", 8)):
        old = getattr(steps[index], field); setattr(steps[index], field, value)
        require(create() is None and error.value == 48, "overlapping/invalid layout slots accepted")
        setattr(steps[index], field, old)
    branch_index = next(i for i, s in enumerate(proofs[CALLER]["steps"]) if s["kind"] == 10)
    for value in (0, branch_index, n - 2, 0xFFFE):
        old = flows[branch_index].next_a; flows[branch_index].next_a = value
        require(create() is None and error.value == 48, "invalid layout CFG edge accepted")
        flows[branch_index].next_a = old
    table[0].cfg.info.run = cast(lib.oot_layout_bad, c_void_p).value
    for mode_index, (instruction, _action, expected_error) in enumerate(modes, 1):
        context = create(); require(context is not None, "layout fault fixture rejected")
        lib.oot_layout_bad_set(mode_index)
        try:
            state = initial(); trace.clear(); reference.run(state, 1000); prefix = trace.index(CALLER + instruction * 4)
            require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0 and lib.oot_stack_run(context, byref(state), prefix, byref(report)) == 1,
                    "layout fault setup rejected")
            before, saved = state.values(), bytes(stack[:STACK_SIZE])
            require(lib.oot_stack_run(context, byref(state), 1, byref(report)) == 4 and report.error == expected_error and
                state.values() == before and bytes(stack[:STACK_SIZE]) == saved, f"layout fault mutated committed state: mode {mode_index}")
            calls = lib.oot_layout_bad_count()
            require(lib.oot_stack_run(context, byref(state), 100, byref(report)) == 4 and lib.oot_layout_bad_count() == calls, "layout fault not latched")
            lib.oot_stack_abort(context, byref(report))
        finally: lib.oot_stack_destroy(context)
    lib.oot_runtime_close(image)
    result = {"schema_version": 1, "result": "passed", "synthetic_only": True, "game_code_executed": False,
        "whole_call_cases": len(operands), "layout_matrix_cases": matrix_cases, "layout_count": len(matrix),
        "prefix_step_checks": prefixes, "budget_yields": yields, "max_depth": 16, "max_frame": 256,
        "native_fault_modes": len(modes), "observed_retirements": sorted(counts), "weighted_max_steps": root_proof["max_retired_instructions"],
        "reference": {"unicorn": version("unicorn")}, "native_build": build}
    destination = directory / f"{mode}-report.json"; destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result, destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--compiler", choices=("gcc", "cmake"), default="cmake")
    result, path = run_validation(parser.parse_args().compiler)
    print(json.dumps({"result": result["result"], "whole_call_cases": result["whole_call_cases"], "report": str(path)}))
