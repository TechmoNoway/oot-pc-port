"""Synthetic framed branches, callee saves, weighted bounds, and fault guards."""

import argparse
from ctypes import POINTER, Structure, byref, c_uint8, c_uint16, c_uint32, c_uint64, c_void_p, cast, create_string_buffer, memset, sizeof, string_at
from dataclasses import replace
from importlib.metadata import version
import json
import os
from pathlib import Path
import random

from arm64_lifter import U64
from dispatcher_validation import CALLER, EXIT, STACK_LOW, STACK_HIGH, STACK_SIZE, CodeHash, LeafFunction, Reference, Report
from leaf_validation import leaf_programs, remainder, rotate
from input_formats import require
from lifter_validation import compile_library
from lifter_validation_types import Program, State
from pair_validation import pair
from prepare_registry import emit_stack_factory
from stack_cfg_verifier import BRANCH, RESTORE, emit_cfg_stack_descriptor, verify_cfg_stack_functions
from stack_validation import StackFunction, add, call, package, scalar, stack_bindings

ROOT = Path(__file__).resolve().parent.parent


class CfgStep(Structure):
    _fields_ = [("next_a", c_uint16), ("next_b", c_uint16), ("saved_a", c_uint16), ("saved_b", c_uint16),
                ("max_steps", c_uint32), ("writable_mask", c_uint32)]


class CfgFunction(Structure):
    _fields_ = [("info", StackFunction), ("flow", POINTER(CfgStep)), ("saved_mask", c_uint32), ("locals_begin", c_uint32)]


def bindings(lib):
    stack_bindings(lib)
    args = lib.oot_stack_create.argtypes.copy()
    args[1] = POINTER(CfgFunction)
    lib.oot_stack_create_cfg.argtypes, lib.oot_stack_create_cfg.restype = args, c_void_p


class Assembler:
    def __init__(self, name, base, size, saves=()):
        self.name, self.base, self.size, self.saves = name, base, size, list(saves)
        self.words = [pair(2, False, 29, 30, 31, 3, -size // 8), 0x910003FD]
        self.labels, self.fixups = {}, []
        offset = 16
        for regs in saves:
            self.words.append(pair(2, False, *regs, 31, 2, offset // 8) if len(regs) == 2 else scalar(8, False, regs[0], 31, offset))
            offset += len(regs) * 8

    def emit(self, *words): self.words.extend(words)
    def label(self, name): self.labels[name] = len(self.words)
    def branch(self, name, opcode, bits=19):
        self.fixups.append((len(self.words), name, opcode, bits)); self.words.append(0)
    def bl(self, target): self.emit(call(self.base, len(self.words), target))
    def finish(self):
        self.label("epilogue")
        offset = 16 + sum(len(r) * 8 for r in self.saves)
        for regs in reversed(self.saves):
            offset -= len(regs) * 8
            self.emit(pair(2, True, *regs, 29, 2, offset // 8) if len(regs) == 2 else scalar(8, True, regs[0], 29, offset))
        self.emit(pair(2, True, 29, 30, 31, 1, self.size // 8), 0xD65F03C0)
        for index, name, opcode, bits in self.fixups:
            offset = (self.labels[name] - index) & ((1 << bits) - 1)
            self.words[index] = opcode | (offset if bits == 26 else offset << 5)
        return Program(self.name, self.words, [], base=self.base)


def mov(rd, rn): return 0xAA0003E0 | (rn << 16) | rd
def immediate(rd, n): return 0xD2800000 | (n << 5) | rd
def add_immediate(rd, rn, n): return 0x91000000 | (n << 10) | (rn << 5) | rd


def synthetic_programs():
    originals = {p.name: p for p in leaf_programs()}
    leaves = [replace(originals[name], name="cfg_" + name, trials=[], base=CALLER + (i + 2) * 0x10000)
              for i, name in enumerate(("leaf_remainder", "leaf_mix"))]
    child_base = CALLER + 0x10000
    root = Assembler("cfg_root", CALLER, 80, ((19, 20), (21,)))
    root.emit(mov(19, 0), mov(20, 1), mov(21, 3), pair(2, False, 19, 20, 31, 2, 5), scalar(8, False, 21, 29, 56))
    root.branch("zero", 0xB4000000)  # cbz x0
    root.branch("negative", 0xB7F80000, 14)  # tbnz x0,#63
    root.emit(0xEB01001F)  # cmp x0,x1
    root.branch("lower", 0x54000003)  # b.lo
    root.bl(child_base); root.emit(add_immediate(0, 0, 11)); root.branch("join", 0x14000000, 26)
    root.label("lower"); root.bl(leaves[0].base); root.emit(add_immediate(0, 0, 7)); root.branch("join", 0x14000000, 26)
    root.label("negative"); root.bl(child_base); root.emit(immediate(2, 0x55), 0xCA020000); root.branch("join", 0x14000000, 26)
    root.label("zero"); root.emit(immediate(0, 42))
    root.label("join"); root.emit(scalar(8, True, 4, 31, 40), add(0, 0, 4), scalar(8, True, 1, 29, 48), mov(3, 21))
    root.bl(leaves[1].base); root.emit(scalar(8, False, 0, 31, 64), scalar(8, True, 0, 29, 64))
    main = root.finish()
    child = Assembler("cfg_child", child_base, 64, ((20, 19), (28,)))
    child.emit(mov(19, 0), mov(20, 1), mov(28, 3), scalar(8, False, 19, 31, 40))
    child.branch("zero", 0xB4000001)  # cbz x1
    child.bl(leaves[0].base); child.emit(add(0, 0, 19)); child.branch("done", 0x14000000, 26)
    child.label("zero"); child.emit(add_immediate(0, 19, 5))
    child.label("done"); child.emit(mov(28, 0), scalar(8, False, 0, 29, 48), scalar(8, True, 0, 31, 48))
    return [main, child.finish()], leaves


def condition_programs():
    result = []
    for cond in range(16):
        a = Assembler(f"cfg_cond_{cond}", CALLER + (4 + cond) * 0x10000, 16)
        a.branch("taken", 0x54000000 | cond)
        a.emit(immediate(0, 20)); a.branch("epilogue", 0x14000000, 26)
        a.label("taken"); a.emit(immediate(0, 10))
        result.append(a.finish())
    all_saved = Assembler("cfg_all_saved", CALLER + 20 * 0x10000, 256,
        [(r, r + 1) for r in range(19, 29, 2)])
    for r in range(19, 29): all_saved.emit(add_immediate(r, 0, r))
    all_saved.emit(mov(0, 19))
    for r in range(20, 29): all_saved.emit(add(0, 0, r))
    all_saved.branch("epilogue", 0x36000001, 14)  # tbz x1,#0
    all_saved.emit(add_immediate(0, 0, 3))
    result.append(all_saved.finish())
    return result


def holds(cond, flags):
    n, z, c, v = ((flags >> i) & 1 for i in (3, 2, 1, 0))
    if cond >= 14: return True
    value = (z, c, n, v, c and not z, n == v, not z and n == v)[cond // 2]
    return not value if cond & 1 else bool(value)


def run_validation(mode="cmake"):
    frames, leaves = synthetic_programs()
    singles = condition_programs()
    proofs = verify_cfg_stack_functions({p.base: p.data for p in frames}, {p.base: p.data for p in leaves}, CALLER)
    single_proofs = {p.base: verify_cfg_stack_functions({p.base: p.data}, {}, p.base)[p.base] for p in singles}
    programs = frames + leaves + singles
    blob, digest = package(programs)
    extra = "\n".join(emit_cfg_stack_descriptor(proofs[p.base], "oot_lift_" + p.name) for p in frames)
    extra += "\n" + "\n".join(emit_cfg_stack_descriptor(single_proofs[p.base], "oot_lift_" + p.name) for p in singles)
    extra += emit_stack_factory([p.name for p in frames], [p.name for p in leaves], CALLER, digest.hex(), [EXIT], cfg=True)
    for p in singles:
        extra += emit_stack_factory([p.name], [], p.base, digest.hex(), [EXIT], cfg=True).replace("oot_create_bound_registry", "oot_create_" + p.name)
    branch_index = next(i for i, s in enumerate(proofs[CALLER]["steps"]) if s["kind"] == BRANCH)
    restore_index = next(i for i, s in enumerate(proofs[CALLER]["steps"]) if s["kind"] == RESTORE)
    modes = [(2, "(void)oot_memory_store(m, s->sp + 16, 8, 0);", 49),
        (2, "s->x[19] ^= 1;", 12), (4, "s->x[18] ^= 1;", 12),
        (branch_index, f"s->pc = UINT64_C(0x{CALLER + 16:x});", 11),
        (7, "(void)oot_memory_store(m, s->sp + 16, 8, 0);", 49), (4, "s->x[22] ^= 1;", 12),
        (restore_index, "s->x[21] ^= 1;", 12), (restore_index + 1, "s->x[19] ^= 1;", 12),
        (len(frames[0].words) - 2, "s->x[20] ^= 1;", 12), (4, "*n = 0;", 10),
        (4, "result = OOT_LIFT_DISPATCH;", 13), (4, "s->nzcv |= 1;", 9),
        (7, "(void)oot_memory_store(m, s->sp - 8, 8, 0);", 50)]
    extra += '''
static unsigned cfg_bad_mode, cfg_bad_calls;
OOT_LIFT_EXPORT void oot_cfg_bad_set(unsigned mode) { cfg_bad_mode = mode; }
OOT_LIFT_EXPORT unsigned oot_cfg_bad_count(void) { return cfg_bad_calls; }
OOT_LIFT_EXPORT int oot_cfg_bad(OotArm64State *s, OotGuestMemory *m, uint64_t b, uint64_t *n)
{
    uint64_t pc = s->pc;
    int result;
    ++cfg_bad_calls;
    result = oot_lift_cfg_root(s, m, b, n);
    switch (cfg_bad_mode) {
'''
    for mode_index, (index, action, _) in enumerate(modes, 1):
        extra += f"    case {mode_index}: if (pc == UINT64_C(0x{CALLER + index * 4:x})) {{ {action} }} break;\n"
    extra += "    }\n    return result;\n}\n"
    lib, build = compile_library(programs, mode, extra)
    bindings(lib)
    lib.oot_cfg_bad_set.argtypes, lib.oot_cfg_bad_set.restype = [c_uint32], None
    lib.oot_cfg_bad_count.argtypes, lib.oot_cfg_bad_count.restype = [], c_uint32
    directory = ROOT / "build/stack-cfg-validation"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{mode}-synthetic.ootmem"
    path.write_bytes(blob)
    message, error, report = create_string_buffer(192), c_uint32(), Report()
    image = lib.oot_runtime_open(os.fsencode(path), message, len(message))
    require(image is not None, f"CFG fixture rejected: {message.value}")
    memory = lib.oot_runtime_memory(image)
    stack = memory.contents.regions[1].data
    reference = Reference(programs)
    trace = []
    from unicorn import UC_HOOK_CODE
    reference.engine.hook_add(UC_HOOK_CODE, lambda _engine, pc, _size, _data: trace.append(pc))
    rng = random.Random(0xCF659ED)
    completed, prefixes, yields, counts, condition_cases = 0, 0, 0, set(), 0

    def initial(base=CALLER, a=1, b=1, flags=None):
        s = State(); s.x[:] = [rng.getrandbits(64) for _ in range(31)]
        s.pc, s.sp, s.x[0], s.x[1], s.x[30], s.nzcv = base, STACK_HIGH, a, b, EXIT, (rng.randrange(16) if flags is None else flags) << 28
        return s

    def check_case(context, start, formula, schedule, prefix=False):
        nonlocal prefixes, yields
        state = State.from_buffer_copy(bytes(start)); memset(stack, 0, STACK_SIZE)
        trace.clear()
        expected, retired, expected_stack = reference.run(state, 1000)
        require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "CFG begin rejected")
        for iteration in range(1000):
            budget = schedule[min(iteration, len(schedule) - 1)]
            before = state.values()
            status = lib.oot_stack_run(context, byref(state), budget, byref(report))
            require(status in (1, 2) and report.error == 0, f"CFG run failed: {status} {report.error} pc={state.pc:x}")
            if not budget: require(state.values() == before and report.retired_this_call == 0, "zero CFG budget changed state")
            if status == 2: break
            yields += 1
        else: raise ValueError("CFG call did not terminate")
        require(state.values() == expected and state.x[0] == formula and bytes(stack[:STACK_SIZE]) == expected_stack and report.total_retired == retired,
                "CFG whole call differs from reference or formula")
        require(lib.oot_stack_run(context, byref(state), 1, byref(report)) == 2 and report.retired_this_call == 0, "CFG return not idempotent")
        if prefix:
            state = State.from_buffer_copy(bytes(start)); memset(stack, 0, STACK_SIZE)
            for register, value in zip(reference.ids, state.x): reference.engine.reg_write(register, value)
            reference.engine.reg_write(reference.regs.UC_ARM64_REG_SP, state.sp)
            reference.engine.reg_write(reference.regs.UC_ARM64_REG_NZCV, state.nzcv)
            reference.engine.mem_write(STACK_LOW, bytes(STACK_SIZE))
            require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "CFG prefix begin rejected")
            for step in range(retired):
                reference.engine.emu_start(state.pc, EXIT, count=1)
                status = lib.oot_stack_run(context, byref(state), 1, byref(report))
                expected_prefix = (tuple(reference.engine.reg_read(r) for r in reference.ids), reference.engine.reg_read(reference.regs.UC_ARM64_REG_SP),
                    reference.engine.reg_read(reference.regs.UC_ARM64_REG_PC), reference.engine.reg_read(reference.regs.UC_ARM64_REG_NZCV))
                require(status == (2 if step + 1 == retired else 1) and report.total_retired == step + 1 and
                    state.values() == expected_prefix and bytes(stack[:STACK_SIZE]) == bytes(reference.engine.mem_read(STACK_LOW, STACK_SIZE)), "CFG instruction prefix mismatch")
                prefixes += 1
        return retired

    context = lib.oot_create_bound_registry(image, byref(error))
    require(context is not None, f"CFG registry rejected: {error.value}")
    try:
        edges = [0, 1, U64, 1 << 63, (1 << 63) - 1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF]
        operands = [(a, b) for a in edges for b in edges] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(64)]
        for index, (a, b) in enumerate(operands):
            start = initial(a=a, b=b)
            child = (a + 5 if b == 0 else remainder(a, b) + a) & U64
            value = 42 if a == 0 else child ^ 0x55 if a >> 63 else remainder(a, b) + 7 if a < b else child + 11
            formula = rotate((((value + a + 2 * b) & U64) ^ 0xFFFF), start.x[3])
            counts.add(check_case(context, start, formula, ((0, 1), (1,), (4,), (U64,))[index % 4], index in (0, 8, 9, 10, 16, 24, 32, 64, 127)))
            completed += 1
        require(max(counts) == proofs[CALLER]["max_retired_instructions"] and len(counts) > 1, "weighted CFG bound/paths not exercised")
        start = initial(a=1, b=1)
        trace.clear(); reference.run(start, 1000)
        leaf_entry = trace.index(leaves[0].base)
        require(lib.oot_stack_begin(context, byref(start), EXIT, byref(report)) == 0, "CFG ownership setup rejected")
        require(lib.oot_stack_run(context, byref(start), leaf_entry, byref(report)) == 1, "CFG nested setup failed")
        before = start.values()
        for offset in (STACK_SIZE - 80 + 16, STACK_SIZE - 80 + 40, STACK_SIZE - 144 + 16):
            stack[offset] ^= 1
            require(lib.oot_stack_run(context, byref(start), 0, byref(report)) == 3 and report.error == 49 and start.values() == before,
                    "changed saved/local bytes accepted in CFG")
            stack[offset] ^= 1
        for offset in (0, 0x10000, 0x20000):
            pointer = memory.contents.regions[0].data; pointer[offset] ^= 1
            require(lib.oot_stack_run(context, byref(start), 1, byref(report)) == 3 and report.error == 17 and start.values() == before,
                    "changed active CFG code accepted")
            pointer[offset] ^= 1
        require(lib.oot_stack_abort(context, byref(report)) == 0 and start.values() == before, "CFG abort undid prefix")
    finally:
        lib.oot_stack_destroy(context)
    for p in singles:
        factory = getattr(lib, "oot_create_" + p.name)
        factory.argtypes, factory.restype = [c_void_p, POINTER(c_uint32)], c_void_p
        context = factory(image, byref(error))
        require(context is not None, f"standalone CFG rejected: {error.value}")
        try:
            for flags in range(16):
                start = initial(p.base, a=rng.getrandbits(64), b=flags, flags=flags)
                formula = (10 * start.x[0] + 235 + (3 if flags & 1 else 0)) & U64 if p == singles[-1] else 10 if holds(int(p.name.rsplit('_', 1)[1]), flags) else 20
                check_case(context, start, formula, (0, 1), prefix=flags == 0)
                condition_cases += 1
        finally:
            lib.oot_stack_destroy(context)

    # Deliberately invalid metadata/native callbacks are trusted synthetic fixtures.
    table, leaf_table, hashes = (CfgFunction * 2)(), (LeafFunction * 2)(), (CodeHash * 2)()
    for i, p in enumerate(frames):
        getter = getattr(lib, "oot_stack_cfg_descriptor_" + p.name); getter.restype = POINTER(CfgFunction)
        table[i] = getter().contents
    for i, p in enumerate(leaves):
        getter = getattr(lib, "oot_leaf_descriptor_" + p.name); getter.restype = POINTER(LeafFunction); leaf_table[i] = getter().contents
        getter = getattr(lib, "oot_leaf_code_hash_" + p.name); getter.restype = POINTER(CodeHash); hashes[i] = getter().contents
    body, returns = (c_uint8 * 32).from_buffer_copy(digest), (c_uint64 * 1)(EXIT)
    flow_copy = (CfgStep * table[0].info.instruction_count).from_buffer_copy(string_at(table[0].flow, sizeof(CfgStep) * table[0].info.instruction_count))
    table[0].flow = flow_copy

    def create(): return lib.oot_stack_create_cfg(image, table, 2, CALLER, leaf_table, 2, hashes, body, returns, 1, byref(error))

    common = (StackFunction * 2)(table[0].info, table[1].info)
    require(lib.oot_stack_create(image, common, 2, CALLER, leaf_table, 2, hashes, body, returns, 1, byref(error)) is None and error.value == 48,
            "policy-v1 constructor accepted CFG descriptors")
    owned = create(); require(owned is not None, "CFG ownership fixture rejected")
    old_edge, old_mask = flow_copy[branch_index].next_a, table[0].saved_mask
    flow_copy[branch_index].next_a = 0; table[0].saved_mask = 0
    try:
        start = initial(a=10, b=3)
        check_case(owned, start, rotate(38 ^ 0xFFFF, start.x[3]), (0, 1))
    finally:
        flow_copy[branch_index].next_a = old_edge; table[0].saved_mask = old_mask
        lib.oot_stack_destroy(owned)

    for index, field, value in ((branch_index, "next_a", 0), (branch_index, "next_a", branch_index),
            (branch_index, "max_steps", 1), (4, "writable_mask", 1 << 18), (restore_index, "saved_a", 22),
            (len(frames[0].words) - 2, "next_a", 0xFFFE)):
        old = getattr(flow_copy[index], field); setattr(flow_copy[index], field, value)
        rejected = create()
        require(rejected is None and error.value == 48, "malformed CFG metadata accepted")
        setattr(flow_copy[index], field, old)
    for field, value in (("saved_mask", 0), ("locals_begin", 16)):
        old = getattr(table[0], field); setattr(table[0], field, value)
        rejected = create()
        require(rejected is None and error.value == 48, "invalid save-slot metadata accepted")
        setattr(table[0], field, old)
    table[0].info.run = cast(lib.oot_cfg_bad, c_void_p).value
    for mode_index, (instruction, _action, expected_error) in enumerate(modes, 1):
        context = create(); require(context is not None, "native CFG fault fixture rejected")
        lib.oot_cfg_bad_set(mode_index)
        try:
            state = initial(a=1, b=1)
            trace.clear(); reference.run(state, 1000)
            prefix = trace.index(CALLER + instruction * 4)
            require(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)) == 0, "CFG fault begin failed")
            require(lib.oot_stack_run(context, byref(state), prefix, byref(report)) == 1, "CFG fault prefix failed")
            before, saved = state.values(), bytes(stack[:STACK_SIZE])
            require(lib.oot_stack_run(context, byref(state), 1, byref(report)) == 4 and report.error == expected_error and
                state.values() == before and bytes(stack[:STACK_SIZE]) == saved, f"CFG fault committed changes: mode {mode_index}")
            calls = lib.oot_cfg_bad_count()
            require(lib.oot_stack_run(context, byref(state), 100, byref(report)) == 4 and lib.oot_cfg_bad_count() == calls, "CFG failure not latched")
            require(lib.oot_stack_abort(context, byref(report)) == 0 and state.values() == before, "CFG fault abort failed")
        finally:
            lib.oot_stack_destroy(context)
    lib.oot_runtime_close(image)
    result = {"schema_version": 1, "result": "passed", "synthetic_only": True, "game_code_executed": False,
        "whole_call_cases": completed, "condition_and_save_cases": condition_cases, "prefix_step_checks": prefixes,
        "budget_yields": yields, "observed_retirements": sorted(counts), "weighted_max_steps": proofs[CALLER]["max_retired_instructions"],
        "max_saved_registers": 10, "native_fault_modes": len(modes), "reference": {"unicorn": version("unicorn")}, "native_build": build}
    destination = directory / f"{mode}-report.json"
    destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result, destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", choices=("gcc", "cmake"), default="cmake")
    report, path = run_validation(parser.parse_args().compiler)
    print(json.dumps({"result": report["result"], "whole_call_cases": report["whole_call_cases"], "report": str(path)}))
