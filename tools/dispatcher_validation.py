"""Validate controlled dispatch using compiled synthetic leaves and ARM64 callers."""

import argparse
from ctypes import (POINTER, Structure, byref, c_int, c_size_t, c_uint8, c_uint16, c_uint32,
                    c_uint64, c_void_p)
from dataclasses import replace
from importlib.metadata import version
import json
from pathlib import Path
import random

from arm64_lifter import U64
from input_formats import require
from leaf_validation import leaf_programs, remainder, rotate
from lifter_validation import compile_library
from lifter_validation_types import Memory, Program, RegionSpec, State
from memory_validation import initialize_native_memory

ROOT = Path(__file__).resolve().parent.parent
CALLER = 0x100200000
EXIT = CALLER + 0x8000
STACK_LOW, STACK_SIZE = 0x7000000000, 4096
STACK_HIGH = STACK_LOW + STACK_SIZE
SEED = 0xD15A7C4


class LeafStep(Structure):
    _fields_ = [("next_a", c_uint16), ("next_b", c_uint16), ("max_steps", c_uint16), ("reserved", c_uint16)]


class LeafFunction(Structure):
    _fields_ = [("entry", c_uint64), ("instruction_count", c_uint32), ("max_steps", c_uint32),
                ("abi_version", c_uint32), ("policy_version", c_uint32),
                ("run", c_void_p), ("steps", POINTER(LeafStep))]


class CodeHash(Structure):
    _fields_ = [("bytes", c_uint8 * 32)]


class Report(Structure):
    _fields_ = [("status", c_uint32), ("error", c_uint32), ("entry", c_uint64), ("pc", c_uint64),
                ("expected_return", c_uint64), ("retired_this_call", c_uint64), ("total_retired", c_uint64)]


def bindings(library):
    library.oot_leaf_dispatcher_create.argtypes = [POINTER(LeafFunction), c_size_t, POINTER(c_uint64), c_size_t,
                                                  c_uint64, c_uint64, POINTER(c_uint32)]
    library.oot_leaf_dispatcher_create.restype = c_void_p
    library.oot_leaf_dispatcher_create_bound.argtypes = [c_void_p, POINTER(LeafFunction), c_size_t, POINTER(CodeHash),
        POINTER(c_uint8), POINTER(c_uint64), c_size_t, POINTER(c_uint32)]
    library.oot_leaf_dispatcher_create_bound.restype = c_void_p
    library.oot_leaf_dispatcher_destroy.argtypes = [c_void_p]
    library.oot_leaf_dispatcher_destroy.restype = c_int
    library.oot_leaf_begin.argtypes = [c_void_p, POINTER(State), c_uint64, c_uint64, POINTER(Report)]
    library.oot_leaf_begin.restype = c_int
    library.oot_leaf_run.argtypes = [c_void_p, POINTER(State), c_uint64, POINTER(Report)]
    library.oot_leaf_run.restype = c_int
    library.oot_leaf_abort.argtypes = [c_void_p, POINTER(Report)]
    library.oot_leaf_abort.restype = c_int


def programs():
    leaves = [replace(p, name="dispatch_" + p.name, base=CALLER + (i + 1) * 0x10000, trials=[])
              for i, p in enumerate(leaf_programs())]
    by_name = {p.name: p for p in leaves}

    def call(index, target):
        return 0x94000000 | (((target - (CALLER + index * 4)) // 4) & 0x3FFFFFF)

    caller = Program("dispatch_caller", [0xA9BF7BFD,
        call(1, by_name["dispatch_leaf_remainder"].base), 0x91001C00,
        call(3, by_name["dispatch_leaf_mix"].base), 0xA8C17BFD, 0xD65F03C0], [], base=CALLER)
    return leaves, caller


def registry(library, leaves):
    descriptors = []
    for program in leaves:
        getter = getattr(library, "oot_leaf_descriptor_" + program.name)
        getter.argtypes, getter.restype = [], POINTER(LeafFunction)
        descriptors.append(LeafFunction.from_buffer_copy(getter().contents))
    table = (LeafFunction * len(descriptors))(*descriptors)
    returns = (c_uint64 * 3)(CALLER + 8, CALLER + 16, EXIT)
    error = c_uint32(U64 & 0xFFFFFFFF)
    context = library.oot_leaf_dispatcher_create(table, len(table), returns, len(returns), STACK_LOW, STACK_HIGH, byref(error))
    require(context is not None and error.value == 0, "generated leaf registry was rejected")
    return context, table, returns


class Reference:
    def __init__(self, code_programs):
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
        from unicorn import arm64_const as regs
        self.regs, self.engine = regs, Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.ids = [getattr(regs, f"UC_ARM64_REG_X{i}") for i in range(31)]
        self.pcs = {pc for p in code_programs for pc in range(p.base, p.base + len(p.data), 4)}
        for program in code_programs:
            self.engine.mem_map(program.base, 4096)
            self.engine.mem_write(program.base, program.data)
        self.engine.mem_map(EXIT, 4096)
        self.engine.mem_map(STACK_LOW, STACK_SIZE)
        self.steps, self.unexpected = 0, None

        def hook(engine, address, size, user):
            if address not in self.pcs:
                self.unexpected = address
                engine.emu_stop()
            else:
                self.steps += 1

        self.engine.hook_add(UC_HOOK_CODE, hook)

    def run(self, state, limit):
        for register, value in zip(self.ids, state.x):
            self.engine.reg_write(register, value)
        self.engine.reg_write(self.regs.UC_ARM64_REG_SP, state.sp)
        self.engine.reg_write(self.regs.UC_ARM64_REG_NZCV, state.nzcv)
        self.engine.mem_write(STACK_LOW, bytes(STACK_SIZE))
        self.steps, self.unexpected = 0, None
        self.engine.emu_start(state.pc, EXIT, count=limit)
        result = (tuple(self.engine.reg_read(r) for r in self.ids), self.engine.reg_read(self.regs.UC_ARM64_REG_SP),
                  self.engine.reg_read(self.regs.UC_ARM64_REG_PC), self.engine.reg_read(self.regs.UC_ARM64_REG_NZCV))
        require(self.unexpected is None and result[2] == EXIT, "synthetic reference did not return to its exit token")
        return result, self.steps, bytes(self.engine.mem_read(STACK_LOW, STACK_SIZE))


def finish_leaf(library, context, state, schedule, counters):
    report, total, iterations = Report(), 0, 0
    while True:
        budget = schedule[min(iterations, len(schedule) - 1)]
        before = state.values()
        status = library.oot_leaf_run(context, byref(state), budget, byref(report))
        require(status in (1, 2) and report.status == status and report.error == 0, "valid synthetic dispatch was rejected")
        total += report.retired_this_call
        require(report.total_retired == total and report.pc == state.pc, "dispatcher retirement report mismatch")
        if budget == 0:
            require(state.values() == before and report.retired_this_call == 0, "zero dispatch budget changed guest state")
            counters["zero_budget_yields"] += 1
        if status == 2:
            break
        counters["budget_yields"] += 1
        iterations += 1
        require(iterations <= 258, "synthetic leaf dispatch failed to terminate")
    before = state.values()
    require(library.oot_leaf_run(context, byref(state), 10, byref(report)) == 2 and
            report.retired_this_call == 0 and state.values() == before, "completed return was not idempotent")
    return total


def guard_checks(library, context, leaf):
    checked = 0
    report = Report()
    library.oot_leaf_abort(context, None)
    for kind in range(10):
        state = State()
        state.pc, state.sp, state.x[30] = leaf.base, STACK_HIGH, EXIT
        entry, target, expected_error = leaf.base, EXIT, 0
        if kind == 0: state.pc += 4; expected_error = 5
        if kind == 1: entry += 4; expected_error = 5
        if kind == 2: entry += 0x800; expected_error = 5
        if kind == 3: state.x[30] = CALLER + 8; expected_error = 6
        if kind == 4: state.x[30] = target = leaf.base; expected_error = 6
        if kind == 5: state.x[30] = target = EXIT + 4; expected_error = 6
        if kind == 6: state.sp -= 1; expected_error = 8
        if kind == 7: state.sp = STACK_LOW - 16; expected_error = 8
        if kind == 8: state.sp = STACK_HIGH + 16; expected_error = 8
        if kind == 9: state.nzcv = 1; expected_error = 9
        before = state.values()
        require(library.oot_leaf_begin(context, byref(state), entry, target, byref(report)) == 3 and
                report.error == expected_error and state.values() == before and report.retired_this_call == 0,
                f"entry guard failed for case {kind}")
        checked += 1
    state = State()
    state.pc, state.sp, state.x[30] = leaf.base, STACK_HIGH, EXIT
    require(library.oot_leaf_begin(context, byref(state), leaf.base, EXIT, byref(report)) == 0, "valid guard setup failed")
    require(library.oot_leaf_begin(context, byref(state), leaf.base, EXIT, byref(report)) == 3 and report.error == 3,
            "busy dispatch frame was replaced")
    require(library.oot_leaf_run(context, byref(state), 1, byref(report)) == 1, "guard setup did not yield")
    checkpoint = bytes(state)
    for field in ("pc", "x0", "lr", "sp", "nzcv"):
        state = State.from_buffer_copy(checkpoint)
        if field == "x0": state.x[0] ^= 1
        elif field == "lr": state.x[30] ^= 4
        else: setattr(state, field, getattr(state, field) ^ (16 if field == "sp" else 1))
        before = state.values()
        require(library.oot_leaf_run(context, byref(state), 10, byref(report)) == 3 and report.error == 7 and
                state.values() == before and report.retired_this_call == 0, "resume accepted altered checkpoint state")
        checked += 1
    state = State.from_buffer_copy(checkpoint)
    require(library.oot_leaf_run(context, byref(state), U64, byref(report)) == 2, "repaired checkpoint could not resume")
    library.oot_leaf_abort(context, None)
    require(library.oot_leaf_run(context, byref(state), 1, byref(report)) == 3 and report.error == 4,
            "aborted frame was still runnable")
    return checked + 2


def run_validation(mode="cmake"):
    original_leaves = leaf_programs()
    leaves, caller = programs()
    library, build = compile_library([*leaves, caller], mode)
    bindings(library)
    context, table, returns = registry(library, leaves)
    reference = Reference([*leaves, caller])
    counters = {"zero_budget_yields": 0, "budget_yields": 0}
    leaf_cases, caller_cases = 0, 0
    try:
        # Input metadata is copied; changing the original return table must have no effect.
        returns[2] = leaves[0].base
        for original, program in zip(original_leaves, leaves):
            for index, trial in enumerate(t for t in original.trials if t.expected_x is not None):
                state, report = State(), Report()
                state.x[:] = trial.registers
                state.pc, state.sp, state.nzcv, state.x[30] = program.base, STACK_HIGH, trial.nzcv, EXIT
                expected, steps, _ = reference.run(state, 256)
                require(library.oot_leaf_begin(context, byref(state), program.base, EXIT, byref(report)) == 0,
                        "valid verified leaf entry was rejected")
                schedules = ([0, 1], [1], [2], [U64])
                retired = finish_leaf(library, context, state, schedules[index % 4], counters)
                require(state.values() == expected and retired == steps and
                        all(state.x[r] == v for r, v in trial.expected_x.items()), "dispatched leaf result mismatch")
                leaf_cases += 1

        native_caller = library.oot_lift_dispatch_caller
        native_caller.argtypes, native_caller.restype = [POINTER(State), POINTER(Memory), c_uint64, POINTER(c_uint64)], c_int
        by_name = {p.name: p for p in leaves}
        call_sites = {CALLER + 4: by_name["dispatch_leaf_remainder"].base,
                      CALLER + 12: by_name["dispatch_leaf_mix"].base}
        rng = random.Random(SEED)
        edges = [0, 1, U64, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF]
        operands = [(a, b) for a in edges for b in edges] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(64)]
        for index, (a, b) in enumerate(operands):
            state = State()
            state.x[:] = [rng.getrandbits(64) for _ in range(31)]
            state.x[0], state.x[1], state.x[30], state.pc, state.sp, state.nzcv = a, b, EXIT, CALLER, STACK_HIGH, rng.randrange(16) << 28
            rotation = state.x[3]
            expected, expected_steps, expected_memory = reference.run(state, 64)
            memory, regions, buffers = initialize_native_memory(library, (RegionSpec(STACK_LOW, bytes(STACK_SIZE)),))
            retired, iterations = 0, 0
            while state.pc != EXIT:
                require(CALLER <= state.pc < CALLER + len(caller.data), "caller resumed at an unexpected guest address")
                pc, count = state.pc, c_uint64(U64)
                status = native_caller(byref(state), byref(memory), 1, byref(count))
                require(count.value == 1 and status in (0, 1), "synthetic caller did not retire exactly one instruction")
                retired += 1
                if pc in call_sites:
                    require(state.pc == call_sites[pc] and status == 0, "caller BL did not select the intended leaf")
                    report = Report()
                    require(library.oot_leaf_begin(context, byref(state), call_sites[pc], pc + 4, byref(report)) == 0,
                            "caller continuation was rejected")
                    retired += finish_leaf(library, context, state, ([0, 1] if index % 2 else [2]), counters)
                iterations += 1
                require(iterations <= len(caller.words), "synthetic caller did not terminate")
            formula = rotate((((remainder(a, b) + 7 + 2 * b) & U64) ^ 0xFFFF), rotation)
            require(state.values() == expected and state.x[0] == formula and retired == expected_steps and
                    bytes(buffers[0]) == expected_memory, "caller/callee/return chain diverged from ARM64")
            caller_cases += 1
        guards = guard_checks(library, context, leaves[0])
    finally:
        require(library.oot_leaf_dispatcher_destroy(context) == 1, "dispatcher did not close cleanly")
    report = {"schema_version": 1, "result": "passed", "seed": SEED, "synthetic_only": True,
              "game_code_executed": False, "reference": {"engine": "Unicorn ARM64", "version": version("unicorn")},
              "leaf_result_cases": leaf_cases, "caller_chain_cases": caller_cases, "guard_cases": guards,
              "yield_checks": counters, "native_build": build,
              "comparison": ["all integer state", "NZCV", "PC", "retired counts", "caller stack bytes", "mathematical results"]}
    destination = ROOT / f"build/dispatcher-validation/{mode}-report.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report, destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", choices=("cmake", "gcc"), default="cmake")
    args = parser.parse_args()
    report, destination = run_validation(args.compiler)
    print(json.dumps({"result": report["result"], "leaf_cases": report["leaf_result_cases"],
                      "caller_chains": report["caller_chain_cases"], "report": str(destination)}))


if __name__ == "__main__":
    main()
