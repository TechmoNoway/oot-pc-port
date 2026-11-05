"""Synthetic hash-bound PAC frame DAGs, retained keys, and transactional guards."""

import argparse
from ctypes import (POINTER, Structure, byref, c_uint8, c_uint32, c_uint64, c_void_p,
                    cast, create_string_buffer, memset, sizeof, string_at)
from dataclasses import replace
from importlib.metadata import version
import json
import os
from pathlib import Path
import random

from arm64_lifter import U64
from dispatcher_validation import CALLER, EXIT, STACK_LOW, STACK_SIZE, STACK_HIGH, Report, CodeHash, LeafFunction
from input_formats import require
from leaf_validation import leaf_programs, remainder
from lifter_validation import compile_library
from lifter_validation_types import State
from pauth_lifter import emit_pauth_c
from pauth_validation import Reference, KEYS, SIGN, AUTH, RETURN, bindings as key_bindings
from prepare_registry import emit_stack_factory
from stack_cfg_validation import add_immediate, immediate, mov, CfgStep
from stack_layout_validation import LayoutAssembler, LayoutFunction, LayoutStep, add, bindings as layout_bindings, memory_word
from stack_layout_verifier import verify_pauth_stack_functions, emit_pauth_stack_descriptor, RECORD_RESTORE
from stack_validation import package, StackStep

ROOT = Path(__file__).resolve().parent.parent


class PauthFunction(Structure):
    _fields_ = [("layout", LayoutFunction), ("run", c_void_p), ("sign_word", c_uint32), ("auth_word", c_uint32)]


def bindings(lib):
    layout_bindings(lib); key_bindings(lib)
    args = lib.oot_stack_create_layout.argtypes.copy(); args[1] = POINTER(PauthFunction)
    lib.oot_stack_create_pauth.argtypes = args[:-1] + [c_void_p, args[-1]]
    lib.oot_stack_create_pauth.restype = c_void_p
    lib.oot_create_bound_registry.argtypes = [c_void_p, c_void_p, POINTER(c_uint32)]
    lib.oot_create_bound_registry.restype = c_void_p


class PauthAssembler(LayoutAssembler):
    def __init__(self, *args, key=1, explicit_auth=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.key, self.explicit_auth = key, explicit_auth
        self.words.insert(0, SIGN[key])  # Synthetic assembly; fixups are created afterwards.

    def finish(self):
        p = super().finish()
        p.words[-1:] = [AUTH[self.key], 0xD65F03C0] if self.explicit_auth else [RETURN[self.key]]
        return p


def synthetic_programs():
    leaf = replace(next(p for p in leaf_programs() if p.name == "leaf_remainder"),
                   name="pac_remainder", base=CALLER + 0x30000, trials=[])
    root = PauthAssembler("pac_root", CALLER, 96, 80, ((48, (19, 20)), (72, (21,))), fp_first=False)
    root.emit(mov(19, 0)); root.branch("zero", 0xB4000000)
    root.bl(CALLER + 0x10000); root.emit(add(0, 0, 19)); root.bl(leaf.base)
    root.emit(add_immediate(0, 0, 7)); root.branch("epilogue", 0x14000000, 26)
    root.label("zero"); root.emit(immediate(0, 42))
    child = PauthAssembler("pac_child", CALLER + 0x10000, 64, 0, ((40, (19,)),),
                           key=0, explicit_auth=True, split=False, fp_first=False)
    child.emit(mov(19, 0)); child.bl(CALLER + 0x20000); child.emit(add_immediate(0, 0, 6))
    inner = PauthAssembler("pac_inner", CALLER + 0x20000, 48, 32, key=1, explicit_auth=True)
    inner.emit(add_immediate(0, 0, 5))
    return [root.finish(), child.finish(), inner.finish()], [leaf]


def matrix_programs():
    result = []
    for key in range(2):
        for explicit in (False, True):
            for split in (False, True):
                index = len(result)
                # All ten saved registers plus the FP/LR record and disjoint locals.
                a = PauthAssembler(f"pac_matrix{index}", CALLER + (index + 5) * 0x10000, 128,
                    112 if split else 0, tuple((16 + i * 16, (19 + 2 * i, 20 + 2 * i)) for i in range(5)),
                    key=key, explicit_auth=explicit, split=split, fp_first=False)
                a.emit(memory_word(8, False, 0, 31, 96), memory_word(8, True, 0, 31, 96))
                for r in range(19, 29): a.emit(add_immediate(r, 0, r))
                a.emit(mov(0, 19))
                for r in range(20, 29): a.emit(add(0, 0, r))
                result.append(a.finish())
    return result


def depth_programs():
    result = []
    for index in range(16):
        a = PauthAssembler(f"pac_depth{index}", CALLER + (32 + index) * 0x10000, 256,
            240 if index % 2 == 0 else 0, key=index % 2, explicit_auth=index % 3 == 0, split=index % 2 == 0)
        if index != 15: a.bl(a.base + 0x10000)
        result.append(a.finish())
    return result


class PauthReference(Reference):
    def __init__(self, programs):
        super().__init__()
        self.keys(KEYS)
        self.words = {}
        for p in programs:
            self.u.mem_map(p.base & ~4095, 4096)
            self.u.mem_write(p.base, p.data)
            self.words.update({p.base + 4 * i: w for i, w in enumerate(p.words)})
        self.u.mem_map(EXIT & ~4095, 4096)

    def trace(self, initial):
        self.u.mem_write(STACK_LOW, bytes(STACK_SIZE))
        states, memories = [State.from_buffer_copy(initial)], [bytes(STACK_SIZE)]
        s = states[0]
        while s.pc != EXIT:
            require(s.pc in self.words and len(states) < 1000, "PAC reference left declared DAG")
            s = self.step(s, self.words[s.pc]); states.append(s)
            memories.append(bytes(self.u.mem_read(STACK_LOW, STACK_SIZE)))
        return states, memories


def run_validation(mode="cmake"):
    require(version("unicorn") == "2.1.4", "pinned PAuth reference required")
    frames, leaves = synthetic_programs(); matrix, chain = matrix_programs(), depth_programs()
    proofs = verify_pauth_stack_functions({p.base: p.data for p in frames}, {p.base: p.data for p in leaves}, CALLER)
    singles = {p.base: verify_pauth_stack_functions({p.base: p.data}, {}, p.base)[p.base] for p in matrix}
    depths = verify_pauth_stack_functions({p.base: p.data for p in chain}, {}, chain[0].base)
    programs = frames + leaves + matrix + chain
    blob, digest = package(programs)
    source = ""
    for p in frames + matrix + chain:
        proof = (proofs if p in frames else singles if p in matrix else depths)[p.base]
        source += emit_pauth_c(p.data, p.base, "oot_pauth_lift_" + p.name)[0]
        source += emit_pauth_stack_descriptor(proof, "oot_pauth_lift_" + p.name)
    source += emit_stack_factory([p.name for p in frames], [p.name for p in leaves], CALLER, digest.hex(), [EXIT], pauth=True)
    for p in matrix:
        source += emit_stack_factory([p.name], [], p.base, digest.hex(), [EXIT], pauth=True).replace("oot_create_bound_registry", "oot_create_" + p.name)
    source += emit_stack_factory([p.name for p in chain], [], chain[0].base, digest.hex(), [EXIT], pauth=True).replace("oot_create_bound_registry", "oot_create_pac_depth")
    restore = next(i for i, s in enumerate(proofs[CALLER]["steps"]) if s["kind"] == RECORD_RESTORE)
    modes = [(0, "s->x[30] ^= 1;", 12), (0, "s->x[30] = old_lr;", 12),
        (0, "s->sp -= 16;", 12), (0, "*n = 0;", 10), (0, "result = OOT_LIFT_DISPATCH;", 13),
        (1, "s->sp += 16;", 12), (2, "(void)oot_memory_store(m, s->sp + 88, 8, 0);", 49),
        (restore, "s->x[30] ^= UINT64_C(1) << 39;", 12),
        (restore + 1, "s->sp -= 16;", 12), (len(frames[0].words) - 1, "s->pc ^= 4;", 11),
        (len(frames[0].words) - 1, "s->x[30] = s->pc;", 12)]
    source += '''
static unsigned pac_bad_mode, pac_bad_calls;
OOT_LIFT_EXPORT void oot_pac_bad_set(unsigned mode) { pac_bad_mode = mode; }
OOT_LIFT_EXPORT unsigned oot_pac_bad_count(void) { return pac_bad_calls; }
OOT_LIFT_EXPORT int oot_pac_bad(OotArm64State *s, OotGuestMemory *m, const OotPauth *p, uint64_t b, uint64_t *n)
{
    uint64_t pc = s->pc, old_lr = s->x[30];
    int result;
    ++pac_bad_calls;
    result = oot_pauth_lift_pac_root(s, m, p, b, n);
    switch (pac_bad_mode) {
'''
    for i, (index, action, _) in enumerate(modes, 1):
        source += f"    case {i}: if (pc == UINT64_C(0x{CALLER + 4 * index:x})) {{ {action} }} break;\n"
    source += "    }\n    return result;\n}\n"
    lib, build = compile_library(leaves, mode, source); bindings(lib)
    lib.oot_pac_bad_set.argtypes = [c_uint32]; lib.oot_pac_bad_count.restype = c_uint32
    path = Path(build["directory"]) / "synthetic.ootmem"; path.write_bytes(blob)
    message, error, report = create_string_buffer(192), c_uint32(), Report()
    image = lib.oot_runtime_open(os.fsencode(path), message, len(message)); require(image, f"PAC image rejected: {message.value}")
    memory = lib.oot_runtime_memory(image); stack = memory.contents.regions[1].data
    keys = (c_uint64 * 4)(*KEYS); key_context = lib.oot_pauth_create(1, keys)
    require(key_context, "PAC keys rejected")
    reference, rng, prefixes, whole = PauthReference(programs), random.Random(0x50414344), 0, 0

    def initial(base=CALLER, a=1, b=1):
        s = State(); s.x[:] = [rng.getrandbits(64) for _ in range(31)]
        s.pc, s.sp, s.x[0], s.x[1], s.x[30], s.nzcv = base, STACK_HIGH, a, b, EXIT, rng.randrange(16) << 28
        return s

    def check(context, start, formula, budget=1, prefix=False):
        nonlocal prefixes, whole
        states, memories = reference.trace(start)
        s = State.from_buffer_copy(start); memset(stack, 0, STACK_SIZE)
        require(lib.oot_stack_begin(context, byref(s), EXIT, byref(report)) == 0, f"PAC begin rejected {report.error}")
        require(lib.oot_stack_run(context, byref(s), 0, byref(report)) == 1 and report.total_retired == 0, "PAC zero budget failed")
        for _ in range(1000):
            status = lib.oot_stack_run(context, byref(s), budget, byref(report))
            require(status in (1, 2) and report.error == 0, f"PAC dispatcher failed {status}/{report.error} pc={s.pc:x}")
            n = report.total_retired
            require(s.values() == states[n].values() and bytes(stack[:STACK_SIZE]) == memories[n], "PAC dispatcher differs from reference prefix")
            if prefix: prefixes += 1
            if status == 2: break
        else: raise ValueError("PAC dispatcher did not terminate")
        require(s.x[0] == formula and report.total_retired == len(states) - 1, "PAC formula/retirement mismatch")
        require(lib.oot_stack_run(context, byref(s), 1, byref(report)) == 2 and report.retired_this_call == 0, "PAC returned call not idempotent")
        whole += 1

    context = lib.oot_create_bound_registry(image, key_context, byref(error)); require(context, f"PAC registry rejected {error.value}")
    try:
        edges = (0, 1, U64, 1 << 63, (1 << 63) - 1, 0xFFFFFFFF)
        for index, (a, b) in enumerate([(a, b) for a in edges for b in edges] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(28)]):
            check(context, initial(a=a, b=b), (42 if a == 0 else remainder((2 * a + 11) & U64, b) + 7) & U64,
                  (1, 3, U64)[index % 3], prefix=index % 3 == 0)
        # Every instruction, not just a bulk budget, for a taken full nested path.
        check(context, initial(a=10, b=3), 8, prefix=True)
        trace, _ = reference.trace(initial(a=10, b=3))
        pauses = (CALLER + 8, CALLER + 12, frames[1].base + 8, CALLER + 4 * (restore + 1))
        for pc in pauses:  # Allocated/root/ancestor/restored record stays owned until deallocation.
            count = next(i for i, state in enumerate(trace) if state.pc == pc)
            s = initial(); memset(stack, 0, STACK_SIZE)
            require(lib.oot_stack_begin(context, byref(s), EXIT, byref(report)) == 0 and
                    lib.oot_stack_run(context, byref(s), count, byref(report)) == 1, "PAC owner setup failed")
            saved = s.values(); offset = STACK_SIZE - 96 + 88; stack[offset] ^= 1
            require(lib.oot_stack_run(context, byref(s), 0, byref(report)) == 3 and report.error == 49 and s.values() == saved,
                    "signed ancestor frame corruption was not rejected")
            stack[offset] ^= 1; lib.oot_stack_abort(context, byref(report))
        s = initial(); memset(stack, 0, STACK_SIZE)
        require(lib.oot_stack_begin(context, byref(s), EXIT, byref(report)) == 0 and
                lib.oot_stack_run(context, byref(s), 1, byref(report)) == 1, "signed checkpoint setup failed")
        s.x[30] ^= 1
        require(lib.oot_stack_run(context, byref(s), 0, byref(report)) == 3 and report.error == 7, "changed signed checkpoint accepted")
        s.x[30] ^= 1
        text = memory.contents.regions[0].data; text[0] ^= 1
        require(lib.oot_stack_run(context, byref(s), 0, byref(report)) == 3 and report.error == 17, "changed PAC code accepted on resume")
        text[0] ^= 1; lib.oot_stack_abort(context, byref(report))
    finally: lib.oot_stack_destroy(context)
    for p in matrix + [chain[0]]:
        factory = getattr(lib, "oot_create_" + p.name if p in matrix else "oot_create_pac_depth")
        factory.argtypes, factory.restype = [c_void_p, c_void_p, POINTER(c_uint32)], c_void_p
        context = factory(image, key_context, byref(error)); require(context, f"PAC matrix/depth rejected {error.value}")
        try:
            for a in (0, U64, 1 << 63):
                s = initial(p.base, a=a)
                check(context, s, (10 * a + sum(range(19, 29))) & U64 if p in matrix else a, prefix=True)
        finally: lib.oot_stack_destroy(context)

    table = (PauthFunction * len(frames))()
    for i, p in enumerate(frames):
        getter = getattr(lib, "oot_stack_pauth_descriptor_" + p.name); getter.restype = POINTER(PauthFunction)
        table[i] = getter().contents
    leaf_table, hashes = (LeafFunction * len(leaves))(), (CodeHash * len(leaves))()
    for i, p in enumerate(leaves):
        getter = getattr(lib, "oot_leaf_descriptor_" + p.name); getter.restype = POINTER(LeafFunction); leaf_table[i] = getter().contents
        getter = getattr(lib, "oot_leaf_code_hash_" + p.name); getter.restype = POINTER(CodeHash); hashes[i] = getter().contents
    body, returns = (c_uint8 * 32).from_buffer_copy(digest), (c_uint64 * 1)(EXIT)
    def create(ctx=key_context):
        return lib.oot_stack_create_pauth(image, table, len(frames), CALLER, leaf_table, len(leaves), hashes, body, returns, 1, ctx, byref(error))
    require(create(None) is None, "missing PAC context accepted")
    body[0] ^= 1
    require(create() is None and error.value == 16, "wrong PAC image hash accepted")
    body[0] ^= 1
    text = memory.contents.regions[0].data; text[0] ^= 1
    require(create() is None and error.value == 17, "changed PAC function bytes accepted at creation")
    text[0] ^= 1
    table[0].layout.cfg.info.run = table[0].run
    require(create() is None and error.value == 48, "old callback ABI accepted in PAC descriptor")
    table[0].layout.cfg.info.run = None
    for field, value in (("sign_word", SIGN[0]), ("auth_word", AUTH[0]), ("run", None)):
        old = getattr(table[0], field); setattr(table[0], field, value)
        require(create() is None and error.value == 48, f"invalid PAC metadata {field} accepted")
        setattr(table[0], field, old)
    n = table[0].layout.cfg.info.instruction_count
    states = (LayoutStep * n).from_buffer_copy(string_at(table[0].layout.states, sizeof(LayoutStep) * n)); table[0].layout.states = states
    for index, field, value in ((0, "lr", 0), (0, "sp", 0), (restore, "lr", 1), (n - 1, "lr", 1)):
        old = getattr(states[index], field); setattr(states[index], field, value)
        require(create() is None and error.value == 48, "invalid PAC state phase accepted")
        setattr(states[index], field, old)
    table[0].run = cast(lib.oot_pac_bad, c_void_p).value
    for mode_index, (instruction, _action, expected_error) in enumerate(modes, 1):
        context = create(); require(context, "PAC bad-callback fixture rejected")
        lib.oot_pac_bad_set(mode_index)
        try:
            s = initial(a=10, b=3); trace, _ = reference.trace(s); prefix = next(i for i, st in enumerate(trace) if st.pc == CALLER + 4 * instruction)
            memset(stack, 0, STACK_SIZE)
            require(lib.oot_stack_begin(context, byref(s), EXIT, byref(report)) == 0 and
                    lib.oot_stack_run(context, byref(s), prefix, byref(report)) == 1, "PAC fault setup failed")
            before, backing = s.values(), bytes(stack[:STACK_SIZE])
            require(lib.oot_stack_run(context, byref(s), 1, byref(report)) == 4 and report.error == expected_error and
                    s.values() == before and bytes(stack[:STACK_SIZE]) == backing, f"PAC bad callback committed mode {mode_index}, error {report.error}")
            calls = lib.oot_pac_bad_count()
            require(lib.oot_stack_run(context, byref(s), 100, byref(report)) == 4 and lib.oot_pac_bad_count() == calls, "PAC fault not latched")
        finally: lib.oot_stack_destroy(context)
    # Dispatcher pins keys and image even after the caller releases both handles.
    table[0].run = cast(lib.oot_pauth_lift_pac_root, c_void_p).value
    context = create(); require(context, "retained PAC fixture rejected")
    lib.oot_pauth_destroy(key_context); lib.oot_runtime_close(image)
    try: check(context, initial(a=10, b=3), 8, prefix=True)
    finally: lib.oot_stack_destroy(context)
    report_data = {"schema_version": 1, "result": "passed", "game_code_executed": False,
        "whole_call_cases": whole, "prefix_step_checks": prefixes, "native_fault_modes": len(modes),
        "matrix_layouts": len(matrix), "max_depth": 16, "reference": {"unicorn": version("unicorn"), "model": "QARMA5/VA39/TBI0"},
        "native_build": build}
    destination = Path(build["directory"]) / "pauth-stack-report.json"
    destination.write_text(json.dumps(report_data, indent=2) + "\n", encoding="utf-8")
    return report_data, destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--compiler", choices=("gcc", "cmake"), default="cmake")
    result, destination = run_validation(parser.parse_args().compiler); print(json.dumps(result, indent=2)); print(destination)
