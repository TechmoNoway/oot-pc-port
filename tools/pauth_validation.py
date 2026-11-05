"""Pinned, PAuth-enabled ARM64 reference versus independent native C semantics.

All code, pointers, memory, and keys here are synthetic. No game inputs are read.
"""

import argparse
from ctypes import (POINTER, byref, c_int, c_size_t, c_uint8, c_uint32, c_uint64,
                    c_void_p, sizeof, string_at)
from importlib.metadata import version
import json
from pathlib import Path
import random
import struct

from arm64_lifter import U64
from input_formats import require
from lifter_validation import compile_library
from lifter_validation_types import BASE, Memory, Region, State
from pair_validation import pair
from pauth_lifter import MODEL, WORDS, emit_pauth_c

ROOT = Path(__file__).resolve().parent.parent
STACK = 0x7000000000
EXIT = BASE + 0x800
KEYS = (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x1020304050607080, 0x9080706050403020)
SIGN = (0xD503233F, 0xD503237F)
AUTH = (0xD50323BF, 0xD50323FF)
RETURN = (0xD65F0BFF, 0xD65F0FFF)
PAC_MASK = 0xFF7FFF8000000000


def copy_state(state):
    return State.from_buffer_copy(state)


def bindings(lib):
    lib.oot_pauth_create.argtypes, lib.oot_pauth_create.restype = [c_uint32, c_void_p], c_void_p
    lib.oot_pauth_destroy.argtypes, lib.oot_pauth_destroy.restype = [c_void_p], None
    lib.oot_pauth_model.argtypes, lib.oot_pauth_model.restype = [c_void_p], c_uint32
    lib.oot_pauth_step.argtypes, lib.oot_pauth_step.restype = [c_void_p, POINTER(State), c_uint32], c_int
    lib.oot_memory_init.argtypes = [POINTER(Memory), POINTER(Region), c_size_t]
    lib.oot_memory_init.restype = c_int


class Reference:
    def __init__(self):
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
        from unicorn import arm64_const as r
        self.r = r
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.u.ctl_set_cpu_model(r.UC_CPU_ARM64_MAX)
        # Assert basic QARMA5, not implementation-defined crypto or newer failures.
        self.isar1 = self.u.cpr_read(3, 0, 0, 6, 1)
        require((self.isar1 >> 4) & 15 == 1 and (self.isar1 >> 8) & 15 == 0,
                "reference must implement basic QARMA5 PAuth")
        self.u.cpr_write(3, 6, 1, 1, 0, (1 << 17) | (1 << 10) | 1)  # SCR: API/RW/NS
        self.u.cpr_write(3, 4, 1, 1, 0, 1 << 41)  # HCR: API
        self.sctlr = self.u.cpr_read(3, 0, 1, 0, 0) | (1 << 31) | (1 << 30)
        self.u.cpr_write(3, 0, 1, 0, 0, self.sctlr)  # SCTLR: EnIA/EnIB
        self.tcr = 25 | (25 << 16)  # T0SZ=T1SZ=25; TBI0=TBI1=0
        self.u.cpr_write(3, 0, 2, 0, 2, self.tcr)
        require(self.u.cpr_read(3, 0, 2, 0, 2) == self.tcr, "reference TCR write failed")
        require(self.u.cpr_read(3, 0, 1, 0, 0) == self.sctlr and self.sctlr & 1 == 0,
                "reference needs PAuth enabled and MMU disabled")
        self.u.reg_write(r.UC_ARM64_REG_PSTATE, 0)  # EL0t, flags set per trial
        require(self.u.reg_read(r.UC_ARM64_REG_PSTATE) & 15 == 0, "reference must run at EL0t")
        self.registers = [getattr(r, f"UC_ARM64_REG_X{i}") for i in range(31)]
        self.u.mem_map(BASE, 4096)
        self.u.mem_map(STACK, 4096)
        self.code(struct.pack("<6I", *WORDS))

    def keys(self, keys):
        for i, value in enumerate(keys):
            self.u.cpr_write(3, 0, 2, 1, i, value)
            require(self.u.cpr_read(3, 0, 2, 1, i) == value, "reference key write failed")

    def code(self, data):
        self.u.mem_write(BASE, bytes(data))
        self.u.ctl_remove_cache(BASE, BASE + 4096)

    def set(self, state):
        for reg, value in zip(self.registers, state.x):
            self.u.reg_write(reg, value)
        self.u.reg_write(self.r.UC_ARM64_REG_SP, state.sp)
        self.u.reg_write(self.r.UC_ARM64_REG_PC, state.pc)
        self.u.reg_write(self.r.UC_ARM64_REG_NZCV, state.nzcv)

    def get(self):
        s = State()
        for i, reg in enumerate(self.registers): s.x[i] = self.u.reg_read(reg)
        s.sp = self.u.reg_read(self.r.UC_ARM64_REG_SP)
        s.pc = self.u.reg_read(self.r.UC_ARM64_REG_PC)
        s.nzcv = self.u.reg_read(self.r.UC_ARM64_REG_NZCV)
        return s

    def step(self, state, word):
        from unicorn import UcError, UC_ERR_FETCH_UNMAPPED
        self.set(state)
        try: self.u.emu_start(state.pc, 0, count=1)
        except UcError as error:
            # An authenticated branch retires before the next unmapped fetch.
            require((word in RETURN or word == 0xD65F03C0) and error.errno == UC_ERR_FETCH_UNMAPPED,
                    f"unexpected reference exception: {error}")
        return self.get()


def primitive_checks(lib, reference, rng):
    comparisons = 0
    poisoned = 0
    for case in range(128):
        keys = KEYS if case == 0 else tuple(rng.getrandbits(64) for _ in range(4))
        key_array = (c_uint64 * 4)(*keys)
        context = lib.oot_pauth_create(1, key_array)
        require(context is not None, "synthetic PAC context allocation failed")
        reference.keys(keys)
        key_array[0] ^= U64  # Prove context keys were copied, not borrowed.
        try:
            # Both canonical ranges and boundary bits. Noncanonical signing is rejected below.
            pointers = [0, 1, (1 << 39) - 1, U64 ^ ((1 << 39) - 1), U64, EXIT,
                        rng.getrandbits(39), (U64 ^ ((1 << 39) - 1)) | rng.getrandbits(39)]
            for key in range(2):
                for pointer in pointers:
                    state = State()
                    for i in range(31): state.x[i] = rng.getrandbits(64)
                    state.sp = 0x7000001000 if case == 0 else rng.getrandbits(64)
                    state.nzcv = rng.randrange(16) << 28
                    state.pc, state.x[30] = BASE + key * 4, pointer
                    expected = reference.step(state, SIGN[key])
                    actual = copy_state(state)
                    require(lib.oot_pauth_step(context, byref(actual), SIGN[key]) == 0 and
                            actual.values() == expected.values(), f"PAC signing mismatch {case}/{key}/{pointer:x}")
                    comparisons += 1
                    signed = actual.x[30]
                    if case == 0 and pointer == EXIT:
                        # Independently recorded constants; the reference must not be a NOP.
                        # SP is fixed for case zero above, EXIT differs from the C self-test vector.
                        require(signed != pointer, "PAuth reference is disabled")
                    variations = [(signed, state.sp, key)]
                    variations += [(signed ^ (1 << bit), state.sp, key) for bit in range(39, 64)]
                    variations += [(signed ^ 1, state.sp, key), (signed, state.sp ^ 16, key),
                                   (signed, state.sp, 1 - key), (rng.getrandbits(64), state.sp, key)]
                    for value, sp, auth_key in variations:
                        for returning in (False, True):
                            word = RETURN[auth_key] if returning else AUTH[auth_key]
                            trial = copy_state(state)
                            trial.x[30], trial.sp = value, sp
                            trial.pc = BASE + (4 if returning else 2) * 4 + auth_key * 4
                            expected = reference.step(trial, word)
                            result = lib.oot_pauth_step(context, byref(trial), word)
                            require(result in (1, 2) and trial.values() == expected.values(),
                                    f"PAC authentication mismatch {case}/{key}/{word:x}/{value:x}/{sp:x}")
                            poisoned += result == 2
                            comparisons += 1
        finally: lib.oot_pauth_destroy(context)
    return comparisons, poisoned


def frame_words(key, explicit_auth):
    # Synthetic nested frame: root adds 7; child adds 11 with the other key.
    root = [SIGN[key], pair(2, False, 29, 30, 31, 3, -4), 0x910003FD, 0x91001C00,
            0x94000000 | ((0x100 - 16) // 4), pair(2, True, 29, 30, 31, 1, 4)]
    root += [AUTH[key], 0xD65F03C0] if explicit_auth else [RETURN[key]]
    child = [SIGN[1 - key], 0xD100C3FF, pair(2, False, 29, 30, 31, 2, 2), 0x910043FD,
             0x91002C00, pair(2, True, 29, 30, 31, 2, 2), 0x9100C3FF]
    child += [RETURN[1 - key]] if explicit_auth else [AUTH[1 - key], 0xD65F03C0]
    return root + [0xD503201F] * (64 - len(root)) + child


def frame_checks(lib, reference, rng, programs, context):
    whole = prefixes = 0
    reference.keys(KEYS)
    for index, words in enumerate(programs):
        data = struct.pack(f"<{len(words)}I", *words)
        reference.code(data)
        fn = getattr(lib, f"oot_pauth_lift_frame{index}")
        fn.argtypes = [POINTER(State), POINTER(Memory), c_void_p, c_uint64, POINTER(c_uint64)]
        fn.restype = c_int
        for case in range(16):
            initial = State()
            for i in range(31): initial.x[i] = rng.getrandbits(64)
            initial.sp, initial.pc, initial.x[30] = STACK + 0x800 + case * 16, BASE, EXIT
            initial.nzcv = rng.randrange(16) << 28
            pattern = rng.randbytes(4096)
            # Independent complete execution and every retired instruction prefix.
            reference.u.mem_write(STACK, pattern)
            states, memories = [copy_state(initial)], [pattern]
            s = copy_state(initial)
            while BASE <= s.pc < BASE + len(data):
                word = words[(s.pc - BASE) // 4]
                s = reference.step(s, word)
                states.append(s); memories.append(bytes(reference.u.mem_read(STACK, 4096)))
                require(len(states) < 64, "synthetic frame exceeded finite step bound")
            require(s.pc == EXIT and s.sp == initial.sp and s.x[0] == (initial.x[0] + 18) & U64,
                    "synthetic frame independent result failed")
            require(tuple(s.x[18:30]) == tuple(initial.x[18:30]), "synthetic frame did not restore registers")
            for budget in range(len(states) + 1):
                buffer = (c_uint8 * 4096).from_buffer_copy(pattern)
                regions = (Region * 1)(Region(STACK, 4096, buffer, 3))
                memory = Memory(); require(lib.oot_memory_init(byref(memory), regions, 1), "memory setup failed")
                actual, retired = copy_state(initial), c_uint64()
                status = fn(byref(actual), byref(memory), context, budget, byref(retired))
                n = min(budget, len(states) - 1)
                require((status, retired.value) == (0 if n == len(states) - 1 else 1, n) and
                        actual.values() == states[n].values() and bytes(buffer) == memories[n],
                        f"PAC frame prefix mismatch {index}/{case}/{budget}")
                prefixes += 1
            # Repeated resumptions retain the same immutable PAC context and saved PAC bytes.
            actual = copy_state(initial)
            buffer = (c_uint8 * 4096).from_buffer_copy(pattern)
            regions = (Region * 1)(Region(STACK, 4096, buffer, 3)); memory = Memory()
            require(lib.oot_memory_init(byref(memory), regions, 1), "resume memory setup failed")
            total = 0
            for _ in range(64):
                count = c_uint64()
                status = fn(byref(actual), byref(memory), context, 1, byref(count))
                total += count.value
                require(count.value == 1 and actual.values() == states[total].values() and
                        bytes(buffer) == memories[total], "PAC yield/resume mismatch")
                if status == 0: break
                require(status == 1, "PAC resume unexpectedly failed")
            require(total == len(states) - 1, "PAC resumed instruction count mismatch")
            whole += 1
    return whole, prefixes


def rejection_checks(lib, context, frame_fn):
    checks = 0
    s = State(); s.pc, s.sp, s.x[30] = BASE, STACK + 0x800, EXIT
    original = string_at(byref(s), sizeof(s))
    for ctx, word in ((None, SIGN[0]), (context, 0xD503201F), (context, 0xD50320FF),
                      (context, 0xD65F0BFE), (context, 0xFFFFFFFF)):
        require(lib.oot_pauth_step(ctx, byref(s), word) == -1 and
                string_at(byref(s), sizeof(s)) == original, "rejected PAC step mutated state")
        checks += 1
    for model in (0, 2, 0xFFFFFFFF):
        require(lib.oot_pauth_create(model, None) is None, "unknown PAC model accepted")
        checks += 1
    for pointer in (1 << 39, 1 << 55, 1 << 63):
        s.x[30] = pointer; before = string_at(byref(s), sizeof(s))
        require(lib.oot_pauth_step(context, byref(s), SIGN[0]) == -1 and
                string_at(byref(s), sizeof(s)) == before, "noncanonical signing did not fail closed")
        checks += 1
    s.x[30] = EXIT
    s.pc += 1; before = string_at(byref(s), sizeof(s))
    require(lib.oot_pauth_step(context, byref(s), SIGN[0]) == -1 and
            string_at(byref(s), sizeof(s)) == before, "misaligned PAC PC mutated state")
    checks += 1; s.pc = BASE
    count = c_uint64(99)
    require(frame_fn(byref(s), None, None, 100, byref(count)) == 3 and count.value == 0 and
            string_at(byref(s), sizeof(s)) == original, "missing PAC context did not fail closed")
    checks += 1
    # PAC retires; a subsequent checked STP fault must not alter SP/frame bytes.
    empty = Memory(); require(lib.oot_memory_init(byref(empty), None, 0), "empty memory setup failed")
    require(frame_fn(byref(s), byref(empty), context, 100, byref(count)) == 2 and
            count.value == 1 and s.pc == BASE + 4 and s.sp == STACK + 0x800 and
            empty.fault.reason == 1, "PAC followed by failed frame store retired incorrectly")
    checks += 1
    before = string_at(byref(s), sizeof(s))
    require(frame_fn(byref(s), byref(empty), context, 100, byref(count)) == 2 and
            count.value == 0 and string_at(byref(s), sizeof(s)) == before,
            "retrying rejected frame store mutated state")
    return checks + 1


def corrupted_frame_checks(lib, reference, programs, context):
    """Corrupt saved LR, change keys across a yield, or change return-time SP."""
    changed_keys = tuple(key ^ 0x10203 for key in KEYS)
    key_array = (c_uint64 * 4)(*changed_keys)
    changed = lib.oot_pauth_create(1, key_array)
    require(changed is not None, "changed-key context allocation failed")
    cases = 0
    try:
        for index, words in enumerate(programs):
            reference.code(struct.pack(f"<{len(words)}I", *words))
            fn = getattr(lib, f"oot_pauth_lift_frame{index}")
            for mode in ("saved-pac", "saved-address", "changed-key", "changed-sp"):
                reference.keys(KEYS)
                initial = State(); initial.pc, initial.sp, initial.x[30] = BASE, STACK + 0x800, EXIT
                actual, expected = copy_state(initial), copy_state(initial)
                buffer = (c_uint8 * 4096)()
                regions = (Region * 1)(Region(STACK, 4096, buffer, 3)); memory = Memory()
                require(lib.oot_memory_init(byref(memory), regions, 1), "corruption memory setup failed")
                reference.u.mem_write(STACK, bytes(buffer))
                # Stop after the signed LR was stored. For SP corruption, stop just
                # after restoring the root frame, before authenticating its LR.
                pause_pc = BASE + (24 if mode == "changed-sp" else 8)
                steps = 0
                while expected.pc != pause_pc:
                    word = words[(expected.pc - BASE) // 4]
                    expected = reference.step(expected, word); steps += 1
                    require(steps < 64, "corruption pause not reached")
                count = c_uint64()
                require(fn(byref(actual), byref(memory), context, steps, byref(count)) == 1 and
                        count.value == steps and actual.values() == expected.values() and
                        bytes(buffer) == bytes(reference.u.mem_read(STACK, 4096)), "corruption prefix mismatch")
                ctx = context
                if mode in ("saved-pac", "saved-address"):
                    offset = initial.sp - 24 - STACK
                    value = int.from_bytes(bytes(buffer[offset:offset + 8]), "little")
                    value ^= 1 << (39 if mode == "saved-pac" else 2)
                    for j, byte in enumerate(value.to_bytes(8, "little")): buffer[offset + j] = byte
                    reference.u.mem_write(STACK, bytes(buffer))
                elif mode == "changed-key":
                    ctx = changed; reference.keys(changed_keys)
                else:
                    actual.sp ^= 16; expected.sp ^= 16
                retired = 0
                while BASE <= expected.pc < BASE + len(words) * 4:
                    word = words[(expected.pc - BASE) // 4]
                    expected = reference.step(expected, word); retired += 1
                    require(retired < 64, "corruption exit not reached")
                require(fn(byref(actual), byref(memory), ctx, 100, byref(count)) == 0 and
                        count.value == retired and actual.values() == expected.values() and
                        bytes(buffer) == bytes(reference.u.mem_read(STACK, 4096)), "corrupted frame mismatch")
                require(actual.pc >> 61 == (1 if index // 2 == 0 else 2),
                        "corrupted frame did not dispatch a poisoned guest PC")
                cases += 1
    finally: lib.oot_pauth_destroy(changed)
    return cases


def run_validation(mode="cmake"):
    require(version("unicorn") == "2.1.4", "PAC reference requires pinned Unicorn 2.1.4")
    reference = Reference()
    programs = [frame_words(key, auth) for key in range(2) for auth in (False, True)]
    sources = [emit_pauth_c(struct.pack(f"<{len(words)}I", *words), BASE,
                            f"oot_pauth_lift_frame{i}")[0] for i, words in enumerate(programs)]
    lib, build = compile_library([], mode, "\n".join(sources))
    bindings(lib)
    rng = random.Random(0x50414339)
    comparisons, poisoned = primitive_checks(lib, reference, rng)
    keys = (c_uint64 * 4)(*KEYS); context = lib.oot_pauth_create(1, keys)
    require(context is not None, "PAC frame context allocation failed")
    try:
        whole, prefixes = frame_checks(lib, reference, rng, programs, context)
        checks = rejection_checks(lib, context, lib.oot_pauth_lift_frame0)
        corrupted = corrupted_frame_checks(lib, reference, programs, context)
    finally: lib.oot_pauth_destroy(context)
    report = {"schema_version": 1, "model": MODEL, "pauth_abi_version": 1,
              "reference": {"engine": "Unicorn", "version": version("unicorn"), "cpu": "MAX",
                            "isar1": hex(reference.isar1), "tcr_el1": hex(reference.tcr),
                            "sctlr_el1": hex(reference.sctlr), "exception_level": 0},
              "primitive_comparisons": comparisons, "poisoned_comparisons": poisoned,
              "nested_frame_cases": whole, "frame_prefix_checks": prefixes,
              "rejection_checks": checks, "corrupted_frame_cases": corrupted, "native_build": build,
              "game_code_executed": False, "registry_compatible": False}
    path = Path(build["directory"]) / "pauth-report.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report, path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", choices=("cmake", "gcc"), default="cmake")
    result, destination = run_validation(parser.parse_args().compiler)
    print(json.dumps(result, indent=2)); print(destination)
