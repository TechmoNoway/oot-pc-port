"""Artificial paired-transfer programs; no game-derived instructions."""

from ctypes import POINTER, byref, c_int, c_uint64

from arm64_lifter import U64
from input_formats import require
from lifter_validation_types import BASE, Memory, MemoryTrial, Program, RegionSpec, State
from memory_validation import DATA, PATTERN, initialize_native_memory


def pair(opc, load, rt, rt2, rn, mode=2, immediate=0):
    return ((opc << 30) | 0x28000000 | (mode << 23) | (int(load) << 22) |
            ((immediate & 127) << 15) | (rt2 << 10) | (rn << 5) | rt)


def pair_programs():
    words, trials, faults, fault_trials = [], [], [], []
    common = (RegionSpec(DATA, PATTERN),)
    for opc, load in ((0, False), (0, True), (1, True), (2, False), (2, True)):
        size = 8 if opc == 2 else 4
        for mode in (1, 2, 3):
            for immediate in (-64, -1, 0, 1, 63):
                for rn in (1, 31):
                    destinations = [(0, 2), (31, 2), (0, 31)] + ([] if load else [(0, 0), (31, 31)])
                    for rt, rt2 in destinations:
                        index = len(words)
                        words.append(pair(opc, load, rt, rt2, rn, mode, immediate))
                        for unaligned in (0, 1, 7):
                            regs = [0xAABBCCDDEEFF0011 + i for i in range(31)]
                            regs[0], regs[2] = 0x1122334455667788, 0xFFEEDDCCBBAA9988
                            base = DATA + 0x400 + unaligned
                            if rn != 31:
                                regs[rn] = base
                            trials.append(MemoryTrial(index, regs, base, 0xB0000000, regions=common))
            index = len(faults)
            faults.append(pair(opc, load, 0, 2, 1, mode, -2))
            for permission in (None, 2 if load else 1):
                target = DATA + 0x2000
                regions = (RegionSpec(DATA, PATTERN[:4096]),)
                if permission is not None:
                    regions += (RegionSpec(target, PATTERN[:4096], permission),)
                regs = [U64] * 31
                regs[1] = target if mode == 1 else target + 2 * size
                fault_trials.append(MemoryTrial(index, regs, DATA, 0xA0000000,
                    regions=regions, expected_fault=(target, target, size * 2, 1 if load else 2, 1 if permission is None else 2),
                    reference_fault_sizes=(size, size * 2)))
    # Address must be captured before either overlapping destination is changed.
    for rt, rt2 in ((1, 2), (0, 1)):
        index = len(words)
        words.append(pair(2, True, rt, rt2, 1))
        regs = [U64] * 31
        regs[1] = DATA + 0x400
        trials.append(MemoryTrial(index, regs, DATA, 0, regions=common))
    # A normal stack frame, paired save/restore, and a terminating fallthrough.
    stack = [pair(2, False, 29, 30, 31, 3, -2), 0x910003FD, 0xD280001E,
             pair(2, True, 29, 30, 31, 1, 2)]
    regs = [U64 - i for i in range(31)]
    programs = [Program("paired_memory", words, trials, memory=True),
                Program("paired_faults", faults, fault_trials, memory=True),
                Program("paired_stack", stack, [MemoryTrial(0, regs, DATA + 0x800, 0xF0000000, budget, regions=common)
                                                 for budget in (0, 1, 2, 3, 4, 16)], memory=True)]
    # Cross two separately backed regions and exercise the final valid pair range.
    boundary_words = [pair(2, False, 0, 2, 1), pair(2, True, 0, 2, 1)]
    regions = (RegionSpec(DATA, PATTERN[:4096]), RegionSpec(DATA + 4096, PATTERN[4096:8192]))
    boundary_trials = []
    for index in (0, 1):
        for address in (DATA + 4089, DATA + 4095, DATA + 8192 - 16):
            regs = [0] * 31
            regs[0], regs[1], regs[2] = 0x0123456789ABCDEF, address, U64
            boundary_trials.append(MemoryTrial(index, regs, DATA, 0, regions=regions))
    programs.append(Program("paired_boundaries", boundary_words, boundary_trials, memory=True))
    return programs


def validate_pair_policy(library):
    native = library.oot_lift_paired_boundaries
    native.argtypes = [POINTER(State), POINTER(Memory), c_uint64, POINTER(c_uint64)]
    native.restype = c_int
    for permissions in (None, 1, 2):
        specs = (RegionSpec(DATA, b"\xA5" * 4096),)
        if permissions is not None:
            specs += (RegionSpec(DATA + 4096, b"\x5A" * 4096, permissions),)
        for index in (0, 1):
            if (index == 0 and permissions == 2) or (index == 1 and permissions == 1):
                continue
            memory, table, buffers = initialize_native_memory(library, specs)
            state, count = State(), c_uint64(U64)
            state.pc, state.x[0], state.x[1], state.x[2] = BASE + index * 4, 0x1234, DATA + 4088, 0x5678
            before, snapshot = state.values(), [bytes(b) for b in buffers]
            require(native(byref(state), byref(memory), 1, byref(count)) == 2 and count.value == 0 and
                    state.values() == before and [bytes(b) for b in buffers] == snapshot and
                    memory.fault.address == DATA + 4088 and memory.fault.failing_address == DATA + 4096 and memory.fault.size == 16,
                    "rejected second pair element must preserve both registers and both memory elements")
    memory, table, buffers = initialize_native_memory(library, (RegionSpec(U64 - 15, b"\xA5" * 16),))
    state, count = State(), c_uint64(U64)
    state.pc, state.x[1] = BASE, U64 - 7
    before = state.values()
    require(native(byref(state), byref(memory), 1, byref(count)) == 2 and memory.fault.reason == 3 and
            state.values() == before and count.value == 0 and bytes(buffers[0]) == b"\xA5" * 16,
            "pair range wrapping must be rejected before first-element mutation")
    return ["pair_second_element_preflight", "pair_range_wrap"]
