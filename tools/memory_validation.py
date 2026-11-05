"""Synthetic scalar transfers and independent reference memory/fault checks."""

from ctypes import POINTER, byref, c_int, c_size_t, c_uint8, c_uint64, cast
import json
import random

from arm64_lifter import U64, decode_block
from input_formats import InputError, require
from lifter_validation_types import BASE, Memory, MemoryTrial, Program, Region, RegionSpec, State

DATA = 0x200000000
PATTERN = bytes([0x80, 0xFF, 0x7F, 0x80, 0x01, 0xA5, 0xFE, 0x80]) * 8192


def transfer(size, opc, rt, rn, mode="unsigned", immediate=0, rm=2, extend=3, scaled=0):
    word = (size << 30) | (opc << 22) | (rn << 5) | rt
    if mode == "unsigned":
        return word | 0x39000000 | (immediate << 10)
    if mode == "register":
        return word | 0x38200800 | (rm << 16) | (extend << 13) | (scaled << 12)
    return word | 0x38000000 | ((immediate & 0x1FF) << 12) | ({"unscaled": 0, "post": 1, "pre": 3}[mode] << 10)


def memory_programs():
    rng = random.Random(0x57A0E)
    common = (RegionSpec(DATA, PATTERN),)
    words, trials = [], []
    faults, fault_trials = [], []

    def add(word, rn, base_value, regions=common, rm=None, rm_value=0):
        index = len(words)
        words.append(word)
        for pattern_index, unaligned in enumerate((0, 1, 7)):
            registers = [rng.getrandbits(64) for _ in range(31)]
            registers[0] = (0, U64, 0x80FF7FFF80000001)[pattern_index]
            stack = base_value + unaligned
            if rn != 31:
                registers[rn] = stack
            if rm is not None and rm != 31:
                registers[rm] = rm_value
            trials.append(MemoryTrial(index, registers, stack, rng.randrange(16) << 28,
                                      regions=regions))

    for size in range(4):
        for opc in range(4):
            if (size == 3 and opc >= 2) or (size == 2 and opc == 3):
                continue
            for rn in (1, 31):
                for rt in (0, 31):
                    for immediate in (0, 1, 4095):
                        add(transfer(size, opc, rt, rn, immediate=immediate), rn, DATA + 0x400)
                    for mode in ("unscaled", "pre", "post"):
                        for immediate in (-256, -1, 0, 1, 255):
                            add(transfer(size, opc, rt, rn, mode, immediate), rn, DATA + 0x400)
                    for extend in (2, 3, 6, 7):
                        for scaled in (0, 1):
                            for rm in (2, 31):
                                # UXTW must discard high bits; signed offsets must extend before scaling.
                                rm_value = (0xABCD000000000003 if extend == 2 else
                                            0x12345678FFFFFFFD if extend == 6 else
                                            U64 - 2 if extend == 7 else 3)
                                raw_offset = (rm_value & 0xFFFFFFFF) if extend in (2, 6) else rm_value
                                if extend == 6 and raw_offset & 0x80000000:
                                    raw_offset -= 1 << 32
                                if rm == 31:
                                    raw_offset = 0
                                offset = raw_offset << (size if scaled else 0)
                                base_value = (DATA + 0x400 - offset) & U64
                                add(transfer(size, opc, rt, rn, "register", rm=rm, extend=extend, scaled=scaled),
                                    rn, base_value, rm=rm, rm_value=rm_value)
            # Aligned faults are compared with the reference, not hardware partial-store behavior.
            for mode in ("unsigned", "unscaled", "pre", "post", "register"):
                index = len(faults)
                immediate = {"unsigned": 1, "unscaled": -16, "pre": -16, "post": 16, "register": 0}[mode]
                offset = ((1 << size) if mode == "unsigned" else -16 if mode in ("unscaled", "pre") else
                          8 if mode == "register" else 0)
                faults.append(transfer(size, opc, 0, 1, mode, immediate))
                for permission in (None, 2 if opc else 1):
                    target = DATA + 0x2000
                    regions = (RegionSpec(DATA, PATTERN[:4096]),)
                    if permission is not None:
                        regions += (RegionSpec(target, PATTERN[:4096], permission),)
                    registers = [0] * 31
                    registers[0], registers[1], registers[2] = 0xDEADBEEF87654321, target - offset, 8
                    fault = (target, target, 1 << size, 1 if opc else 2, 1 if permission is None else 2)
                    fault_trials.append(MemoryTrial(index, registers, DATA, 0xA0000000,
                                                    regions=regions, expected_fault=fault))
    # Base/destination aliases are legal without writeback.
    add(transfer(3, 1, 1, 1), 1, DATA + 0x400)
    add(transfer(3, 0, 1, 1), 1, DATA + 0x400)
    # The zero destination still performs a faulting read; SP base is not XZR.
    fault_index = len(faults)
    faults.append(transfer(3, 1, 31, 31, "pre", -16))
    target = DATA + 0x2000
    fault_trials.append(MemoryTrial(fault_index, [0] * 31, target + 16, 0,
                                    regions=common[:0], expected_fault=(target, target, 8, 1, 1)))
    programs = [Program("scalar_memory", words, trials, memory=True),
                Program("memory_faults", faults, fault_trials, memory=True)]

    boundary_words, boundary_trials = [], []
    adjacent = (RegionSpec(DATA, PATTERN[:4096]), RegionSpec(DATA + 4096, PATTERN[4096:8192]))
    for size in range(4):
        for opc in (0, 1):
            index = len(boundary_words)
            boundary_words.append(transfer(size, opc, 0, 1))
            for address in (DATA, DATA + 4093, DATA + 4095, DATA + 8192 - (1 << size)):
                regs = [0] * 31
                regs[0], regs[1] = 0xAABBCCDDEEFF0080, address
                boundary_trials.append(MemoryTrial(index, regs, DATA, 0xF0000000, regions=adjacent))
    programs.append(Program("memory_boundaries", boundary_words, boundary_trials, memory=True))

    literal_words, literal_trials = [], []
    for opc in range(3):
        for sign in (-1, 1):
            for rt in (0, 31):
                index = len(literal_words)
                target = BASE + sign * 0x80000
                displacement = (target - (BASE + index * 4)) // 4
                literal_words.append(0x18000000 | (opc << 30) | ((displacement & 0x7FFFF) << 5) | rt)
                literal_trials.append(MemoryTrial(index, [U64] * 31, DATA, 0xB0000000,
                    regions=(RegionSpec(target, PATTERN[:4096], 1),)))
    programs.append(Program("literal_memory", literal_words, literal_trials, memory=True))
    # A stack-like save/change/restore sequence; each instruction must see previous stores.
    stack_words = [transfer(3, 0, 0, 31, "pre", -16), 0xD2800000,
                   transfer(3, 1, 0, 31, "post", 16), transfer(2, 0, 0, 1, immediate=1),
                   transfer(2, 2, 2, 1, immediate=1)]
    regs = [U64] * 31
    regs[1] = DATA + 0x800
    programs.append(Program("memory_sequence", stack_words,
        [MemoryTrial(0, regs, DATA + 0x800, 0xF0000000, budget, regions=common)
         for budget in (0, 1, 2, 3, 5, 16)], memory=True))
    resume_words = [transfer(3, 0, 0, 1), transfer(3, 1, 2, 3)]
    regs = [0] * 31
    regs[0], regs[1], regs[3] = U64, DATA, DATA + 0x2000
    programs.append(Program("memory_fault_after_store", resume_words,
        [MemoryTrial(0, regs, DATA, 0, budget, regions=(RegionSpec(DATA, PATTERN[:4096]),),
                     expected_fault=(DATA + 0x2000, DATA + 0x2000, 8, 1, 1) if budget > 1 else None)
         for budget in (0, 1, 2, 8)], memory=True))
    regs = [0] * 31
    regs[1] = U64 - 7  # Address arithmetic wraps, then the actual transfer at zero is valid.
    programs.append(Program("memory_address_wrap", [transfer(3, 1, 0, 1, immediate=1)],
        [MemoryTrial(0, regs, DATA, 0, regions=(RegionSpec(0, PATTERN[:4096]),))], memory=True))
    alias_words, alias_trials = [], []
    for opc in (0, 1):
        for same_base in (False, True):
            index = len(alias_words)
            alias_words.append(transfer(3, opc, 1 if same_base else 2, 1, "register", rm=1 if same_base else 2))
            regs = [0] * 31
            regs[1], regs[2] = (DATA // 2 + 0x400 if same_base else DATA + 0x400), 8
            alias_trials.append(MemoryTrial(index, regs, DATA, 0x90000000, regions=common))
    programs.append(Program("memory_register_aliases", alias_words, alias_trials, memory=True))
    return programs


def initialize_native_memory(library, specs):
    buffers = [(c_uint8 * len(spec.data)).from_buffer_copy(spec.data) for spec in specs]
    table = (Region * len(specs))(*[Region(s.base, len(s.data), cast(b, POINTER(c_uint8)), s.permissions)
                                   for s, b in zip(specs, buffers)])
    memory = Memory()
    library.oot_memory_init.argtypes = [POINTER(Memory), POINTER(Region), c_size_t]
    library.oot_memory_init.restype = c_int
    require(library.oot_memory_init(byref(memory), table, len(specs)) == 1, "invalid synthetic memory map")
    return memory, table, buffers  # Keep backing and region table alive through the native call.


def validate_memory_policy(library):
    """Check runtime contracts beyond the deliberately bounded oracle fault cases."""
    native = library.oot_lift_memory_fault_after_store
    native.argtypes = [POINTER(State), POINTER(Memory), c_uint64, POINTER(c_uint64)]
    native.restype = c_int
    state, count = State(), c_uint64(U64)
    state.pc, state.x[0], state.x[1], state.x[2], state.x[3] = BASE, U64, DATA, 0x1234, DATA + 0x2000
    memory, table, buffers = initialize_native_memory(library, (RegionSpec(DATA, PATTERN[:4096]),))
    require(native(byref(state), byref(memory), 8, byref(count)) == 2 and count.value == 1,
            "fault after a retired store must report exactly one retired instruction")
    require(state.pc == BASE + 4 and state.x[2] == 0x1234 and bytes(buffers[0][:8]) == b"\xff" * 8,
            "fault must preserve destination and PC while retaining prior retired stores")
    require(native(byref(state), byref(memory), 0, byref(count)) == 1 and count.value == 0 and memory.fault.reason == 0,
            "zero budget must clear stale fault without performing an access")
    require(native(byref(state), byref(memory), 8, byref(count)) == 2 and count.value == 0 and state.pc == BASE + 4,
            "retry against an unchanged map must fault without repeating a retired instruction")
    specs = (RegionSpec(DATA, bytes(buffers[0])), RegionSpec(DATA + 0x2000, b"\x42" * 4096, 1))
    memory, table, buffers = initialize_native_memory(library, specs)
    require(native(byref(state), byref(memory), 8, byref(count)) == 0 and count.value == 1 and
            state.pc == BASE + 8 and state.x[2] == 0x4242424242424242 and memory.fault.reason == 0,
            "mapping the missing page must allow resuming at the faulting PC")

    native = library.oot_lift_memory_boundaries
    native.argtypes = [POINTER(State), POINTER(Memory), c_uint64, POINTER(c_uint64)]
    native.restype = c_int
    memory, table, buffers = initialize_native_memory(library, (RegionSpec(U64 - 7, b"\xA5" * 8),))
    for index in (6, 7):  # Eight-byte store and load, crossing the uint64 address limit.
        state = State()
        state.pc, state.x[0], state.x[1], state.nzcv = BASE + index * 4, 0x1234, U64 - 3, 0xA0000000
        before = state.values()
        require(native(byref(state), byref(memory), 1, byref(count)) == 2 and count.value == 0 and
                memory.fault.reason == 3 and state.values() == before and bytes(buffers[0]) == b"\xA5" * 8,
                "wrapping scalar transfers must fail before state or backing mutation")
        require(native(byref(state), None, 1, byref(count)) == 2 and count.value == 0 and state.values() == before,
                "a missing memory object must return a fault without dereferencing native memory")
    return ["fault_retirement_and_pc", "clear_stale_fault_at_zero_budget", "retry_after_mapping",
            "reject_wrapping_transfer_without_mutation", "null_memory_is_a_fault"]


def validate_memory_program(library, program):
    try:
        from unicorn import (Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID,
                             UC_MEM_READ_UNMAPPED, UC_MEM_READ_PROT, UC_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_PROT)
        from unicorn import arm64_const as registers
    except ImportError as error:
        raise InputError("install tools/requirements-lifter.txt for memory validation") from error
    native = getattr(library, f"oot_lift_{program.name}")
    native.argtypes = [POINTER(State), POINTER(Memory), c_uint64, POINTER(c_uint64)]
    native.restype = c_int
    reg_ids = [getattr(registers, f"UC_ARM64_REG_X{i}") for i in range(31)]
    pcs = set(range(program.base, program.base + len(program.data), 4))
    code_start = program.base & ~4095
    code_size = ((program.base + len(program.data) - code_start + 4095) // 4096) * 4096
    rcpc = any(i.form == "load_acquire_rcpc" for i in decode_block(program.data,program.base))
    for case_index, trial in enumerate(program.trials):
        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        if rcpc:
            machine.ctl_set_cpu_model(registers.UC_CPU_ARM64_MAX)
            require((machine.cpr_read(3,0,0,6,1) >> 20) & 15 >= 1, "reference CPU lacks FEAT_LRCPC")
        machine.mem_map(code_start, code_size)
        machine.mem_write(program.base, program.data)
        for spec in trial.regions:
            machine.mem_map(spec.base, len(spec.data), spec.permissions)
            machine.mem_write(spec.base, spec.data)
        steps, faults = [0], []

        def hook(engine, address, size, user):
            if address not in pcs:
                engine.emu_stop()
            else:
                steps[0] += 1

        def invalid(engine, access, address, size, value, user):
            access_kind = 1 if access in (UC_MEM_READ_UNMAPPED, UC_MEM_READ_PROT) else 2
            reason = 1 if access in (UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED) else 2
            require(access in (UC_MEM_READ_UNMAPPED, UC_MEM_READ_PROT, UC_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_PROT),
                    "unexpected reference instruction-fetch fault")
            faults.append((address, address, size, access_kind, reason))
            return False

        machine.hook_add(UC_HOOK_CODE, hook)
        machine.hook_add(UC_HOOK_MEM_INVALID, invalid)
        state = State()
        state.x[:] = trial.registers
        state.sp, state.pc, state.nzcv = trial.sp, program.base + trial.index * 4, trial.nzcv
        for register, value in zip(reg_ids, trial.registers):
            machine.reg_write(register, value)
        machine.reg_write(registers.UC_ARM64_REG_SP, state.sp)
        machine.reg_write(registers.UC_ARM64_REG_NZCV, state.nzcv)
        machine.reg_write(registers.UC_ARM64_REG_PC, state.pc)
        if trial.budget:
            # End address stops successful fallthrough before an instruction fetch outside the range.
            try:
                machine.emu_start(state.pc, program.base + len(program.data), count=trial.budget)
            except UcError:
                if not faults:
                    raise
        reference_fault = trial.expected_fault
        if faults and trial.reference_fault_sizes:
            require(len(faults) == 1 and faults[0][2] in trial.reference_fault_sizes,
                    "unexpected reference paired-access fault width")
            reference_fault = (*reference_fault[:2], faults[0][2], *reference_fault[3:])
        require(faults == ([reference_fault] if reference_fault else []),
                f"unexpected reference fault in {program.name} case {case_index}: {faults}")
        expected = (tuple(machine.reg_read(r) for r in reg_ids),
                    machine.reg_read(registers.UC_ARM64_REG_SP), machine.reg_read(registers.UC_ARM64_REG_PC),
                    machine.reg_read(registers.UC_ARM64_REG_NZCV))
        expected_status = 2 if faults else int(expected[2] in pcs)
        expected_count = steps[0] - bool(faults)
        memory, table, buffers = initialize_native_memory(library, trial.regions)
        count = c_uint64(U64)
        status = native(byref(state), byref(memory), trial.budget, byref(count))
        memory_matches = all(bytes(b) == bytes(machine.mem_read(s.base, len(s.data)))
                             for s, b in zip(trial.regions, buffers))
        actual_fault = memory.fault.values() if memory.fault.reason else None
        if trial.expected_x is not None:
            require(all(state.x[r]==v for r,v in trial.expected_x.items()), "independent ordered-load value mismatch")
        if (state.values() != expected or count.value != expected_count or status != expected_status or
                not memory_matches or actual_fault != trial.expected_fault):
            raise AssertionError(json.dumps({"program": program.name, "case": case_index,
                "word": hex(program.words[trial.index]), "initial_registers": trial.registers,
                "expected": expected, "actual": state.values(), "memory_matches": memory_matches,
                "fault": [trial.expected_fault, actual_fault], "status": [expected_status, status],
                "retired": [expected_count, count.value]}))
    return len(program.trials)
