"""Compile synthetic lifted C and compare state, memory, and faults with Unicorn ARM64."""

import argparse
from ctypes import CDLL, POINTER, byref, c_int, c_uint64
from importlib.metadata import version
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile

from arm64_lifter import FORMS, U64, decode_block, emit_c
from input_formats import InputError, require
from lifter_validation_types import BASE, Memory, Program, State, Trial
from memory_validation import memory_programs, validate_memory_policy, validate_memory_program
from pair_validation import pair_programs, validate_pair_policy
from integer_validation import integer_programs
from leaf_validation import leaf_programs
from leaf_verifier import emit_leaf_descriptor, verify_leaf
from frame_verifier import emit_frame_descriptor, verify_frame
from ordered_programs import ordered_programs
from conditional_programs import conditional_programs

ROOT = Path(__file__).resolve().parent.parent
SEED = 0x0CA41234


def move(sf, opc, rd, immediate=0xA55A, hw=0):
    return (sf << 31) | 0x12800000 | (opc << 29) | (hw << 21) | (immediate << 5) | rd


def add_imm(sf, subtract, flags, rd, rn, immediate=1, shift=0):
    return ((sf << 31) | 0x11000000 | (subtract << 30) | (flags << 29) |
            (shift << 22) | (immediate << 10) | (rn << 5) | rd)


def branch(index, target, call=False):
    return (0x94000000 if call else 0x14000000) | ((target - index) & 0x3FFFFFF)


def integer_words():
    words = [0xD503201F]
    for sf in (0, 1):
        width = 64 if sf else 32
        for opc in (0, 2, 3):
            for hw in range(width // 16):
                for rd in (0, 1, 31):
                    words.append(move(sf, opc, rd, hw=hw))
        for subtract in (0, 1):
            for flags in (0, 1):
                for rd, rn in ((0, 1), (0, 0), (31, 1), (0, 31), (31, 31)):
                    for shift in (0, 1):
                        for immediate in (0, 1, 0xFFF):
                            words.append(add_imm(sf, subtract, flags, rd, rn, immediate, shift))
                for shift in range(3):
                    for amount in (0, 1, width - 1):
                        for rd, rn, rm in ((0, 1, 2), (0, 0, 0), (31, 1, 2), (0, 31, 31)):
                            words.append((sf << 31) | 0x0B000000 | (subtract << 30) | (flags << 29) |
                                         (shift << 22) | (rm << 16) | (amount << 10) | (rn << 5) | rd)
        for opc in range(4):
            for invert in (0, 1):
                for shift in range(4):
                    for amount in (0, 1, width - 1):
                        for rd, rn, rm in ((0, 1, 2), (0, 0, 0), (31, 31, 31)):
                            words.append((sf << 31) | 0x0A000000 | (opc << 29) | (shift << 22) |
                                         (invert << 21) | (rm << 16) | (amount << 10) | (rn << 5) | rd)
    for page in (0, 1):
        for immediate in (0, 1, -1, (1 << 20) - 1, -(1 << 20)):
            for rd in (0, 31):
                encoded = immediate & 0x1FFFFF
                words.append((page << 31) | 0x10000000 | ((encoded & 3) << 29) |
                             ((encoded >> 2) << 5) | rd)
    return words


def branch_words():
    words = [branch(0, 1), branch(0, -1), branch(0, 1, True), branch(0, -1, True)]
    for condition in range(16):
        for displacement in (1, -1):
            words.append(0x54000000 | ((displacement & 0x7FFFF) << 5) | condition)
    for sf in (0, 1):
        for nonzero in (0, 1):
            for rt in (0, 31):
                for displacement in (1, -1):
                    words.append((sf << 31) | 0x34000000 | (nonzero << 24) |
                                 ((displacement & 0x7FFFF) << 5) | rt)
    for bit in range(64):
        for nonzero in (0, 1):
            for rt in (0, 31):
                words.append(((bit >> 5) << 31) | 0x36000000 | (nonzero << 24) |
                             ((bit & 31) << 19) | ((-1 & 0x3FFF) << 5) | rt)
    return words


def synthetic_programs():
    rng = random.Random(SEED)
    edges = [0, 1, U64, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000,
             0x7FFFFFFFFFFFFFFF, 0x8000000000000000]

    def trials(words, branch_flags=False):
        result = []
        for index, word in enumerate(words):
            values = edges + [rng.getrandbits(64) for _ in range(4)]
            if word & 0x7E000000 == 0x36000000:
                bit = ((word >> 31) << 5) | ((word >> 19) & 31)
                values += [1 << bit, U64 ^ (1 << bit)]
            for j, value in enumerate(values):
                regs = ([value] * 31 if j < len(edges) else [rng.getrandbits(64) for _ in range(31)])
                regs[0] = value
                result.append(Trial(index, regs, value, rng.randrange(16) << 28))
            if branch_flags and word & 0xFF000010 == 0x54000000:
                for flags in range(16):
                    result.append(Trial(index, [0] * 31, 0, flags << 28))
        return result

    integers, branches = integer_words(), branch_words()
    programs = [Program("integer", integers, trials(integers)),
                Program("branches", branches, trials(branches, True))]
    indirect = [op | (reg << 5) for op in (0xD61F0000, 0xD63F0000, 0xD65F0000) for reg in (0, 30, 31)]
    indirect_trials = []
    for index, word in enumerate(indirect):
        for target in (BASE, BASE + 4, BASE + 0x8000):
            regs = [rng.getrandbits(64) for _ in range(31)]
            reg = (word >> 5) & 31
            if reg != 31:
                regs[reg] = target
            indirect_trials.append(Trial(index, regs, 0x800000, 0x90000000))
    programs.append(Program("indirect", indirect, indirect_trials))
    # mov x0,5; subs x0,x0,1; b.ne loop; bl sub; b exit; add x1,x1,7; ret
    loop = [move(1, 2, 0, 5), add_imm(1, 1, 1, 0, 0), 0x54FFFFE1,
            branch(3, 5, True), branch(4, 7), add_imm(1, 0, 0, 1, 1, 7), 0xD65F03C0]
    programs.append(Program("loop_call", loop, [Trial(0, [0] * 31, 0x800000, 0, budget)
                                               for budget in (0, 1, 2, 3, 10, 11, 12, 14, 15, 64)]))
    # An intentional endless loop must return at the instruction budget.
    programs.append(Program("endless", [0x14000000], [Trial(0, [0] * 31, 0, 0, b) for b in (0, 1, 100)]))
    # Multiple aliases and a high-address W write, then an external dispatcher exit.
    sequence = [move(1, 2, 0, 0xFFFF, 3), move(0, 3, 0, 0xBEEF),
                add_imm(1, 0, 0, 31, 31, 16), add_imm(0, 1, 1, 31, 0, 1),
                0x2A0003E1, branch(5, 6)]
    programs.append(Program("sequence", sequence, [Trial(0, [U64] * 31, 0x800000, 0xF0000000, 32)]))
    high = [0x10FFFFE0, 0xF0FFFFE1, 0x10000082, 0x90000003, branch(4, 5, True)]
    programs.append(Program("high_address", high, [Trial(0, [U64] * 31, 0x800000, 0xF0000000, 32)],
                            base=0x100200FF0))
    programs.append(Program("outside_entry", [0xD503201F],
                            [Trial(index, [0] * 31, 0, 0, budget)
                             for index in (-1, 1) for budget in (0, 1)]))
    return (programs + memory_programs() + pair_programs() + integer_programs() + leaf_programs() +
            ordered_programs() + conditional_programs())


def find_cmake():
    found = shutil.which("cmake")
    if found:
        return found
    path = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / (
        "Microsoft Visual Studio/2022/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe")
    require(path.is_file(), "CMake is required for native differential validation")
    return str(path)


def compile_library(programs, mode="cmake", extra_source=""):
    parent = ROOT / "build/lifter-validation"
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=f"{mode}-", dir=parent))
    source = directory / "lifted.c"
    chunks, reports = [], []
    for program in programs:
        code, report = emit_c(program.data, program.base, f"oot_lift_{program.name}")
        if program.leaf:
            report["leaf_verification"] = verify_leaf(program.data, program.base)
            code += "\n" + emit_leaf_descriptor(program.data, program.base, f"oot_lift_{program.name}")
        if program.frame_leaves is not None:
            report["frame_verification"] = verify_frame(program.data, program.base, program.frame_leaves)
            code += "\n" + emit_frame_descriptor(program.data, program.base, program.frame_leaves, f"oot_lift_{program.name}")
        chunks.append(code)
        reports.append(report)
    source.write_text("\n".join(chunks) + "\n" + extra_source, encoding="utf-8")

    def run(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        with (directory / "compile.log").open("a", encoding="utf-8") as log:
            log.write(result.stdout + result.stderr)
        require(result.returncode == 0, f"native compilation failed; see {directory / 'compile.log'}")

    if mode == "gcc":
        compiler = shutil.which("gcc")
        require(compiler is not None, "gcc is not available on PATH")
        library = directory / ("lifted.dll" if os.name == "nt" else "lifted.so")
        run([compiler, "-std=c17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-shared",
             "-DOOT_MEMORY_SHARED_EXPORTS", "-D_CRT_SECURE_NO_WARNINGS", "-D_WIN32_WINNT=0x0A00",
             "-I", str(ROOT / "src"), str(source), str(ROOT / "src/guest_memory.c"),
             str(ROOT / "src/runtime_image.c"), str(ROOT / "src/host_win32.c"), str(ROOT / "src/leaf_dispatch.c"),
             str(ROOT / "src/frame_dispatch.c"), str(ROOT / "src/stack_dispatch.c"), str(ROOT / "src/pauth.c"), str(ROOT / "src/checked_read.c"), str(ROOT / "src/plt_bridge.c"),
             "-lbcrypt", "-o", str(library)])
        compiler_info = subprocess.run([compiler, "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    else:
        cmake = find_cmake()
        (directory / "CMakeLists.txt").write_text(
            'cmake_minimum_required(VERSION 3.20)\nproject(lift_validation LANGUAGES C)\n'
            f'add_library(lifted SHARED lifted.c "{(ROOT / "src/guest_memory.c").as_posix()}" '
            f'"{(ROOT / "src/runtime_image.c").as_posix()}" "{(ROOT / "src/host_win32.c").as_posix()}" '
            f'"{(ROOT / "src/leaf_dispatch.c").as_posix()}" "{(ROOT / "src/frame_dispatch.c").as_posix()}" '
            f'"{(ROOT / "src/stack_dispatch.c").as_posix()}" "{(ROOT / "src/pauth.c").as_posix()}" "{(ROOT / "src/checked_read.c").as_posix()}" "{(ROOT / "src/plt_bridge.c").as_posix()}")\n'
            'target_link_libraries(lifted PRIVATE bcrypt)\n'
            'target_compile_definitions(lifted PRIVATE OOT_MEMORY_SHARED_EXPORTS _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0A00)\n'
            'target_compile_features(lifted PRIVATE c_std_17)\n'
            f'target_include_directories(lifted PRIVATE "{(ROOT / "src").as_posix()}")\n'
            'if(MSVC)\n target_compile_options(lifted PRIVATE /W4 /WX)\n'
            'else()\n target_compile_options(lifted PRIVATE -Wall -Wextra -Wpedantic -Werror)\nendif()\n',
            encoding="utf-8")
        run([cmake, "-S", str(directory), "-B", str(directory / "native"), "-DCMAKE_BUILD_TYPE=Release"])
        run([cmake, "--build", str(directory / "native"), "--config", "Release"])
        suffix = "*.dll" if os.name == "nt" else "*.so"
        libraries = list((directory / "native").rglob(suffix))
        require(len(libraries) == 1, "expected one generated native validation library")
        library = libraries[0]
        metadata = list((directory / "native/CMakeFiles").glob("*/CMakeCCompiler.cmake"))
        require(len(metadata) == 1, "expected CMake C compiler metadata")
        compiler_text = metadata[0].read_text(encoding="utf-8")
        compiler_info = " ".join(re.findall(
            r'set\(CMAKE_C_COMPILER(?:_ID|_VERSION)? "([^"]+)"\)', compiler_text))
        require(bool(compiler_info), "missing native compiler identity")
    return CDLL(str(library)), {"mode": mode, "compiler": compiler_info,
                                "directory": str(directory), "programs": reports}


def validate_program(library, program):
    if program.memory:
        return validate_memory_program(library, program)
    try:
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
        from unicorn import arm64_const as registers
    except ImportError as error:
        raise InputError("install tools/requirements-lifter.txt for differential validation") from error
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mapping_base = (program.base & ~0xFFF) - 0x1000
    machine.mem_map(mapping_base, 0x102000)
    machine.mem_map(0, 0x1000)
    machine.mem_write(program.base, program.data)
    reg_ids = [getattr(registers, f"UC_ARM64_REG_X{index}") for index in range(31)]
    pcs = set(range(program.base, program.base + len(program.data), 4))
    steps = [0]

    def hook(engine, address, size, user):
        if address not in pcs:
            engine.emu_stop()
        else:
            steps[0] += 1

    machine.hook_add(UC_HOOK_CODE, hook)
    native = getattr(library, f"oot_lift_{program.name}")
    native.argtypes = [POINTER(State), POINTER(Memory), c_uint64, POINTER(c_uint64)]
    native.restype = c_int
    for case_index, trial in enumerate(program.trials):
        state = State()
        state.x[:] = trial.registers
        state.sp, state.pc, state.nzcv = trial.sp, program.base + trial.index * 4, trial.nzcv
        for register, value in zip(reg_ids, trial.registers):
            machine.reg_write(register, value)
        machine.reg_write(registers.UC_ARM64_REG_SP, state.sp)
        machine.reg_write(registers.UC_ARM64_REG_NZCV, state.nzcv)
        machine.reg_write(registers.UC_ARM64_REG_PC, state.pc)
        steps[0] = 0
        if trial.budget:
            machine.emu_start(state.pc, 0, count=trial.budget)
        expected = (tuple(machine.reg_read(r) for r in reg_ids),
                    machine.reg_read(registers.UC_ARM64_REG_SP),
                    machine.reg_read(registers.UC_ARM64_REG_PC),
                    machine.reg_read(registers.UC_ARM64_REG_NZCV))
        expected_status = int(expected[2] in pcs)
        count = c_uint64(U64)
        status = native(byref(state), None, trial.budget, byref(count))
        if trial.expected_nzcv is not None:
            require(state.nzcv == expected[3] == trial.expected_nzcv,
                    f"independent flag result mismatch: {program.name} {case_index}")
        if trial.expected_x is not None:
            require(program.leaf and status == 0 and all(state.x[r] == v for r, v in trial.expected_x.items()),
                    f"complete leaf mathematical result mismatch: {program.name} {case_index}")
        if state.values() != expected or status != expected_status or count.value != steps[0]:
            raise AssertionError(json.dumps({"program": program.name, "case": case_index,
                "word": f"0x{program.words[trial.index]:08x}" if 0 <= trial.index < len(program.words) else None,
                "trial": vars(trial),
                "expected": expected, "actual": state.values(), "status": [expected_status, status],
                "executed": [steps[0], count.value]}))
    return len(program.trials)


def run_validation(mode="cmake"):
    programs = synthetic_programs()
    library, build = compile_library(programs, mode)
    count = sum(validate_program(library, program) for program in programs)
    memory_policy = validate_memory_policy(library) + validate_pair_policy(library)
    observed_forms = sorted({ins.form for p in programs for ins in decode_block(p.data, p.base)})
    require(set(observed_forms) == set(FORMS), "validation must exercise every implemented form")
    report = {"schema_version": 2, "abi_version": 2, "result": "passed", "seed": SEED,
              "reference": {"engine": "Unicorn ARM64", "version": version("unicorn")},
              "synthetic_only": True, "game_code_executed": False,
              "comparison": ["x0-x30", "sp", "pc", "nzcv", "retired_instruction_count", "exit_status",
                             "all_mapped_data_bytes", "aligned_unmapped_and_permission_faults"],
              "memory_trial_count": sum(len(p.trials) for p in programs if p.memory),
              "verified_synthetic_leaf_count": sum(p.leaf for p in programs),
              "whole_leaf_result_trials": sum(t.expected_x is not None for p in programs if p.leaf for t in p.trials),
              "independent_flag_trials": sum(t.expected_nzcv is not None for p in programs for t in p.trials),
              "memory_policy_checks": memory_policy,
              "reference_fault_trial_count": sum(t.expected_fault is not None for p in programs if p.memory for t in p.trials),
              "fault_policy": "preflight whole scalar access; cross-boundary store atomicity is a project policy, not hardware equivalence",
              "trial_count": count, "program_count": len(programs), "forms": observed_forms,
              "native_build": build}
    report_path = ROOT / f"build/lifter-validation/{mode}-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report, report_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", choices=("cmake", "gcc"), default="cmake")
    args = parser.parse_args()
    report, path = run_validation(args.compiler)
    print(json.dumps({"result": report["result"], "trials": report["trial_count"], "report": str(path)}))


if __name__ == "__main__":
    main()
