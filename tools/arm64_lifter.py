"""Independent integer/control-flow ARM64 decoder and bounded C17 emitter.

Only exact encodings accepted here have implemented semantics. Capstone syntax
decoding is deliberately not used to decide semantic support.
"""

from collections import Counter
from dataclasses import dataclass
import re
import struct

from input_formats import InputError, require

U64 = (1 << 64) - 1
MAX_WORDS = 16384
FORMS = ("move_wide", "addsub_immediate", "addsub_shifted", "logical_shifted",
         "pc_relative", "branch_immediate", "branch_condition", "compare_branch",
         "test_branch", "branch_register", "nop")


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


class UnsupportedInstruction(InputError):
    def __init__(self, pc, word, reason="instruction form is not implemented"):
        super().__init__(f"ARM64 at 0x{pc:x}: 0x{word:08x}: {reason}")


@dataclass(frozen=True)
class Instruction:
    pc: int
    word: int
    form: str
    width: int = 64
    rd: int = 0
    rn: int = 0
    rm: int = 0
    immediate: int = 0
    shift: int = 0
    amount: int = 0
    operation: int = 0
    flags: bool = False
    invert: bool = False
    target: int = 0


def decode_instruction(word, pc):
    require(isinstance(word, int) and 0 <= word <= 0xFFFFFFFF, "instruction must be a uint32")
    require(isinstance(pc, int) and 0 <= pc <= U64 and pc % 4 == 0, "PC must be an aligned uint64")
    width = 64 if word >> 31 else 32
    rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31

    def ins(form, **kwargs):
        return Instruction(pc, word, form, **kwargs)

    def reject(reason):
        raise UnsupportedInstruction(pc, word, reason)

    if word == 0xD503201F:
        return ins("nop")
    if word & 0x1F800000 == 0x12800000:
        operation, amount = (word >> 29) & 3, ((word >> 21) & 3) * 16
        if operation == 1 or amount >= width:
            reject("reserved move-wide encoding")
        return ins("move_wide", width=width, rd=rd, operation=operation,
                   immediate=((word >> 5) & 0xFFFF) << amount, amount=amount)
    if word & 0x1F800000 == 0x11000000:
        return ins("addsub_immediate", width=width, rd=rd, rn=rn,
                   operation=(word >> 30) & 1, flags=bool(word & (1 << 29)),
                   immediate=((word >> 10) & 0xFFF) << (12 if word & (1 << 22) else 0))
    if word & 0x1F200000 == 0x0B000000:
        shift, amount = (word >> 22) & 3, (word >> 10) & 63
        if shift == 3 or amount >= width:
            reject("reserved add/sub shifted-register encoding")
        return ins("addsub_shifted", width=width, rd=rd, rn=rn, rm=rm,
                   operation=(word >> 30) & 1, flags=bool(word & (1 << 29)),
                   shift=shift, amount=amount)
    if word & 0x1F000000 == 0x0A000000:
        amount = (word >> 10) & 63
        if amount >= width:
            reject("reserved 32-bit logical shift amount")
        return ins("logical_shifted", width=width, rd=rd, rn=rn, rm=rm,
                   operation=(word >> 29) & 3, invert=bool(word & (1 << 21)),
                   shift=(word >> 22) & 3, amount=amount)
    if word & 0x1F000000 == 0x10000000:
        immediate = signed((((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3), 21)
        target = ((pc & ~0xFFF) + (immediate << 12) if word >> 31 else pc + immediate) & U64
        return ins("pc_relative", rd=rd, target=target)
    if word & 0x7C000000 == 0x14000000:
        return ins("branch_immediate", operation=word >> 31,
                   target=(pc + signed(word & 0x3FFFFFF, 26) * 4) & U64)
    if word & 0xFF000010 == 0x54000000:
        return ins("branch_condition", operation=word & 15,
                   target=(pc + signed((word >> 5) & 0x7FFFF, 19) * 4) & U64)
    if word & 0x7E000000 == 0x34000000:
        return ins("compare_branch", width=width, rd=rd, operation=(word >> 24) & 1,
                   target=(pc + signed((word >> 5) & 0x7FFFF, 19) * 4) & U64)
    if word & 0x7E000000 == 0x36000000:
        return ins("test_branch", rd=rd, operation=(word >> 24) & 1,
                   amount=((word >> 31) << 5) | ((word >> 19) & 31),
                   target=(pc + signed((word >> 5) & 0x3FFF, 14) * 4) & U64)
    opcode = word & 0xFFFFFC1F
    if opcode in (0xD61F0000, 0xD63F0000, 0xD65F0000):
        return ins("branch_register", rn=rn, operation=int(opcode == 0xD63F0000))
    reject("instruction form is not implemented")


def decode_block(data, base):
    require(data and len(data) % 4 == 0, "input must contain whole ARM64 words")
    require(len(data) <= MAX_WORDS * 4, f"block exceeds the {MAX_WORDS * 4}-byte translation limit")
    require(isinstance(base, int) and base % 4 == 0 and 0 <= base <= U64 - len(data),
            "block base/range must fit in aligned uint64 addresses without wrapping")
    return [decode_instruction(word[0], base + offset)
            for offset, word in zip(range(0, len(data), 4), struct.iter_unpack("<I", data))]


def constant(value):
    return f"UINT64_C(0x{value & U64:x})"


def body(ins):
    width, rd, rn, rm = ins.width, ins.rd, ins.rn, ins.rm
    next_pc = constant(ins.pc + 4)

    def read(reg, use_sp=False):
        return f"oot_arm64_read(s, {reg}, {width}, {int(use_sp)})"

    def write(value, use_sp=False):
        return f"oot_arm64_write(s, {rd}, {width}, {int(use_sp)}, {value});"

    lines = []
    if ins.form == "move_wide":
        value = constant(ins.immediate)
        if ins.operation == 0:
            value = f"~{value}"
        elif ins.operation == 3:
            value = f"({read(rd)} & ~{constant(0xFFFF << ins.amount)}) | {value}"
        lines.append(write(value))
    elif ins.form in ("addsub_immediate", "addsub_shifted"):
        immediate = ins.form == "addsub_immediate"
        right = constant(ins.immediate) if immediate else (
            f"oot_arm64_shift({read(rm)}, {ins.shift}, {ins.amount}, {width})")
        lines.extend([f"uint64_t a = {read(rn, immediate)};", f"uint64_t b = {right};",
                      f"uint64_t r = oot_arm64_addsub(s, a, b, {width}, {ins.operation}, {int(ins.flags)});",
                      write("r", immediate and not ins.flags)])
    elif ins.form == "logical_shifted":
        lines.extend([f"uint64_t a = {read(rn)};",
                      f"uint64_t b = oot_arm64_shift({read(rm)}, {ins.shift}, {ins.amount}, {width});"])
        if ins.invert:
            lines.append(f"b = ~b & {constant((1 << width) - 1)};")
        operator = ("&", "|", "^", "&")[ins.operation]
        lines.append(f"uint64_t r = a {operator} b;")
        if ins.operation == 3:
            lines.append(f"s->nzcv = oot_arm64_nz(r, {width});")
        lines.append(write("r"))
    elif ins.form == "pc_relative":
        lines.append(write(constant(ins.target)))
    elif ins.form == "branch_immediate":
        if ins.operation:
            lines.append(f"s->x[30] = {next_pc};")
        next_pc = constant(ins.target)
    elif ins.form == "branch_condition":
        next_pc = f"oot_arm64_condition(s->nzcv, {ins.operation}) ? {constant(ins.target)} : {next_pc}"
    elif ins.form == "compare_branch":
        operator = "!=" if ins.operation else "=="
        next_pc = f"{read(rd)} {operator} 0 ? {constant(ins.target)} : {next_pc}"
    elif ins.form == "test_branch":
        operator = "!=" if ins.operation else "=="
        next_pc = f"({read(rd)} & {constant(1 << ins.amount)}) {operator} 0 ? {constant(ins.target)} : {next_pc}"
    elif ins.form == "branch_register":
        # BLR X30 must capture its target before writing the link register.
        lines.append(f"uint64_t target = {read(rn)};")
        if ins.operation:
            lines.append(f"s->x[30] = {next_pc};")
        next_pc = "target"
    elif ins.form != "nop":
        raise InputError(f"missing emitter for {ins.form}")
    lines.append(f"s->pc = {next_pc};")
    return lines


def emit_c(data, base, name="oot_lift_run"):
    require(re.fullmatch(r"oot_lift_[A-Za-z0-9_]+", name) is not None,
            "function name must start with oot_lift_ and contain only identifier characters")
    instructions = decode_block(data, base)  # Complete validation before producing source.
    lines = ['/* Generated ARM64 integer/control-flow translation. */', '#include "arm64_lift.h"', "",
             f"OOT_LIFT_EXPORT int {name}(OotArm64State *s, uint64_t budget, uint64_t *executed)",
             "{", "    uint64_t count = 0;", "    for (;;) {", "        switch (s->pc) {"]
    for ins in instructions:
        lines.extend([f"        case {constant(ins.pc)}: {{ /* {ins.form} 0x{ins.word:08x} */",
                      "            if (count == budget) { *executed = count; return OOT_LIFT_BUDGET; }"])
        lines.extend(f"            {line}" for line in body(ins))
        lines.extend(["            ++count;", "            break;", "        }"])
    lines.extend(["        default: *executed = count; return OOT_LIFT_DISPATCH;",
                  "        }", "    }", "}", ""])
    report = {"schema_version": 1, "base": base, "byte_count": len(data),
              "instruction_count": len(instructions), "forms": dict(Counter(i.form for i in instructions)),
              "function": name, "guest_memory_access": False, "game_runtime_ready": False}
    return "\n".join(lines), report
