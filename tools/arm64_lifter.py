"""Independent integer/scalar-memory/control-flow decoder and bounded C17 emitter.

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
         "test_branch", "branch_register", "nop", "loadstore_unsigned", "loadstore_immediate",
         "loadstore_register", "load_literal", "loadstore_pair", "logical_immediate", "bitfield",
         "conditional_select", "conditional_compare_register", "conditional_compare_immediate",
         "addsub_extended", "variable_shift", "multiply_add", "multiply_long", "divide", "addsub_carry", "load_acquire_rcpc",
         "bit_reverse", "byte_reverse", "count_leading", "multiply_high")
MEMORY_FORMS = frozenset(("loadstore_unsigned", "loadstore_immediate", "loadstore_register", "load_literal", "loadstore_pair", "load_acquire_rcpc"))


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
    access_size: int = 0
    load: bool = False
    sign_extend: bool = False
    writeback: bool = False
    post_index: bool = False
    extend: int = 0
    rt2: int = 0
    mask: int = 0
    top_mask: int = 0
    condition: int = 0
    ra: int = 0
    nzcv: int = 0


def bit_masks(n, imms, immr, width, logical):
    """Decode repeating bit masks without relying on disassembler aliases."""
    length = ((n << 6) | (~imms & 63)).bit_length() - 1
    require(length >= 1 and (1 << length) <= width, "reserved bit-mask element size")
    element_bits = 1 << length
    levels = element_bits - 1
    s, r = imms & levels, immr & levels
    require(not logical or s != levels, "reserved all-ones logical immediate")
    element_mask = (1 << element_bits) - 1
    ones = (1 << (s + 1)) - 1
    rotated = ((ones >> r) | (ones << (element_bits - r))) & element_mask
    top = (1 << (((s - r) & levels) + 1)) - 1
    return (sum(rotated << i for i in range(0, width, element_bits)),
            sum(top << i for i in range(0, width, element_bits)))


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
    one_source = word & 0x7FFFFC00
    if one_source in (0x5AC00000, 0x5AC00400, 0x5AC00800, 0x5AC00C00, 0x5AC01000, 0x5AC01400):
        operation = (word >> 10) & 7
        if operation == 3 and width == 32:
            reject("reserved 64-bit reversal container in W encoding")
        if operation == 0:
            return ins("bit_reverse", width=width, rd=rd, rn=rn)
        if operation <= 3:
            return ins("byte_reverse", width=width, rd=rd, rn=rn, amount=8 << operation)
        return ins("count_leading", width=width, rd=rd, rn=rn, operation=operation - 4)
    if word & 0x3FFFFC00 == 0x38BFC000:
        size = word >> 30
        return ins("load_acquire_rcpc", rd=rd, rn=rn, access_size=1 << size,
                   load=True, width=64 if size == 3 else 32)
    if word & 0x1F800000 in (0x12000000, 0x13000000):
        logical = word & 0x1F800000 == 0x12000000
        n, immr, imms, opc = (word >> 22) & 1, (word >> 16) & 63, (word >> 10) & 63, (word >> 29) & 3
        if not logical and (opc == 3 or n != (width == 64) or immr >= width or imms >= width):
            reject("reserved bitfield encoding")
        try:
            mask, top_mask = bit_masks(n, imms, immr, width, logical)
        except InputError as error:
            reject(str(error))
        return ins("logical_immediate" if logical else "bitfield", width=width, rd=rd, rn=rn,
                   operation=opc, amount=immr, immediate=imms, mask=mask, top_mask=top_mask)
    if word & 0x3FE00800 == 0x1A800000:
        return ins("conditional_select", width=width, rd=rd, rn=rn, rm=rm,
                   condition=(word >> 12) & 15, operation=(((word >> 30) & 1) << 1) | ((word >> 10) & 1))
    if word & 0x3FE00410 == 0x3A400000:
        immediate = bool(word & (1 << 11))
        # The low nibble is fallback NZCV, never a destination register.
        return ins("conditional_compare_immediate" if immediate else "conditional_compare_register",
                   width=width, rd=31, rn=rn, rm=0 if immediate else rm,
                   immediate=rm if immediate else 0, operation=(word >> 30) & 1,
                   flags=True, condition=(word >> 12) & 15, nzcv=word & 15)
    if word & 0x1FE00000 == 0x0B200000:
        amount = (word >> 10) & 7
        if amount > 4:
            reject("reserved extended-register shift")
        return ins("addsub_extended", width=width, rd=rd, rn=rn, rm=rm, extend=(word >> 13) & 7,
                   amount=amount, operation=(word >> 30) & 1, flags=bool(word & (1 << 29)))
    if word & 0x1FE0FC00 == 0x1A000000:
        return ins("addsub_carry", width=width, rd=rd, rn=rn, rm=rm,
                   operation=(word >> 30) & 1, flags=bool(word & (1 << 29)))
    if word & 0x7FE00000 == 0x1B000000:
        return ins("multiply_add", width=width, rd=rd, rn=rn, rm=rm, ra=(word >> 10) & 31,
                   operation=(word >> 15) & 1)
    if word & 0xFF600000 == 0x9B200000:
        return ins("multiply_long", width=64, rd=rd, rn=rn, rm=rm, ra=(word >> 10) & 31,
                   operation=(word >> 15) & 1, sign_extend=not bool(word & (1 << 23)))
    if word & 0xFF608000 == 0x9B400000:
        # Ra is ignored by this encoding; it is not an accumulator operand.
        return ins("multiply_high", width=64, rd=rd, rn=rn, rm=rm, ra=(word >> 10) & 31,
                   sign_extend=not bool(word & (1 << 23)))
    opcode = word & 0x7FE0FC00
    if opcode in (0x1AC02000, 0x1AC02400, 0x1AC02800, 0x1AC02C00):
        return ins("variable_shift", width=width, rd=rd, rn=rn, rm=rm, shift=(word >> 10) & 3)
    if opcode in (0x1AC00800, 0x1AC00C00):
        return ins("divide", width=width, rd=rd, rn=rn, rm=rm, operation=(word >> 10) & 1)
    if word & 0x3E000000 == 0x28000000:
        opc, mode, load, rt2 = word >> 30, (word >> 23) & 3, bool(word & (1 << 22)), (word >> 10) & 31
        if opc == 3 or (opc == 1 and not load) or mode == 0:
            reject("reserved, tagged, or non-temporal pair encoding is not implemented")
        if load and rd == rt2:
            reject("constrained-unpredictable pair load destination overlap")
        if mode != 2 and rn != 31 and rn in (rd, rt2):
            reject("constrained-unpredictable pair writeback/base overlap")
        scale = 3 if opc == 2 else 2
        return ins("loadstore_pair", width=32 if opc == 0 else 64, rd=rd, rt2=rt2, rn=rn,
                   access_size=1 << scale, load=load, sign_extend=opc == 1,
                   immediate=signed((word >> 15) & 0x7F, 7) << scale,
                   writeback=mode != 2, post_index=mode == 1)
    if word & 0x3F000000 == 0x18000000:
        opc = word >> 30
        if opc == 3:
            reject("prefetch literal is not implemented")
        return ins("load_literal", rd=rd, width=32 if opc == 0 else 64,
                   access_size=8 if opc == 1 else 4, load=True, sign_extend=opc == 2,
                   target=(pc + signed((word >> 5) & 0x7FFFF, 19) * 4) & U64)
    if word & 0x3F000000 in (0x39000000, 0x38000000):
        size, opc = word >> 30, (word >> 22) & 3
        if (size == 3 and opc >= 2) or (size == 2 and opc == 3):
            reject("reserved or prefetch scalar memory encoding")
        args = dict(rd=rd, rn=rn, access_size=1 << size, load=opc != 0,
                    sign_extend=opc >= 2, width=64 if size == 3 or opc == 2 else 32)
        if word & (1 << 24):
            return ins("loadstore_unsigned", immediate=((word >> 10) & 0xFFF) << size, **args)
        if word & (1 << 21):
            extend = (word >> 13) & 7
            if ((word >> 10) & 3) != 2 or extend not in (2, 3, 6, 7):
                reject("unsupported scalar register-offset encoding")
            return ins("loadstore_register", rm=rm, extend=extend,
                       amount=size if word & (1 << 12) else 0, **args)
        mode = (word >> 10) & 3
        if mode == 2:
            reject("unprivileged scalar memory encoding is not implemented")
        if mode != 0 and rn == rd and rn != 31:
            reject("constrained-unpredictable writeback/base overlap")
        return ins("loadstore_immediate", immediate=signed((word >> 12) & 0x1FF, 9),
                   writeback=mode != 0, post_index=mode == 1, **args)
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


def memory_body(ins):
    lines = []
    if ins.form == "load_acquire_rcpc":
        return [f"uint64_t address = oot_arm64_read(s, {ins.rn}, 64, 1);", "uint64_t value = 0;",
                f"if (!oot_memory_load_rcpc(memory, address, {ins.access_size}, {int(ins.rn == 31)}, &value))",
                "    { *executed = count; return OOT_LIFT_MEMORY_FAULT; }",
                f"oot_arm64_write(s, {ins.rd}, {ins.width}, 0, value);"]
    if ins.form == "load_literal":
        lines.append(f"uint64_t address = {constant(ins.target)};")
    else:
        lines.append(f"uint64_t base = oot_arm64_read(s, {ins.rn}, 64, 1);")
        if ins.form == "loadstore_register":
            width = 32 if ins.extend in (2, 6) else 64
            lines.append(f"uint64_t offset = oot_arm64_read(s, {ins.rm}, {width}, 0);")
            if ins.extend == 6:
                lines.append("offset = oot_arm64_sign_extend(offset, 32);")
            if ins.amount:
                lines.append(f"offset <<= {ins.amount};")
        else:
            lines.append(f"uint64_t offset = {constant(ins.immediate)};")
        lines.append("uint64_t address = base;" if ins.post_index else "uint64_t address = base + offset;")
    lines.append("uint64_t value = 0;" if ins.load else
                 f"uint64_t value = oot_arm64_read(s, {ins.rd}, {ins.width}, 0);")
    pair = ins.form == "loadstore_pair"
    if pair:
        lines.append("uint64_t second = 0;" if ins.load else
                     f"uint64_t second = oot_arm64_read(s, {ins.rt2}, {ins.width}, 0);")
        transfer = (f"oot_memory_load_pair(memory, address, {ins.access_size}, &value, &second)" if ins.load else
                    f"oot_memory_store_pair(memory, address, {ins.access_size}, value, second)")
    else:
        transfer = (f"oot_memory_load(memory, address, {ins.access_size}, &value)" if ins.load else
                    f"oot_memory_store(memory, address, {ins.access_size}, value)")
    lines.append(f"if (!{transfer}) {{ *executed = count; return OOT_LIFT_MEMORY_FAULT; }}")
    if ins.load:
        if ins.sign_extend:
            lines.append(f"value = oot_arm64_sign_extend(value, {ins.access_size * 8});")
        lines.append(f"oot_arm64_write(s, {ins.rd}, {ins.width}, 0, value);")
        if pair:
            if ins.sign_extend:
                lines.append(f"second = oot_arm64_sign_extend(second, {ins.access_size * 8});")
            lines.append(f"oot_arm64_write(s, {ins.rt2}, {ins.width}, 0, second);")
    if ins.writeback:
        lines.append(f"oot_arm64_write(s, {ins.rn}, 64, 1, base + offset);")
    return lines


def body(ins):
    width, rd, rn, rm = ins.width, ins.rd, ins.rn, ins.rm
    next_pc = constant(ins.pc + 4)

    def read(reg, use_sp=False):
        return f"oot_arm64_read(s, {reg}, {width}, {int(use_sp)})"

    def write(value, use_sp=False):
        return f"oot_arm64_write(s, {rd}, {width}, {int(use_sp)}, {value});"

    lines = []
    if ins.form in MEMORY_FORMS:
        lines.extend(memory_body(ins))
    elif ins.form == "move_wide":
        value = constant(ins.immediate)
        if ins.operation == 0:
            value = f"~{value}"
        elif ins.operation == 3:
            value = f"({read(rd)} & ~{constant(0xFFFF << ins.amount)}) | {value}"
        lines.append(write(value))
    elif ins.form in ("addsub_immediate", "addsub_shifted", "addsub_extended"):
        immediate = ins.form == "addsub_immediate"
        right = constant(ins.immediate) if immediate else (
            f"oot_arm64_shift({read(rm)}, {ins.shift}, {ins.amount}, {width})")
        use_sp = ins.form != "addsub_shifted"
        if ins.form == "addsub_extended":
            right = f"oot_arm64_extend(oot_arm64_read(s, {rm}, 64, 0), {ins.extend}, {ins.amount}, {width})"
        lines.extend([f"uint64_t a = {read(rn, use_sp)};", f"uint64_t b = {right};",
                      f"uint64_t r = oot_arm64_addsub(s, a, b, {width}, {ins.operation}, {int(ins.flags)});",
                      write("r", use_sp and not ins.flags)])
    elif ins.form == "addsub_carry":
        lines.extend([f"uint64_t a = {read(rn)};", f"uint64_t b = {read(rm)};",
                      f"uint64_t r = oot_arm64_carry(s, a, b, {width}, {ins.operation}, {int(ins.flags)});", write("r")])
    elif ins.form in ("conditional_compare_register", "conditional_compare_immediate"):
        right = constant(ins.immediate) if ins.form == "conditional_compare_immediate" else read(rm)
        lines.extend([f"if (oot_arm64_condition(s->nzcv, {ins.condition})) {{",
                      f"    (void)oot_arm64_addsub(s, {read(rn)}, {right}, {width}, {ins.operation}, 1);",
                      "} else {", f"    s->nzcv = UINT32_C(0x{ins.nzcv << 28:08x});", "}"])
    elif ins.form == "logical_immediate":
        operator = ("&", "|", "^", "&")[ins.operation]
        lines.append(f"uint64_t r = {read(rn)} {operator} {constant(ins.mask)};")
        if ins.operation == 3:
            lines.append(f"s->nzcv = oot_arm64_nz(r, {width});")
        lines.append(write("r", ins.operation != 3))
    elif ins.form == "bitfield":
        lines.extend([f"uint64_t source = {read(rn)};",
                      f"uint64_t bottom = oot_arm64_shift(source, 3, {ins.amount}, {width}) & {constant(ins.mask)};"])
        if ins.operation == 1:
            lines.append(f"uint64_t previous = {read(rd)};")
            lines.append(f"bottom |= previous & ~{constant(ins.mask)};")
            top = "previous"
        elif ins.operation == 0:
            top = f"((source >> {ins.immediate}) & 1) ? UINT64_MAX : 0"
        else:
            top = "0"
        lines.extend([f"uint64_t top = {top};", write(f"(top & ~{constant(ins.top_mask)}) | (bottom & {constant(ins.top_mask)})")])
    elif ins.form == "conditional_select":
        other = (read(rm), f"{read(rm)} + 1", f"~{read(rm)}", f"0 - {read(rm)}")[ins.operation]
        lines.extend([f"uint64_t r = oot_arm64_condition(s->nzcv, {ins.condition}) ? {read(rn)} : ({other});", write("r")])
    elif ins.form == "variable_shift":
        lines.append(write(f"oot_arm64_shift({read(rn)}, {ins.shift}, (unsigned)({read(rm)} & {width - 1}), {width})"))
    elif ins.form == "bit_reverse":
        lines.append(write(f"oot_arm64_rbit({read(rn)}, {width})"))
    elif ins.form == "byte_reverse":
        lines.append(write(f"oot_arm64_reverse_bytes({read(rn)}, {width}, {ins.amount})"))
    elif ins.form == "count_leading":
        lines.append(write(f"oot_arm64_leading({read(rn)}, {width}, {ins.operation})"))
    elif ins.form == "multiply_add":
        operator = "-" if ins.operation else "+"
        lines.append(write(f"{read(ins.ra)} {operator} ({read(rn)} * {read(rm)})"))
    elif ins.form == "multiply_long":
        left, right = (f"oot_arm64_read(s, {reg}, 32, 0)" for reg in (rn, rm))
        if ins.sign_extend:
            left, right = (f"oot_arm64_sign_extend({value}, 32)" for value in (left, right))
        operator = "-" if ins.operation else "+"
        # Unsigned 64-bit arithmetic implements the signed result modulo 2^64.
        lines.extend([f"uint64_t a = {left};", f"uint64_t b = {right};",
                      f"uint64_t accumulator = {read(ins.ra)};", write(f"accumulator {operator} (a * b)")])
    elif ins.form == "multiply_high":
        lines.append(write(f"oot_arm64_mul_high({read(rn)}, {read(rm)}, {int(ins.sign_extend)})"))
    elif ins.form == "divide":
        lines.append(write(f"oot_arm64_divide({read(rn)}, {read(rm)}, {width}, {ins.operation})"))
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
    lines = ['/* Generated ARM64 integer/scalar-memory/control-flow translation. */', '#include "arm64_lift.h"', "",
             f"OOT_LIFT_EXPORT int {name}(OotArm64State *s, OotGuestMemory *memory, uint64_t budget, uint64_t *executed)",
             "{", "    uint64_t count = 0;", "    oot_memory_clear_fault(memory);",
             "    for (;;) {", "        switch (s->pc) {"]
    for ins in instructions:
        lines.extend([f"        case {constant(ins.pc)}: {{ /* {ins.form} 0x{ins.word:08x} */",
                      "            if (count == budget) { *executed = count; return OOT_LIFT_BUDGET; }"])
        lines.extend(f"            {line}" for line in body(ins))
        lines.extend(["            ++count;", "            break;", "        }"])
    lines.extend(["        default: *executed = count; return OOT_LIFT_DISPATCH;",
                  "        }", "    }", "}", ""])
    report = {"schema_version": 2, "abi_version": 2, "base": base, "byte_count": len(data),
              "instruction_count": len(instructions), "forms": dict(Counter(i.form for i in instructions)),
              "function": name, "guest_memory_access": any(i.form in MEMORY_FORMS for i in instructions),
              "game_runtime_ready": False}
    return "\n".join(lines), report
