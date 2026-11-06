"""Artificial CCMP/CCMN encodings and independent integer/flag expectations."""

import random

from integer_validation import select
from lifter_validation_types import BASE, Program, Trial

MASK64 = (1 << 64) - 1


def compare(sf, subtract, rn, operand, fallback, condition, immediate=False):
    return ((sf << 31) | (subtract << 30) | 0x3A400000 | (operand << 16) |
            (condition << 12) | (int(immediate) << 11) | (rn << 5) | fallback)


def condition_holds(flags, condition):
    """Truth table, independent of the production decoder and C condition helper."""
    n, z, c, v = (bool(flags & (1 << bit)) for bit in (31, 30, 29, 28))
    return (z, not z, c, not c, n, not n, v, not v, c and not z,
            not c or z, n == v, n != v, not z and n == v, z or n != v, True, True)[condition]


def arithmetic_flags(left, right, width, subtract):
    """Unbounded unsigned and signed mathematics; no host-style overflow formula."""
    modulus, sign = 1 << width, 1 << (width - 1)
    left, right = left % modulus, right % modulus
    total = left - right if subtract else left + right
    result = total % modulus
    signed_left = left if left < sign else left - modulus
    signed_right = right if right < sign else right - modulus
    signed_total = signed_left - signed_right if subtract else signed_left + signed_right
    carry = left >= right if subtract else total >= modulus
    overflow = not -sign <= signed_total < sign
    return ((int(result >= sign) << 31) | (int(result == 0) << 30) |
            (int(carry) << 29) | (int(overflow) << 28))


def compare_flags(registers, incoming, sf, subtract, rn, operand, fallback, condition, immediate=False):
    if not condition_holds(incoming, condition):
        return fallback << 28
    left = registers[rn] if rn != 31 else 0
    right = operand if immediate else registers[operand] if operand != 31 else 0
    return arithmetic_flags(left, right, 64 if sf else 32, subtract)


def conditional_programs():
    rng = random.Random(0xCC4ECC4E)
    matrix, operands = Program("conditional_matrix", [], []), Program("conditional_operands", [], [])
    for sf in (0, 1):
        width = 64 if sf else 32
        mask, sign = (1 << width) - 1, 1 << (width - 1)
        pairs = [(0, 0), (0, 1), (1, 0), (mask, 1), (mask, mask), (sign - 1, 1),
                 (sign, mask), (sign, 1), (31, 31), (32, 31),
                 (0xA55AFFFF00000000, 0x8000000000000001),
                 (0xDEADBEEF7FFFFFFF, 0xF000000080000000)]
        for subtract in (0, 1):
            for immediate in (False, True):
                def append(program, params, values):
                    index = len(program.words)
                    program.words.append(compare(*params))
                    for registers, incoming, budget in values:
                        flags = compare_flags(registers, incoming, *params) if budget else incoming
                        program.trials.append(Trial(index, registers, 0x123456789ABCDEF0,
                                                    incoming, budget, expected_nzcv=flags))

                for condition in range(16):
                    for fallback in range(16):
                        params = (sf, subtract, 1, 31 if immediate else 2, fallback, condition, immediate)
                        regs = [rng.getrandbits(64) for _ in range(31)]
                        regs[1], regs[2] = pairs[fallback % len(pairs)]
                        append(matrix, params, [(regs, f << 28, 1) for f in range(16)] + [(regs, 0xF0000000, 0)])
                # Every Rn, Rm/imm5 and source alias, including all protected registers
                # and ZR, plus high X bits that must be ignored by W comparisons.
                for operand in range(32):
                    for rn, rhs in ((operand, (operand + 1) % 32), (operand, operand), (31, operand)):
                        if immediate:
                            rhs = operand
                        params = (sf, subtract, rn, rhs, operand % 16, 14, immediate)
                        values = []
                        for j, (left, right) in enumerate(pairs + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(4)]):
                            regs = [rng.getrandbits(64) for _ in range(31)]
                            if not immediate and rhs != 31:
                                regs[rhs] = right
                            if rn != 31:
                                regs[rn] = left
                            values.append((regs, (j % 16) << 28, 1))
                        append(operands, params, values)
    return [matrix, operands] + conditional_leaves()


def conditional_leaves():
    # (W0 == W1 && W2 < 31) ? X3 : X4. False fallback C=1 prevents LO.
    first = Program("leaf_conditional_range", [0x6B01001F, compare(0, 1, 2, 31, 2, 0, True),
                    select(1, 0, 0, 3, 4, 3), 0xD65F03C0], [], leaf=True)
    # A flag chain with a V-consuming diamond and a C-consuming selection.
    second = Program("leaf_conditional_chain", [0xF100001F, compare(1, 0, 1, 2, 0, 1),
                     0x54000086, compare(1, 1, 3, 31, 0, 1, True), select(1, 0, 0, 4, 5, 2),
                     0xD65F03C0, 0xAA0603E0, 0xD65F03C0], [], leaf=True)
    rng = random.Random(0xCC1EAFFF)
    edges = [0, 1, 30, 31, 32, MASK64, (1 << 63) - 1, 1 << 63,
             (1 << 31) - 1, 1 << 31, 0xFFFFFFFF, 0xF000000000000001]
    for a, b in [(a, b) for a in edges for b in edges] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(32)]:
        regs = [rng.getrandbits(64) for _ in range(31)]
        regs[0], regs[1], regs[2], regs[3] = a, b, b, a
        for p, bound in ((first, 4), (second, 6)):
            r = regs.copy(); r[30] = BASE + len(p.data)
            incoming = rng.randrange(16) << 28
            if p is first:
                result = r[3] if a & 0xFFFFFFFF == b & 0xFFFFFFFF and b & 0xFFFFFFFF < 31 else r[4]
                flags = compare_flags(r, arithmetic_flags(a, b, 32, True), 0, 1, 2, 31, 2, 0, True)
            else:
                flags = compare_flags(r, arithmetic_flags(a, 0, 64, True), 1, 0, 1, 2, 0, 1)
                signed_b = b if b < 1 << 63 else b - (1 << 64)
                if a != 0 and not -(1 << 63) <= 2 * signed_b < 1 << 63:
                    result = r[6]
                else:
                    result = r[4] if (a == 0 or (2 * b) & MASK64 != 0) and a >= 31 else r[5]
                    flags = compare_flags(r, flags, 1, 1, 3, 31, 0, 1, True)
            p.trials.extend(Trial(0, r, 0x800000, incoming, budget) for budget in range(bound))
            p.trials.append(Trial(0, r, 0x800000, incoming, bound, {0: result}, expected_nzcv=flags))
    return [first, second]
