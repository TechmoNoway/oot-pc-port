"""Artificial widening multiply cases with independent unbounded arithmetic."""

import random

from lifter_validation_types import BASE, Program, Trial

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def multiply_long(signed, subtract, rd, rn, rm, ra):
    return (0x9B200000 | (int(not signed) << 23) | (rm << 16) | (subtract << 15) |
            (ra << 10) | (rn << 5) | rd)


def operand32(value, signed):
    value %= 1 << 32
    return value - (1 << 32) if signed and value >= 1 << 31 else value


def mathematical_result(registers, signed, subtract, rn, rm, ra):
    left = operand32(registers[rn], signed) if rn != 31 else 0
    right = operand32(registers[rm], signed) if rm != 31 else 0
    accumulator = registers[ra] if ra != 31 else 0
    return (accumulator + (-1 if subtract else 1) * left * right) % (1 << 64)


def multiply_programs():
    rng = random.Random(0x10A64ADD)
    program = Program("multiply_long_operands", [], [])
    triples = [(0, 0, 0), (1, 1, 1), (MASK32, MASK32, MASK64),
               (1 << 31, 1 << 31, 0), ((1 << 31)-1, (1 << 31)-1, 1 << 63),
               (1 << 31, MASK32, MASK64), (MASK32, 1, 0), (1 << 31, 1, MASK64),
               ((1 << 31)-1, MASK32, 1), (1, MASK32, MASK64),
               (MASK32, 1 << 31, 1 << 31), ((1 << 31)-1, 1 << 31, 0x123456789ABCDEF0),
               (0x80000000, 0xFFFFFFFF, 0xFEDCBA9876543210),
               (0x1234567880000000, 0x87654321FFFFFFFF, 0xFEDCBA9876543210),
               (0xFFFFFFFF00000001, 0xDEADBEEF00000000, 0x100000000),
               (0xFFFFFFFFFFFFFFFF, 0x111111117FFFFFFF, 0x8000000000000000)]
    for signed in (False, True):
        for subtract in (0, 1):
            for r in range(32):
                patterns = [(r, (r+1)%32, (r+2)%32, (r+3)%32),
                            (r, r, (r+1)%32, (r+2)%32), (r, (r+1)%32, r, (r+2)%32),
                            (r, (r+1)%32, (r+2)%32, r), (r, r, r, r),
                            (r, 31, (r+1)%32, 31), (r, (r+1)%32, 31, (r+2)%32),
                            (31, (r+1)%32, (r+2)%32, (r+3)%32)]
                for rd, rn, rm, ra in patterns:
                    index = len(program.words)
                    program.words.append(multiply_long(signed, subtract, rd, rn, rm, ra))
                    for j, (left, right, accumulator) in enumerate(triples + [tuple(rng.getrandbits(64) for _ in range(3)) for _ in range(4)]):
                        regs = [rng.getrandbits(64) for _ in range(31)]
                        for reg, value in ((rn, left), (rm, right), (ra, accumulator)):
                            if reg != 31: regs[reg] = value
                        expected = {rd: mathematical_result(regs, signed, subtract, rn, rm, ra)} if rd != 31 else {}
                        flags = (j % 16) << 28
                        program.trials.append(Trial(index, regs, 0xFEDCBA9876543210, flags,
                                                    expected_x=expected, expected_nzcv=flags))
    return [program] + multiply_leaves()


def multiply_leaves():
    rng = random.Random(0x10A61EAF)
    edges = [0, 1, 2, 0x7FFFFFFF, 0x80000000, MASK32, 1 << 63, MASK64,
             0xFEDCBA9800000000, 0xA55A000080000001, 0xFFFFFFFF00000001, 0x100000000]
    programs = []
    for signed in (False, True):
        p = Program("leaf_multiply_" + ("signed" if signed else "unsigned"),
            [multiply_long(signed, 0, 7, 0, 1, 31), multiply_long(signed, 0, 0, 2, 3, 7),
             multiply_long(signed, 1, 4, 4, 5, 31), multiply_long(signed, 1, 0, 4, 6, 0), 0xD65F03C0], [], leaf=True)
        for j, (left, right) in enumerate([(a, b) for a in edges for b in edges] +
                                         [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(32)]):
            regs = [rng.getrandbits(64) for _ in range(31)]
            regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6] = left, right, right, left, left, right, left ^ right
            regs[30] = BASE + len(p.data)
            a, b, c = (operand32(value, signed) for value in (left, right, left ^ right))
            product, negative = (a*b) & MASK64, (-a*b) & MASK64
            expected = {0: (2*a*b - operand32(negative, signed)*c) & MASK64, 4: negative, 7: product}
            flags = (j % 16) << 28
            p.trials.extend(Trial(0, regs, 0x800000, flags, budget, expected_nzcv=flags) for budget in range(5))
            p.trials.append(Trial(0, regs, 0x800000, flags, 5, expected, expected_nzcv=flags))
        programs.append(p)
    return programs
