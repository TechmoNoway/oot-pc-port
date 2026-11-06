"""Synthetic high products checked with independent arbitrary-precision math."""

import random

from lifter_validation_types import BASE, Program, Trial

MASK64 = (1 << 64)-1


def multiply_high(signed, rd, rn, rm, ra=31):
    return 0x9B400000 | (int(not signed) << 23) | (rm << 16) | (ra << 10) | (rn << 5) | rd


def full_product(left, right, signed):
    left, right = left % (1 << 64), right % (1 << 64)
    if signed:
        left = left - (1 << 64) if left >= 1 << 63 else left
        right = right - (1 << 64) if right >= 1 << 63 else right
    return left * right


def high_product(left, right, signed):
    return divmod(full_product(left, right, signed), 1 << 64)[0] % (1 << 64)


def high_multiply_programs():
    rng = random.Random(0xA164128)
    fields, ignored, walking = (Program(name, [], []) for name in ("high_fields", "high_ignored_ra", "high_walking"))
    pairs = [(0, 0), (0, MASK64), (1, MASK64), (MASK64, MASK64), (1 << 63, 1 << 63),
             (MASK64, 1 << 63), ((1 << 63)-1, (1 << 63)-1), (MASK64, (1 << 63)-1),
             ((1 << 32)-1, (1 << 32)-1), (1 << 32, 1 << 32),
             (0xFFFFFFFF00000000, 0x00000000FFFFFFFF), (0xFFFFFFFF00000001, 0xFFFFFFFEFFFFFFFF),
             (0x80000000FFFFFFFF, 0xFFFFFFFF80000000), (0xFFFF0000FFFF0000, 0x0000FFFF0000FFFF),
             (0x123456789ABCDEF0, 0xFEDCBA9876543210), (1 << 63, 1)]

    def append(program, signed, rd, rn, rm, values, ra=31, zero_budget=False):
        index = len(program.words); program.words.append(multiply_high(signed, rd, rn, rm, ra))
        for j, (left, right) in enumerate(values):
            regs = [rng.getrandbits(64) for _ in range(31)]
            if rn != 31: regs[rn] = left
            if rm != 31: regs[rm] = right
            expected = {rd: high_product(regs[rn] if rn != 31 else 0, regs[rm] if rm != 31 else 0, signed)} if rd != 31 else dict(enumerate(regs))
            flags = (j % 16) << 28
            program.trials.append(Trial(index, regs, 0xFEDCBA9876543210, flags, expected_x=expected, expected_nzcv=flags))
        if zero_budget:
            program.trials.append(Trial(index, regs, 0xFEDCBA9876543210, flags, 0,
                                        dict(enumerate(regs)), expected_nzcv=flags))

    for signed in (False, True):
        for r in range(32):
            for rd, rn, rm in ((r, (r+1)%32, (r+2)%32), (r, r, (r+1)%32), (r, (r+1)%32, r),
                              (r, r, r), (r, 31, (r+1)%32), (r, (r+1)%32, 31),
                              (31, r, (r+1)%32), (r, (r+1)%32, (r+1)%32)):
                append(fields, signed, rd, rn, rm, pairs + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(4)], zero_budget=True)
        for ra in range(32):
            append(ignored, signed, 0, 1, 2, pairs + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(4)], ra)
        values = []
        for a in range(64):
            for b in range(64):
                left, right = 1 << a, 1 << b
                values.extend(((left, right), (left ^ MASK64, right),
                               (left, right ^ MASK64), (left ^ MASK64, right ^ MASK64)))
        values += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(512)]
        append(walking, signed, 0, 1, 2, values)
    return [fields, ignored, walking] + high_leaves()


def high_leaves():
    rng = random.Random(0xA161EAF)
    edges = [0, 1, MASK64, 1 << 63, (1 << 63)-1, (1 << 32)-1, 1 << 32,
             0xFFFFFFFF00000000, 0x80000000FFFFFFFF, 0xFFFFFFFF80000000, 0xFFFFFFFEFFFFFFFF, 0xAAAAAAAAAAAAAAAA]
    programs = []
    for signed in (False, True):
        p = Program("leaf_high_"+("signed" if signed else "unsigned"),
                    [multiply_high(signed, 2, 0, 1), 0x9B017C00, 0xD65F03C0], [], leaf=True)
        for j, (left, right) in enumerate([(a, b) for a in edges for b in edges] +
                                         [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(32)]):
            regs = [rng.getrandbits(64) for _ in range(31)]
            regs[0], regs[1], regs[30] = left, right, BASE+len(p.data)
            product = full_product(left, right, signed)
            low, high = product % (1 << 64), (product // (1 << 64)) % (1 << 64)
            flags = (j % 16) << 28
            p.trials.extend(Trial(0, regs, 0x800000, flags, budget, expected_nzcv=flags) for budget in range(3))
            p.trials.append(Trial(0, regs, 0x800000, flags, 3, {0: low, 2: high}, expected_nzcv=flags))
        programs.append(p)
    return programs
