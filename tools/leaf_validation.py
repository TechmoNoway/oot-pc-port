"""Complete artificial leaf functions with independent mathematical result checks."""

import random

from arm64_lifter import U64
from integer_validation import bitfield, logical, multiply, select
from leaf_verifier import verify_leaf
from lifter_validation_types import BASE, Program, Trial


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def rotate(value, amount):
    amount &= 63
    return ((value >> amount) | (value << ((64 - amount) & 63))) & U64


def remainder(a, b):
    left, right = signed(a, 64), signed(b, 64)
    quotient = 0 if right == 0 else (abs(left) // abs(right)) * (-1 if (left < 0) != (right < 0) else 1)
    return (left - quotient * right) & U64


def leaf_programs():
    definitions = [
        ("leaf_mix", [0x8B010402, logical(1, 2, 2, 2, 64, 16, 0), 0x9AC32C40, 0xD65F03C0],
         lambda r: {0: rotate(((r[0] + 2 * r[1]) & U64) ^ 0xFFFF, r[3])}),
        ("leaf_min_signed", [0x6B01001F, select(0, 0, 0, 0, 1, 11), 0xD65F03C0],
         lambda r: {0: min(signed(r[0], 32), signed(r[1], 32)) & 0xFFFFFFFF}),
        ("leaf_insert", [bitfield(1, 2, 2, 0, 8, 23), bitfield(1, 1, 1, 2, 32, 15), 0xAA0103E0, 0xD65F03C0],
         lambda r: {0: (r[1] & ~(0xFFFF << 32)) | (((r[0] >> 8) & 0xFFFF) << 32)}),
        ("leaf_remainder", [0x9AC10C02, multiply(1, 1, 0, 2, 1, 0), 0xD65F03C0],
         lambda r: {0: remainder(r[0], r[1])}),
        ("leaf_wide_add", [0xAB010002, 0x9A040060, 0xD65F03C0],
         lambda r: {2: (r[0] + r[1]) & U64, 0: (r[3] + r[4] + int(r[0] + r[1] > U64)) & U64}),
        ("leaf_diamond", [0x34000060, 0x11000400, 0xD65F03C0, 0x52800540, 0xD65F03C0],
         lambda r: {0: 42 if (r[0] & 0xFFFFFFFF) == 0 else (r[0] + 1) & 0xFFFFFFFF}),
    ]
    rng = random.Random(0x1EAF1234)
    edges = [0, 1, U64, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF]
    programs = []
    for name, words, expected in definitions:
        program = Program(name, words, [], leaf=True)
        proof = verify_leaf(program.data, BASE)
        values = [(a, b) for a in edges for b in edges] + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(64)]
        for a, b in values:
            regs = [rng.getrandbits(64) for _ in range(31)]
            regs[0], regs[1], regs[3], regs[4], regs[30] = a, b, a, b, BASE + len(program.data)
            program.trials.append(Trial(0, regs, 0x800000, rng.randrange(16) << 28,
                                        proof["max_retired_instructions"], expected_x=expected(regs)))
        regs = [0] * 31
        regs[30] = BASE + len(program.data)
        program.trials.extend(Trial(0, regs, 0x800000, 0, budget) for budget in (0, 1))
        programs.append(program)
    return programs
