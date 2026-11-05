"""Independent encodings and directed operands for the extended integer subset."""

import random

from arm64_lifter import U64
from lifter_validation_types import Program, Trial


def logical(sf, opc, rd, rn, element_bits, ones, rotation):
    n = int(element_bits == 64)
    imms = ((-2 * element_bits) & 63) | (ones - 1)
    return (sf << 31) | 0x12000000 | (opc << 29) | (n << 22) | (rotation << 16) | (imms << 10) | (rn << 5) | rd


def bitfield(sf, opc, rd, rn, rotation, size):
    return (sf << 31) | 0x13000000 | (opc << 29) | (sf << 22) | (rotation << 16) | (size << 10) | (rn << 5) | rd


def select(sf, operation, rd, rn, rm, condition):
    return ((sf << 31) | 0x1A800000 | ((operation >> 1) << 30) | ((operation & 1) << 10) |
            (condition << 12) | (rm << 16) | (rn << 5) | rd)


def multiply(sf, subtract, rd, rn, rm, ra):
    return (sf << 31) | 0x1B000000 | (rm << 16) | (subtract << 15) | (ra << 10) | (rn << 5) | rd


def integer_programs():
    words = []
    for sf in (0, 1):
        width = 64 if sf else 32
        for element in (2, 4, 8, 16, 32, 64):
            if element > width:
                continue
            for opc in range(4):
                for ones in sorted({1, element // 2, element - 1}):
                    for rotation in sorted({0, 1, element - 1}):
                        for rd, rn in ((0, 1), (31, 31)):
                            words.append(logical(sf, opc, rd, rn, element, ones, rotation))
        for opc in range(3):
            for rotation in (0, 1, width // 2, width - 1):
                for size in (0, 1, width // 2, width - 1):
                    for rd, rn in ((0, 1), (0, 0), (31, 31)):
                        words.append(bitfield(sf, opc, rd, rn, rotation, size))
        for operation in range(4):
            for condition in range(16):
                for rd, rn, rm in ((0, 1, 2), (0, 0, 0), (31, 31, 31)):
                    words.append(select(sf, operation, rd, rn, rm, condition))
        for subtract in (0, 1):
            for flags in (0, 1):
                for rd, rn, rm in ((0, 1, 2), (31, 31, 31), (1, 1, 1), (0, 31, 2)):
                    common = (sf << 31) | (subtract << 30) | (flags << 29) | (rm << 16) | (rn << 5) | rd
                    words.append(common | 0x1A000000)
                    for option in range(8):
                        for amount in (0, 1, 4):
                            words.append(common | 0x0B200000 | (option << 13) | (amount << 10))
            for rd, rn, rm, ra in ((0, 1, 2, 3), (0, 0, 0, 0), (31, 31, 31, 31), (0, 1, 2, 31)):
                words.append(multiply(sf, subtract, rd, rn, rm, ra))
        for opcode in (0x1AC02000, 0x1AC02400, 0x1AC02800, 0x1AC02C00, 0x1AC00800, 0x1AC00C00):
            for rd, rn, rm in ((0, 1, 2), (0, 0, 0), (31, 31, 31)):
                words.append((sf << 31) | opcode | (rm << 16) | (rn << 5) | rd)
    words = list(dict.fromkeys(words))
    rng = random.Random(0x1A64C0DE)
    edges = [(0, 0), (U64, 1), (0x7FFFFFFFFFFFFFFF, 1), (0x8000000000000000, U64),
             (0x8000000000000000, 1), (1, 0), (U64, U64), (0, U64), (0x7FFFFFFF, 1),
             (0x80000000, 0xFFFFFFFF), (0xFFFFFFFF, 32), (0x80000000, 64), (1, 31), (U64, 63)]
    trials = []
    for index, word in enumerate(words):
        values = edges + [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(4)]
        for j, (left, right) in enumerate(values):
            regs = [rng.getrandbits(64) for _ in range(31)]
            regs[0], regs[1], regs[2], regs[3] = right, left, right, left
            trials.append(Trial(index, regs, left, ((j & 1) << 29) | (rng.randrange(16) << 28 & 0xD0000000)))
        if word & 0x3FE00800 == 0x1A800000:
            for flags in range(16):
                regs = [0x1111111111111111 + j for j in range(31)]
                trials.append(Trial(index, regs, 0x800000, flags << 28))
    return [Program("extended_integer", words, trials)]
