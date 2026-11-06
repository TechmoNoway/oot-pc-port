"""EXTR/ROR and CRC32 synthetic milestone with independent mathematical oracles."""

import random

from lifter_validation_types import BASE, Program, Trial

MASK64 = (1 << 64)-1


def extract(sf, rd, rn, rm, amount):
    return (sf << 31) | (sf << 22) | 0x13800000 | (rm << 16) | (amount << 10) | (rn << 5) | rd


def crc_word(castagnoli, size, rd, rn, rm):
    return (int(size == 3) << 31) | 0x1AC04000 | (rm << 16) | (castagnoli << 12) | (size << 10) | (rn << 5) | rd


def extract_result(high, low, width, amount):
    modulus = 1 << width
    return ((high % modulus)*modulus + low % modulus) // (1 << amount) % modulus


def reverse(value, bits):
    return int(f"{value % (1 << bits):0{bits}b}"[::-1], 2)


def crc_result(accumulator, value, bits, castagnoli):
    # Polynomial long division, independent of the reflected native recurrence.
    polynomial = (1 << 32) | (0x1EDC6F41 if castagnoli else 0x04C11DB7)
    dividend = (reverse(accumulator, 32) << bits) ^ (reverse(value, bits) << 32)
    while dividend.bit_length() > 32:
        dividend ^= polynomial << (dividend.bit_length()-33)
    return reverse(dividend, 32)


def frontier_programs():
    rng = random.Random(0xF2046432)
    ex, crc, boundaries = (Program(name, [], []) for name in ("extract_fields", "crc_fields", "frontier_boundaries"))
    edges = [0, 1, MASK64, 1 << 63, (1 << 63)-1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF,
             0x100000000, 0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xAAAAAAAAAAAAAAAA,
             0x5555555555555555, 0xFF, 0xFFFF, 0xFFFFFFFF00000000]

    def append(p, word, rd, rn, rm, values, formula, zero=True):
        index = len(p.words); p.words.append(word)
        for j, (left, right) in enumerate(values):
            regs = [rng.getrandbits(64) for _ in range(31)]
            if rn != 31: regs[rn] = left
            if rm != 31: regs[rm] = right
            value = formula(regs[rn] if rn != 31 else 0, regs[rm] if rm != 31 else 0)
            expected = {rd: value} if rd != 31 else dict(enumerate(regs))
            flags = (j % 16) << 28
            p.trials.append(Trial(index, regs, 0xFEDCBA9876543210, flags, expected_x=expected, expected_nzcv=flags))
        if zero:
            p.trials.append(Trial(index, regs, 0xFEDCBA9876543210, flags, 0, dict(enumerate(regs)), expected_nzcv=flags))

    for sf in (0, 1):
        width = 64 if sf else 32
        for r in range(32):
            for j, (rd, rn, rm) in enumerate(patterns(r)):
                amount = (2*r+j) % width
                append(ex, extract(sf, rd, rn, rm, amount), rd, rn, rm,
                       list(zip(edges, reversed(edges))), lambda a, b: extract_result(a, b, width, amount))
        for amount in range(width):
            pairs = [(a, b) for a, b in zip(edges, reversed(edges))]
            pairs += [(1 << b, 0) for b in range(width)] + [(0, 1 << b) for b in range(width)]
            pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(8)]
            append(boundaries, extract(sf, 0, 1, 2, amount), 0, 1, 2, pairs,
                   lambda a, b: extract_result(a, b, width, amount), False)
    for castagnoli in (0, 1):
        for size in range(4):
            bits = 8 << size
            for r in range(32):
                for rd, rn, rm in patterns(r):
                    append(crc, crc_word(castagnoli, size, rd, rn, rm), rd, rn, rm,
                           list(zip(edges, reversed(edges))), lambda a, b: crc_result(a, b, bits, castagnoli))
            pairs = [(rng.getrandbits(64), b) for b in range(256)]
            pairs += [(1 << b, 0) for b in range(32)] + [(0, 1 << b) for b in range(bits)]
            pairs += [(MASK64, rng.getrandbits(64)) for _ in range(32)]
            append(boundaries, crc_word(castagnoli, size, 0, 1, 2), 0, 1, 2, pairs,
                   lambda a, b: crc_result(a, b, bits, castagnoli), False)
    return [ex, crc, boundaries] + frontier_leaves()


def patterns(r):
    return ((r, (r+1)%32, (r+2)%32), (r, r, (r+1)%32), (r, (r+1)%32, r), (r, r, r),
            (r, 31, (r+1)%32), (r, (r+1)%32, 31), (31, r, (r+1)%32), (r, (r+1)%32, (r+1)%32))


def frontier_leaves():
    rng = random.Random(0xF201EAF)
    definitions = []
    for sf in (0, 1):
        width = 64 if sf else 32
        definitions.append(("leaf_rotate"+str(sf), [extract(sf, 0, 0, 0, width-1), extract(sf, 0, 0, 0, 1), 0xD65F03C0],
                            lambda r, w=width: {0: r[0] % (1 << w)}))
    for c in (0, 1):
        def expected(r, c=c):
            acc = r[0]
            for size in range(4): acc = crc_result(acc, r[size+1], 8 << size, c)
            return {0: acc}
        definitions.append(("leaf_crc"+str(c), [crc_word(c, size, 0, 0, size+1) for size in range(4)]+[0xD65F03C0], expected))
    programs = []
    for name, words, formula in definitions:
        p = Program(name, words, [], leaf=True)
        for j in range(128):
            regs = [rng.getrandbits(64) for _ in range(31)]
            if j < 64: regs[0] = 1 << j
            regs[30] = BASE+len(p.data); flags = (j % 16) << 28
            p.trials.extend(Trial(0, regs, 0x800000, flags, budget, expected_nzcv=flags) for budget in range(len(words)))
            p.trials.append(Trial(0, regs, 0x800000, flags, len(words), formula(regs), expected_nzcv=flags))
        programs.append(p)
    return programs
