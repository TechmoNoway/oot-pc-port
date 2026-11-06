"""Independent encodings and string/byte expectations for one-source integers."""

import random

from lifter_validation_types import BASE, Program, Trial

MASK64 = (1 << 64) - 1


def bit_word(sf, operation, rd, rn):
    return (sf << 31) | 0x5AC00000 | (operation << 10) | (rn << 5) | rd


def expected_value(value, width, operation):
    value %= 1 << width
    bits = f"{value:0{width}b}"
    if operation == 0:
        return int(bits[::-1], 2)
    if operation <= 3:
        raw, group = value.to_bytes(width // 8, "little"), 1 << operation
        return int.from_bytes(b"".join(raw[i:i+group][::-1] for i in range(0, len(raw), group)), "little")
    if operation == 4:
        return width - value.bit_length()
    return len(bits) - len(bits.lstrip(bits[0])) - 1


def variants():
    return [(sf, op) for sf in (0, 1) for op in range(6) if sf or op != 3]


def bit_programs():
    rng = random.Random(0xB1746411)
    fields, walking = Program("bit_fields", [], []), Program("bit_walking", [], [])
    edges = [0, 1, MASK64, 1 << 63, (1 << 63)-1, 0x80000000, 0x7FFFFFFF, 0xFFFFFFFF,
             0x100000000, 0x0123456789ABCDEF, 0xFEDCBA9876543210, 0x00FF0080FF00FF01,
             0xAAAAAAAAAAAAAAAA, 0x5555555555555555, 0x0000000100000001, 0xFFFFFFFF00000000]
    for sf, operation in variants():
        width = 64 if sf else 32
        for r in range(32):
            for rd, rn in ((r, (r+1)%32), (r, r), (r, 31), (31, r)):
                index = len(fields.words); fields.words.append(bit_word(sf, operation, rd, rn))
                for j, value in enumerate(edges):
                    regs = [rng.getrandbits(64) for _ in range(31)]
                    if rn != 31: regs[rn] = value
                    expected = {rd: expected_value(regs[rn] if rn != 31 else 0, width, operation)} if rd != 31 else dict(enumerate(regs))
                    flags = j << 28
                    fields.trials.append(Trial(index, regs, 0xFEDCBA9876543210, flags,
                                               expected_x=expected, expected_nzcv=flags))
                fields.trials.append(Trial(index, regs, 0xFEDCBA9876543210, flags, 0,
                                           dict(enumerate(regs)), expected_nzcv=flags))
        index = len(walking.words); walking.words.append(bit_word(sf, operation, 0, 1))
        mask = (1 << width)-1
        values = sorted({0, mask, *(1 << b for b in range(width)), *(mask ^ (1 << b) for b in range(width)),
                         *((1 << n)-1 for n in range(width+1)), *(mask ^ ((1 << n)-1) for n in range(width+1))})
        for j, value in enumerate(values + [rng.getrandbits(width) for _ in range(32)]):
            regs = [rng.getrandbits(64) for _ in range(31)]
            regs[1] = value | (rng.getrandbits(32) << 32) if width == 32 else value
            flags = (j % 16) << 28
            walking.trials.append(Trial(index, regs, 0x800000, flags, expected_x={0: expected_value(value, width, operation)},
                                        expected_nzcv=flags))
    return [fields, walking] + bit_leaves()


def bit_leaves():
    rng = random.Random(0xB171EAF)
    trailing = Program("leaf_trailing_zero", [bit_word(1, 0, 1, 0), bit_word(1, 4, 0, 1), 0xD65F03C0], [], leaf=True)
    mixed = Program("leaf_bit_normalize", [bit_word(0, 0, 1, 0), bit_word(0, 5, 0, 1),
                    bit_word(1, 1, 4, 4), bit_word(1, 2, 4, 4), bit_word(1, 3, 4, 4),
                    bit_word(1, 4, 3, 4), 0x8B030000, 0xD65F03C0], [], leaf=True)
    values = [0, MASK64] + [1 << b for b in range(64)] + [MASK64 ^ (1 << b) for b in range(64)]
    values += [rng.getrandbits(64) for _ in range(32)]
    for j, value in enumerate(values):
        regs = [rng.getrandbits(64) for _ in range(31)]; regs[0] = value
        raw = regs[4].to_bytes(8, "little")
        permuted = int.from_bytes(bytes(raw[i] for i in (5, 4, 7, 6, 1, 0, 3, 2)), "little")
        reverse_w = f"{value & 0xFFFFFFFF:032b}"[::-1]
        sign_count = len(reverse_w)-len(reverse_w.lstrip(reverse_w[0]))-1
        for p, expected in ((trailing, {0: 64 if not value else (value & -value).bit_length()-1}),
                             (mixed, {0: sign_count + 64-permuted.bit_length(), 4: permuted})):
            r = regs.copy(); r[30] = BASE+len(p.data)
            flags = (j % 16) << 28
            p.trials.extend(Trial(0, r, 0x800000, flags, budget, expected_nzcv=flags) for budget in range(len(p.words)))
            p.trials.append(Trial(0, r, 0x800000, flags, len(p.words), expected, expected_nzcv=flags))
    return [trailing, mixed]
