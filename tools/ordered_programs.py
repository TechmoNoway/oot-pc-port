"""Synthetic no-offset RCpc loads; independent values and aligned fault cases."""

import random
from lifter_validation_types import BASE, Program, MemoryTrial, RegionSpec

DATA = 0x200000000


def rcpc(size, rt=0, rn=1):
    return 0x38BFC000 | (size << 30) | (rn << 5) | rt


def ordered_programs():
    rng = random.Random(0xAC901234)
    words, trials = [], []
    patterns = [bytes(4096), b"\xff" * 4096, bytes(range(256)) * 16, rng.randbytes(4096)]
    for size in range(4):
        width = 1 << size
        for rn in (0, 1, 17, 30, 31):
            for rt in (0, 1, 17, 30, 31):
                index = len(words); words.append(rcpc(size, rt, rn))
                for pattern in patterns:
                    for offset in (0, 16, 256, 4080):
                        regs = [rng.getrandbits(64) for _ in range(31)]
                        address = DATA + offset
                        if rn != 31: regs[rn] = address
                        value = int.from_bytes(pattern[offset:offset + width], "little")
                        trials.append(MemoryTrial(index, regs, address if rn == 31 else DATA, rng.randrange(16) << 28,
                            expected_x={rt:value} if rt != 31 else {}, regions=(RegionSpec(DATA,pattern,1),)))
    matrix = Program("ordered_matrix", words, trials, memory=True)
    words, trials = [], []
    for size in range(4):
        for rn,rt in ((0,0),(1,0),(31,0),(1,31),(31,31)):
            index=len(words);words.append(rcpc(size,rt,rn))
            for permissions in (None,2):
                address=DATA+0x2000 if permissions is None else DATA
                regs=[rng.getrandbits(64) for _ in range(31)]
                if rn != 31:regs[rn]=address
                trials.append(MemoryTrial(index,regs,address if rn==31 else DATA,0xF0000000,
                    regions=(RegionSpec(DATA,patterns[2],1 if permissions is None else permissions),),
                    expected_fault=(address,address,1<<size,1,1 if permissions is None else 2)))
    faults=Program("ordered_faults",words,trials,memory=True)
    # Store -> acquire -> store -> narrow acquire, with zero/partial/full budgets.
    words=[0xF9000022,rcpc(3,0,1),0xF9000060,rcpc(2,4,3)]
    trials=[]
    for budget in range(6):
        regs=[rng.getrandbits(64) for _ in range(31)];regs[1],regs[2],regs[3]=DATA,0xFEDCBA9876543210,DATA+16
        trials.append(MemoryTrial(0,regs,DATA,0xA0000000,budget,regions=(RegionSpec(DATA,patterns[0]),)))
    sequence=Program("ordered_sequence",words,trials,memory=True)
    # A retired ordinary store survives a following acquire's unmapped fault.
    regs=[0]*31;regs[1],regs[2],regs[3]=DATA,0x12345678,DATA+0x2000
    after=Program("ordered_after_store",[0xF9000022,rcpc(3,0,3)],
        [MemoryTrial(0,regs,DATA,0,8,regions=(RegionSpec(DATA,patterns[0]),),
                     expected_fault=(DATA+0x2000,DATA+0x2000,8,1,1))],memory=True)
    return [matrix,faults,sequence,after]
