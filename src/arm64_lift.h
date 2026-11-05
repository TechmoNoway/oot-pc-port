#ifndef OOT_ARM64_LIFT_H
#define OOT_ARM64_LIFT_H

#include <stdint.h>

#if defined(_WIN32)
#define OOT_LIFT_EXPORT __declspec(dllexport)
#else
#define OOT_LIFT_EXPORT
#endif

/* Integer-only guest state. No guest address is a native function pointer. */
typedef struct OotArm64State {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint32_t nzcv; /* Architectural bits 31:28; other bits must be zero. */
} OotArm64State;

enum OotLiftStatus {
    OOT_LIFT_DISPATCH = 0, /* PC left the translated instruction set. */
    OOT_LIFT_BUDGET = 1    /* PC is translated, but the budget was exhausted. */
};

static inline uint64_t oot_arm64_mask(unsigned width)
{
    return width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
}

static inline uint64_t oot_arm64_read(const OotArm64State *s, unsigned reg,
                                     unsigned width, unsigned use_sp)
{
    uint64_t value = reg == 31 ? (use_sp ? s->sp : 0) : s->x[reg];
    return value & oot_arm64_mask(width);
}

static inline void oot_arm64_write(OotArm64State *s, unsigned reg, unsigned width,
                                   unsigned use_sp, uint64_t value)
{
    value &= oot_arm64_mask(width);
    if (reg != 31)
        s->x[reg] = value;
    else if (use_sp)
        s->sp = value;
}

/* The decoder guarantees amount < width. Avoid signed shifts and shift-by-64. */
static inline uint64_t oot_arm64_shift(uint64_t value, unsigned kind,
                                      unsigned amount, unsigned width)
{
    uint64_t mask = oot_arm64_mask(width);
    value &= mask;
    if (amount == 0)
        return value;
    switch (kind) {
    case 0: return (value << amount) & mask;
    case 1: return value >> amount;
    case 2: return (value >> amount) |
                   ((value >> (width - 1)) ? (mask ^ (mask >> amount)) : 0);
    default: return ((value >> amount) | (value << (width - amount))) & mask;
    }
}

static inline uint32_t oot_arm64_nz(uint64_t value, unsigned width)
{
    return (uint32_t)((value >> (width - 1)) << 31) |
           (value == 0 ? UINT32_C(0x40000000) : 0);
}

static inline uint64_t oot_arm64_addsub(OotArm64State *s, uint64_t left,
                                       uint64_t right, unsigned width,
                                       unsigned subtract, unsigned set_flags)
{
    uint64_t result = (subtract ? left - right : left + right) & oot_arm64_mask(width);
    if (set_flags) {
        unsigned carry = subtract ? left >= right : result < left;
        uint64_t overflow = (subtract ? (left ^ right) : ~(left ^ right)) &
                            (left ^ result);
        s->nzcv = oot_arm64_nz(result, width) | ((uint32_t)carry << 29) |
                  (uint32_t)(((overflow >> (width - 1)) & 1) << 28);
    }
    return result;
}

static inline unsigned oot_arm64_condition(uint32_t nzcv, unsigned condition)
{
    unsigned n = (nzcv >> 31) & 1, z = (nzcv >> 30) & 1;
    unsigned c = (nzcv >> 29) & 1, v = (nzcv >> 28) & 1, holds;
    switch (condition >> 1) {
    case 0: holds = z; break;
    case 1: holds = c; break;
    case 2: holds = n; break;
    case 3: holds = v; break;
    case 4: holds = c && !z; break;
    case 5: holds = n == v; break;
    case 6: holds = (n == v) && !z; break;
    default: holds = 1; break;
    }
    return (condition & 1) && condition != 15 ? !holds : holds;
}

#endif
