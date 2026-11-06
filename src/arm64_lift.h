#ifndef OOT_ARM64_LIFT_H
#define OOT_ARM64_LIFT_H

#include <stdint.h>
#include "guest_memory.h"

#define OOT_LIFT_ABI_VERSION 2

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
    OOT_LIFT_BUDGET = 1,   /* PC is translated, but the budget was exhausted. */
    OOT_LIFT_MEMORY_FAULT = 2 /* Faulting instruction did not retire. */
};

static inline uint64_t oot_arm64_sign_extend(uint64_t value, unsigned bits)
{
    if (bits == 64)
        return value;
    return value | ((value & (UINT64_C(1) << (bits - 1))) ? (UINT64_MAX << bits) : 0);
}

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

/* Exact one-source encodings guarantee W/X widths and valid byte containers. */
static inline uint64_t oot_arm64_rbit(uint64_t value, unsigned width)
{
    uint64_t result = 0;
    unsigned i;
    for (i = 0; i < width; ++i) {
        result = (result << 1) | (value & 1);
        value >>= 1;
    }
    return result;
}

static inline uint64_t oot_arm64_reverse_bytes(uint64_t value, unsigned width,
                                              unsigned container)
{
    uint64_t result = 0;
    unsigned base, byte;
    for (base = 0; base < width; base += container)
        for (byte = 0; byte < container; byte += 8)
            result |= ((value >> (base + byte)) & UINT64_C(0xff)) <<
                      (base + container - 8 - byte);
    return result;
}

static inline uint64_t oot_arm64_leading(uint64_t value, unsigned width,
                                       unsigned sign_bits)
{
    uint64_t bit = UINT64_C(1) << (width - 1), mask = oot_arm64_mask(width);
    unsigned count = 0;
    value &= mask;
    if (sign_bits && (value & bit))
        value = ~value & mask;
    while (bit && !(value & bit)) {
        ++count;
        bit >>= 1;
    }
    /* A normalized sign-bit operand always has at least one leading zero. */
    return sign_bits ? count - 1 : count;
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

/* All arithmetic stays unsigned, including signed divide magnitudes. */
static inline uint64_t oot_arm64_divide(uint64_t left, uint64_t right,
                                       unsigned width, unsigned signed_division)
{
    uint64_t mask = oot_arm64_mask(width), sign = UINT64_C(1) << (width - 1);
    unsigned negative = signed_division && ((left ^ right) & sign) != 0;
    uint64_t quotient;
    if (right == 0)
        return 0;
    if (signed_division) {
        if (left & sign) left = (0 - left) & mask;
        if (right & sign) right = (0 - right) & mask;
    }
    quotient = left / right;
    return (negative ? 0 - quotient : quotient) & mask;
}

static inline uint64_t oot_arm64_extend(uint64_t value, unsigned option,
                                       unsigned shift, unsigned width)
{
    unsigned bits = 8u << (option & 3);
    if (bits != 64)
        value &= (UINT64_C(1) << bits) - 1;
    if (option & 4)
        value = oot_arm64_sign_extend(value, bits);
    return (value << shift) & oot_arm64_mask(width);
}

static inline uint64_t oot_arm64_carry(OotArm64State *s, uint64_t left, uint64_t right,
                                      unsigned width, unsigned subtract, unsigned set_flags)
{
    uint64_t mask = oot_arm64_mask(width), first, result, overflow;
    unsigned input_carry = (s->nzcv >> 29) & 1, carry;
    if (subtract)
        right = ~right & mask;
    first = (left + right) & mask;
    result = (first + input_carry) & mask;
    if (set_flags) {
        carry = first < left || result < first;
        overflow = ~(left ^ right) & (left ^ result);
        s->nzcv = oot_arm64_nz(result, width) | ((uint32_t)carry << 29) |
                  (uint32_t)(((overflow >> (width - 1)) & 1) << 28);
    }
    return result;
}

#endif
