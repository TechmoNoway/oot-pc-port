#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include "pauth.h"

struct OotPauth {
    uint32_t model;
    uint32_t references;
    OotPauthKeys keys;
};

/* Independent nibble/matrix implementation of the QARMA5 specification.
 * Nibble zero is the least significant nibble. See docs/pointer-authentication.md.
 * This functional model has not been audited for side-channel resistance. */
static const unsigned cells[16] = {13, 6, 11, 0, 7, 12, 1, 10, 8, 3, 14, 5, 2, 9, 4, 15};
static const unsigned tweaks[16] = {4, 5, 6, 7, 11, 2, 3, 8, 12, 13, 14, 15, 0, 1, 10, 9};
static const unsigned sbox[16] = {11, 6, 8, 15, 12, 0, 9, 14, 3, 7, 4, 5, 13, 2, 1, 10};
static const uint64_t rounds[5] = {
    UINT64_C(0), UINT64_C(0x13198a2e03707344), UINT64_C(0xa4093822299f31d0),
    UINT64_C(0x082efa98ec4e6c89), UINT64_C(0x452821e638d01377)
};

static unsigned nibble(uint64_t value, unsigned index)
{
    return (unsigned)((value >> (4 * index)) & 15);
}

static uint64_t permute(uint64_t value, const unsigned table[16], unsigned inverse)
{
    uint64_t result = 0;
    unsigned i;
    for (i = 0; i < 16; ++i)
        result |= (uint64_t)nibble(value, inverse ? i : table[i]) << (4 * (inverse ? table[i] : i));
    return result;
}

static uint64_t substitute(uint64_t value, unsigned inverse)
{
    uint64_t result = 0;
    unsigned i, j;
    for (i = 0; i < 16; ++i) {
        unsigned v = nibble(value, i);
        if (inverse) {
            for (j = 0; sbox[j] != v; ++j) { }
            v = j;
        } else v = sbox[v];
        result |= (uint64_t)v << (4 * i);
    }
    return result;
}

static unsigned rotate(unsigned value, unsigned amount)
{
    return ((value << amount) | (value >> (4 - amount))) & 15;
}

static uint64_t mix(uint64_t value)
{
    uint64_t result = 0;
    unsigned row, col;
    for (row = 0; row < 4; ++row) {
        for (col = 0; col < 4; ++col) {
            unsigned v = rotate(nibble(value, 4 * ((row + 1) % 4) + col), 1) ^
                         rotate(nibble(value, 4 * ((row + 2) % 4) + col), 2) ^
                         rotate(nibble(value, 4 * ((row + 3) % 4) + col), 1);
            result |= (uint64_t)v << (4 * (4 * row + col));
        }
    }
    return result;
}

static uint64_t tweak(uint64_t value, unsigned inverse)
{
    /* Rotated output cells in the forward tweak permutation. */
    const unsigned rotated = (1u << 2) | (1u << 4) | (1u << 7) | (1u << 11) |
                             (1u << 12) | (1u << 14) | (1u << 15);
    uint64_t result = 0;
    unsigned i;
    for (i = 0; i < 16; ++i) {
        unsigned v = nibble(value, inverse ? i : tweaks[i]);
        if (rotated & (1u << i))
            v = inverse ? ((v << 1) & 15) | ((v ^ (v >> 3)) & 1) :
                          (v >> 1) | (((v ^ (v >> 1)) & 1) << 3);
        result |= (uint64_t)v << (4 * (inverse ? tweaks[i] : i));
    }
    return result;
}

static uint64_t qarma5(uint64_t data, uint64_t modifier, uint64_t high, uint64_t low)
{
    uint64_t whitening = ((high >> 1) | (high << 63)) ^ (high >> 63);
    uint64_t value = data ^ high;
    unsigned i;
    for (i = 0; i < 5; ++i) {
        value ^= low ^ modifier ^ rounds[i];
        if (i) value = mix(permute(value, cells, 0));
        value = substitute(value, 0);
        modifier = tweak(modifier, 0);
    }
    value = substitute(mix(permute(value ^ whitening ^ modifier, cells, 0)), 0);
    value = permute(mix(permute(value, cells, 0)) ^ low, cells, 1);
    value = permute(mix(substitute(value, 1)), cells, 1) ^ high ^ modifier;
    for (i = 0; i < 5; ++i) {
        value = substitute(value, 1);
        if (i != 4) value = permute(mix(value), cells, 1);
        modifier = tweak(modifier, 1);
        value ^= rounds[4 - i] ^ low ^ modifier ^ UINT64_C(0xc0ac29b7c97c50dd);
    }
    return value ^ whitening;
}

#define ADDRESS_MASK UINT64_C(0x0000007fffffffff)
#define PAC_MASK UINT64_C(0xff7fff8000000000)

static uint64_t extend_pointer(uint64_t pointer, unsigned selector_bit)
{
    return (pointer & ADDRESS_MASK) | ((pointer & (UINT64_C(1) << selector_bit)) ? ~ADDRESS_MASK : 0);
}

static uint64_t sign_pointer(uint64_t pointer, uint64_t modifier, uint64_t high, uint64_t low)
{
    uint64_t canonical = extend_pointer(pointer, 63);
    uint64_t code = qarma5(canonical, modifier, high, low);
    return (code & PAC_MASK) | (canonical & ~PAC_MASK);
}

OotPauth *oot_pauth_create(uint32_t model, const OotPauthKeys *keys)
{
    OotPauth *context;
    if (model != OOT_PAUTH_QARMA5_VA39) return NULL;
    context = (OotPauth *)calloc(1, sizeof(*context));
    if (!context) return NULL;
    if (keys) context->keys = *keys;
    else if (BCryptGenRandom(NULL, (PUCHAR)&context->keys, (ULONG)sizeof(context->keys),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        oot_pauth_destroy(context);
        return NULL;
    }
    context->model = model;
    context->references = 1;
    return context;
}

void oot_pauth_destroy(OotPauth *context)
{
    if (context) {
        if (context->references > 1) { --context->references; return; }
        SecureZeroMemory(context, sizeof(*context));
        free(context);
    }
}

int oot_pauth_retain(OotPauth *context)
{
    if (!context || context->model != OOT_PAUTH_QARMA5_VA39 || !context->references ||
        context->references == UINT32_MAX) return 0;
    ++context->references;
    return 1;
}

uint32_t oot_pauth_model(const OotPauth *context)
{
    return context ? context->model : 0;
}

int oot_pauth_step(const OotPauth *context, OotArm64State *state, uint32_t word)
{
    unsigned key_b, signing, returning;
    uint64_t high, low, result;
    int status;
    if (oot_pauth_model(context) != OOT_PAUTH_QARMA5_VA39 || !state || (state->pc & 3))
        return OOT_PAUTH_REJECTED;
    switch (word) {
    case UINT32_C(0xd503233f): key_b = 0; signing = 1; returning = 0; break;
    case UINT32_C(0xd503237f): key_b = 1; signing = 1; returning = 0; break;
    case UINT32_C(0xd50323bf): key_b = 0; signing = 0; returning = 0; break;
    case UINT32_C(0xd50323ff): key_b = 1; signing = 0; returning = 0; break;
    case UINT32_C(0xd65f0bff): key_b = 0; signing = 0; returning = 1; break;
    case UINT32_C(0xd65f0fff): key_b = 1; signing = 0; returning = 1; break;
    default: return OOT_PAUTH_REJECTED;
    }
    high = key_b ? context->keys.ib_hi : context->keys.ia_hi;
    low = key_b ? context->keys.ib_lo : context->keys.ia_lo;
    if (signing) {
        if (state->x[30] != extend_pointer(state->x[30], 63)) return OOT_PAUTH_REJECTED;
        result = sign_pointer(state->x[30], state->sp, high, low);
        status = OOT_PAUTH_SIGNED;
    } else {
        result = extend_pointer(state->x[30], 55);
        status = OOT_PAUTH_AUTHENTICATED;
        if ((qarma5(result, state->sp, high, low) ^ state->x[30]) & PAC_MASK) {
            result = (result & ~(UINT64_C(3) << 61)) | ((uint64_t)(key_b ? 2 : 1) << 61);
            status = OOT_PAUTH_POISONED;
        }
    }
    if (returning) state->pc = result;
    else { state->x[30] = result; state->pc += 4; }
    return status;
}
