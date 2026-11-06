#include "checked_read.h"

static int decode(uint32_t word, uint64_t pc, const OotArm64State *s, OotReadEffect *e, int store, int extended)
{
    unsigned rn = (word >> 5) & 31, size = word >> 30, opc = (word >> 22) & 3;
    unsigned post = 0;
    uint64_t offset = 0;
    *e = (OotReadEffect){0};
    e->rd = word & 31; e->rt2 = 31;
    e->rn = rn;
    e->sp_base = rn == 31; e->frame_base = rn == 31 || rn == 29;
    e->address = oot_arm64_read(s,rn,64,1);
    if ((word & UINT32_C(0x3ffffc00)) == UINT32_C(0x38bfc000)) {
        if (store) return 0;
        e->element = 1u << size; e->width = size == 3 ? 64 : 32; e->rcpc = 1;
    } else if ((word & UINT32_C(0x3f000000)) == UINT32_C(0x18000000)) {
        unsigned literal = word >> 30;
        if (store || literal == 3) return 0;
        e->element = literal == 1 ? 8 : 4; e->width = literal ? 64 : 32;
        e->sign_extend = literal == 2; e->sp_base = e->frame_base = 0;
        e->address = pc + (oot_arm64_sign_extend((word >> 5) & 0x7ffff,19) << 2);
    } else if ((word & UINT32_C(0x3e000000)) == UINT32_C(0x28000000)) {
        unsigned kind = word >> 30, mode = (word >> 23) & 3;
        if (!mode || (!extended && mode != 2) || !!(word & (1u << 22)) == store || kind == 3 || (store && kind == 1)) return 0;
        e->pair = 1; e->rt2 = (word >> 10) & 31;
        if (!store && e->rd == e->rt2) return 0;
        e->writeback = mode != 2;
        if (e->writeback && rn != 31 && (rn == e->rd || rn == e->rt2)) return 0;
        post = mode == 1;
        e->element = kind == 2 ? 8 : 4; e->width = kind ? 64 : 32; e->sign_extend = kind == 1;
        offset = oot_arm64_sign_extend((word >> 15) & 127,7) * e->element;
    } else if ((word & UINT32_C(0x3f000000)) == UINT32_C(0x39000000) ||
               (word & UINT32_C(0x3f000000)) == UINT32_C(0x38000000)) {
        if (store ? opc != 0 : (!opc || (size == 3 && opc >= 2) || (size == 2 && opc == 3))) return 0;
        e->element = 1u << size; e->width = size == 3 || opc == 2 ? 64 : 32; e->sign_extend = opc >= 2;
        if (word & (1u << 24)) offset = (uint64_t)((word >> 10) & 4095) << size;
        else if (word & (1u << 21)) {
            unsigned extend = (word >> 13) & 7, rm = (word >> 16) & 31;
            if (((word >> 10) & 3) != 2 || (extend != 2 && extend != 3 && extend != 6 && extend != 7)) return 0;
            offset = oot_arm64_extend(oot_arm64_read(s,rm,64,0),extend,word & (1u << 12) ? size : 0,64);
        } else {
            unsigned mode = (word >> 10) & 3;
            if (mode == 2 || (!extended && mode != 0)) return 0;
            e->writeback = mode != 0;
            if (e->writeback && rn != 31 && rn == e->rd) return 0;
            post = mode == 1;
            offset = oot_arm64_sign_extend((word >> 12) & 511,9);
        }
    } else return 0;
    if (e->writeback) e->base_after = e->address + offset;
    if (!post) e->address += offset;
    e->size = e->element * (e->pair ? 2u : 1u);
    return 1;
}

int oot_read_decode(uint32_t word, uint64_t pc, const OotArm64State *s, OotReadEffect *e)
{
    return decode(word,pc,s,e,0,0);
}

int oot_write_decode(uint32_t word, uint64_t pc, const OotArm64State *s, OotReadEffect *e)
{
    return decode(word,pc,s,e,1,0);
}

int oot_leaf_read_decode(uint32_t word, uint64_t pc, const OotArm64State *s, OotReadEffect *e)
{
    return decode(word,pc,s,e,0,1);
}

int oot_leaf_write_decode(uint32_t word, uint64_t pc, const OotArm64State *s, OotReadEffect *e)
{
    return decode(word,pc,s,e,1,1);
}

void oot_write_expected(const OotReadEffect *e, const OotArm64State *s, uint8_t bytes[16], OotArm64State *expected)
{
    uint64_t first = oot_arm64_read(s,e->rd,64,0), second = oot_arm64_read(s,e->rt2,64,0);
    unsigned i;
    for (i = 0; i < e->element; ++i) {
        bytes[i] = (uint8_t)(first >> (i*8));
        if (e->pair) bytes[e->element+i] = (uint8_t)(second >> (i*8));
    }
    *expected = *s;
    expected->pc += 4;
}

int oot_write_commit(OotGuestMemory *memory, const OotReadEffect *e, const OotArm64State *s)
{
    uint64_t first = oot_arm64_read(s,e->rd,64,0), second = oot_arm64_read(s,e->rt2,64,0);
    return e->pair ? oot_memory_store_pair(memory,e->address,e->element,first,second) :
        oot_memory_store(memory,e->address,e->element,first);
}

int oot_read_capture(OotGuestMemory *memory, const OotReadEffect *e, uint8_t bytes[16], OotArm64State *expected)
{
    uint64_t first = 0, second = 0;
    unsigned i;
    int ok = e->pair ? oot_memory_load_pair(memory,e->address,e->element,&first,&second) :
        e->rcpc ? oot_memory_load_rcpc(memory,e->address,e->element,e->sp_base,&first) :
                  oot_memory_load(memory,e->address,e->element,&first);
    if (!ok) return 0;
    for (i = 0; i < e->element; ++i) {
        bytes[i] = (uint8_t)(first >> (i * 8));
        if (e->pair) bytes[e->element + i] = (uint8_t)(second >> (i * 8));
    }
    if (e->sign_extend) {
        first = oot_arm64_sign_extend(first,e->element * 8);
        second = oot_arm64_sign_extend(second,e->element * 8);
    }
    oot_arm64_write(expected,e->rd,e->width,0,first);
    if (e->pair) oot_arm64_write(expected,e->rt2,e->width,0,second);
    expected->pc += 4;
    return 1;
}

int oot_leaf_read_capture(OotGuestMemory *memory, const OotReadEffect *e, uint8_t bytes[16], OotArm64State *expected)
{
    if (!oot_read_capture(memory,e,bytes,expected)) return 0;
    if (e->writeback) oot_arm64_write(expected,e->rn,64,1,e->base_after);
    return 1;
}

void oot_leaf_write_expected(const OotReadEffect *e, const OotArm64State *s, uint8_t bytes[16], OotArm64State *expected)
{
    oot_write_expected(e,s,bytes,expected);
    if (e->writeback) oot_arm64_write(expected,e->rn,64,1,e->base_after);
}
