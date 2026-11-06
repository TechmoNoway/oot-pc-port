#include "plt_bridge.h"

int oot_plt_decode(const OotPltFunction *p, uint64_t *page)
{
    uint32_t a = p->words[0], l = p->words[1], add = p->words[2];
    uint64_t low = ((l >> 10) & 4095) * 8;
    if (p->entry % 4 || p->entry > (UINT64_C(1) << 39) - 16 ||
        p->slot % 8 || p->slot > (UINT64_C(1) << 39) - 8 ||
        p->target % 4 || p->target >= (UINT64_C(1) << 39) || p->run == NULL ||
        (a & UINT32_C(0x9f00001f)) != UINT32_C(0x90000010) ||
        (l & UINT32_C(0xffc003ff)) != UINT32_C(0xf9400211) ||
        (add & UINT32_C(0xffc003ff)) != UINT32_C(0x91000210) ||
        ((add >> 10) & 4095) != low || p->words[3] != UINT32_C(0xd61f0220)) return 0;
    *page = (p->entry & ~UINT64_C(4095)) +
        (oot_arm64_sign_extend(((a >> 29) & 3) | (((a >> 5) & 0x7ffff) << 2),21) << 12);
    return *page + low == p->slot;
}

int oot_plt_expected(const OotPltFunction *p, uint64_t page, unsigned index,
                     const OotArm64State *s, OotArm64State *e)
{
    *e = *s;
    if (index == 0) e->x[16] = page;
    else if (index == 1) { if (s->x[16] != page) return 0; e->x[17] = p->target; }
    else if (index == 2) { if (s->x[16] != page) return 0; e->x[16] = p->slot; }
    else if (index == 3) {
        if (s->x[16] != p->slot || s->x[17] != p->target) return 0;
        e->pc = p->target; return 1;
    } else return 0;
    e->pc += 4;
    return 1;
}
