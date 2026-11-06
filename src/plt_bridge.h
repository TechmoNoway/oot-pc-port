#ifndef OOT_PLT_BRIDGE_H
#define OOT_PLT_BRIDGE_H
#include "stack_dispatch.h"
int oot_plt_decode(const OotPltFunction *plt, uint64_t *page);
int oot_plt_expected(const OotPltFunction *plt, uint64_t page, unsigned index,
                     const OotArm64State *state, OotArm64State *expected);
#endif
