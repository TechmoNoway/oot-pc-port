#ifndef OOT_STARTUP_FLOAT_H
#define OOT_STARTUP_FLOAT_H
#include "guest_memory.h"
/* INIT-only nearest rounding, default or FZ FPCR. Binary finite inputs; generated
 * infinities/default NaNs and cumulative exception bits are explicit. Host
 * floating environment/errno are private to each calculation and restored.
 * Operations 0 MUL, 1 DIV, 2 ADD, 3 SUB, 4 convert from the other S/D width,
 * 5 square root. The separate fused helper rounds the product/addend once.
 * Conversion explicitly preserves NaN payload/sign and quiets signaling NaNs. */
OOT_MEMORY_API int oot_startup_float_binary(unsigned operation,unsigned width,unsigned fpcr,
    uint64_t left,uint64_t right,uint64_t *result,uint32_t *exceptions);
OOT_MEMORY_API int oot_startup_float_fmadd(unsigned width,unsigned fpcr,uint64_t left,
    uint64_t right,uint64_t addend,uint64_t *result,uint32_t *exceptions);
#endif
