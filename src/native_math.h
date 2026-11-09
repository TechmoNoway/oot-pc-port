#ifndef OOT_NATIVE_MATH_H
#define OOT_NATIVE_MATH_H
#include "guest_memory.h"
enum OotNativeMathHandler { OOT_NATIVE_MATH_LOG=256 };
/* Host libm replacement, not an ARM FP instruction emulator. Binary64 D0 only;
 * finite positive inputs, nearest rounding, no guest FP exception interface.
 * Host errno, rounding mode and exception flags are restored on every outcome.
 * Rejection preserves output. Other inputs remain explicit unsupported calls. */
OOT_MEMORY_API int oot_native_math_prepare(uint32_t id,uint64_t input,uint64_t *output);
#endif
