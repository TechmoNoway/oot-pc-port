// Independent compiler portability shim; dependency sources remain unchanged.
#pragma once
#if defined(_MSC_VER) && !defined(__clang__)
#define __builtin_unreachable() __assume(0)
#endif
