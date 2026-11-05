#include <stdio.h>
#include <string.h>
#include "pauth.h"

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expr); return 1; } } while (0)

int main(void)
{
    /* Public synthetic keys and independently recorded Unicorn 2.1.4 vectors. */
    OotPauthKeys keys = {UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
                         UINT64_C(0x1020304050607080), UINT64_C(0x9080706050403020)};
    const uint64_t signed_lr[2] = {UINT64_C(0x3f290f8001000040), UINT64_C(0x6536f88001000040)};
    const uint32_t sign[2] = {0xd503233f, 0xd503237f};
    const uint32_t auth[2] = {0xd50323bf, 0xd50323ff};
    const uint32_t ret[2] = {0xd65f0bff, 0xd65f0fff};
    OotPauth *context = oot_pauth_create(OOT_PAUTH_QARMA5_VA39, &keys), *fresh;
    OotArm64State s = {0}, before;
    unsigned i;
    CHECK(context && oot_pauth_model(context) == OOT_PAUTH_QARMA5_VA39);
    memset(&keys, 0, sizeof(keys)); /* Context owns a copy. */
    s.sp = UINT64_C(0x7000001000); s.nzcv = 0xf0000000;
    for (i = 0; i < 2; ++i) {
        s.pc = 0x1000000; s.x[30] = 0x1000040; before = s;
        CHECK(oot_pauth_step(context, &s, sign[i]) == OOT_PAUTH_SIGNED);
        CHECK(s.x[30] == signed_lr[i]);
        CHECK(s.pc == before.pc + 4 && s.sp == before.sp && s.nzcv == before.nzcv);
        CHECK(oot_pauth_step(context, &s, ret[i]) == OOT_PAUTH_AUTHENTICATED);
        CHECK(s.pc == before.x[30] && s.x[30] == signed_lr[i]);
        s.pc = 0x1000000;
        CHECK(oot_pauth_step(context, &s, auth[i]) == OOT_PAUTH_AUTHENTICATED);
        CHECK(s.x[30] == before.x[30]);
        s.x[30] = signed_lr[i] ^ (UINT64_C(1) << 39);
        CHECK(oot_pauth_step(context, &s, ret[i]) == OOT_PAUTH_POISONED);
        CHECK(s.pc == (((uint64_t)(i + 1) << 61) | UINT64_C(0x1000040)));
        CHECK(s.x[30] == (signed_lr[i] ^ (UINT64_C(1) << 39)));
        s.pc = 0x1000000;
        CHECK(oot_pauth_step(context, &s, auth[i]) == OOT_PAUTH_POISONED);
        CHECK(s.x[30] == (((uint64_t)(i + 1) << 61) | UINT64_C(0x1000040)));
    }
    s.pc = 0x1000000; before = s;
    CHECK(oot_pauth_step(NULL, &s, sign[0]) == OOT_PAUTH_REJECTED);
    CHECK(memcmp(&s, &before, sizeof(s)) == 0);
    CHECK(oot_pauth_step(context, &s, 0xd503201f) == OOT_PAUTH_REJECTED);
    CHECK(memcmp(&s, &before, sizeof(s)) == 0);
    CHECK(oot_pauth_step(context, NULL, sign[0]) == OOT_PAUTH_REJECTED);
    CHECK(!oot_pauth_create(0, NULL));
    CHECK(!oot_pauth_create(2, NULL));
    fresh = oot_pauth_create(OOT_PAUTH_QARMA5_VA39, NULL);
    CHECK(fresh && oot_pauth_model(fresh) == OOT_PAUTH_QARMA5_VA39);
    s.pc = 0x1000000; s.x[30] = 0x1000040;
    CHECK(oot_pauth_step(fresh, &s, sign[0]) == OOT_PAUTH_SIGNED);
    CHECK(oot_pauth_step(fresh, &s, auth[0]) == OOT_PAUTH_AUTHENTICATED && s.x[30] == 0x1000040);
    oot_pauth_destroy(fresh); oot_pauth_destroy(context); oot_pauth_destroy(NULL);
    puts("Pointer authentication self-test passed.");
    return 0;
}
