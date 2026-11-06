#ifndef OOT_CHECKED_READ_H
#define OOT_CHECKED_READ_H
#include "arm64_lift.h"

/* Internal policy-5 decoder/capture, not a general interpreter. No writeback. */
typedef struct OotReadEffect {
    uint64_t address;
    unsigned size, element, width, rd, rt2, pair, sign_extend, rcpc, sp_base, frame_base;
} OotReadEffect;
int oot_read_decode(uint32_t word, uint64_t pc, const OotArm64State *state, OotReadEffect *effect);
int oot_write_decode(uint32_t word, uint64_t pc, const OotArm64State *state, OotReadEffect *effect);
void oot_write_expected(const OotReadEffect *effect, const OotArm64State *state, uint8_t bytes[16], OotArm64State *expected);
int oot_write_commit(OotGuestMemory *memory, const OotReadEffect *effect, const OotArm64State *state);
int oot_read_capture(OotGuestMemory *memory, const OotReadEffect *effect,
                     uint8_t bytes[16], OotArm64State *expected);
#endif
