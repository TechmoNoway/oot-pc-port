#ifndef OOT_CHECKED_READ_H
#define OOT_CHECKED_READ_H
#include "arm64_lift.h"

/* Internal checked-effect metadata, not a general interpreter. The original
 * decoders remain no-writeback; only the separate leaf helpers opt in. */
typedef struct OotReadEffect {
    uint64_t address;
    unsigned size, element, width, rd, rt2, pair, sign_extend, rcpc, sp_base, frame_base;
    unsigned rn, writeback;
    uint64_t base_after;
} OotReadEffect;
int oot_read_decode(uint32_t word, uint64_t pc, const OotArm64State *state, OotReadEffect *effect);
int oot_write_decode(uint32_t word, uint64_t pc, const OotArm64State *state, OotReadEffect *effect);
void oot_write_expected(const OotReadEffect *effect, const OotArm64State *state, uint8_t bytes[16], OotArm64State *expected);
int oot_write_commit(OotGuestMemory *memory, const OotReadEffect *effect, const OotArm64State *state);
int oot_read_capture(OotGuestMemory *memory, const OotReadEffect *effect,
                     uint8_t bytes[16], OotArm64State *expected);
int oot_leaf_read_decode(uint32_t word, uint64_t pc, const OotArm64State *state, OotReadEffect *effect);
int oot_leaf_write_decode(uint32_t word, uint64_t pc, const OotArm64State *state, OotReadEffect *effect);
/* Read destinations and writeback are published only after whole capture.
 * Store bytes always come from the pre-instruction state; commit still uses
 * oot_write_commit with that same checkpoint and the decoded effective address. */
int oot_leaf_read_capture(OotGuestMemory *memory, const OotReadEffect *effect,
                         uint8_t bytes[16], OotArm64State *expected);
void oot_leaf_write_expected(const OotReadEffect *effect, const OotArm64State *state,
                             uint8_t bytes[16], OotArm64State *expected);
#endif
