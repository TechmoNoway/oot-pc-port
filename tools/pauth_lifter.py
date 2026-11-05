"""Separate opt-in PAC ABI. Existing lifter and registry policies stay unchanged."""

from collections import Counter
import re
import struct

from arm64_lifter import (Instruction, MAX_WORDS, MEMORY_FORMS, U64, body, constant,
                         decode_instruction)
from input_formats import require

MODEL = "qarma5-va39-tbi0-basic"
WORDS = {0xD503233F: "paciasp", 0xD503237F: "pacibsp", 0xD50323BF: "autiasp",
         0xD50323FF: "autibsp", 0xD65F0BFF: "retaa", 0xD65F0FFF: "retab"}


def decode_pauth_block(data, base):
    require(data and len(data) % 4 == 0, "input must contain whole ARM64 words")
    require(len(data) <= MAX_WORDS * 4, "PAC block exceeds translation limit")
    require(isinstance(base, int) and base % 4 == 0 and 0 <= base <= U64 - len(data),
            "PAC block base/range must be aligned and nonwrapping")
    return [Instruction(base + i * 4, word, WORDS[word]) if word in WORDS else
            decode_instruction(word, base + i * 4)
            for i, (word,) in enumerate(struct.iter_unpack("<I", data))]


def emit_pauth_c(data, base, name="oot_pauth_lift_run"):
    require(re.fullmatch(r"oot_pauth_lift_[A-Za-z0-9_]+", name) is not None,
            "PAC function name must start with oot_pauth_lift_ and be a C identifier")
    instructions = decode_pauth_block(data, base)
    lines = ['/* Generated opt-in basic QARMA5/VA39 synthetic translation. */', '#include "pauth.h"',
             f"OOT_LIFT_EXPORT int {name}(OotArm64State *s, OotGuestMemory *memory,",
             "    const OotPauth *pauth, uint64_t budget, uint64_t *executed)", "{",
             "    uint64_t count = 0;",
             "    if (!executed) return OOT_PAUTH_LIFT_CONFIGURATION;", "    *executed = 0;",
             "    if (!s || oot_pauth_model(pauth) != OOT_PAUTH_QARMA5_VA39)",
             "        return OOT_PAUTH_LIFT_CONFIGURATION;", "    oot_memory_clear_fault(memory);",
             "    for (;;) {", "        switch (s->pc) {"]
    for ins in instructions:
        lines += [f"        case {constant(ins.pc)}: {{ /* {ins.form} */",
                  "            if (count == budget) { *executed = count; return OOT_LIFT_BUDGET; }"]
        if ins.word in WORDS:
            lines += [f"            if (oot_pauth_step(pauth, s, UINT32_C(0x{ins.word:08x})) == OOT_PAUTH_REJECTED)",
                      "                { *executed = count; return OOT_PAUTH_LIFT_CONFIGURATION; }"]
        else:
            lines += [f"            {line}" for line in body(ins)]
        lines += ["            ++count;", "            break;", "        }"]
    lines += ["        default: *executed = count; return OOT_LIFT_DISPATCH;", "        }", "    }", "}", ""]
    return "\n".join(lines), {"pauth_abi_version": 1, "state_abi_version": 2, "model": MODEL,
                              "base": base, "byte_count": len(data), "function": name,
                              "forms": dict(Counter(i.form for i in instructions)),
                              "guest_memory_access": any(i.form in MEMORY_FORMS for i in instructions),
                              "registry_compatible": False, "game_runtime_ready": False}
