"""Separate linear framed-caller policy; existing register-leaf rules stay strict."""

import hashlib
import re
from arm64_lifter import decode_block
from input_formats import require
from leaf_verifier import VALUE_FORMS, leaf_edges, verify_leaf

MAX_FRAME_WORDS = 64


def verify_frame(data, base, leaves):
    require(20 <= len(data) <= MAX_FRAME_WORDS * 4, "framed caller size is outside policy")
    ins = decode_block(data, base)
    require([i.word for i in ins[:2]] == [0xA9BF7BFD, 0x910003FD] and
            [i.word for i in ins[-2:]] == [0xA8C17BFD, 0xD65F03C0], "framed caller requires canonical FP/LR frame")
    proofs = {entry: verify_leaf(code, entry) for entry, code in leaves.items()}
    ranges = sorted([(base, base + len(data))] + [(entry, entry + len(code)) for entry, code in leaves.items()])
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "framed caller and leaves overlap")
    steps, bound, calls = [{"kind": 0, "callee": 0}, {"kind": 1, "callee": 0}], len(ins), 0
    for instruction in ins[2:-2]:
        if instruction.form == "branch_immediate" and instruction.operation == 1:
            require(instruction.target in proofs, "framed caller target is not a verified leaf")
            steps.append({"kind": 3, "callee": instruction.target})
            bound += proofs[instruction.target]["max_retired_instructions"]
            calls += 1
        else:
            require(instruction.form in VALUE_FORMS or instruction.form == "nop", "framed caller body must be linear register operations")
            leaf_edges(instruction, base, base + len(data))
            steps.append({"kind": 2, "callee": 0})
    require(calls > 0, "framed caller profile requires a direct leaf call")
    steps += [{"kind": 4, "callee": 0}, {"kind": 5, "callee": 0}]
    return {"schema_version": 1, "policy": "linear-fp-lr-caller-v1", "base": base,
            "byte_count": len(data), "instruction_count": len(ins), "max_retired_instructions": bound,
            "source_sha256": hashlib.sha256(data).hexdigest(), "steps": steps, "call_count": calls,
            "guest_code_executed": False, "stack_bytes": 16}


def emit_frame_descriptor(data, base, leaves, name):
    require(re.fullmatch(r"oot_lift_[A-Za-z0-9_]+", name) is not None, "invalid frame function identifier")
    proof, suffix = verify_frame(data, base, leaves), name[len("oot_lift_"):]
    lines = ['#include "frame_dispatch.h"', '#if OOT_FRAME_POLICY_VERSION != 1 || OOT_LIFT_ABI_VERSION != 2',
             '#error Regenerate framed descriptor', '#endif', f"static const OotFrameStep oot_frame_steps_{suffix}[] = {{"]
    lines += [f"    {{{s['kind']}, 0, UINT64_C(0x{s['callee']:x})}}," for s in proof["steps"]]
    lines += ["};", f"static const OotFrameFunction oot_frame_info_{suffix} = {{",
              f"    UINT64_C(0x{base:x}), {proof['instruction_count']}, {proof['max_retired_instructions']}, 2, 1,",
              f"    {name}, oot_frame_steps_{suffix}, {{{{",
              "        " + ", ".join(f"0x{b:02x}" for b in bytes.fromhex(proof["source_sha256"])), "    }}", "};",
              f"OOT_LIFT_EXPORT const OotFrameFunction *oot_frame_descriptor_{suffix}(void)",
              "{", f"    return &oot_frame_info_{suffix};", "}", ""]
    return "\n".join(lines)
