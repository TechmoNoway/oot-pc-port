"""Separate bounded local-stack/direct-call DAG profile; no game execution."""

import hashlib
import re

from arm64_lifter import decode_block
from input_formats import require
from leaf_verifier import VALUE_FORMS, leaf_edges, verify_leaf

MAX_FUNCTIONS, MAX_WORDS, MAX_FRAME, MAX_DEPTH, MAX_STEPS = 32, 128, 256, 16, 1000000
OPEN, FP, NORMAL, CALL, CLOSE, RETURN, LOAD, STORE = range(8)


def verify_stack_functions(frames, leaves, root):
    require(0 < len(frames) <= MAX_FUNCTIONS and len(leaves) <= 256 and root in frames,
            "invalid stack-function registry/root")
    ranges = sorted((entry, entry + len(code)) for entry, code in [*frames.items(), *leaves.items()])
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "stack registry code ranges overlap")
    leaf_proofs = {entry: verify_leaf(code, entry) for entry, code in leaves.items()}
    proofs = {}
    for entry, code in frames.items():
        require(16 <= len(code) <= MAX_WORDS * 4, "stack function size is outside policy")
        ins = decode_block(code, entry)
        first, last = ins[0], ins[-2]
        size = -first.immediate
        require(first.form == "loadstore_pair" and first.word & ~0x003F8000 == 0xA9807BFD and
                16 <= size <= MAX_FRAME and size % 16 == 0 and ins[1].word == 0x910003FD and
                last.form == "loadstore_pair" and last.word & ~0x003F8000 == 0xA8C07BFD and
                last.immediate == size and ins[-1].word == 0xD65F03C0,
                "stack function requires matching canonical FP/LR frame")
        steps = [{"kind": OPEN, "offset": 0, "size": 16, "callee": 0},
                 {"kind": FP, "offset": 0, "size": 0, "callee": 0}]
        calls = []
        for i in ins[2:-2]:
            step = {"kind": NORMAL, "offset": 0, "size": 0, "callee": 0}
            if i.form == "branch_immediate" and i.operation == 1:
                require(i.target in frames or i.target in leaves, "unregistered stack call target")
                step.update(kind=CALL, callee=i.target)
                calls.append(i.target)
            elif i.form in ("loadstore_unsigned", "loadstore_immediate", "loadstore_pair"):
                width = i.access_size * (2 if i.form == "loadstore_pair" else 1)
                require(i.rn in (29, 31) and not i.writeback and not i.post_index and
                        16 <= i.immediate and i.immediate + width <= size, "memory must stay inside current frame locals")
                require(not i.load or (not 18 <= i.rd <= 30 and
                        (i.form != "loadstore_pair" or not 18 <= i.rt2 <= 30)), "local load writes protected register")
                step.update(kind=LOAD if i.load else STORE, offset=i.immediate, size=width)
            else:
                require(i.form in VALUE_FORMS or i.form == "nop", "stack body must be linear")
                leaf_edges(i, entry, entry + len(code))
            steps.append(step)
        steps += [{"kind": CLOSE, "offset": 0, "size": 0, "callee": 0},
                  {"kind": RETURN, "offset": 0, "size": 0, "callee": 0}]
        proofs[entry] = {"schema_version": 1, "policy": "linear-local-stack-dag-v1", "base": entry,
            "byte_count": len(code), "instruction_count": len(ins), "frame_size": size,
            "source_sha256": hashlib.sha256(code).hexdigest(), "steps": steps, "calls": calls,
            "guest_code_executed": False, "proof_scope": "structural policy, not function identity or universal semantics"}
    visiting, visited = set(), set()

    def visit(entry):
        require(entry not in visiting, "stack call graph contains recursion/cycle")
        if entry in visited:
            return
        visiting.add(entry)
        proof = proofs[entry]
        bound, depth, stack_bytes = proof["instruction_count"], 1, proof["frame_size"]
        for target in proof["calls"]:
            if target in proofs:
                visit(target)
                child = proofs[target]
                depth = max(depth, 1 + child["max_depth"])
                stack_bytes = max(stack_bytes, proof["frame_size"] + child["max_stack_bytes"])
            else:
                child = leaf_proofs[target]
            bound += child["max_retired_instructions"]
        require(depth <= MAX_DEPTH and bound <= MAX_STEPS, "stack call depth/retirement bound exceeds policy")
        proof.update(max_depth=depth, max_retired_instructions=bound, max_stack_bytes=stack_bytes)
        visiting.remove(entry)
        visited.add(entry)

    visit(root)
    require(len(visited) == len(frames), "stack registry contains unreachable functions")
    return proofs


def emit_stack_descriptor(proof, name):
    require(re.fullmatch(r"oot_lift_[A-Za-z0-9_]+", name) is not None, "invalid stack function identifier")
    suffix = name[len("oot_lift_"):]
    lines = ['#include "stack_dispatch.h"', '#if OOT_STACK_POLICY_VERSION != 1 || OOT_LIFT_ABI_VERSION != 2',
        '#error Regenerate stack descriptor', '#endif', f"static const OotStackStep oot_stack_steps_{suffix}[] = {{"]
    lines += [f"    {{{s['kind']}, {s['offset']}, {s['size']}, 0, UINT64_C(0x{s['callee']:x})}}," for s in proof["steps"]]
    lines += ["};", f"static const OotStackFunction oot_stack_info_{suffix} = {{",
        f"    UINT64_C(0x{proof['base']:x}), {proof['instruction_count']}, {proof['max_retired_instructions']}, 2, 1,",
        f"    {proof['frame_size']}, {proof['max_depth']}, {name}, oot_stack_steps_{suffix}, {{{{",
        "        " + ", ".join(f"0x{b:02x}" for b in bytes.fromhex(proof["source_sha256"])), "    }}", "};",
        f"OOT_LIFT_EXPORT const OotStackFunction *oot_stack_descriptor_{suffix}(void)",
        "{", f"    return &oot_stack_info_{suffix};", "}", ""]
    return "\n".join(lines)
