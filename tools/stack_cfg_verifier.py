"""Acyclic framed CFGs with explicit callee-save slots; separate policy v2."""

from dataclasses import replace
import hashlib
import re

from arm64_lifter import decode_block
from input_formats import require
from leaf_verifier import VALUE_FORMS, leaf_edges, verify_leaf
from stack_verifier import MAX_FUNCTIONS, MAX_WORDS, MAX_FRAME, MAX_DEPTH, MAX_STEPS, OPEN, FP, NORMAL, CALL, CLOSE, RETURN, LOAD, STORE

SAVE, RESTORE, BRANCH = 8, 9, 10
NONE = 0xFFFF


def saved_access(i, load):
    if i.form not in ("loadstore_unsigned", "loadstore_immediate", "loadstore_pair"):
        return None
    registers = [i.rd, i.rt2] if i.form == "loadstore_pair" else [i.rd]
    if i.load != load or i.access_size != 8 or i.rn not in (29, 31) or i.writeback or i.post_index or not all(19 <= r <= 28 for r in registers):
        return None
    return registers


def verify_cfg_stack_functions(frames, leaves, root):
    require(0 < len(frames) <= MAX_FUNCTIONS and len(leaves) <= 256 and root in frames, "invalid CFG registry/root")
    ranges = sorted((entry, entry + len(code)) for entry, code in [*frames.items(), *leaves.items()])
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "CFG registry code overlaps")
    leaf_proofs = {entry: verify_leaf(code, entry) for entry, code in leaves.items()}
    proofs = {}
    for entry, data in frames.items():
        require(16 <= len(data) <= MAX_WORDS * 4, "CFG function size exceeds policy")
        ins = decode_block(data, entry)
        size = -ins[0].immediate
        require(ins[0].form == "loadstore_pair" and ins[0].word & ~0x003F8000 == 0xA9807BFD and
                16 <= size <= MAX_FRAME and size % 16 == 0 and ins[1].word == 0x910003FD and
                ins[-2].form == "loadstore_pair" and ins[-2].word & ~0x003F8000 == 0xA8C07BFD and
                ins[-2].immediate == size and ins[-1].word == 0xD65F03C0, "CFG function requires canonical FP/LR frame")
        saves, saved_mask, local_start = [], 0, 16
        for i in ins[2:-2]:
            regs = saved_access(i, False)
            if regs is None or i.immediate != local_start:
                break
            require(len(set(regs)) == len(regs) and not any(saved_mask & (1 << r) for r in regs), "duplicate saved register")
            width = len(regs) * 8
            require(local_start + width <= size, "saved slots exceed frame")
            saves.append((local_start, width, regs))
            saved_mask |= sum(1 << r for r in regs)
            local_start += width
        body_start, epilogue = 2 + len(saves), len(ins) - 2 - len(saves)
        require(body_start <= epilogue, "missing register restores")
        for index, (offset, width, regs) in enumerate(reversed(saves)):
            i = ins[epilogue + index]
            require(saved_access(i, True) == regs and i.immediate == offset, "mismatched saved-register restore")

        steps, flows, calls, restored = [], [], [], 0
        for index, i in enumerate(ins):
            step = {"kind": NORMAL, "offset": 0, "size": 0, "callee": 0}
            flow = {"next": [index + 1], "saved_a": NONE, "saved_b": NONE, "writable_mask": 0}
            if index == 0:
                step.update(kind=OPEN, size=16)
            elif index == 1:
                step["kind"] = FP
            elif index < body_start:
                offset, width, regs = saves[index - 2]
                step.update(kind=SAVE, offset=offset, size=width)
                flow.update(saved_a=regs[0], saved_b=regs[1] if len(regs) == 2 else NONE)
            elif index < epilogue:
                flow["writable_mask"] = saved_mask
                if i.form == "branch_immediate" and i.operation == 1:
                    require(i.target in frames or i.target in leaves, "unregistered CFG call target")
                    step.update(kind=CALL, callee=i.target)
                    calls.append(i.target)
                elif i.form in ("branch_condition", "compare_branch", "test_branch") or i.form == "branch_immediate":
                    targets = [i.target] if i.form == "branch_immediate" else list(dict.fromkeys((i.target, i.pc + 4)))
                    successors = [(pc - entry) // 4 for pc in targets]
                    require(all(entry + n * 4 == pc and body_start <= n <= epilogue for n, pc in zip(successors, targets)),
                            "branch escapes body or enters prologue/restore tail")
                    step["kind"] = BRANCH
                    flow["next"] = successors
                elif i.form in ("loadstore_unsigned", "loadstore_immediate", "loadstore_pair"):
                    width = i.access_size * (2 if i.form == "loadstore_pair" else 1)
                    require(i.rn in (29, 31) and not i.writeback and not i.post_index and
                            local_start <= i.immediate and i.immediate + width <= size, "CFG memory must stay in locals")
                    regs = [i.rd, i.rt2] if i.form == "loadstore_pair" else [i.rd]
                    require(not i.load or all(r == 31 or r < 18 or saved_mask & (1 << r) for r in regs),
                            "CFG load writes unsaved protected register")
                    step.update(kind=LOAD if i.load else STORE, offset=i.immediate, size=width)
                else:
                    require(i.form in VALUE_FORMS or i.form == "nop", "unsupported CFG body effect")
                    leaf_edges(replace(i, rd=0) if saved_mask & (1 << i.rd) else i, entry, entry + len(data))
            elif index < len(ins) - 2:
                offset, width, regs = saves[len(ins) - 3 - index]
                restored |= sum(1 << r for r in regs)
                step.update(kind=RESTORE, offset=offset, size=width)
                flow.update(saved_a=regs[0], saved_b=regs[1] if len(regs) == 2 else NONE, writable_mask=saved_mask & ~restored)
            elif index == len(ins) - 2:
                step["kind"] = CLOSE
            else:
                step["kind"] = RETURN
                flow["next"] = []
            steps.append(step)
            flows.append(flow)
        proofs[entry] = {"schema_version": 1, "policy": "acyclic-saved-stack-dag-v2", "base": entry,
            "instruction_count": len(ins), "byte_count": len(data), "frame_size": size, "locals_begin": local_start,
            "saved_mask": saved_mask, "saved_registers": [r for r in range(19, 29) if saved_mask & (1 << r)],
            "steps": steps, "control_flow": flows, "calls": calls, "source_sha256": hashlib.sha256(data).hexdigest(),
            "guest_code_executed": False, "proof_scope": "structural CFG/register policy, not original identity or universal semantics"}
    visiting, visited = set(), set()

    def visit_function(entry):
        require(entry not in visiting, "CFG call graph contains recursion/cycle")
        if entry in visited: return
        visiting.add(entry)
        p = proofs[entry]
        depth, stack = 1, p["frame_size"]
        for target in p["calls"]:
            if target in proofs:
                visit_function(target)
                depth = max(depth, 1 + proofs[target]["max_depth"])
                stack = max(stack, p["frame_size"] + proofs[target]["max_stack_bytes"])
        colors = {}

        def visit_step(index):
            require(colors.get(index) != 1, "CFG contains a control-flow cycle")
            if colors.get(index) == 2: return p["control_flow"][index]["max_steps"]
            colors[index] = 1
            step, flow = p["steps"][index], p["control_flow"][index]
            weight = 1
            if step["kind"] == CALL:
                weight += (proofs if step["callee"] in proofs else leaf_proofs)[step["callee"]]["max_retired_instructions"]
            bound = weight + max((visit_step(n) for n in flow["next"]), default=0)
            require(bound <= MAX_STEPS, "CFG retirement bound exceeds policy")
            flow["max_steps"] = bound
            colors[index] = 2
            return bound

        bound = visit_step(0)
        require(len(colors) == p["instruction_count"], "CFG contains unreachable words")
        require(depth <= MAX_DEPTH, "CFG call depth exceeds policy")
        p.update(max_depth=depth, max_stack_bytes=stack, max_retired_instructions=bound)
        visiting.remove(entry)
        visited.add(entry)
    visit_function(root)
    require(len(visited) == len(proofs), "CFG registry contains unreachable functions")
    return proofs


def emit_cfg_stack_descriptor(proof, name):
    require(re.fullmatch(r"oot_lift_[A-Za-z0-9_]+", name) is not None, "invalid CFG identifier")
    suffix = name[len("oot_lift_"):]
    lines = ['#include "stack_dispatch.h"', '#if OOT_STACK_CFG_POLICY_VERSION != 2 || OOT_LIFT_ABI_VERSION != 2',
        '#error Regenerate CFG descriptor', '#endif', f'static const OotStackStep oot_cfg_steps_{suffix}[] = {{']
    lines += [f"    {{{s['kind']}, {s['offset']}, {s['size']}, 0, UINT64_C(0x{s['callee']:x})}}," for s in proof["steps"]]
    lines += ['};', f'static const OotStackCfgStep oot_cfg_flow_{suffix}[] = {{']
    for f in proof["control_flow"]:
        a, b = (f["next"][0], f["next"][-1]) if f["next"] else (NONE, NONE)
        lines += [f"    {{{a}, {b}, {f['saved_a']}, {f['saved_b']}, {f['max_steps']}, UINT32_C(0x{f['writable_mask']:x})}},"]
    lines += ['};', f'static const OotStackCfgFunction oot_cfg_info_{suffix} = {{', '    {',
        f"        UINT64_C(0x{proof['base']:x}), {proof['instruction_count']}, {proof['max_retired_instructions']}, 2, 2,",
        f"        {proof['frame_size']}, {proof['max_depth']}, {name}, oot_cfg_steps_{suffix}, {{{{",
        '            ' + ', '.join(f'0x{b:02x}' for b in bytes.fromhex(proof['source_sha256'])), '        }}', '    },',
        f"    oot_cfg_flow_{suffix}, UINT32_C(0x{proof['saved_mask']:x}), {proof['locals_begin']}", '};',
        f'OOT_LIFT_EXPORT const OotStackCfgFunction *oot_stack_cfg_descriptor_{suffix}(void)',
        '{', f'    return &oot_cfg_info_{suffix};', '}', '']
    return '\n'.join(lines)
