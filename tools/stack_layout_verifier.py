"""Explicit fixed-allocation/offset-frame layouts, separate stack policy v3."""

from dataclasses import replace
import hashlib
import re

from arm64_lifter import decode_block
from input_formats import require
from leaf_verifier import VALUE_FORMS, leaf_edges, verify_leaf
from stack_cfg_verifier import BRANCH, SAVE, RESTORE, NONE, verify_cfg_graphs
from stack_verifier import MAX_FUNCTIONS, MAX_WORDS, MAX_FRAME, OPEN, FP, NORMAL, CALL, CLOSE, RETURN, LOAD, STORE

ALLOC, RECORD_SAVE, RECORD_RESTORE, DEALLOC = 11, 12, 13, 14


def sp_change(i, subtract):
    return i.form == "addsub_immediate" and i.width == 64 and not i.flags and i.operation == int(subtract) and i.rd == i.rn == 31


def fp_set(i, offset):
    return i.form == "addsub_immediate" and i.width == 64 and not i.flags and not i.operation and i.rd == 29 and i.rn == 31 and i.immediate == offset


def record_access(i, load):
    return i.form == "loadstore_pair" and i.access_size == 8 and i.rd == 29 and i.rt2 == 30 and i.rn == 31 and i.load == load


def access(i, record, fp_ready):
    require(i.form in ("loadstore_unsigned", "loadstore_immediate", "loadstore_pair") and not i.writeback and
            not i.post_index and (i.rn == 31 or i.rn == 29 and fp_ready), "unsupported frame base/addressing")
    regs = [i.rd, i.rt2] if i.form == "loadstore_pair" else [i.rd]
    return i.immediate + (record if i.rn == 29 else 0), i.access_size * len(regs), regs


def verify_layout_stack_functions(frames, leaves, root):
    require(0 < len(frames) <= MAX_FUNCTIONS and len(leaves) <= 256 and root in frames, "invalid layout registry/root")
    ranges = sorted((entry, entry + len(code)) for entry, code in [*frames.items(), *leaves.items()])
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "layout registry code overlaps")
    leaf_proofs = {entry: verify_leaf(code, entry) for entry, code in leaves.items()}
    proofs = {}
    for entry, data in frames.items():
        require(16 <= len(data) <= MAX_WORDS * 4, "layout function size exceeds policy")
        ins = decode_block(data, entry)
        split = sp_change(ins[0], True)
        size = ins[0].immediate if split else -ins[0].immediate
        require(16 <= size <= MAX_FRAME and size % 16 == 0 and ins[-1].word == 0xD65F03C0, "invalid fixed frame/return")
        if split:
            require(len(ins) >= 6 and record_access(ins[1], False) and not ins[1].writeback and not ins[1].post_index,
                    "split allocation requires offset FP/LR save")
            record = ins[1].immediate
            require(record >= 0 and record % 8 == 0 and record + 16 <= size, "invalid frame-record offset")
            require(record_access(ins[-3], True) and not ins[-3].writeback and ins[-3].immediate == record and
                    sp_change(ins[-2], False) and ins[-2].immediate == size, "mismatched split frame restore/deallocation")
            start, tail = 2, 3
        else:
            require(record_access(ins[0], False) and ins[0].writeback and not ins[0].post_index and
                    record_access(ins[-2], True) and ins[-2].post_index and ins[-2].immediate == size,
                    "unsupported combined frame layout")
            record, start, tail = 0, 1, 2
        reserved, saves, roles, fp_ready, mask = [(record, record + 16)], [], {}, False, 0
        index = start
        while index < len(ins) - tail:
            i = ins[index]
            if fp_set(i, record):
                require(not fp_ready, "duplicate FP setup")
                fp_ready = True; roles[index] = (FP, 0, 0, [])
            elif i.form in ("loadstore_unsigned", "loadstore_immediate", "loadstore_pair") and not i.load and i.access_size == 8 and (
                    19 <= i.rd <= 28 and (i.form != "loadstore_pair" or 19 <= i.rt2 <= 28)):
                offset, width, regs = access(i, record, fp_ready)
                require(offset >= 0 and offset % 8 == 0 and offset + width <= size and
                        all(offset + width <= lo or offset >= hi for lo, hi in reserved), "overlapping/out-of-frame saved slots")
                require(len(regs) == len(set(regs)) and not any(mask & (1 << r) for r in regs), "duplicate saved register")
                mask |= sum(1 << r for r in regs)
                reserved.append((offset, offset + width)); saves.append((offset, width, regs))
                roles[index] = (SAVE, offset, width, regs)
            else:
                break
            index += 1
        require(fp_ready, "missing FP setup")
        body, epilogue = index, len(ins) - tail - len(saves)
        require(body <= epilogue, "missing saved-register restores")
        for k, (offset, width, regs) in enumerate(reversed(saves)):
            i = ins[epilogue + k]
            actual = access(i, record, True)
            require(i.load and i.access_size == 8 and actual == (offset, width, regs), "mismatched saved-register restore")

        steps, flows, states, calls, fp_ready, restored = [], [], [], [], False, 0
        for index, i in enumerate(ins):
            s = {"kind": NORMAL, "offset": 0, "size": 0, "callee": 0}
            f = {"next": [index + 1], "saved_a": NONE, "saved_b": NONE, "writable_mask": 0}
            state = {"sp": 0, "fp": int(fp_ready), "lr": 0, "owner": 0}
            if index == 0:
                s.update(kind=ALLOC if split else OPEN, offset=0, size=0 if split else 16); state["owner"] = 1
            elif split and index == 1:
                s.update(kind=RECORD_SAVE, offset=record, size=16)
            elif index < body:
                kind, offset, width, regs = roles[index]
                s.update(kind=kind, offset=offset, size=width)
                if kind == FP: fp_ready = True; state["fp"] = 1
                else: f.update(saved_a=regs[0], saved_b=regs[1] if len(regs) == 2 else NONE)
            elif index < epilogue:
                f["writable_mask"] = mask
                if i.form == "branch_immediate" and i.operation == 1:
                    require(i.target in frames or i.target in leaves, "unregistered layout call target")
                    s.update(kind=CALL, callee=i.target); state["lr"] = 2; calls.append(i.target)
                elif i.form in ("branch_condition", "compare_branch", "test_branch") or i.form == "branch_immediate":
                    targets = [i.target] if i.form == "branch_immediate" else list(dict.fromkeys((i.target, i.pc + 4)))
                    successors = [(pc - entry) // 4 for pc in targets]
                    require(all(entry + n * 4 == pc and body <= n <= epilogue for n, pc in zip(successors, targets)), "layout branch escapes body/epilogue entry")
                    s["kind"] = BRANCH; f["next"] = successors
                elif i.form in ("loadstore_unsigned", "loadstore_immediate", "loadstore_pair"):
                    offset, width, regs = access(i, record, True)
                    require(0 <= offset and offset + width <= size and all(offset + width <= lo or offset >= hi for lo, hi in reserved),
                            "local access overlaps reserved slots or frame bounds")
                    require(not i.load or all(r == 31 or r < 18 or mask & (1 << r) for r in regs), "load writes unsaved protected register")
                    s.update(kind=LOAD if i.load else STORE, offset=offset, size=width)
                else:
                    require(i.form in VALUE_FORMS or i.form == "nop", "unsupported layout body effect")
                    leaf_edges(replace(i, rd=0) if mask & (1 << i.rd) else i, entry, entry + len(data))
            elif index < len(ins) - tail:
                offset, width, regs = saves[len(ins) - tail - 1 - index]
                s.update(kind=RESTORE, offset=offset, size=width)
                restored |= sum(1 << r for r in regs)
                f.update(saved_a=regs[0], saved_b=regs[1] if len(regs) == 2 else NONE, writable_mask=mask & ~restored)
            elif split and index == len(ins) - 3:
                s.update(kind=RECORD_RESTORE, offset=record, size=16); state.update(fp=0, lr=1)
            elif index == len(ins) - 2:
                s["kind"] = DEALLOC if split else CLOSE; state.update(sp=1, fp=0, lr=1, owner=2)
            else:
                s["kind"] = RETURN; f["next"] = []; state.update(sp=1, fp=0, lr=1)
            steps.append(s); flows.append(f); states.append(state)
        proofs[entry] = {"schema_version": 1, "policy": "fixed-layout-stack-dag-v3", "base": entry,
            "instruction_count": len(ins), "byte_count": len(data), "frame_size": size, "record_offset": record,
            "layout": "split" if split else "combined", "saved_mask": mask, "locals_begin": 0,
            "reserved_ranges": sorted(reserved), "saved_registers": [r for r in range(19, 29) if mask & (1 << r)],
            "steps": steps, "control_flow": flows, "states": states, "calls": calls,
            "source_sha256": hashlib.sha256(data).hexdigest(), "guest_code_executed": False,
            "proof_scope": "structural layout/CFG policy, not original identity or universal semantics"}
    return verify_cfg_graphs(proofs, leaf_proofs, root)


def emit_layout_stack_descriptor(p, name):
    require(re.fullmatch(r"oot_lift_[A-Za-z0-9_]+", name) is not None, "invalid layout identifier")
    suffix = name[len("oot_lift_"):]
    lines = ['#include "stack_dispatch.h"', '#if OOT_STACK_LAYOUT_POLICY_VERSION != 3 || OOT_LIFT_ABI_VERSION != 2',
             '#error Regenerate layout descriptor', '#endif', f'static const OotStackStep oot_layout_steps_{suffix}[] = {{']
    lines += [f"    {{{s['kind']}, {s['offset']}, {s['size']}, 0, UINT64_C(0x{s['callee']:x})}}," for s in p['steps']]
    lines += ['};', f'static const OotStackCfgStep oot_layout_flow_{suffix}[] = {{']
    for f in p['control_flow']:
        a, b = (f['next'][0], f['next'][-1]) if f['next'] else (NONE, NONE)
        lines += [f"    {{{a}, {b}, {f['saved_a']}, {f['saved_b']}, {f['max_steps']}, UINT32_C(0x{f['writable_mask']:x})}},"]
    lines += ['};', f'static const OotStackLayoutStep oot_layout_states_{suffix}[] = {{']
    lines += [f"    {{{s['sp']}, {s['fp']}, {s['lr']}, {s['owner']}}}," for s in p['states']]
    lines += ['};', f'static const OotStackLayoutFunction oot_layout_info_{suffix} = {{', '    {', '        {',
        f"            UINT64_C(0x{p['base']:x}), {p['instruction_count']}, {p['max_retired_instructions']}, 2, 3,",
        f"            {p['frame_size']}, {p['max_depth']}, {name}, oot_layout_steps_{suffix}, {{{{",
        '                ' + ', '.join(f'0x{b:02x}' for b in bytes.fromhex(p['source_sha256'])), '            }}', '        },',
        f"        oot_layout_flow_{suffix}, UINT32_C(0x{p['saved_mask']:x}), 0", '    },',
        f"    oot_layout_states_{suffix}, {p['record_offset']}, 0", '};',
        f'OOT_LIFT_EXPORT const OotStackLayoutFunction *oot_stack_layout_descriptor_{suffix}(void)',
        '{', f'    return &oot_layout_info_{suffix};', '}', '']
    return '\n'.join(lines)
