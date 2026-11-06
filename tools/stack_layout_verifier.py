"""Explicit fixed-allocation/offset-frame layouts, separate stack policy v3."""

from dataclasses import replace
import hashlib
import re

from arm64_lifter import decode_block
from input_formats import require
from leaf_verifier import VALUE_FORMS, leaf_edges, verify_leaf
from stack_cfg_verifier import BRANCH, SAVE, RESTORE, NONE, verify_cfg_graphs
from stack_verifier import MAX_FUNCTIONS, MAX_WORDS, MAX_FRAME, OPEN, FP, NORMAL, CALL, CLOSE, RETURN, LOAD, STORE
from pauth_lifter import decode_pauth_block, MODEL

ALLOC, RECORD_SAVE, RECORD_RESTORE, DEALLOC = 11, 12, 13, 14
SIGN, AUTH, READ = 15, 16, 17
OPEN_LR, CLOSE_LR = 18, 19
READ_FORMS = frozenset(("loadstore_unsigned", "loadstore_immediate", "loadstore_register", "load_literal", "loadstore_pair", "load_acquire_rcpc"))


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
    return _verify_layout(frames, leaves, root, False)


def verify_pauth_stack_functions(frames, leaves, root):
    return _verify_layout(frames, leaves, root, True)


def verify_read_stack_functions(frames, leaves, root):
    return _verify_layout(frames, leaves, root, True, True)


def verify_call_stack_functions(frames, leaves, root):
    return _verify_layout(frames, leaves, root, True, True, True)


def lr_pair(i, load):
    return (i.form == "loadstore_pair" and i.access_size == 8 and i.rn == 31 and i.load == load and
            i.writeback and i.post_index == load and
            ((i.rd == 30 and 19 <= i.rt2 <= 28) or (i.rt2 == 30 and 19 <= i.rd <= 28)))


def _verify_layout(frames, leaves, root, pauth, reads=False, lr_calls=False):
    require(0 < len(frames) <= MAX_FUNCTIONS and len(leaves) <= 256 and root in frames, "invalid layout registry/root")
    ranges = sorted((entry, entry + len(code)) for entry, code in [*frames.items(), *leaves.items()])
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "layout registry code overlaps")
    leaf_proofs = {entry: verify_leaf(code, entry) for entry, code in leaves.items()}
    proofs = {}
    for entry, data in frames.items():
        require(16 <= len(data) <= MAX_WORDS * 4, "layout function size exceeds policy")
        ins = (decode_pauth_block if pauth else decode_block)(data, entry)
        head, auth_tail, signed = int(pauth), 0, 3 if pauth else 1
        if pauth:
            require(ins[0].form in ("paciasp", "pacibsp"), "PAC frame requires entry signing")
            key_b = ins[0].form == "pacibsp"
            if ins[-1].form in ("retaa", "retab"):
                require(ins[-1].form == ("retab" if key_b else "retaa"), "PAC return key mismatch")
                auth_word = ins[-1].word
            else:
                require(ins[-1].word == 0xD65F03C0 and ins[-2].form == ("autibsp" if key_b else "autiasp"),
                        "PAC frame requires matching authentication/return")
                auth_tail, auth_word = 1, ins[-2].word
        else:
            require(ins[-1].word == 0xD65F03C0, "invalid fixed frame/return")
        lr_frame = lr_calls and lr_pair(ins[head], False)
        partner = (ins[head].rt2 if ins[head].rd == 30 else ins[head].rd) if lr_frame else None
        split = sp_change(ins[head], True)
        size = ins[head].immediate if split else -ins[head].immediate
        require(16 <= size <= MAX_FRAME and size % 16 == 0, "invalid fixed frame/return")
        close_index = len(ins) - 2 - auth_tail
        if split:
            require(len(ins) >= 6 + head + auth_tail and record_access(ins[head + 1], False) and not ins[head + 1].writeback and not ins[head + 1].post_index,
                    "split allocation requires offset FP/LR save")
            record = ins[head + 1].immediate
            require(record >= 0 and record % 8 == 0 and record + 16 <= size, "invalid frame-record offset")
            require(record_access(ins[close_index - 1], True) and not ins[close_index - 1].writeback and ins[close_index - 1].immediate == record and
                    sp_change(ins[close_index], False) and ins[close_index].immediate == size, "mismatched split frame restore/deallocation")
            start, tail = head + 2, 3 + auth_tail
        elif lr_frame:
            require(lr_pair(ins[close_index], True) and ins[close_index].immediate == size and
                    (ins[close_index].rd, ins[close_index].rt2) == (ins[head].rd, ins[head].rt2),
                    "mismatched LR pair restore/deallocation")
            record, start, tail = 0, head + 1, 2 + auth_tail
        else:
            require(record_access(ins[head], False) and ins[head].writeback and not ins[head].post_index and
                    record_access(ins[close_index], True) and ins[close_index].post_index and ins[close_index].immediate == size,
                    "unsupported combined frame layout")
            record, start, tail = 0, head + 1, 2 + auth_tail
        reserved, saves, roles, fp_ready, mask = [(record, record + 16)], [], {}, False, (1 << partner if lr_frame else 0)
        index = start
        while index < len(ins) - tail:
            i = ins[index]
            if fp_set(i, record):
                require(not lr_frame, "LR pair frame must preserve FP")
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
        require(fp_ready or lr_frame, "missing FP setup")
        body, epilogue = index, len(ins) - tail - len(saves)
        require(body <= epilogue, "missing saved-register restores")
        for k, (offset, width, regs) in enumerate(reversed(saves)):
            i = ins[epilogue + k]
            actual = access(i, record, not lr_frame)
            require(i.load and i.access_size == 8 and actual == (offset, width, regs), "mismatched saved-register restore")

        steps, flows, states, calls, read_words, fp_ready, restored = [], [], [], [], [], False, 0
        for index, i in enumerate(ins):
            s = {"kind": NORMAL, "offset": 0, "size": 0, "callee": 0}
            f = {"next": [index + 1], "saved_a": NONE, "saved_b": NONE, "writable_mask": 0}
            state = {"sp": 0, "fp": int(fp_ready), "lr": 0, "owner": 0}
            if pauth and index == 0:
                s["kind"] = SIGN; state.update(sp=1, fp=0, lr=3)
            elif index == head:
                s.update(kind=ALLOC if split else OPEN_LR if lr_frame else OPEN, offset=0, size=0 if split else 16); state["owner"] = 1
            elif split and index == head + 1:
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
                elif reads and i.form in READ_FORMS and i.load and not i.writeback and not i.post_index:
                    require(not lr_frame or i.form == "load_literal" or i.rn != 29, "LR pair frame excludes FP-based memory")
                    regs = [i.rd, i.rt2] if i.form == "loadstore_pair" else [i.rd]
                    require(all(r == 31 or r < 18 or mask & (1 << r) for r in regs), "checked read writes unsaved protected register")
                    if i.rn in (29, 31) and i.form in ("loadstore_unsigned", "loadstore_immediate", "loadstore_pair", "load_acquire_rcpc"):
                        offset = i.immediate + (record if i.rn == 29 else 0)
                        width = i.access_size * len(regs)
                        require(0 <= offset and offset + width <= size and all(offset + width <= lo or offset >= hi for lo,hi in reserved),
                                "checked frame read overlaps reserved slots or frame bounds")
                    s["kind"] = READ
                elif i.form in ("loadstore_unsigned", "loadstore_immediate", "loadstore_pair"):
                    offset, width, regs = access(i, record, not lr_frame)
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
            elif split and index == close_index - 1:
                s.update(kind=RECORD_RESTORE, offset=record, size=16); state.update(fp=0, lr=signed)
            elif index == close_index:
                s["kind"] = DEALLOC if split else CLOSE_LR if lr_frame else CLOSE; state.update(sp=1, fp=0, lr=signed, owner=2)
            elif pauth and auth_tail and index == len(ins) - 2:
                s["kind"] = AUTH; state.update(sp=1, fp=0, lr=1)
            else:
                s["kind"] = RETURN; f["next"] = []; state.update(sp=1, fp=0, lr=signed if pauth and not auth_tail else 1)
            steps.append(s); flows.append(f); states.append(state)
            read_words.append(i.word if s["kind"] == READ else 0)
        proofs[entry] = {"schema_version": 1, "policy": "fixed-layout-stack-dag-v3", "base": entry,
            "instruction_count": len(ins), "byte_count": len(data), "frame_size": size, "record_offset": record,
            "layout": "split" if split else "combined", "saved_mask": mask, "locals_begin": 0,
            "reserved_ranges": sorted(reserved), "saved_registers": [r for r in range(19, 29) if mask & (1 << r)],
            "steps": steps, "control_flow": flows, "states": states, "calls": calls,
            "source_sha256": hashlib.sha256(data).hexdigest(), "guest_code_executed": False,
            "proof_scope": "structural layout/CFG policy, not original identity or universal semantics"}
        if pauth:
            proofs[entry].update(policy="pauth-layout-stack-dag-v4", pauth_model=MODEL,
                                 sign_word=ins[0].word, auth_word=auth_word)
        if reads:
            proofs[entry].update(policy="checked-read-pauth-stack-dag-v5", read_words=read_words,
                checked_read_count=sum(s["kind"] == READ for s in steps),
                runtime_read_preconditions="unreserved owned locals or explicit retained-image read ranges; alignment/permissions checked at runtime")
        if lr_calls:
            proofs[entry].update(policy="lr-pair-read-stack-dag-v6", layout="lr-pair" if lr_frame else proofs[entry]["layout"],
                open_word=ins[head].word if lr_frame else 0, close_word=ins[close_index].word if lr_frame else 0)
    return verify_cfg_graphs(proofs, leaf_proofs, root)


def emit_layout_stack_descriptor(p, name):
    return _emit_descriptor(p, name, False)


def emit_pauth_stack_descriptor(p, name):
    return _emit_descriptor(p, name, True)


def emit_read_stack_descriptor(p, name):
    return _emit_descriptor(p, name, True, True)


def emit_call_stack_descriptor(p, name):
    return _emit_descriptor(p, name, True, True, True)


def _emit_descriptor(p, name, pauth, reads=False, lr_calls=False):
    prefix = "oot_pauth_lift_" if pauth else "oot_lift_"
    require(re.fullmatch(prefix + r"[A-Za-z0-9_]+", name) is not None, "invalid layout identifier")
    suffix = name[len(prefix):]
    lines = ['#include "stack_dispatch.h"', '#if OOT_STACK_LAYOUT_POLICY_VERSION != 3 || OOT_LIFT_ABI_VERSION != 2',
             '#error Regenerate layout descriptor', '#endif', f'static const OotStackStep oot_layout_steps_{suffix}[] = {{']
    lines += [f"    {{{s['kind']}, {s['offset']}, {s['size']}, 0, UINT64_C(0x{s['callee']:x})}}," for s in p['steps']]
    lines += ['};', f'static const OotStackCfgStep oot_layout_flow_{suffix}[] = {{']
    for f in p['control_flow']:
        a, b = (f['next'][0], f['next'][-1]) if f['next'] else (NONE, NONE)
        lines += [f"    {{{a}, {b}, {f['saved_a']}, {f['saved_b']}, {f['max_steps']}, UINT32_C(0x{f['writable_mask']:x})}},"]
    lines += ['};', f'static const OotStackLayoutStep oot_layout_states_{suffix}[] = {{']
    lines += [f"    {{{s['sp']}, {s['fp']}, {s['lr']}, {s['owner']}}}," for s in p['states']]
    descriptor = "OotStackCallFunction" if lr_calls else "OotStackReadFunction" if reads else "OotStackPauthFunction" if pauth else "OotStackLayoutFunction"
    lines += ['};']
    if pauth: lines += ['#if OOT_STACK_PAUTH_POLICY_VERSION != 4 || OOT_PAUTH_ABI_VERSION != 1', '#error Regenerate PAC descriptor', '#endif']
    if reads:
        lines += ['#if OOT_STACK_READ_POLICY_VERSION != 5', '#error Regenerate read descriptor', '#endif',
                  f'static const uint32_t oot_read_words_{suffix}[] = {{' + ', '.join(f'UINT32_C(0x{w:08x})' for w in p['read_words']) + '};']
    if lr_calls: lines += ['#if OOT_STACK_CALL_POLICY_VERSION != 6', '#error Regenerate call descriptor', '#endif']
    lines += [f'static const {descriptor} oot_layout_info_{suffix} = {{']
    if lr_calls: lines += ['    {']
    if reads: lines += ['    {']
    if pauth: lines += ['    {']
    lines += ['    {', '        {',
        f"            UINT64_C(0x{p['base']:x}), {p['instruction_count']}, {p['max_retired_instructions']}, 2, {6 if lr_calls else 5 if reads else 4 if pauth else 3},",
        f"            {p['frame_size']}, {p['max_depth']}, {'NULL' if pauth else name}, oot_layout_steps_{suffix}, {{{{",
        '                ' + ', '.join(f'0x{b:02x}' for b in bytes.fromhex(p['source_sha256'])), '            }}', '        },',
        f"        oot_layout_flow_{suffix}, UINT32_C(0x{p['saved_mask']:x}), 0", '    },',
        f"    oot_layout_states_{suffix}, {p['record_offset']}, 0"]
    if pauth: lines += ['    },', f"    {name}, UINT32_C(0x{p['sign_word']:08x}), UINT32_C(0x{p['auth_word']:08x})"]
    if reads: lines += ['    },', f'    oot_read_words_{suffix}']
    if lr_calls: lines += ['    },', f"    UINT32_C(0x{p['open_word']:08x}), UINT32_C(0x{p['close_word']:08x})"]
    lines += ['};',
        f'OOT_LIFT_EXPORT const {descriptor} *oot_stack_{"call" if lr_calls else "read" if reads else "pauth" if pauth else "layout"}_descriptor_{suffix}(void)',
        '{', f'    return &oot_layout_info_{suffix};', '}', '']
    return '\n'.join(lines)
