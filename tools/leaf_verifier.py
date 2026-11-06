"""Conservative structural verification of bounded, acyclic register-only leaves."""

from collections import Counter
import hashlib
import re

from arm64_lifter import decode_block
from input_formats import InputError, require

MAX_LEAF_WORDS = 256
POLICY = "acyclic-register-leaf-v1"
VALUE_FORMS = frozenset(("move_wide", "addsub_immediate", "addsub_shifted", "addsub_extended",
    "addsub_carry", "logical_shifted", "logical_immediate", "bitfield", "conditional_select",
    "conditional_compare_register", "conditional_compare_immediate",
    "pc_relative", "variable_shift", "multiply_add", "multiply_long", "divide",
    "bit_reverse", "byte_reverse", "count_leading", "multiply_high", "extract_register", "crc32"))


def leaf_edges(ins, base, end):
    """Validate instruction effects and return conservative direct successor PCs."""
    if ins.form in VALUE_FORMS:
        writes_sp = ins.rd == 31 and (
            (ins.form in ("addsub_immediate", "addsub_extended") and not ins.flags) or
            (ins.form == "logical_immediate" and ins.operation != 3))
        require(not writes_sp and not 18 <= ins.rd <= 30, "leaf writes protected X18-X30 or SP")
        successors = [ins.pc + 4]
    elif ins.form == "nop":
        successors = [ins.pc + 4]
    elif ins.form == "branch_immediate":
        require(ins.operation == 0, "leaf contains a call")
        successors = [ins.target]
    elif ins.form in ("branch_condition", "compare_branch", "test_branch"):
        successors = list(dict.fromkeys((ins.target, ins.pc + 4)))
    elif ins.form == "branch_register" and ins.word == 0xD65F03C0:
        return []
    else:
        raise InputError(f"leaf policy excludes {ins.form}")
    require(all(base <= pc < end and (pc - base) % 4 == 0 for pc in successors),
            "leaf has an external edge or falls off its declared range")
    return successors


def verify_leaf(data, base):
    require(0 < len(data) <= MAX_LEAF_WORDS * 4, "leaf range exceeds policy limit")
    instructions = decode_block(data, base)
    end = base + len(data)
    edges = {ins.pc: leaf_edges(ins, base, end) for ins in instructions}
    colors, lengths = {}, {}

    def visit(pc):
        require(colors.get(pc) != 1, "leaf control flow contains a cycle")
        if colors.get(pc) == 2:
            return lengths[pc]
        colors[pc] = 1
        longest = 1 + max((visit(target) for target in edges[pc]), default=0)
        colors[pc], lengths[pc] = 2, longest
        return longest

    bound = visit(base)
    require(len(colors) == len(instructions), "declared leaf range includes unreachable words")
    returns = sum(not targets for targets in edges.values())
    require(returns > 0, "leaf has no standard return")
    return {"schema_version": 1, "policy": POLICY, "base": base, "byte_count": len(data),
            "source_sha256": hashlib.sha256(data).hexdigest(), "instruction_count": len(instructions),
            "forms": dict(sorted(Counter(i.form for i in instructions).items())),
            "control_flow": [{"next": [(pc - base) // 4 for pc in edges[ins.pc]],
                              "max_steps": lengths[ins.pc]} for ins in instructions],
            "return_count": returns, "max_retired_instructions": bound,
            "acyclic": True, "all_declared_words_reachable": True,
            "protected_registers": "x18-x30,sp", "memory_access": False, "external_calls": False,
            "preconditions": ["entry PC equals base", "X30 is outside the declared range", "canonical NZCV"],
            "guest_code_executed": False, "proof_scope": "structural policy, not function identity or universal semantic equivalence"}


def emit_leaf_descriptor(data, base, function_name):
    """Bind verified CFG metadata to a compiled symbol, never a guest pointer."""
    require(re.fullmatch(r"oot_lift_[A-Za-z0-9_]+", function_name) is not None, "invalid leaf function identifier")
    proof = verify_leaf(data, base)
    return emit_verified_leaf_descriptor(proof,function_name)


def emit_verified_leaf_descriptor(proof, function_name, memory=False):
    require(re.fullmatch(r"oot_lift_[A-Za-z0-9_]+", function_name) is not None, "invalid leaf function identifier")
    base=proof["base"]
    suffix = function_name[len("oot_lift_"):]
    steps, descriptor = f"oot_leaf_steps_{suffix}", f"oot_leaf_info_{suffix}"
    lines = ['#include "leaf_dispatch.h"',
             '#if OOT_LIFT_ABI_VERSION != 2 || OOT_LEAF_POLICY_VERSION != 1' + (' || OOT_LEAF_MEMORY_POLICY_VERSION != 2' if memory else ''),
             '#error Regenerate this leaf descriptor for the current ABI and policy', '#endif',
             f"static const OotLeafStep {steps}[] = {{"]
    for row in proof["control_flow"]:
        successors = row["next"]
        a = successors[0] if successors else "OOT_LEAF_RETURN"
        b = successors[-1] if successors else "OOT_LEAF_RETURN"
        lines.append(f"    {{{a}, {b}, {row['max_steps']}, 0}},")
    lines.extend(["};", f"static const OotLeafFunction {descriptor} = {{",
                  f"    UINT64_C(0x{base:x}), {proof['instruction_count']}, {proof['max_retired_instructions']},",
                  f"    OOT_LIFT_ABI_VERSION, {'OOT_LEAF_MEMORY_POLICY_VERSION' if memory else 'OOT_LEAF_POLICY_VERSION'}, {function_name}, {steps}", "};",
                  f"OOT_LIFT_EXPORT const OotLeafFunction *oot_leaf_descriptor_{suffix}(void)",
                  "{", f"    return &{descriptor};", "}",
                  f"static const OotCodeHash oot_leaf_hash_{suffix} = {{{{",
                  "    " + ", ".join(f"0x{byte:02x}" for byte in bytes.fromhex(proof["source_sha256"])), "}};",
                  f"OOT_LIFT_EXPORT const OotCodeHash *oot_leaf_code_hash_{suffix}(void)",
                  "{", f"    return &oot_leaf_hash_{suffix};", "}", ""])
    return "\n".join(lines)
