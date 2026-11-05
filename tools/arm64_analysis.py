"""Conservative, metadata-rooted ARM64 code discovery for future lifting."""

from bisect import bisect_right
from collections import Counter, deque
import struct

from arm64_decode import (CALL, CONDITIONAL, FAMILIES, INDIRECT_CALL, INDIRECT_JUMP, JUMP, NORMAL, RETURN,
                          TRAP, direct_target, literal_reference, signed)
from input_formats import InputError, require
from arm64_lifter import UnsupportedInstruction, decode_instruction
from module_linker import MAX_RELOCATIONS, MAX_SYMBOLS

SOURCES = {"module_entry": 1, "unwind_table": 2, "function_symbol": 4, "initializer": 8,
           "relocated_code_pointer": 16, "direct_call": 32, "plt_stub": 64}
NONLOCAL = {"setjmp", "_setjmp", "sigsetjmp", "__sigsetjmp", "longjmp", "_longjmp", "siglongjmp"}
LONGJMP = {"longjmp", "_longjmp", "siglongjmp"}


def unwind_entries(module):
    begin, end = module.mod0["exception_start"], module.mod0["exception_end"]
    if begin == end:
        return []
    require(end - begin >= 12, f"{module.name}: truncated unwind header")
    header = module.read(begin, end - begin)
    require(header[:4] == b"\x01\x1b\x03\x3b", f"{module.name}: unsupported unwind-header encoding")
    eh_frame = begin + 4 + struct.unpack_from("<i", header, 4)[0]
    module.check_range(eh_frame, 4)
    count = struct.unpack_from("<I", header, 8)[0]
    require(count <= MAX_SYMBOLS and 12 + count * 8 <= len(header), f"{module.name}: unwind table exceeds its range")
    entries, previous = [], -1
    for initial, fde in struct.iter_unpack("<ii", header[12:12 + count * 8]):
        pc = begin + initial
        require(module.is_code(pc) and pc >= previous, f"{module.name}: invalid or unsorted unwind function entry")
        module.check_range(begin + fde, 4)
        entries.append(pc)
        previous = pc
    return entries


def plt_stubs(module):
    slots = {}
    for _, table in module.rela:
        for offset, info, _ in struct.iter_unpack("<QQq", table):
            index, kind = info >> 32, info & 0xFFFFFFFF
            if index and kind in (257, 1025, 1026):
                require(index < len(module.symbols), "PLT symbol index exceeds its module")
                slots[offset] = module.symbols[index].name
    found = {}
    text_size = module.header["segments"][0]["memory_size"]
    for index, (word,) in enumerate(struct.iter_unpack("<I", memoryview(module.image)[:text_size])):
        if word != 0xD61F0220 or index < 3:
            continue
        pc = index * 4 - 12
        adrp, load, add = struct.unpack_from("<3I", module.image, pc)
        if adrp & 0x9F00001F != 0x90000010 or load & 0xFFC003FF != 0xF9400211 or add & 0xFFC003FF != 0x91000210:
            continue
        low = ((load >> 10) & 0xFFF) * 8
        if (add >> 10) & 0xFFF != low:
            continue
        page_delta = signed(((adrp >> 29) & 3) | (((adrp >> 5) & 0x7FFFF) << 2), 21) * 4096
        slot = (pc & ~4095) + page_delta + low
        if slot in slots:
            found[pc] = {"symbol": slots[slot], "got_offset": slot,
                         "resolved_address": f"0x{module.unpack('<Q', slot, memory=True)[0]:x}"}
    return found


def relocated_code_seeds(modules):
    found = {module.name: set() for module in modules}
    for owner in modules:
        def accept(offset, width):
            value = owner.unpack("<I" if width == 4 else "<Q", offset, memory=True)[0]
            for target in modules:
                relative = value - target.base
                if target.is_code(relative):
                    found[target.name].add(relative)
                    break
        cursor, expanded = None, 0
        for (word,) in struct.iter_unpack("<Q", owner.relr):
            if word & 1 == 0:
                positions = (word,)
                cursor = word + 8
            else:
                require(cursor is not None, "RELR bitmap before address during code discovery")
                positions = (cursor + bit * 8 for bit in range(63) if word & (1 << (bit + 1)))
                cursor += 63 * 8
            for offset in positions:
                expanded += 1
                require(expanded <= MAX_RELOCATIONS, "Excessive pointer-discovery relocations")
                accept(offset, 8)
        for _, table in owner.rela:
            for offset, info, _ in struct.iter_unpack("<QQq", table):
                kind = info & 0xFFFFFFFF
                if kind in (257, 258, 1025, 1026, 1027):
                    accept(offset, 4 if kind == 258 else 8)
    return found


def analyze_module(module, decoder, pointer_seeds=(), progress=None, sample_limit=32, lifter_coverage=False):
    require(0 <= sample_limit <= 4096, "Analysis sample limit must be between 0 and 4096")
    ids, flows, families, mnemonics, linear = decoder.scan(module, progress)
    words = len(ids)
    candidates, visited, literal_hints = bytearray(words), bytearray(words), bytearray(words)
    pending = deque()
    source_counts = Counter()

    def seed(pc, source):
        if not module.is_code(pc):
            return
        index, bit = pc // 4, SOURCES[source]
        if not candidates[index] & bit:
            source_counts[source] += 1
        if not candidates[index]:
            pending.append(index)
        candidates[index] |= bit

    seed(0, "module_entry")
    unwind = unwind_entries(module)
    for pc in unwind:
        seed(pc, "unwind_table")
    for symbol in module.symbols:
        if 0 < symbol.section < 0xFF00 and symbol.kind == 2:
            seed(symbol.value, "function_symbol")
    for tag in (12, 13):
        if module.dynamic.get(tag):
            seed(module.dynamic[tag], "initializer")
    for offset, count in module.initializer_tables.values():
        for index in range(count):
            seed(module.unpack("<Q", offset + index * 8)[0] - module.base, "initializer")
    for pc in pointer_seeds:
        seed(pc, "relocated_code_pointer")
    stubs = plt_stubs(module)
    for pc in stubs:
        seed(pc, "plt_stub")
    plt_returns = {pc + 12: item for pc, item in stubs.items()}
    histogram, groups, control, svc = Counter(), Counter(), Counter(), Counter()
    supported_forms = Counter()
    unsupported_mnemonics, unsupported_families = Counter(), Counter()
    unsupported_samples = []
    unknown, branch_samples, indirect_samples, nonlocal_calls = [], [], [], []
    outside, unknown_count, unresolved_jumps, unresolved_calls = 0, 0, 0, 0

    def enqueue_target(target):
        nonlocal outside
        if module.is_code(target):
            if not visited[target // 4]:
                pending.append(target // 4)
        else:
            outside += 1

    while pending:
        index = pending.pop()
        while 0 <= index < words and not visited[index]:
            identifier = ids[index]
            pc = index * 4
            visited[index] = 1 if identifier else 2
            word = struct.unpack_from("<I", module.image, pc)[0]
            if not identifier:
                unknown_count += 1
                if len(unknown) < sample_limit:
                    unknown.append({"offset": pc, "address": f"0x{module.base + pc:x}", "word": f"0x{word:08x}"})
                break
            mnemonic, flow = mnemonics[identifier], flows[index]
            histogram[mnemonic] += 1
            groups[FAMILIES[families[index]]] += 1
            if lifter_coverage:
                try:
                    implemented = decode_instruction(word, module.base + pc)
                except UnsupportedInstruction as error:
                    unsupported_mnemonics[mnemonic] += 1
                    unsupported_families[FAMILIES[families[index]]] += 1
                    if len(unsupported_samples) < sample_limit:
                        unsupported_samples.append({"offset": pc, "word": f"0x{word:08x}",
                                                    "mnemonic": mnemonic, "reason": str(error)})
                else:
                    supported_forms[implemented.form] += 1
            literal = literal_reference(word, pc)
            if literal:
                begin, width = literal
                if 0 <= begin and begin + width <= words * 4:
                    for position in range(begin // 4, (begin + width) // 4):
                        literal_hints[position] = 1
            if mnemonic == "svc":
                svc[(word >> 5) & 0xFFFF] += 1
            if flow in (CALL, JUMP, CONDITIONAL):
                target = direct_target(word, pc)
                label = "direct_call" if flow == CALL else "unconditional_branch" if flow == JUMP else "conditional_branch"
                control[label] += 1
                if len(branch_samples) < sample_limit:
                    branch_samples.append({"offset": pc, "kind": label, "target_offset": target})
                if flow == CALL:
                    seed(target, "direct_call")
                enqueue_target(target)
                stub = stubs.get(target)
                if flow in (CALL, JUMP) and stub and stub["symbol"] in NONLOCAL:
                    nonlocal_calls.append({"offset": pc, "symbol": stub["symbol"], "plt_offset": target,
                                           "continuation_offset": pc + 4 if flow == CALL and stub["symbol"] not in LONGJMP else None})
                    if stub["symbol"] in LONGJMP:
                        break
                if flow == JUMP:
                    break
            elif flow in (INDIRECT_CALL, INDIRECT_JUMP):
                if pc in plt_returns:
                    control["resolved_plt_dispatch"] += 1
                else:
                    label = "indirect_call" if flow == INDIRECT_CALL else "indirect_branch"
                    control[label] += 1
                    if flow == INDIRECT_CALL:
                        unresolved_calls += 1
                    else:
                        unresolved_jumps += 1
                    if len(indirect_samples) < sample_limit:
                        indirect_samples.append({"offset": pc, "kind": label, "mnemonic": mnemonic})
                if flow == INDIRECT_JUMP:
                    break
            elif flow in (RETURN, TRAP):
                control["return" if flow == RETURN else "trap_or_undefined"] += 1
                break
            index += 1

    entries = [index * 4 for index, flags in enumerate(candidates) if flags]
    for call in nonlocal_calls:
        owner = bisect_right(entries, call["offset"]) - 1
        call["enclosing_entry_candidate"] = entries[owner] if owner >= 0 else None
    decoded_code = sum(histogram.values())
    hint_words = sum(bool(hint) and not state for hint, state in zip(literal_hints, visited))
    conflicts = sum(bool(hint) and bool(state) for hint, state in zip(literal_hints, visited))
    return {
        "name": module.name, "base": f"0x{module.base:x}", "build_id": module.header["build_id"],
        "source_sha256": module.source_sha256, "text_bytes": words * 4, "text_words": words,
        "linear_syntax_decoded_words": sum(linear.values()),
        "linear_undecoded_words": words - sum(linear.values()),
        "discovered_code_words": decoded_code, "undecoded_code_frontiers": unknown_count,
        "literal_candidate_words": hint_words, "code_literal_conflict_words": conflicts,
        "unclassified_words": words - decoded_code - unknown_count - hint_words,
        "function_entry_candidate_count": len(entries), "candidate_source_counts": dict(source_counts),
        "function_entry_samples": entries[:sample_limit], "mnemonics": dict(sorted(histogram.items())),
        "encoding_families": dict(sorted(groups.items())), "control_flow": dict(control),
        "svc_immediates": {str(key): value for key, value in sorted(svc.items())},
        "direct_targets_outside_text": outside,
        "unresolved_indirect_branches": unresolved_jumps, "unresolved_indirect_calls": unresolved_calls,
        "unknown_samples": unknown, "unknown_samples_truncated": unknown_count > len(unknown),
        "branch_samples": branch_samples, "indirect_samples": indirect_samples,
        "plt_stub_count": len(stubs),
        "nonlocal_plt_stubs": [{"offset": pc, **item} for pc, item in stubs.items() if item["symbol"] in NONLOCAL],
        "nonlocal_direct_calls": nonlocal_calls, "nonlocal_runtime_implemented": False,
        "sample_limit": sample_limit, "all_code_discovered": False,
        "lifter_coverage_measured": lifter_coverage,
        "lifter_supported_encoding_words": sum(supported_forms.values()) if lifter_coverage else None,
        "lifter_unsupported_encoding_words": decoded_code - sum(supported_forms.values()) if lifter_coverage else None,
        "lifter_form_counts": dict(sorted(supported_forms.items())) if lifter_coverage else None,
        "lifter_unsupported_mnemonics": dict(sorted(unsupported_mnemonics.items())) if lifter_coverage else None,
        "lifter_unsupported_families": dict(sorted(unsupported_families.items())) if lifter_coverage else None,
        "lifter_unsupported_samples": unsupported_samples if lifter_coverage else None,
        "translated_code_executed": False,
    }
