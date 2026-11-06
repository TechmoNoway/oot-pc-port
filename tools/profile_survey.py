"""Bounded metadata-region discovery and actual profile proofs; never emit/run C."""

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import struct

from arm64_analysis import unwind_entries
from arm64_decode import Decoder, family, flow_kind
from arm64_lifter import UnsupportedInstruction, decode_instruction
from frame_verifier import verify_frame
from input_formats import require
from leaf_verifier import verify_leaf
from stack_cfg_verifier import verify_cfg_stack_functions
from stack_layout_verifier import verify_layout_stack_functions
from stack_layout_verifier import verify_pauth_stack_functions, verify_read_stack_functions, verify_call_stack_functions
from pauth_lifter import decode_pauth_instruction, MODEL
from stack_verifier import verify_stack_functions

PROFILES = ("register_leaf", "leaf_caller", "linear_stack", "cfg_stack", "fixed_layout")
POLICIES = ("acyclic-register-leaf-v1", "linear-fp-lr-caller-v1", "linear-local-stack-dag-v1",
            "acyclic-saved-stack-dag-v2", "fixed-layout-stack-dag-v3")


class Syntax:
    def __init__(self):
        self.decoder, self.cache = Decoder(), {}
        self.metadata = self.decoder.metadata

    def describe(self, word):
        if word not in self.cache:
            result = list(self.decoder.engine.disasm_lite(struct.pack("<I", word), 0))
            mnemonic = result[0][2] if result else ".word"
            if mnemonic == ".word": category = "undecoded"
            else:
                index = family(word, mnemonic, flow_kind(word, mnemonic))
                category = {1: "integer", 2: "integer", 3: "load_store", 4: "simd_fp", 5: "system",
                    6: "supervisor_call", 7: "pointer_authentication", 8: "atomic_ordered", 9: "control_flow"}.get(index, "other")
            self.cache[word] = (mnemonic, category)
        return self.cache[word]


@dataclass
class Region:
    module: object
    offset: int
    sources: list
    data: bytes
    calls: tuple
    returns: int

    @property
    def entry(self): return self.module.base + self.offset


def metadata_windows(module, max_words):
    require(type(max_words) is int and 1 <= max_words <= 256, "survey word limit must be 1-256")
    entries, ends = defaultdict(set), {}
    entries[0].add("module_entry")
    for offset in unwind_entries(module): entries[offset].add("unwind_table")
    for symbol in module.symbols:
        if 0 < symbol.section < 0xFF00 and symbol.kind == 2 and module.is_code(symbol.value):
            entries[symbol.value].add("function_symbol")
            if symbol.size: ends[symbol.value] = min(ends.get(symbol.value, len(module.image)), symbol.value + symbol.size)
    offsets, text_end = sorted(entries), module.ranges[0][1]
    for index, offset in enumerate(offsets):
        limits = {"text_end": text_end, "word_limit": offset + max_words * 4}
        if index + 1 < len(offsets): limits["next_metadata_entry"] = offsets[index + 1]
        if offset in ends: limits["symbol_size"] = ends[offset]
        end = min(limits.values())
        yield offset, end, sorted(entries[offset]), sorted(k for k, v in limits.items() if v == end)


def discover(module, offset, end, sources, syntax, pauth=False):
    base, stop = module.base + offset, module.base + end
    pending, seen, calls, returns = [base], set(), [], 0
    while pending:
        pc = pending.pop()
        if pc in seen: continue
        if not base <= pc or pc + 4 > stop:
            return None, {"reason": "window_boundary", "offset": pc - module.base}
        seen.add(pc)
        word = struct.unpack_from("<I", module.image, pc - module.base)[0]
        try: i = (decode_pauth_instruction if pauth else decode_instruction)(word, pc)
        except UnsupportedInstruction:
            mnemonic, category = syntax.describe(word)
            return None, {"reason": "unsupported_encoding", "offset": pc - module.base, "mnemonic": mnemonic, "category": category}
        if pauth and i.form in ("retaa", "retab"):
            returns += 1
        elif i.form == "branch_register":
            if word != 0xD65F03C0:
                reason = "nonstandard_return" if word & 0xFFFFFC1F == 0xD65F0000 else "indirect_call" if i.operation else "indirect_jump"
                return None, {"reason": reason, "offset": pc - module.base}
            returns += 1
        elif i.form == "branch_immediate":
            if i.operation: calls.append(i.target); pending.append(pc + 4)
            else: pending.append(i.target)
        elif i.form in ("branch_condition", "compare_branch", "test_branch"):
            pending.extend((i.target, pc + 4))  # Deterministic fallthrough-first traversal.
        else: pending.append(pc + 4)
    if not returns: return None, {"reason": "no_standard_return", "offset": offset}
    end = max(seen) - module.base + 4
    return Region(module, offset, sources, bytes(module.image[offset:end]), tuple(sorted(set(calls))), returns), None


def observe_prefix(module, offset, end, syntax):
    """Diagnostic only: never feed a skipped/modified prefix to a verifier."""
    cursor, leading = offset, []
    for _ in range(4):
        if cursor + 4 > end: break
        word = struct.unpack_from("<I", module.image, cursor)[0]
        mnemonic, _ = syntax.describe(word)
        if mnemonic not in ("paciasp", "pacibsp", "bti"): break
        leading.append(mnemonic); cursor += 4
    shape, size = "other", None
    if cursor + 4 <= end:
        word = struct.unpack_from("<I", module.image, cursor)[0]
        try: i = decode_instruction(word, module.base + cursor)
        except UnsupportedInstruction: pass
        else:
            if i.form == "addsub_immediate" and i.width == 64 and i.rd == i.rn == 31 and i.operation == 1 and not i.flags:
                shape, size = "sub_sp", i.immediate
            elif i.form == "loadstore_pair" and not i.load and i.rn == 31 and i.writeback and not i.post_index:
                shape, size = ("stp_fp_lr_preindex" if (i.rd, i.rt2) == (29, 30) else "stp_other_preindex"), -i.immediate
    return {"shape": shape, "allocation_bytes": size, "leading_hints": leading}


def rejection(error):
    if isinstance(error, UnsupportedInstruction): return "unsupported_in_declared_span", "unsupported encoding in selected span"
    message = str(error)
    lower = message.lower()
    for needles, category in (
        (("unregistered", "not a verified leaf"), "call_dependency"),
        (("recursion", "cycle"), "call_cycle" if "call graph" in lower else "control_cycle"),
        (("unreachable",), "unreachable_words"),
        (("size", "range exceeds", "translation limit"), "size_limit"),
        (("depth", "bound", "registry"), "bounds_or_registry_limit"),
        (("protected",), "register_policy"),
        (("memory", "locals", "addressing", "frame base", "local access"), "memory_policy"),
        (("canonical", "fixed frame", "frame layout", "fp/lr frame"), "frame_shape"),
        (("saved", "restore", "slots", "fp setup"), "save_layout"),
        (("external edge", "escapes", "branch"), "control_flow"),
        (("linear", "effect", "excludes", "contains a call"), "instruction_policy")):
        if any(needle in lower for needle in needles): return category, message
    return "policy_rejection", message


def proof_summary(proof):
    keys = ("policy", "instruction_count", "max_retired_instructions", "max_depth", "max_stack_bytes",
            "frame_size", "stack_bytes", "layout", "record_offset", "saved_registers", "source_sha256",
            "checked_read_count", "runtime_read_preconditions")
    return {k: proof[k] for k in keys if k in proof}


def check_profile(profile, region, regions, leaf_codes):
    if profile == "register_leaf": return verify_leaf(region.data, region.entry), 1, 0
    leaves = {pc: leaf_codes[pc] for pc in region.calls if pc in leaf_codes}
    if profile == "leaf_caller": return verify_frame(region.data, region.entry, leaves), 1, len(leaves)
    verifier = {"linear_stack": verify_stack_functions, "cfg_stack": verify_cfg_stack_functions,
                "fixed_layout": verify_layout_stack_functions, "pauth_stack": verify_pauth_stack_functions,
                "checked_reads": verify_read_stack_functions, "lr_calls": verify_call_stack_functions}[profile]
    # Most roots fail their own policy. Run the real root-only verifier first,
    # with actual verified leaf bytes; no fabricated callee bodies are supplied.
    try: return verifier({region.entry: region.data}, leaves, region.entry)[region.entry], 1, len(leaves)
    except ValueError as error:
        if rejection(error)[0] != "call_dependency": raise
    frames, leaves, pending = {}, {}, [region.entry]
    while pending:
        pc = pending.pop()
        if pc in frames: continue
        current = regions[pc]
        frames[pc] = current.data
        require(len(frames) <= 32, "survey closure exceeds the 32-function registry limit")
        for target in current.calls:
            if target in leaf_codes: leaves[target] = leaf_codes[target]
            elif target in regions:
                if target not in frames: pending.append(target)
            # Unknown targets stay unregistered and the real verifier rejects them.
    proof = verifier(frames, leaves, region.entry)[region.entry]
    return proof, len(frames), len(leaves)


def survey_modules(modules, sample_limit=16, max_words=256, progress=None, pauth=False, reads=False, lr_calls=False):
    require(type(sample_limit) is int and 0 <= sample_limit <= 4096, "survey sample limit must be 0-4096")
    require(type(max_words) is int and 1 <= max_words <= 256, "survey word limit must be 1-256")
    require(type(pauth) is bool, "PAC survey opt-in must be boolean")
    require(type(reads) is bool,"read survey opt-in must be boolean")
    require(type(lr_calls) is bool,"LR call survey opt-in must be boolean")
    reads = reads or lr_calls
    pauth = pauth or reads
    profiles = ("checked_reads","lr_calls") if lr_calls else ("pauth_stack","checked_reads") if reads else ("pauth_stack",) if pauth else PROFILES
    syntax, regions, reports, module_reports = Syntax(), {}, [], {}
    for module in modules:
        windows = list(metadata_windows(module, max_words))
        require(len(windows) <= 2000000, "excessive survey metadata entries")
        counts, mnemonics, categories, shapes, hints, frame_sizes = (Counter() for _ in range(6))
        samples, sources_count, limit_counts, complete = [], Counter(), Counter(), 0
        for index, (offset, end, sources, limits) in enumerate(windows):
            sources_count.update(sources); limit_counts.update(limits)
            prefix = observe_prefix(module, offset, end, syntax)
            shapes[prefix["shape"]] += 1; hints.update(prefix["leading_hints"])
            if prefix["allocation_bytes"] is not None: frame_sizes[str(prefix["allocation_bytes"])] += 1
            region, failure = discover(module, offset, end, sources, syntax, pauth)
            if failure:
                counts[failure["reason"]] += 1
                if "mnemonic" in failure: mnemonics[failure["mnemonic"]] += 1; categories[failure["category"]] += 1
                if len(samples) < sample_limit: samples.append({"entry_offset": offset, "metadata_sources": sources, "window_bytes": end - offset,
                    "limiting_evidence": limits, "prefix_observation": prefix, **failure})
            else: regions[region.entry] = region; complete += 1
            if progress and (index % 10000 == 0 or index + 1 == len(windows)): progress(module.name, "discovery", index + 1, len(windows))
        result = {"name": module.name, "base": module.base, "build_id": module.header["build_id"], "source_sha256": module.source_sha256,
            "linked_text_sha256": hashlib.sha256(module.image[module.ranges[0][0]:module.ranges[0][1]]).hexdigest(),
            "metadata_entry_candidates": len(windows), "metadata_sources": dict(sources_count), "window_limits": dict(limit_counts),
            "discovery": {"complete_regions": complete, "blocked": dict(counts), "first_unsupported_mnemonics": dict(mnemonics.most_common()),
                "first_unsupported_categories": dict(categories.most_common()), "samples": samples, "samples_truncated": sum(counts.values()) > len(samples)},
            "prefix_observations": {"shapes": dict(shapes), "leading_hints": dict(hints), "allocation_bytes": dict(frame_sizes),
                "diagnostic_only": True, "hints_removed_for_verification": False}, "profiles": {}}
        reports.append(result); module_reports[module.name] = result
    leaf_codes = {}
    outcomes = {"register_leaf": {}}
    for entry, region in regions.items():
        try: proof = verify_leaf(region.data, entry)
        except ValueError as error: outcomes["register_leaf"][entry] = (None, *rejection(error))
        else:
            leaf_codes[entry] = region.data
            outcomes["register_leaf"][entry] = (proof_summary(proof), None, None)
    for name in profiles:
        by_module = {m.name: {"accepted_regions": 0, "accepted_instruction_words": 0, "rejected": Counter(), "details": Counter(),
            "accepted_samples": [], "rejected_samples": []} for m in modules}
        for index, (entry, region) in enumerate(regions.items()):
            proof, category, detail, closure_frames, closure_leaves = None, None, None, 1, 0
            if name == "register_leaf": proof, category, detail = outcomes[name][entry]
            else:
                try:
                    verified, closure_frames, closure_leaves = check_profile(name, region, regions, leaf_codes)
                    proof = proof_summary(verified)
                except ValueError as error: category, detail = rejection(error)
            row = by_module[region.module.name]
            if proof:
                row["accepted_regions"] += 1; row["accepted_instruction_words"] += proof["instruction_count"]
                if len(row["accepted_samples"]) < sample_limit:
                    row["accepted_samples"].append({"offset": region.offset, "metadata_sources": region.sources,
                        "byte_count": len(region.data), "source_sha256": hashlib.sha256(region.data).hexdigest(),
                        "closure_frames": closure_frames, "closure_leaves": closure_leaves, "verification": proof})
            else:
                row["rejected"][category] += 1; row["details"][detail] += 1
                if len(row["rejected_samples"]) < sample_limit:
                    row["rejected_samples"].append({"offset": region.offset, "reason": category, "detail": detail})
            if progress and (index % 10000 == 0 or index + 1 == len(regions)): progress("all", name, index + 1, len(regions))
        for module in modules:
            row, result = by_module[module.name], module_reports[module.name]
            row["rejected"], row["details"] = dict(sorted(row["rejected"].items())), dict(row["details"].most_common())
            row.update(considered_candidates=result["metadata_entry_candidates"], discovery_blocked=sum(result["discovery"]["blocked"].values()),
                evaluated_regions=result["discovery"]["complete_regions"], samples_truncated=row["accepted_regions"] > len(row["accepted_samples"]),
                rejected_samples_truncated=sum(row["rejected"].values()) > len(row["rejected_samples"]))
            result["profiles"][name] = row
    totals = {"metadata_entry_candidates": sum(m["metadata_entry_candidates"] for m in reports),
        "complete_regions": len(regions), "discovery_blocked": sum(sum(m["discovery"]["blocked"].values()) for m in reports), "profiles": {}}
    for name in profiles:
        rows = [m["profiles"][name] for m in reports]
        rejected = Counter()
        for row in rows: rejected.update(row["rejected"])
        totals["profiles"][name] = {"accepted_regions": sum(r["accepted_regions"] for r in rows),
            "accepted_instruction_words": sum(r["accepted_instruction_words"] for r in rows), "rejected": dict(rejected),
            "considered_candidates": totals["metadata_entry_candidates"], "evaluated_regions": len(regions),
            "discovery_blocked": totals["discovery_blocked"]}
    for key in ("blocked", "first_unsupported_mnemonics", "first_unsupported_categories"):
        counter = Counter()
        for m in reports: counter.update(m["discovery"][key])
        totals[key] = dict(counter.most_common())
    totals["prefix_observations"] = {}
    for key in ("shapes", "leading_hints", "allocation_bytes"):
        counter = Counter()
        for m in reports: counter.update(m["prefix_observations"][key])
        totals["prefix_observations"][key] = dict(counter.most_common())
    sizes = totals["prefix_observations"]["allocation_bytes"]
    totals["prefix_observations"]["allocations_in_16_256_aligned_range"] = sum(n for size, n in sizes.items() if 16 <= int(size) <= 256 and int(size) % 16 == 0)
    totals["prefix_observations"]["allocations_outside_16_256_aligned_range"] = sum(sizes.values()) - totals["prefix_observations"]["allocations_in_16_256_aligned_range"]
    return {"schema_version": 1, "format": "arm64-function-profile-survey", "guest_code_executed": False,
        "translation_performed": False, "native_callbacks_registered": False, "function_identity_proven": False,
        "coverage_is_complete": False, "decoder": syntax.metadata,
        "policies": {"checked_reads":"checked-read-pauth-stack-dag-v5","lr_calls":"lr-pair-read-stack-dag-v6"} if lr_calls else {"pauth_stack":"pauth-layout-stack-dag-v4","checked_reads":"checked-read-pauth-stack-dag-v5"} if reads else {"pauth_stack": "pauth-layout-stack-dag-v4"} if pauth else dict(zip(PROFILES, POLICIES)),
        "pauth_model": MODEL if pauth else None,
        "runtime_read_ranges_supplied": False,
        "read_survey_scope": "structural proof only; dynamic addresses/ranges/ownership/alignment checked by runtime; no read capabilities granted" if reads else None,
        "method": {"seeds": ["module_entry", "unwind_table", "defined_function_symbol"], "max_words": max_words,
            "region_boundary": "minimum of next metadata entry, symbol size, exact text end, word limit",
            "traversal": "supported-encoding CFG, fallthrough-first; calls use continuation only; standard RET X30 exits" + ("; RETAA/RETAB exits enabled" if pauth else ""),
            "profile_checks": "unaltered source bytes and actual production verifiers; actual verified callee closures only",
            "prefix_observations": "diagnostic only; never strip hints/PAC, relax policy, emit C, or execute candidates",
            "denominator": "metadata entry candidates, not all original game functions or gameplay coverage"},
        "modules": reports, "totals": totals}
