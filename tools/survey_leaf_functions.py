"""Find structurally closed register-only leaf candidates; no guest execution."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import struct
import sys

from arm64_analysis import unwind_entries
from arm64_lifter import UnsupportedInstruction, decode_instruction
from input_formats import require
from leaf_verifier import MAX_LEAF_WORDS, POLICY, leaf_edges, verify_leaf
from link_exefs import build_destination, load_prepared
from module_linker import Linker


def survey_module(module, sample_limit=128, max_words=MAX_LEAF_WORDS):
    require(0 <= sample_limit <= 4096 and 1 <= max_words <= MAX_LEAF_WORDS, "invalid leaf survey limits")
    entries, symbol_ends = defaultdict(set), {}
    entries[0].add("module_entry")
    for offset in unwind_entries(module):
        entries[offset].add("unwind_table")
    for symbol in module.symbols:
        if 0 < symbol.section < 0xFF00 and symbol.kind == 2 and module.is_code(symbol.value):
            entries[symbol.value].add("function_symbol")
            if symbol.size:
                symbol_ends[symbol.value] = min(symbol_ends.get(symbol.value, len(module.image)), symbol.value + symbol.size)
    offsets = sorted(entries)
    samples, rejected, accepted, return_words = [], Counter(), 0, 0
    text_end = module.ranges[0][1]
    for index, offset in enumerate(offsets):
        end = min(text_end, offset + max_words * 4, offsets[index + 1] if index + 1 < len(offsets) else text_end,
                  symbol_ends.get(offset, text_end))
        begin_pc, end_pc = module.base + offset, module.base + end
        pending, visited = [begin_pc], set()
        try:
            while pending:
                pc = pending.pop()
                if pc in visited:
                    continue
                require(begin_pc <= pc and pc + 4 <= end_pc, "candidate exceeds its conservative metadata window")
                visited.add(pc)
                word = struct.unpack_from("<I", module.image, pc - module.base)[0]
                pending.extend(leaf_edges(decode_instruction(word, pc), begin_pc, end_pc))
            stop = max(visited) - module.base + 4
            proof = verify_leaf(bytes(module.image[offset:stop]), begin_pc)
        except UnsupportedInstruction:
            rejected["unsupported_encoding"] += 1
            continue
        except ValueError as error:
            rejected[str(error)] += 1
            continue
        accepted += 1
        return_words += proof["instruction_count"]
        if len(samples) < sample_limit:
            samples.append({"offset": offset, "metadata_sources": sorted(entries[offset]), "verification": proof})
    return {"name": module.name, "base": module.base, "build_id": module.header["build_id"],
            "source_sha256": module.source_sha256, "metadata_entry_candidates": len(offsets),
            "accepted_leaf_regions": accepted, "accepted_instruction_words": return_words,
            "rejected": dict(sorted(rejected.items())), "samples": samples,
            "samples_truncated": accepted > len(samples), "max_words": max_words,
            "function_identity_proven": False, "guest_code_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exefs", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=128)
    parser.add_argument("--max-words", type=int, default=MAX_LEAF_WORDS)
    args = parser.parse_args()
    try:
        destination = build_destination(args.report)
        require(not destination.is_relative_to(args.exefs.resolve()), "leaf report must be separate from prepared inputs")
        linker = Linker(load_prepared(args.exefs))
        require(linker.apply()["link_complete"], "leaf survey requires a complete offline link")
        report = {"schema_version": 1, "format": "arm64-leaf-survey", "policy": POLICY,
                  "guest_code_executed": False, "function_identity_proven": False, "modules": []}
        for module in linker.modules:
            result = survey_module(module, args.samples, args.max_words)
            report["modules"].append(result)
            print(f"{module.name}: {result['accepted_leaf_regions']} closed leaf candidates", file=sys.stderr, flush=True)
        report["totals"] = {key: sum(m[key] for m in report["modules"]) for key in (
            "metadata_entry_candidates", "accepted_leaf_regions", "accepted_instruction_words")}
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {destination}")
        return 0
    except (OSError, ValueError, EOFError) as error:
        print(f"Leaf survey failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
