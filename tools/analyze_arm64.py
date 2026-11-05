"""Survey ARM64 syntax, static control flow, and nonlocal calls in prepared modules."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm64_analysis import analyze_module, relocated_code_seeds
from arm64_decode import Decoder
from arm64_lifter import FORMS
from input_formats import InputError, require
from link_exefs import build_destination, load_prepared
from module_linker import Linker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exefs", type=Path, help="verified prepared ExeFS directory")
    parser.add_argument("--report", type=Path, required=True, help="JSON destination under build/")
    parser.add_argument("--samples", type=int, default=32)
    parser.add_argument("--lifter-coverage", action="store_true", help="classify discovered encodings with the semantic decoder")
    args = parser.parse_args()
    try:
        destination = build_destination(args.report)
        require(not destination.is_relative_to(args.exefs.resolve()), "Report must be separate from prepared inputs")
        require(0 <= args.samples <= 4096, "Sample count must be between 0 and 4096")
        decoder = Decoder()
        linker = Linker(load_prepared(args.exefs))
        linked = linker.apply()
        require(linked["link_complete"], "ARM64 pointer discovery requires a complete offline link")
        print("Verified input and offline link; discovering code-pointer seeds.", file=sys.stderr, flush=True)
        seeds = relocated_code_seeds(linker.modules)
        report = {"schema_version": 2, "format": "arm64-census", "decoder": decoder.metadata,
                  "guest_code_executed": False, "translation_performed": False,
                  "lifter": {"scope": "integer/scalar-memory/control-flow subset", "forms": list(FORMS),
                             "coverage_measured": args.lifter_coverage, "game_runtime_ready": False},
                  "method": "metadata-rooted static traversal with direct branches and unresolved indirect boundaries",
                  "coverage_is_complete": False, "modules": []}
        for module in linker.modules:
            previous = -1
            def progress(done, total):
                nonlocal previous
                stage = done * 10 // total if total else 10
                if stage != previous:
                    print(f"{module.name}: syntax scan {min(stage * 10, 100)}%", file=sys.stderr, flush=True)
                    previous = stage
            result = analyze_module(module, decoder, seeds[module.name], progress, args.samples, args.lifter_coverage)
            report["modules"].append(result)
            print(f"{module.name}: discovered {result['discovered_code_words']} instruction words, "
                  f"{result['undecoded_code_frontiers']} undecoded frontiers.", file=sys.stderr, flush=True)
        report["totals"] = {key: sum(module[key] for module in report["modules"]) for key in (
            "text_words", "discovered_code_words", "undecoded_code_frontiers", "literal_candidate_words", "unclassified_words",
            "function_entry_candidate_count", "unresolved_indirect_branches", "unresolved_indirect_calls")}
        if args.lifter_coverage:
            for key in ("lifter_supported_encoding_words", "lifter_unsupported_encoding_words"):
                report["totals"][key] = sum(module[key] for module in report["modules"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {destination}")
        return 0
    except (OSError, ValueError, EOFError) as error:
        print(f"ARM64 analysis failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
