"""Survey existing native function profiles against fresh verified linked inputs."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

from input_formats import require
from link_exefs import build_destination, load_prepared
from module_linker import Linker
from profile_survey import survey_modules


def write_report(report, path):
    path = build_destination(path)
    require(not path.exists(), "choose a fresh survey report path")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".profiles-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write((json.dumps(report, indent=2) + "\n").encode("utf-8"))
        require(not path.exists(), "survey output appeared during analysis")
        temporary.rename(path)
    finally:
        if temporary is not None and temporary.exists(): temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exefs", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=16)
    parser.add_argument("--max-words", type=int, default=256)
    parser.add_argument("--pauth", action="store_true", help="separate PAC policy/discovery survey; preserve default profiles")
    args = parser.parse_args()
    try:
        path = build_destination(args.report)
        require(not path.exists(), "choose a fresh survey report path")
        require(not path.is_relative_to(args.exefs.resolve()), "survey output must be separate from prepared inputs")
        require(0 <= args.samples <= 4096 and 1 <= args.max_words <= 256, "invalid survey limits")
        linker = Linker(load_prepared(args.exefs)); linked = linker.apply()
        require(linked["link_complete"], "profile survey requires complete verified offline linking")
        print("Verified prepared inputs and complete link; surveying metadata candidates.", file=sys.stderr, flush=True)
        def progress(module, stage, done, total):
            print(f"{module}: {stage} {done}/{total}", file=sys.stderr, flush=True)
        report = survey_modules(linker.modules, args.samples, args.max_words, progress, pauth=args.pauth)
        report["offline_link"] = linked
        write_report(report, path)
        print(json.dumps({"report": str(path), "metadata_entry_candidates": report["totals"]["metadata_entry_candidates"],
            "complete_regions": report["totals"]["complete_regions"],
            "profile_accepted_regions": {name: row["accepted_regions"] for name, row in report["totals"]["profiles"].items()},
            "guest_code_executed": False}))
        return 0
    except (OSError, ValueError, EOFError) as error:
        print(f"Function profile survey failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__": raise SystemExit(main())
