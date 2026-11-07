"""Inspect private startup evidence under build without executing guest code."""

import argparse
import json
from pathlib import Path
import sys

from input_formats import InputError
from link_exefs import build_destination, load_prepared
from module_linker import Linker
from startup_audit import audit_entry, audit_startup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prepared", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-instructions", type=int, default=8192)
    parser.add_argument("--samples", type=int, default=32)
    parser.add_argument("--raw-entry-only", action="store_true",
                        help="inspect raw entry CFG without resolving initializer tables")
    parser.add_argument("--extra-entry", type=lambda value: int(value, 0), action="append", default=[],
                        help="explicit additional diagnostic code address (raw entry audit only)")
    args = parser.parse_args()
    try:
        report_path = build_destination(args.report)
        if report_path.exists():
            raise InputError("choose a fresh startup report path")
        linker = Linker(load_prepared(args.prepared))
        if args.raw_entry_only:
            report = audit_entry(linker, args.max_instructions, args.extra_entry)
        else:
            if args.extra_entry:
                raise InputError("additional diagnostic entries require --raw-entry-only")
            linker.apply()
            report = audit_startup(linker, args.max_instructions, args.samples)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x", encoding="utf-8") as output:
            output.write(json.dumps(report, indent=2) + "\n")
        print(json.dumps(dict(report=str(report_path), **report.get("initializer_summary", {}),
                              entry_instructions=report["entry_graph"]["instruction_count"],
                              frontier=report["entry_graph"]["frontier_counts"],
                              guest_code_executed=False)))
        return 0
    except (InputError, OSError, ValueError) as error:
        print(f"Startup audit failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
