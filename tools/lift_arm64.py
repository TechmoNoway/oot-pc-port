"""Translate a bounded raw ARM64 code range to C17; no guest code is executed."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

from arm64_lifter import MAX_WORDS, emit_c
from input_formats import require
from link_exefs import build_destination


def integer(text):
    return int(text, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="raw code bytes, not an NSO container")
    parser.add_argument("--base", type=integer, required=True, help="guest address of the selected range")
    parser.add_argument("--offset", type=integer, default=0, help="input file offset")
    parser.add_argument("--size", type=integer, help="range size in bytes (default: remainder of file)")
    parser.add_argument("--output", type=Path, required=True, help="fresh C file under build/")
    parser.add_argument("--report", type=Path, help="fresh JSON file under build/")
    parser.add_argument("--name", default="oot_lift_run")
    args = parser.parse_args()
    try:
        output = build_destination(args.output)
        report_path = build_destination(args.report) if args.report else None
        for path in (output, report_path):
            if path:
                require(not path.exists() and path != args.input.resolve(), "choose a fresh output path")
        require(report_path != output, "C source and report paths must differ")
        total = args.input.stat().st_size
        size = total - args.offset if args.size is None else args.size
        require(0 <= args.offset <= total and 0 < size <= min(MAX_WORDS * 4, total - args.offset),
                "selected input range is empty, out of bounds, or exceeds 64 KiB")
        with args.input.open("rb") as source:
            source.seek(args.offset)
            data = source.read(size)
        require(len(data) == size, "input changed while reading the selected range")
        code, report = emit_c(data, args.base, args.name)
        report.update({"source_sha256": hashlib.sha256(data).hexdigest(), "file_offset": args.offset,
                       "guest_code_executed": False, "translation_does_not_prove_function_completeness": True})
        # Unsupported or malformed instructions cannot leave partially translated source.
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as destination:
            destination.write(code)
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with report_path.open("x", encoding="utf-8") as destination:
                destination.write(json.dumps(report, indent=2) + "\n")
        print(f"Translated {report['instruction_count']} instructions to {output}")
        return 0
    except (OSError, ValueError) as error:
        print(f"ARM64 translation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
