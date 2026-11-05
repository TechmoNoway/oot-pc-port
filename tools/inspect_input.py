"""Inspect local game metadata and verify NUP ExeFS payloads without extracting them."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

# Embedded Python distributions can omit the script directory from sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from input_formats import InputError, inspect_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="NUP, NSO, NPDM, or extracted ExeFS directory")
    parser.add_argument("--package", type=int, help="NUP package index (required when more than one is present)")
    parser.add_argument("--report", type=Path, help="also save JSON to a file under this project's build directory")
    parser.add_argument("--verify-segments", action="store_true", help="decode NSO segments and check required SHA-256 hashes")
    parser.add_argument("--zbic-decoder", type=Path, help="path to the local ZBIC helper")
    args = parser.parse_args()
    try:
        if args.report:
            report_path = args.report.resolve()
            build = Path(__file__).resolve().parent.parent / "build"
            if not report_path.is_relative_to(build) or report_path == args.input.resolve():
                raise InputError("Report destination must be under the project build directory and differ from the input")
        report = {"schema_version": 1, "inspection": inspect_path(args.input, args.package, args.verify_segments, args.zbic_decoder)}
        encoded = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
        if args.report:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
        return 0
    except (InputError, OSError, UnicodeError, ValueError, EOFError, subprocess.SubprocessError) as error:
        print(f"Input inspection failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
