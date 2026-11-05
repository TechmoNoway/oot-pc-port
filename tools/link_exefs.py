"""Relocate prepared ExeFS images offline; no guest instructions are executed."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from input_formats import EXEFS_NAMES, InputError, require
from module_linker import Linker, Module

BUILD_ROOT = Path(__file__).resolve().parent.parent / "build"


def build_destination(path):
    resolved = path.resolve()
    require(resolved.is_relative_to(BUILD_ROOT) and resolved != BUILD_ROOT,
            "Output must be a subdirectory or file under the project build directory")
    return resolved


def load_prepared(directory):
    manifest_path = directory / "manifest.json"
    require(manifest_path.stat().st_size <= 1024 * 1024, "Prepared manifest exceeds size limit")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(isinstance(manifest, dict) and manifest.get("schema_version") == 1 and
            manifest.get("format") == "prepared-exefs", "Unsupported prepared ExeFS manifest")
    records = manifest.get("files")
    require(isinstance(records, list) and 0 < len(records) <= len(EXEFS_NAMES), "Invalid prepared module list")
    entries = {}
    for entry in records:
        require(isinstance(entry, dict) and isinstance(entry.get("name"), str), "Invalid prepared file record")
        name = entry["name"]
        require(name in EXEFS_NAMES and name not in entries, "Unexpected or duplicate prepared file name")
        require(isinstance(entry.get("sha256"), str) and isinstance(entry.get("bytes"), int), "Missing prepared file integrity fields")
        entries[name] = entry
    require("main" in entries, "Prepared ExeFS has no main module")
    modules, allocated = [], 0
    for name in EXEFS_NAMES:
        if name not in entries:
            continue
        record = entries[name]
        path = directory / name
        require(path.resolve().is_relative_to(directory.resolve()), "Prepared file resolves outside the input directory")
        require(path.stat().st_size == record["bytes"] and 0 <= record["bytes"] <= 256 * 1024 * 1024,
                f"Prepared file size mismatch: {name}")
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == record["sha256"], f"Prepared file SHA-256 mismatch: {name}")
        if name == "main.npdm":
            require(raw[:4] == b"META", "Invalid prepared NPDM")
        else:
            module = Module(name, raw, 512 * 1024 * 1024 - allocated)
            allocated += len(module.image)
            modules.append(module)
    return modules


def export_images(linker, report, destination):
    destination = build_destination(destination)
    require(report["link_complete"], "Incomplete link: refusing to export images")
    require(not destination.exists(), "Image destination already exists; choose a fresh build subdirectory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".link-", dir=destination.parent))
    try:
        for module in linker.modules:
            target = (staging / f"{module.name}.image.bin").resolve()
            require(target.is_relative_to(staging), "Unsafe module image output path")
            target.write_bytes(module.image)
        (staging / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        require(not destination.exists(), "Image destination appeared during export")
        staging.rename(destination)
    finally:
        if staging.exists() and staging.resolve().is_relative_to(BUILD_ROOT):
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exefs", type=Path, help="directory produced by tools/prepare_exefs.py")
    parser.add_argument("--base", type=lambda value: int(value, 0), default=0x100000000)
    parser.add_argument("--alignment", type=lambda value: int(value, 0), default=0x200000)
    parser.add_argument("--report", type=Path, help="save JSON diagnostics under build/")
    parser.add_argument("--out", type=Path, help="export completely linked images to a fresh build subdirectory")
    args = parser.parse_args()
    try:
        report_path = build_destination(args.report) if args.report else None
        output_path = build_destination(args.out) if args.out else None
        if report_path:
            require(not report_path.is_relative_to(args.exefs.resolve()), "Report must not overwrite prepared input")
        if output_path:
            require(not args.exefs.resolve().is_relative_to(output_path) and not output_path.is_relative_to(args.exefs.resolve()),
                    "Image destination must be separate from the input directory")
            require(not output_path.exists(), "Image destination already exists; choose a fresh build subdirectory")
            require(report_path is None or not report_path.is_relative_to(output_path), "Report must be outside the image destination")
        linker = Linker(load_prepared(args.exefs), args.base, args.alignment)
        report = linker.apply()
        encoded = json.dumps(report, indent=2) + "\n"
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
        if output_path:
            export_images(linker, report, output_path)
        return 0 if report["link_complete"] else 1
    except (OSError, ValueError, EOFError) as error:
        print(f"Offline linking failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
