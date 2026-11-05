"""Decode and verify ExeFS modules into a fresh local build directory."""

import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from input_formats import EXEFS_NAMES, InputError, NupCatalog, describe_file, require
from nso_segments import decode_nso, normalize_nso

BUILD_ROOT = Path(__file__).resolve().parent.parent / "build"


def prepare(source: Path, destination: Path, package_index=None, decoder=None) -> dict:
    destination = destination.resolve()
    require(destination.is_relative_to(BUILD_ROOT) and destination != BUILD_ROOT,
            "Prepared ExeFS destination must be a subdirectory of the project build directory")
    require(not destination.exists(), "Destination already exists; choose a fresh build subdirectory")
    require(not source.resolve().is_relative_to(destination), "Destination cannot contain the input")
    source_metadata = {"path": str(source.resolve())}
    if source.is_dir():
        require(package_index is None, "--package applies only to NUP input")
        require((source / "main").is_file(), "ExeFS directory has no main module")
        def entries():
            for name in EXEFS_NAMES:
                path = source / name
                if path.is_file():
                    require(path.stat().st_size <= NupCatalog.MAX_MODULE_BYTES, "ExeFS module exceeds size limit")
                    yield name, path.read_bytes(), {}
    else:
        with source.open("rb") as stream:
            magic = stream.read(4)
        if magic == b"NUP\x01":
            catalog = NupCatalog(source)
            require(package_index is not None or len(catalog.packages) == 1,
                    "Multiple NUP packages found; choose one with --package INDEX")
            selected = 0 if package_index is None else package_index
            require(0 <= selected < len(catalog.packages), "NUP package index is out of bounds")
            source_metadata.update({"package": catalog.packages[selected], "catalog_sha256_verified": True})
            entries = lambda: catalog.read_exefs(selected)
        else:
            require(package_index is None, "--package applies only to NUP input")
            require(magic == b"NSO0", "Input must be a NUP, an ExeFS directory, or a standalone NSO")
            require(source.stat().st_size <= NupCatalog.MAX_MODULE_BYTES, "NSO exceeds size limit")
            entries = lambda: iter([(source.name, source.read_bytes(), {})])
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".prepare-", dir=destination.parent))
    try:
        manifest = {"schema_version": 1, "format": "prepared-exefs", "source": source_metadata,
                    "relocations_applied": False, "bss_materialized": False, "files": []}
        names = set()
        for name, data, integrity in entries():
            target = (staging / name).resolve()
            require(target.is_relative_to(staging) and target != staging, "Unsafe ExeFS output path")
            require(name.casefold() not in names and name.casefold() != "manifest.json", "Duplicate or reserved ExeFS output path")
            names.add(name.casefold())
            original = describe_file(name, data)
            if original["format"] == "nso":
                decoded, verified = decode_nso(data, decoder)
                output = normalize_nso(data, decoded)
                report = describe_file(name, output)
                for normalized, source_segment in zip(report["segments"], verified["segments"]):
                    normalized.update({"source_compression": source_segment["compression"],
                                       "source_file_offset": source_segment["file_offset"],
                                       "sha256": source_segment["sha256"],
                                       "hash_verified": source_segment["hash_verified"]})
                for key in ("segments_decoded", "segment_hashes_checked", "verified_segment_hash_count",
                            "required_segment_hashes_verified"):
                    report[key] = verified[key]
                report.update({"source_sha256": original["sha256"], "source_flags": original["flags"]})
            elif original["format"] == "npdm":
                output, report = data, original
                report["source_sha256"] = original["sha256"]
            else:
                raise InputError(f"Unsupported ExeFS payload: {name}")
            report.update(integrity)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(output)
            manifest["files"].append(report)
        require(bool(manifest["files"]), "No ExeFS files were prepared")
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        require(not destination.exists(), "Destination appeared during preparation; existing files were left untouched")
        staging.rename(destination)
        return manifest
    finally:
        # This directory was created above, inside the checked build destination.
        if staging.exists() and staging.resolve().is_relative_to(BUILD_ROOT):
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="fresh destination under build/")
    parser.add_argument("--package", type=int)
    parser.add_argument("--zbic-decoder", type=Path)
    args = parser.parse_args()
    try:
        result = prepare(args.input, args.out, args.package, args.zbic_decoder)
        modules = [item for item in result["files"] if item["format"] == "nso"]
        count = sum(item["verified_segment_hash_count"] for item in modules)
        print(f"Prepared {len(result['files'])} files ({len(modules)} NSO modules, {count} verified segment hashes) at {args.out}")
        return 0
    except (OSError, ValueError, EOFError) as error:
        print(f"ExeFS preparation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
