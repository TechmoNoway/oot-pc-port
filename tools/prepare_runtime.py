"""Package verified offline linked regions for native mapping; never execute guest code."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

from input_formats import require
from link_exefs import build_destination, load_prepared
from module_linker import Linker, PAGE

MAGIC = b"OOTMEM1\0"
HEADER = struct.Struct("<8sII6Q32s")
REGION = struct.Struct("<4QII16sQ")
LIMIT = 512 * 1024 * 1024
ADDRESS_LIMIT = 1 << 39
STACK_BASE = 0x7000000000
STACK_SIZE = 2 * 1024 * 1024


def make_package(linker, stack_base=STACK_BASE, stack_size=STACK_SIZE):
    report = linker.report()
    require(report["link_complete"], "runtime packaging requires a complete offline link")
    return pack_regions(linker.modules, report, stack_base, stack_size)


def pack_regions(modules, provenance, stack_base=STACK_BASE, stack_size=STACK_SIZE):
    """Encode exact data regions; callers establish and label image provenance."""
    require(stack_base % PAGE == 0 and PAGE <= stack_size <= 64 * 1024 * 1024 and stack_size % PAGE == 0 and
            PAGE <= stack_base and stack_base + stack_size + PAGE <= ADDRESS_LIMIT,
            "invalid synthetic stack range or guard pages")
    regions = []
    for module in modules:
        for kind, (begin, end) in enumerate((*module.ranges, (module.bss_start, module.bss_end)), 1):
            if end > begin:
                data = bytes(module.image[begin:end])
                # Preserve relocations into BSS; only an entirely zero BSS can omit payload.
                payload = b"" if kind == 4 and not any(data) else data
                regions.append((module.base + begin, len(data), payload, 1 if kind < 3 else 3, kind, module.name))
    regions.sort()
    require(regions and regions[-1][0] + regions[-1][1] <= stack_base - PAGE,
            "synthetic stack/guard overlaps linked images")
    regions.append((stack_base, stack_size, b"", 3, 5, "stack"))
    require(len(regions) <= 64, "too many runtime regions")
    backing = sum(row[1] for row in regions)
    require(backing <= LIMIT, "runtime backing budget exceeded")
    cursor, previous_end = HEADER.size + REGION.size * len(regions), 0
    descriptors, payloads, records = [], [], []
    for base, size, payload, permissions, kind, name in regions:
        require(previous_end <= base and 0 < size <= ADDRESS_LIMIT - base, "invalid or overlapping runtime region")
        require(name.isascii() and 0 < len(name) < 16 and all(c.islower() or c.isdigit() or c == "_" for c in name),
                "invalid runtime owner name")
        descriptors.append(REGION.pack(base, size, cursor, len(payload), permissions, kind, name.encode(), 0))
        payloads.append(payload)
        records.append({"owner": name, "kind": ("text", "rodata", "data", "bss", "stack")[kind - 1],
                        "base": base, "size": size, "permissions": "r" if permissions == 1 else "rw",
                        "payload_bytes": len(payload), "payload_sha256": hashlib.sha256(payload).hexdigest()})
        cursor += len(payload)
        previous_end = base + size
    require(cursor <= LIMIT, "runtime package exceeds file size budget")
    body = b"".join(descriptors + payloads)
    stack_top = stack_base + stack_size
    package = HEADER.pack(MAGIC, 1, len(regions), stack_top, backing, HEADER.size,
                          HEADER.size + REGION.size * len(regions), cursor, 0, hashlib.sha256(body).digest()) + body
    manifest = {"schema_version": 1, "format": "oot-runtime-memory", "guest_code_executed": False,
                "package_sha256": hashlib.sha256(package).hexdigest(), "package_bytes": len(package),
                "body_sha256": hashlib.sha256(body).hexdigest(), "backing_bytes": backing,
                "initial_sp": stack_top, "stack_guards": [stack_base - PAGE, stack_top],
                "regions": records, "offline_link": provenance}
    return package, manifest


def write_package(linker, output, report_path=None, **options):
    output = build_destination(output)
    report_path = build_destination(report_path) if report_path else None
    require(not output.exists() and (not report_path or not report_path.exists()), "choose fresh runtime output paths")
    require(report_path != output, "package and report must differ")
    package, report = make_package(linker, **options)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".runtime-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(package)
        require(not output.exists(), "runtime output appeared during preparation")
        temporary.rename(output)
        if report_path:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with report_path.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps(report, indent=2) + "\n")
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exefs", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--stack-base", type=lambda s: int(s, 0), default=STACK_BASE)
    parser.add_argument("--stack-size", type=lambda s: int(s, 0), default=STACK_SIZE)
    args = parser.parse_args()
    try:
        for path in (args.output, args.report):
            if path:
                require(not path.resolve().is_relative_to(args.exefs.resolve()), "runtime output must be separate from inputs")
        linker = Linker(load_prepared(args.exefs))
        linker.apply()
        report = write_package(linker, args.output, args.report, stack_base=args.stack_base, stack_size=args.stack_size)
        print(json.dumps({"regions": len(report["regions"]), "backing_bytes": report["backing_bytes"],
                          "initial_sp": report["initial_sp"], "guest_code_executed": False}))
        return 0
    except (OSError, ValueError, EOFError) as error:
        print(f"Runtime preparation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
