"""Freeze verified images, code ranges, and a compiled bound-dispatch factory."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import sys

from arm64_lifter import emit_c
from frame_verifier import emit_frame_descriptor, verify_frame
from input_formats import require
from leaf_verifier import emit_leaf_descriptor, verify_leaf
from link_exefs import BUILD_ROOT, build_destination, load_prepared
from module_linker import Linker
from prepare_runtime import STACK_BASE, STACK_SIZE, make_package


def emit_factory(names, body_hash, returns, root_name=None):
    require(names and len(names) <= 256 and len(set(names)) == len(names) and
            all(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", n) for n in names), "invalid registry names")
    require(root_name is None or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", root_name), "invalid root name")
    require(0 < len(returns) <= 256 and returns == sorted(set(returns)) and
            all(type(pc) is int and 0 <= pc < 1 << 64 and pc % 4 == 0 for pc in returns), "invalid return sites")
    digest = bytes.fromhex(body_hash)
    require(len(digest) == 32, "invalid image SHA-256")
    kind = "OotFrameDispatcher" if root_name else "OotLeafDispatcher"
    lines = ['#include "frame_dispatch.h"', f"OOT_LIFT_EXPORT {kind} *oot_create_bound_registry(OotRuntimeImage *image, uint32_t *error)",
             "{", "    static const uint8_t body_hash[32] = {" + ", ".join(f"0x{b:02x}" for b in digest) + "};",
             "    static const uint64_t returns[] = {" + ", ".join(f"UINT64_C(0x{pc:x})" for pc in returns) + "};",
             f"    OotLeafFunction functions[{len(names)}];", f"    OotCodeHash hashes[{len(names)}];"]
    for index, name in enumerate(names):
        lines += [f"    functions[{index}] = *oot_leaf_descriptor_{name}();",
                  f"    hashes[{index}] = *oot_leaf_code_hash_{name}();"]
    if root_name:
        lines += [f"    return oot_frame_create(image, oot_frame_descriptor_{root_name}(), functions, {len(names)},",
                  f"        hashes, body_hash, returns, {len(returns)}, error);"]
    else:
        lines += [f"    return oot_leaf_dispatcher_create_bound(image, functions, {len(names)}, hashes, body_hash,",
                  f"        returns, {len(returns)}, error);"]
    return "\n".join(lines + ["}", ""])


def build_bundle(linker, config):
    require(isinstance(config, dict) and type(config.get("schema_version")) is int and
            config["schema_version"] == 1, "unsupported registry config")
    records = config.get("leaves")
    require(isinstance(records, list) and 0 < len(records) <= 256, "registry requires 1-256 explicit leaves")
    modules, names = {m.name: m for m in linker.modules}, set()

    def selected(record):
        require(isinstance(record, dict), "invalid function selection")
        name, module_name, offset, size = (record.get(k) for k in ("name", "module", "offset", "size"))
        require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) and name not in names,
                "function names must be safe and unique")
        names.add(name)
        require(isinstance(module_name, str) and module_name in modules and type(offset) is int and type(size) is int and offset % 4 == 0 and
                0 < size <= 1024 and size % 4 == 0, "invalid function range")
        module = modules[module_name]
        require(module.ranges[0][0] <= offset and offset + size <= module.ranges[0][1], "function range must stay in text")
        return {"name": name, "module": module_name, "offset": offset, "size": size,
                "entry": module.base + offset, "data": bytes(module.image[offset:offset + size])}

    leaves = sorted([selected(record) for record in records], key=lambda x: x["entry"])
    root = selected(config["root"]) if config.get("root") is not None else None
    ranges = sorted((r["entry"], r["entry"] + r["size"]) for r in leaves + ([root] if root else []))
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "registered code ranges overlap")
    returns = config.get("return_sites")
    require(isinstance(returns, list) and returns and len(returns) <= 256 and all(type(x) is int for x in returns), "invalid return sites")
    require(returns == sorted(set(returns)) and all(0 <= x < 1 << 64 and x % 4 == 0 and
            all(not begin <= x < end for begin, end in ranges) for x in returns), "return sites overlap code or are invalid")
    stack_base, stack_size = config.get("stack_base", STACK_BASE), config.get("stack_size", STACK_SIZE)
    require(type(stack_base) is int and type(stack_size) is int, "stack bounds must be integers")
    package, image_report = make_package(linker, stack_base, stack_size)
    chunks = []
    for leaf in leaves:
        leaf["verification"] = verify_leaf(leaf["data"], leaf["entry"])
        function = "oot_lift_" + leaf["name"]
        chunks += [emit_c(leaf["data"], leaf["entry"], function)[0], emit_leaf_descriptor(leaf["data"], leaf["entry"], function)]
    if root:
        callees = {leaf["entry"]: leaf["data"] for leaf in leaves}
        root["verification"] = verify_frame(root["data"], root["entry"], callees)
        function = "oot_lift_" + root["name"]
        chunks += [emit_c(root["data"], root["entry"], function)[0], emit_frame_descriptor(root["data"], root["entry"], callees, function)]
    chunks += [emit_factory([r["name"] for r in leaves], image_report["body_sha256"], returns, root["name"] if root else None)]
    source = "\n".join(chunks)
    manifest = {"schema_version": 1, "format": "bound-native-registry", "guest_code_executed": False,
                "factory": "oot_create_bound_registry", "profile": "frame" if root else "leaf",
                "registry_source_sha256": hashlib.sha256(source.encode()).hexdigest(), "return_sites": returns,
                "image": image_report,
                "leaves": [{k: v for k, v in r.items() if k != "data"} for r in leaves],
                "root": {k: v for k, v in root.items() if k != "data"} if root else None}
    return package, source, manifest


def write_bundle(linker, config, destination):
    destination = build_destination(destination)
    require(not destination.exists(), "choose a fresh registry directory")
    package, source, manifest = build_bundle(linker, config)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".registry-", dir=destination.parent))
    try:
        (staging / "image.ootmem").write_bytes(package)
        (staging / "registry.c").write_bytes(source.encode("utf-8"))
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        require(not destination.exists(), "registry output appeared during generation")
        staging.rename(destination)
    finally:
        if staging.exists() and staging.resolve().is_relative_to(BUILD_ROOT) and staging.resolve() != BUILD_ROOT:
            shutil.rmtree(staging)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exefs", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(args.config.stat().st_size <= 1024 * 1024, "registry config exceeds size limit")
        require(not args.output.resolve().is_relative_to(args.exefs.resolve()) and
                not args.exefs.resolve().is_relative_to(args.output.resolve()), "registry output must be separate from prepared inputs")
        config = json.loads(args.config.read_text(encoding="utf-8"))
        linker = Linker(load_prepared(args.exefs))
        require(linker.apply()["link_complete"], "registry requires complete offline linking")
        report = write_bundle(linker, config, args.output)
        print(json.dumps({"profile": report["profile"], "leaves": len(report["leaves"]), "guest_code_executed": False}))
        return 0
    except (OSError, ValueError, EOFError) as error:
        print(f"Registry preparation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
