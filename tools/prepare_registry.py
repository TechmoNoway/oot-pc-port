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
from stack_verifier import emit_stack_descriptor, verify_stack_functions
from stack_cfg_verifier import emit_cfg_stack_descriptor, verify_cfg_stack_functions
from stack_layout_verifier import (emit_layout_stack_descriptor, verify_layout_stack_functions,
                                   emit_pauth_stack_descriptor, verify_pauth_stack_functions,
                                   emit_read_stack_descriptor, verify_read_stack_functions)
from pauth_lifter import emit_pauth_c, MODEL


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


def emit_stack_factory(frame_names, leaf_names, root, body_hash, returns, cfg=False, layout=False, pauth=False, reads=False, read_ranges=()):
    pauth = pauth or reads
    names = frame_names + leaf_names
    require(frame_names and len(frame_names) <= 32 and len(leaf_names) <= 256 and len(names) == len(set(names)) and
            all(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", n) for n in names), "invalid stack registry names")
    require(type(root) is int and 0 <= root < 1 << 64 and root % 4 == 0, "invalid stack root")
    require(0 < len(returns) <= 256 and returns == sorted(set(returns)) and
            all(type(pc) is int and 0 <= pc < 1 << 64 and pc % 4 == 0 for pc in returns), "invalid return sites")
    digest = bytes.fromhex(body_hash)
    require(len(digest) == 32, "invalid image SHA-256")
    descriptor = "OotStackReadFunction" if reads else "OotStackPauthFunction" if pauth else "OotStackLayoutFunction" if layout else "OotStackCfgFunction" if cfg else "OotStackFunction"
    prefix = "read_" if reads else "pauth_" if pauth else "layout_" if layout else "cfg_" if cfg else ""
    constructor = "_reads" if reads else "_pauth" if pauth else "_layout" if layout else "_cfg" if cfg else ""
    lines = ['#include "stack_dispatch.h"',
        f'OOT_LIFT_EXPORT OotStackDispatcher *oot_create_bound_registry(OotRuntimeImage *image, {"OotPauth *pauth, " if pauth else ""}uint32_t *error)',
        '{', '    static const uint8_t body_hash[32] = {' + ', '.join(f'0x{b:02x}' for b in digest) + '};',
        '    static const uint64_t returns[] = {' + ', '.join(f'UINT64_C(0x{pc:x})' for pc in returns) + '};',
        f'    {descriptor} frames[{len(frame_names)}];']
    if reads:
        require(0 < len(read_ranges) <= 128 and all(type(b) is int and type(s) is int and 0 <= b < 1 << 39 and 0 < s <= (1 << 39)-b for b,s in read_ranges) and
                all(a[0]+a[1] <= b[0] for a,b in zip(read_ranges,read_ranges[1:])), "invalid compiled read ranges")
        lines += ['    static const OotReadRange ranges[] = {' + ', '.join(f'{{UINT64_C(0x{b:x}),UINT64_C(0x{s:x})}}' for b,s in read_ranges) + '};']
    if leaf_names:
        lines += [f'    OotLeafFunction leaves[{len(leaf_names)}];', f'    OotCodeHash hashes[{len(leaf_names)}];']
    for i, name in enumerate(frame_names):
        lines += [f'    frames[{i}] = *oot_stack_{prefix}descriptor_{name}();']
    for i, name in enumerate(leaf_names):
        lines += [f'    leaves[{i}] = *oot_leaf_descriptor_{name}();', f'    hashes[{i}] = *oot_leaf_code_hash_{name}();']
    lines += [f'    return oot_stack_create{constructor}(image, frames, {len(frame_names)}, UINT64_C(0x{root:x}),',
        f'        {"leaves" if leaf_names else "NULL"}, {len(leaf_names)}, {"hashes" if leaf_names else "NULL"},',
        f'        body_hash, returns, {len(returns)}, {"pauth, " if pauth else ""}{"ranges, " + str(len(read_ranges)) + ", " if reads else ""}error);', '}', '']
    return '\n'.join(lines)


def build_bundle(linker, config):
    require(isinstance(config, dict) and type(config.get("schema_version")) is int and
            config["schema_version"] in (1, 2, 3, 4, 5, 6), "unsupported registry config")
    read_profile = config["schema_version"] == 6
    pauth_profile = config["schema_version"] in (5,6)
    require(not pauth_profile or config.get("pauth_model") == MODEL, "PAC schema requires explicit PAC model")
    stack_profile = config["schema_version"] in (2, 3, 4, 5, 6)
    cfg_profile = config["schema_version"] in (3, 4, 5, 6)
    layout_profile = config["schema_version"] in (4, 5, 6)
    records = config.get("leaves")
    require(isinstance(records, list) and (0 if stack_profile else 1) <= len(records) <= 256,
            "invalid explicit leaf selection count")
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
    frames = []
    if stack_profile:
        require(isinstance(config.get("frames"), list) and 0 < len(config["frames"]) <= 32, "invalid frame selections")
        frames = sorted([selected(record) for record in config["frames"]], key=lambda x: x["entry"])
        require(isinstance(config.get("root"), str), "stack root must name a selected frame")
        root = next((f for f in frames if f["name"] == config["root"]), None)
        require(root is not None, "stack root must name a selected frame")
    else:
        root = selected(config["root"]) if config.get("root") is not None else None
    ranges = sorted((r["entry"], r["entry"] + r["size"]) for r in leaves + (frames if stack_profile else [root] if root else []))
    require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "registered code ranges overlap")
    returns = config.get("return_sites")
    require(isinstance(returns, list) and returns and len(returns) <= 256 and all(type(x) is int for x in returns), "invalid return sites")
    require(returns == sorted(set(returns)) and all(0 <= x < 1 << 64 and x % 4 == 0 and
            all(not begin <= x < end for begin, end in ranges) for x in returns), "return sites overlap code or are invalid")
    require(not pauth_profile or all(x >> 39 in (0, ((1 << 64) - 1) >> 39) for x in returns),
            "PAC return sites must be canonical VA39 pointers")
    stack_base, stack_size = config.get("stack_base", STACK_BASE), config.get("stack_size", STACK_SIZE)
    require(type(stack_base) is int and type(stack_size) is int, "stack bounds must be integers")
    package, image_report = make_package(linker, stack_base, stack_size)
    read_records = []
    if read_profile:
        requested = config.get("read_ranges")
        require(isinstance(requested,list) and 0 < len(requested) <= 128,"schema 6 requires explicit read ranges")
        for r in requested:
            require(isinstance(r,dict),"invalid read range")
            name,offset,size = r.get("module"),r.get("offset"),r.get("size")
            require(isinstance(name,str) and name in modules and type(offset) is int and offset >= 0 and type(size) is int and size > 0,"invalid read range selection")
            base = modules[name].base + offset
            require(any(row["owner"]==name and row["kind"]!="stack" and "r" in row["permissions"] and
                        base >= row["base"] and base-row["base"] < row["size"] and size <= row["size"]-(base-row["base"])
                        for row in image_report["regions"]),"read range must stay inside one retained image region")
            read_records.append({"module":name,"offset":offset,"size":size,"base":base})
        read_records.sort(key=lambda r:r["base"])
        require(all(a["base"]+a["size"] <= b["base"] for a,b in zip(read_records,read_records[1:])),"read ranges overlap")
    chunks = []
    for leaf in leaves:
        leaf["verification"] = verify_leaf(leaf["data"], leaf["entry"])
        function = "oot_lift_" + leaf["name"]
        chunks += [emit_c(leaf["data"], leaf["entry"], function)[0], emit_leaf_descriptor(leaf["data"], leaf["entry"], function)]
    if stack_profile:
        verifier = verify_read_stack_functions if read_profile else verify_pauth_stack_functions if pauth_profile else verify_layout_stack_functions if layout_profile else verify_cfg_stack_functions if cfg_profile else verify_stack_functions
        emitter = emit_read_stack_descriptor if read_profile else emit_pauth_stack_descriptor if pauth_profile else emit_layout_stack_descriptor if layout_profile else emit_cfg_stack_descriptor if cfg_profile else emit_stack_descriptor
        proofs = verifier({f["entry"]: f["data"] for f in frames},
                                       {f["entry"]: f["data"] for f in leaves}, root["entry"])
        for frame in frames:
            frame["verification"] = proofs[frame["entry"]]
            function = ("oot_pauth_lift_" if pauth_profile else "oot_lift_") + frame["name"]
            chunks += [(emit_pauth_c if pauth_profile else emit_c)(frame["data"], frame["entry"], function)[0],
                       emitter(frame["verification"], function)]
        chunks += [emit_stack_factory([f["name"] for f in frames], [f["name"] for f in leaves],
            root["entry"], image_report["body_sha256"], returns, cfg=cfg_profile, layout=layout_profile, pauth=pauth_profile,
            reads=read_profile,read_ranges=[(r["base"],r["size"]) for r in read_records])]
    elif root:
        callees = {leaf["entry"]: leaf["data"] for leaf in leaves}
        root["verification"] = verify_frame(root["data"], root["entry"], callees)
        function = "oot_lift_" + root["name"]
        chunks += [emit_c(root["data"], root["entry"], function)[0], emit_frame_descriptor(root["data"], root["entry"], callees, function)]
    if not stack_profile:
        chunks += [emit_factory([r["name"] for r in leaves], image_report["body_sha256"], returns, root["name"] if root else None)]
    source = "\n".join(chunks)
    manifest = {"schema_version": config["schema_version"], "format": "bound-native-registry", "guest_code_executed": False,
                "factory": "oot_create_bound_registry", "profile": "checked-read-pauth-stack-dag" if read_profile else "pauth-stack-dag" if pauth_profile else "layout-stack-dag" if layout_profile else "cfg-stack-dag" if cfg_profile else "stack-dag" if stack_profile else "frame" if root else "leaf",
                "registry_source_sha256": hashlib.sha256(source.encode()).hexdigest(), "return_sites": returns,
                "image": image_report,
                "leaves": [{k: v for k, v in r.items() if k != "data"} for r in leaves],
                "root": {k: v for k, v in root.items() if k != "data"} if root else None}
    if stack_profile:
        manifest["frames"] = [{k: v for k, v in f.items() if k != "data"} for f in frames]
    if pauth_profile:
        manifest.update(pauth_model=MODEL, pauth_abi_version=1, keys_embedded=False)
    if read_profile:
        manifest.update(read_ranges=read_records,read_addresses_checked_at_runtime=True)
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
