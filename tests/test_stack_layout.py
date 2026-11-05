"""Fixed SUB/ADD allocation, offset frame records, and schema-4 registries."""

from copy import deepcopy
from ctypes import byref, c_uint32, create_string_buffer
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from dispatcher_validation import CALLER, EXIT, Report
from input_formats import InputError
from leaf_validation import leaf_programs, remainder
from lifter_validation import compile_library
from lifter_validation_types import State
from module_linker import Linker, Module
from prepare_exefs import prepare
from prepare_registry import build_bundle, write_bundle
from stack_cfg_validation import add_immediate, immediate, mov
from stack_cfg_verifier import verify_cfg_stack_functions
from stack_layout_validation import LayoutAssembler, add, bindings, memory_word, matrix_programs, run_validation, synthetic_programs
from stack_layout_verifier import RECORD_RESTORE, verify_layout_stack_functions
from test_module_linker import change_memory, fixture


def bundle_fixture(solo=False):
    base = Linker([Module("main", fixture())]).modules[0].base
    a = LayoutAssembler("layout_solo" if solo else "layout_bundle", base + 0x10, 64 if solo else 80, 0 if solo else 64,
        ((40 if solo else 48, (19,)),), split=not solo, fp_first=False)
    if solo:
        a.emit(mov(19, 0), memory_word(8, False, 19, 31, 16), memory_word(8, True, 0, 29, 16), add_immediate(0, 0, 1))
    else:
        a.emit(memory_word(8, False, 0, 29, -64)); a.branch("zero", 0xB4000000)
        a.emit(mov(19, 0)); a.bl(base + 0x60); a.emit(add(0, 0, 19)); a.branch("join", 0x14000000, 26)
        a.label("zero"); a.emit(immediate(0, 42)); a.label("join")
        a.emit(memory_word(8, True, 19, 29, -64), add(0, 0, 19))
    p = a.finish()
    leaf = next(p for p in leaf_programs() if p.name == "leaf_remainder")
    raw = change_memory(fixture(), 0x10, p.data)
    if not solo: raw = change_memory(raw, 0x60, leaf.data)
    linker = Linker([Module("main", raw)]); assert linker.apply()["link_complete"]
    config = {"schema_version": 4, "root": p.name, "stack_size": 4096, "return_sites": [EXIT],
        "frames": [{"name": p.name, "module": "main", "offset": 0x10, "size": len(p.data)}],
        "leaves": [] if solo else [{"name": "layout_bundle_rem", "module": "main", "offset": 0x60, "size": len(leaf.data)}]}
    return raw, linker, config


class LayoutPolicyTests(unittest.TestCase):
    def test_split_record_offset_sparse_slots_and_expected_state_phases(self):
        frames, leaves = synthetic_programs()
        p = verify_layout_stack_functions({p.base: p.data for p in frames}, {p.base: p.data for p in leaves}, CALLER)[CALLER]
        self.assertEqual((p["layout"], p["frame_size"], p["record_offset"], p["max_depth"], p["max_stack_bytes"]), ("split", 96, 80, 3, 240))
        self.assertEqual(p["reserved_ranges"], [(48, 64), (72, 80), (80, 96)])
        self.assertEqual(p["states"][0], {"sp": 0, "fp": 0, "lr": 0, "owner": 1})
        self.assertEqual(p["states"][4]["fp"], 1)
        restore = next(i for i, s in enumerate(p["steps"]) if s["kind"] == RECORD_RESTORE)
        self.assertEqual(p["states"][restore], {"sp": 0, "fp": 0, "lr": 1, "owner": 0})
        self.assertEqual(p["states"][restore + 1], {"sp": 1, "fp": 0, "lr": 1, "owner": 2})
        with self.assertRaises(InputError):
            verify_cfg_stack_functions({p.base: p.data for p in frames}, {p.base: p.data for p in leaves}, CALLER)

    def test_mismatched_allocation_record_restore_or_fp_setup_rejected(self):
        frames, leaves = synthetic_programs(); root = frames[0]
        for index, word in ((0, 0xD10003FF | (80 << 10)), (1, root.words[1] + (12 << 15)),
                            (4, add_immediate(29, 31, 64)), (-3, root.words[-3] - (2 << 15)), (-2, 0x910003FF | (80 << 10))):
            words = root.words.copy(); words[index] = word
            data = {p.base: p.data for p in frames}; data[CALLER] = struct.pack(f"<{len(words)}I", *words)
            with self.subTest(index=index), self.assertRaises(InputError):
                verify_layout_stack_functions(data, {p.base: p.data for p in leaves}, CALLER)

    def test_overlapping_out_of_bounds_and_duplicate_saved_slots_rejected(self):
        for saves in (((80, (19, 20)),), ((48, (19, 20)), (56, (21,))), ((96, (19,)),), ((40, (19,)), (48, (19,)))):
            a = LayoutAssembler("invalid", CALLER, 96, 80, saves); a.emit(immediate(0, 1))
            with self.subTest(saves=saves), self.assertRaises(InputError):
                verify_layout_stack_functions({CALLER: a.finish().data}, {}, CALLER)

    def test_fp_relative_locals_cannot_touch_record_saves_or_leave_frame(self):
        for rn, offset in ((29, 0), (29, -32), (29, -88), (29, 16), (31, -8), (0, 0), (31, 76)):
            a = LayoutAssembler("bad_local", CALLER, 96, 80, ((48, (19, 20)), (72, (21,))))
            a.emit(memory_word(8, False, 0, rn, offset))
            with self.subTest(rn=rn, offset=offset), self.assertRaises(InputError):
                verify_layout_stack_functions({CALLER: a.finish().data}, {}, CALLER)
        a = LayoutAssembler("good_local", CALLER, 96, 80, ((48, (19, 20)), (72, (21,))))
        a.emit(memory_word(8, False, 0, 31, 64), memory_word(8, True, 19, 29, -16))
        self.assertEqual(verify_layout_stack_functions({CALLER: a.finish().data}, {}, CALLER)[CALLER]["record_offset"], 80)

    def test_fp_base_before_setup_and_branches_into_epilogue_tail_rejected(self):
        frames, leaves = synthetic_programs(); root = frames[0]
        words = root.words.copy(); words[2] = (words[2] & ~(31 << 5)) | (29 << 5)
        data = {p.base: p.data for p in frames}; data[CALLER] = struct.pack(f"<{len(words)}I", *words)
        with self.assertRaises(InputError): verify_layout_stack_functions(data, {p.base: p.data for p in leaves}, CALLER)
        words = root.words.copy(); branch = next(i for i, word in enumerate(words) if word & 0xFF00001F == 0xB4000000)
        words[branch] = 0xB4000000 | ((len(words) - 2 - branch) << 5)
        data[CALLER] = struct.pack(f"<{len(words)}I", *words)
        with self.assertRaises(InputError): verify_layout_stack_functions(data, {p.base: p.data for p in leaves}, CALLER)

    def test_matrix_combined_split_and_all_ten_saved_registers(self):
        layouts = set(); max_saved = 0
        for p, regs in matrix_programs():
            proof = verify_layout_stack_functions({p.base: p.data}, {}, p.base)[p.base]
            layouts.add(proof["layout"]); max_saved = max(max_saved, len(proof["saved_registers"]))
        self.assertEqual(layouts, {"combined", "split"}); self.assertEqual(max_saved, 10)


class LayoutBundleTests(unittest.TestCase):
    def test_schema_four_factory_hashes_and_explicit_previous_policy_rejection(self):
        for solo in (False, True):
            _, linker, config = bundle_fixture(solo); before = bytes(linker.modules[0].image)
            blob, source, manifest = build_bundle(linker, config)
            self.assertEqual((manifest["schema_version"], manifest["profile"]), (4, "layout-stack-dag"))
            self.assertIn("oot_stack_create_layout(image", source)
            self.assertEqual(manifest["image"]["body_sha256"], blob[64:96].hex())
            self.assertEqual(bytes(linker.modules[0].image), before)
            old = deepcopy(config); old["schema_version"] = 3
            with self.assertRaises(InputError): build_bundle(linker, old)

    def test_cli_keeps_sources_and_written_hash_and_refuses_existing_output(self):
        raw, linker, config = bundle_fixture()
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            folder = Path(temporary); source, prepared, selection, output = folder / "main", folder / "prepared", folder / "selection.json", folder / "bundle"
            source.write_bytes(raw); prepare(source, prepared); selection.write_text(json.dumps(config), encoding="utf-8")
            before = {p.name: p.read_bytes() for p in prepared.iterdir()}
            result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/prepare_registry.py"), str(prepared), "--config", str(selection), "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["registry_source_sha256"], hashlib.sha256((output / "registry.c").read_bytes()).hexdigest())
            self.assertEqual({p.name: p.read_bytes() for p in prepared.iterdir()}, before)
            with self.assertRaises(InputError): write_bundle(linker, config, output)


@unittest.skipUnless(os.name == "nt", "native Windows compiler required")
class NativeLayoutBundleTests(unittest.TestCase):
    def test_compiled_split_and_combined_factories_and_retained_image(self):
        sources, bundles = [], []
        for solo in (False, True):
            _, linker, config = bundle_fixture(solo); blob, source, manifest = build_bundle(linker, config)
            sources.append(source.replace("oot_create_bound_registry", "oot_create_layout_solo") if solo else source); bundles.append((blob, manifest))
        lib, _ = compile_library([], os.environ.get("OOT_LIFTER_COMPILER", "cmake"), "\n".join(sources)); bindings(lib)
        lib.oot_create_layout_solo.argtypes, lib.oot_create_layout_solo.restype = lib.oot_create_bound_registry.argtypes, lib.oot_create_bound_registry.restype
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            path = Path(temporary) / "image.ootmem"; message, error, report = create_string_buffer(192), c_uint32(), Report()
            for solo, (blob, manifest) in enumerate(bundles):
                path.write_bytes(blob); image = lib.oot_runtime_open(os.fsencode(path), message, len(message)); self.assertTrue(image, message.value)
                factory = lib.oot_create_layout_solo if solo else lib.oot_create_bound_registry
                context = factory(image, byref(error)); self.assertTrue(context, error.value); lib.oot_runtime_close(image)
                try:
                    for a, b in ((0, 0), (10, 3), ((1 << 64) - 1, 7)):
                        s = State(); s.pc, s.sp, s.x[30] = manifest["root"]["entry"], manifest["image"]["initial_sp"], EXIT
                        s.x[0], s.x[1], s.x[19], s.x[29] = a, b, 0x1234, 0x5678
                        self.assertEqual(lib.oot_stack_begin(context, byref(s), EXIT, byref(report)), 0)
                        self.assertEqual(lib.oot_stack_run(context, byref(s), 1000, byref(report)), 2)
                        expected = a + 1 if solo else 42 if a == 0 else remainder(a, b) + 2 * a
                        self.assertEqual((s.x[0], s.x[19], s.x[29], s.sp, s.pc), (expected & ((1 << 64) - 1), 0x1234, 0x5678, manifest["image"]["initial_sp"], EXIT))
                finally: lib.oot_stack_destroy(context)


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "install tools/requirements-lifter.txt for layout reference tests")
class NativeLayoutTests(unittest.TestCase):
    def test_nested_layouts_matrix_prefixes_and_allocation_guards(self):
        report, path = run_validation(os.environ.get("OOT_LIFTER_COMPILER", "cmake"))
        self.assertEqual((report["whole_call_cases"], report["layout_matrix_cases"], report["layout_count"]), (128, 72, 9))
        self.assertGreater(report["prefix_step_checks"], 400)
        self.assertEqual((report["max_depth"], report["max_frame"], report["native_fault_modes"]), (16, 256, 12))
        self.assertFalse(report["game_code_executed"]); self.assertTrue(path.is_file())


if __name__ == "__main__": unittest.main()
