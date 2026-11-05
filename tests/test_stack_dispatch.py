"""Separate local-stack profile, verified DAGs, and native registry integration."""

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
from dispatcher_validation import Report
from frame_verifier import verify_frame
from input_formats import InputError
from leaf_validation import leaf_programs
from lifter_validation import compile_library
from lifter_validation_types import State
from module_linker import Linker, Module
from prepare_exefs import prepare
from prepare_registry import build_bundle, write_bundle
from stack_validation import CALLER, EXIT, add, call, depth_programs, framed, run_validation, scalar, stack_bindings, synthetic_programs
from stack_verifier import verify_stack_functions
from test_module_linker import change_memory, fixture


def bundle_fixture(solo=False):
    base = Linker([Module("main", fixture())]).modules[0].base
    root = framed("solo" if solo else "stack_caller", base + 0x10, 48,
        # Unscaled, unaligned str/ldr x0 at local byte offset 17.
        [0xF80113E0, 0xF84113A0, 0x91000400] if solo else
        [scalar(8, False, 0, 31, 16), call(base + 0x10, 3, base + 0x40), scalar(8, True, 1, 29, 16),
         add(0, 0, 1), scalar(4, False, 0, 31, 40), scalar(4, True, 0, 29, 40)])
    leaf = next(p for p in leaf_programs() if p.name == "leaf_remainder")
    child = framed("stack_child", base + 0x40, 32, [scalar(8, False, 1, 31, 16),
        call(base + 0x40, 3, base + 0x60), scalar(8, True, 1, 29, 16), add(0, 0, 1)])
    programs = [root] if solo else [root, child]
    raw = fixture()
    for p in programs: raw = change_memory(raw, p.base - base, p.data)
    if not solo: raw = change_memory(raw, 0x60, leaf.data)
    linker = Linker([Module("main", raw)])
    assert linker.apply()["link_complete"]
    config = {"schema_version": 2, "stack_size": 4096, "root": root.name, "return_sites": [EXIT],
        "frames": [{"name": p.name, "module": "main", "offset": p.base - base, "size": len(p.data)} for p in programs],
        "leaves": [] if solo else [{"name": "stack_remainder", "module": "main", "offset": 0x60, "size": len(leaf.data)}]}
    return raw, linker, config


class StackPolicyTests(unittest.TestCase):
    def test_nested_calls_locals_and_proven_bounds(self):
        frames, leaves = synthetic_programs()
        proof = verify_stack_functions({p.base: p.data for p in frames}, {p.base: p.data for p in leaves}, CALLER)[CALLER]
        self.assertEqual((proof["max_depth"], proof["max_stack_bytes"], proof["max_retired_instructions"]), (3, 144, 74))
        self.assertEqual(proof["source_sha256"], hashlib.sha256(frames[0].data).hexdigest())
        self.assertFalse(proof["guest_code_executed"])
        with self.assertRaises(InputError):
            verify_frame(frames[0].data, CALLER, {p.base: p.data for p in leaves})

    def test_local_memory_excludes_frame_record_external_bases_and_writeback(self):
        for instruction in (scalar(8, False, 0, 31, 0), scalar(8, True, 0, 31, 32), scalar(8, True, 0, 0, 16),
                            scalar(8, True, 18, 31, 16), 0xF8410FE0, 0x14000000, 0x910007FF):
            p = framed("invalid", CALLER, 32, [instruction])
            with self.subTest(word=hex(instruction)), self.assertRaises(InputError):
                verify_stack_functions({CALLER: p.data}, {}, CALLER)

    def test_frames_are_aligned_bounded_and_matching(self):
        for size in (0, 8, 24, 272):
            p = framed("invalid", CALLER, size, [])
            with self.subTest(size=size), self.assertRaises(InputError):
                verify_stack_functions({CALLER: p.data}, {}, CALLER)
        p = framed("valid", CALLER, 32, [])
        p.words[-2] = framed("other", CALLER, 16, []).words[-2]
        with self.assertRaises(InputError):
            verify_stack_functions({CALLER: p.data}, {}, CALLER)

    def test_cycles_missing_targets_unreachable_and_overlapping_functions_rejected(self):
        p = framed("root", CALLER, 32, [call(CALLER, 2, CALLER)])
        with self.assertRaisesRegex(InputError, "cycle"):
            verify_stack_functions({CALLER: p.data}, {}, CALLER)
        p = framed("root", CALLER, 32, [call(CALLER, 2, CALLER + 4096)])
        with self.assertRaisesRegex(InputError, "target"):
            verify_stack_functions({CALLER: p.data}, {}, CALLER)
        root, child = framed("root", CALLER, 16, []), framed("child", CALLER + 4096, 16, [])
        with self.assertRaisesRegex(InputError, "unreachable"):
            verify_stack_functions({root.base: root.data, child.base: child.data}, {}, CALLER)
        with self.assertRaisesRegex(InputError, "overlap"):
            verify_stack_functions({root.base: root.data, root.base + 4: child.data}, {}, CALLER)

    def test_depth_and_retirement_limits_reject_exponential_graphs(self):
        chain = depth_programs(17)
        with self.assertRaisesRegex(InputError, "bound"):
            verify_stack_functions({p.base: p.data for p in chain}, {}, CALLER)
        frames = []
        for i in range(4):
            base = CALLER + i * 4096
            frames.append(framed(f"f{i}", base, 16, [call(base, j + 2, base + 4096) for j in range(100)] if i < 3 else []))
        with self.assertRaisesRegex(InputError, "bound"):
            verify_stack_functions({p.base: p.data for p in frames}, {}, CALLER)


class StackBundleTests(unittest.TestCase):
    def test_schema_two_selection_and_no_leaf_registry(self):
        for solo in (False, True):
            _, linker, config = bundle_fixture(solo)
            original = bytes(linker.modules[0].image)
            blob, source, manifest = build_bundle(linker, config)
            self.assertEqual(manifest["profile"], "stack-dag")
            self.assertEqual(manifest["image"]["body_sha256"], blob[64:96].hex())
            self.assertEqual(manifest["root"]["verification"]["max_depth"], 1 if solo else 2)
            self.assertEqual(bytes(linker.modules[0].image), original)
            self.assertIn("oot_stack_create(image", source)
            if solo: self.assertIn("NULL, 0, NULL", source)

    def test_schema_two_requires_named_root_valid_frames_and_disjoint_selection(self):
        _, linker, valid = bundle_fixture()
        for patch in ({"root": {}}, {"root": "missing"}, {"frames": []}, {"frames": "invalid"},
                      {"frames": [valid["frames"][0], valid["frames"][0]]}):
            config = deepcopy(valid); config.update(patch)
            with self.subTest(patch=patch), self.assertRaises(InputError):
                build_bundle(linker, config)

    def test_cli_preserves_inputs_and_written_source_hash(self):
        raw, linker, config = bundle_fixture()
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            folder = Path(temporary)
            source, prepared, selection, output = folder / "main", folder / "prepared", folder / "selection.json", folder / "bundle"
            source.write_bytes(raw)
            prepare(source, prepared)
            selection.write_text(json.dumps(config), encoding="utf-8")
            original = {p.name: p.read_bytes() for p in prepared.iterdir()}
            result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/prepare_registry.py"), str(prepared),
                "--config", str(selection), "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["registry_source_sha256"], hashlib.sha256((output / "registry.c").read_bytes()).hexdigest())
            self.assertEqual({p.name: p.read_bytes() for p in prepared.iterdir()}, original)
            with self.assertRaises(InputError):
                write_bundle(linker, config, output)


@unittest.skipUnless(os.name == "nt", "native Windows compiler required")
class NativeStackBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sources, cls.bundles = [], []
        for solo in (False, True):
            _, linker, config = bundle_fixture(solo)
            blob, source, manifest = build_bundle(linker, config)
            sources.append(source.replace("oot_create_bound_registry", "oot_create_solo_registry") if solo else source)
            cls.bundles.append((blob, manifest))
        cls.lib, _ = compile_library([], os.environ.get("OOT_LIFTER_COMPILER", "cmake"), "\n".join(sources))
        stack_bindings(cls.lib)
        cls.lib.oot_create_solo_registry.argtypes = cls.lib.oot_create_bound_registry.argtypes
        cls.lib.oot_create_solo_registry.restype = cls.lib.oot_create_bound_registry.restype

    def test_actual_generated_factories_and_wrong_snapshot_rejection(self):
        lib = self.lib
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            path = Path(temporary) / "image.ootmem"
            message, error, report = create_string_buffer(192), c_uint32(), Report()
            for solo, (blob, manifest) in enumerate(self.bundles):
                with self.subTest(solo=solo):
                    path.write_bytes(blob)
                    image = lib.oot_runtime_open(os.fsencode(path), message, len(message))
                    self.assertTrue(image, message.value)
                    context = None
                    try:
                        factory = lib.oot_create_solo_registry if solo else lib.oot_create_bound_registry
                        context = factory(image, byref(error))
                        self.assertTrue(context, error.value)
                        state = State()
                        state.pc, state.sp, state.x[30], state.x[29] = manifest["root"]["entry"], manifest["image"]["initial_sp"], EXIT, 0x1234
                        state.x[0], state.x[1] = 10, 3
                        self.assertEqual(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)), 0)
                        self.assertEqual(lib.oot_stack_run(context, byref(state), 1000, byref(report)), 2)
                        self.assertEqual((state.x[0], state.x[29], state.x[30], state.sp, state.pc),
                            (11 if solo else 14, 0x1234, EXIT, manifest["image"]["initial_sp"], EXIT))
                    finally:
                        if context: lib.oot_stack_destroy(context)
                        lib.oot_runtime_close(image)
                    changed = bytearray(blob)
                    text_payload = struct.unpack_from("<Q", changed, 96 + 16)[0]
                    changed[text_payload + 0xF8] ^= 1  # Padding changes identity but leaves all selected code intact.
                    changed[64:96] = hashlib.sha256(changed[96:]).digest()
                    path.write_bytes(changed)
                    image = lib.oot_runtime_open(os.fsencode(path), message, len(message))
                    self.assertTrue(image, message.value)
                    try:
                        rejected = factory(image, byref(error))
                        self.assertFalse(rejected)
                        self.assertEqual(error.value, 16)
                    finally:
                        lib.oot_runtime_close(image)


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "install tools/requirements-lifter.txt for stack reference tests")
class NativeStackTests(unittest.TestCase):
    def test_nested_locals_budgets_ownership_and_faults(self):
        report, path = run_validation(os.environ.get("OOT_LIFTER_COMPILER", "cmake"))
        self.assertEqual(report["result"], "passed")
        self.assertEqual(report["whole_call_cases"], 128)
        self.assertEqual(report["prefix_step_checks"], 296)
        self.assertEqual(report["max_tested_depth"], 16)
        self.assertEqual(report["native_fault_modes"], 9)
        self.assertFalse(report["game_code_executed"])
        self.assertTrue(path.is_file())


if __name__ == "__main__":
    unittest.main()
