"""Explicit synthetic selection, image identity, and framed caller contracts."""

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
from frame_validation import frame_bindings, run_validation, synthetic_programs
from frame_verifier import emit_frame_descriptor, verify_frame
from input_formats import InputError
from leaf_verifier import verify_leaf
from lifter_validation import compile_library
from lifter_validation_types import State
from module_linker import Linker, Module
from prepare_exefs import prepare
from prepare_registry import build_bundle, write_bundle
from test_module_linker import change_memory, fixture
from dispatcher_validation import Report

EXIT = 0x20000000


def bundle_fixture():
    leaves, root = synthetic_programs()
    raw = fixture()
    # All code precedes the fixture's MOD0 header at 0x80.
    offsets = (0x40, 0x60, 0x70)
    words = root.words.copy()
    for index, target in ((2, 0x60), (4, 0x70)):
        words[index] = 0x94000000 | (((target - (0x40 + index * 4)) // 4) & 0x3FFFFFF)
    for offset, data in zip(offsets, (struct.pack("<7I", *words), leaves[0].data, leaves[1].data)):
        raw = change_memory(raw, offset, data)
    linker = Linker([Module("main", raw)])
    assert linker.apply()["link_complete"]
    config = {"schema_version": 1, "stack_size": 4096, "return_sites": [EXIT],
        "leaves": [{"name": name, "module": "main", "offset": offset, "size": len(leaf.data)}
                   for name, offset, leaf in zip(("rem", "mix"), offsets[1:], leaves)],
        "root": {"name": "caller", "module": "main", "offset": 0x40, "size": 28}}
    return raw, linker, config


class FramePolicyTests(unittest.TestCase):
    def test_canonical_frame_calls_and_bound(self):
        leaves, root = synthetic_programs()
        proof = verify_frame(root.data, root.base, root.frame_leaves)
        self.assertEqual((proof["stack_bytes"], proof["call_count"], proof["max_retired_instructions"]), (16, 2, 14))
        self.assertEqual([s["kind"] for s in proof["steps"]], [0, 1, 3, 2, 3, 4, 5])
        self.assertEqual(proof["source_sha256"], hashlib.sha256(root.data).hexdigest())
        self.assertFalse(proof["guest_code_executed"])
        self.assertIn("oot_frame_descriptor_caller(void)",
                      emit_frame_descriptor(root.data, root.base, root.frame_leaves, "oot_lift_caller"))
        with self.assertRaises(InputError):
            verify_leaf(root.data, root.base)  # The old leaf policy has not expanded.

    def test_rejects_other_frames_memory_control_and_protected_writes(self):
        _, root = synthetic_programs()
        for index, word in ((0, 0xD503201F), (1, 0xD503201F), (5, 0xD503201F), (6, 0xD61F03C0),
                            (3, 0xF94003E0), (3, 0x14000000), (3, 0x910007FF), (3, 0x91000412),
                            (2, 0x94000000)):
            words = root.words.copy()
            words[index] = word
            with self.subTest(index=index, word=hex(word)), self.assertRaises(InputError):
                verify_frame(struct.pack("<7I", *words), root.base, root.frame_leaves)

    def test_rejects_missing_calls_overlap_size_and_invalid_callee(self):
        _, root = synthetic_programs()
        words = root.words.copy()
        words[2] = words[4] = 0xD503201F
        invalid = [(struct.pack("<7I", *words), root.frame_leaves), (root.data, {}),
                   (root.data, {root.base: struct.pack("<I", 0xD65F03C0)}),
                   (root.data, {k: struct.pack("<I", 0xF9400000) for k in root.frame_leaves}),
                   (root.data[:-1], root.frame_leaves), (root.data * 10, root.frame_leaves)]
        for data, leaves in invalid:
            with self.subTest(size=len(data), targets=list(leaves)), self.assertRaises(InputError):
                verify_frame(data, root.base, leaves)
        with self.assertRaises(InputError):
            emit_frame_descriptor(root.data, root.base, root.frame_leaves, "oot_lift_x;bad")


class BundleTests(unittest.TestCase):
    def test_package_and_source_share_exact_hashes_without_changing_linked_bytes(self):
        _, linker, config = bundle_fixture()
        before = bytes(linker.modules[0].image)
        package, source, manifest = build_bundle(linker, config)
        self.assertEqual(bytes(linker.modules[0].image), before)
        self.assertEqual(manifest["image"]["body_sha256"], package[64:96].hex())
        self.assertEqual(manifest["registry_source_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(manifest["root"]["verification"]["max_retired_instructions"], 14)
        self.assertIn("oot_frame_create(image, oot_frame_descriptor_caller()", source)
        self.assertFalse(manifest["guest_code_executed"])
        del config["root"]
        _, source, manifest = build_bundle(linker, config)
        self.assertEqual(manifest["profile"], "leaf")
        self.assertIn("oot_leaf_dispatcher_create_bound(image", source)

    def test_rejects_invalid_selection_names_overlap_returns_and_stack(self):
        _, linker, valid = bundle_fixture()
        changes = [{"schema_version": True}, {"leaves": []}, {"stack_base": "wrong"},
                   {"return_sites": [EXIT, EXIT]}, {"return_sites": [True]},
                   {"return_sites": [linker.modules[0].base + 0x40]}]
        for key, value in (("name", "x;attack"), ("module", []), ("module", "missing"),
                           ("offset", -4), ("offset", 0x1000), ("offset", True), ("size", 4096)):
            leaves = deepcopy(valid["leaves"])
            leaves[0][key] = value
            changes.append({"leaves": leaves})
        for patch in changes:
            config = deepcopy(valid)
            config.update(patch)
            with self.subTest(patch=patch), self.assertRaises(InputError):
                build_bundle(linker, config)
        for name, offset in (("rem", 0x40), ("unique", 0x60)):
            config = deepcopy(valid)
            config["root"].update(name=name, offset=offset)
            with self.assertRaises(InputError):
                build_bundle(linker, config)

    def test_cli_preserves_verified_inputs_and_requires_fresh_build_directory(self):
        raw, linker, config = bundle_fixture()
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            folder = Path(temporary)
            source, prepared = folder / "main", folder / "prepared"
            source.write_bytes(raw)
            prepare(source, prepared)
            before = {p.name: p.read_bytes() for p in prepared.iterdir()}
            selection, output = folder / "selection.json", folder / "bundle"
            selection.write_text(json.dumps(config), encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/prepare_registry.py"), str(prepared),
                "--config", str(selection), "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)["guest_code_executed"])
            self.assertEqual({p.name: p.read_bytes() for p in prepared.iterdir()}, before)
            contents = {p.name: p.read_bytes() for p in output.iterdir()}
            self.assertEqual(set(contents), {"registry.c", "image.ootmem", "manifest.json"})
            self.assertEqual(json.loads(contents["manifest.json"])["registry_source_sha256"],
                             hashlib.sha256(contents["registry.c"]).hexdigest())
            with self.assertRaises(InputError):
                write_bundle(linker, config, output)
            self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, contents)
        with self.assertRaises(InputError):
            write_bundle(linker, config, ROOT / "never-write-bundle")


@unittest.skipUnless(os.name == "nt", "native Windows compiler required")
class NativeBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, linker, cls.config = bundle_fixture()
        cls.package, source, cls.manifest = build_bundle(linker, cls.config)
        cls.library, _ = compile_library([], os.environ.get("OOT_LIFTER_COMPILER", "cmake"), source)
        frame_bindings(cls.library)

    def test_compiled_factory_runs_only_its_linked_snapshot(self):
        lib = self.library
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            path = Path(temporary) / "image.ootmem"
            path.write_bytes(self.package)
            message = create_string_buffer(192)
            image = lib.oot_runtime_open(os.fsencode(path), message, len(message))
            self.assertTrue(image, message.value)
            context, error = None, c_uint32()
            try:
                context = lib.oot_create_bound_registry(image, byref(error))
                self.assertTrue(context, error.value)
                state, report = State(), Report()
                state.pc = self.manifest["root"]["entry"]
                state.sp = self.manifest["image"]["initial_sp"]
                state.x[0], state.x[1], state.x[29], state.x[30] = 10, 3, 0x12345678, EXIT
                self.assertEqual(lib.oot_frame_begin(context, byref(state), EXIT, byref(report)), 0)
                self.assertEqual(lib.oot_frame_run(context, byref(state), 100, byref(report)), 2)
                self.assertEqual((state.x[0], state.x[29], state.x[30], state.pc, state.sp, report.total_retired),
                    (0xFFFF ^ 14, 0x12345678, EXIT, EXIT, self.manifest["image"]["initial_sp"], 14))
            finally:
                if context: lib.oot_frame_destroy(context)
                lib.oot_runtime_close(image)


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "install tools/requirements-lifter.txt for framed reference tests")
class NativeFrameTests(unittest.TestCase):
    def test_complete_frames_budget_resumes_and_hash_fault_guards(self):
        report, path = run_validation(os.environ.get("OOT_LIFTER_COMPILER", "cmake"))
        self.assertEqual(report["result"], "passed")
        self.assertEqual(report["framed_cases"], 128)
        self.assertGreater(report["budget_yields"], 0)
        self.assertGreaterEqual(len(report["identity_and_fault_guards"]), 11)
        self.assertFalse(report["game_code_executed"])
        self.assertTrue(path.is_file())


if __name__ == "__main__":
    unittest.main()
