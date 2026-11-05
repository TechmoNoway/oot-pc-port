"""Acyclic framed CFGs, explicit saved registers, and schema-3 native factories."""

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
from stack_cfg_validation import Assembler, add, bindings, condition_programs, immediate, mov, run_validation, synthetic_programs
from stack_cfg_verifier import BRANCH, RESTORE, verify_cfg_stack_functions
from stack_validation import depth_programs, scalar
from stack_verifier import verify_stack_functions
from test_module_linker import change_memory, fixture


def bundle_fixture():
    base = Linker([Module("main", fixture())]).modules[0].base
    root = Assembler("cfg_bundle", base + 0x10, 32, ((19,),))
    root.branch("zero", 0xB4000000)
    root.emit(mov(19, 0)); root.bl(base + 0x60); root.emit(add(0, 0, 19)); root.branch("epilogue", 0x14000000, 26)
    root.label("zero"); root.emit(immediate(0, 42))
    p = root.finish()
    leaf = next(p for p in leaf_programs() if p.name == "leaf_remainder")
    raw = change_memory(change_memory(fixture(), 0x10, p.data), 0x60, leaf.data)
    linker = Linker([Module("main", raw)])
    assert linker.apply()["link_complete"]
    config = {"schema_version": 3, "root": p.name, "return_sites": [EXIT], "stack_size": 4096,
        "frames": [{"name": p.name, "module": "main", "offset": 0x10, "size": len(p.data)}],
        "leaves": [{"name": "cfg_bundle_rem", "module": "main", "offset": 0x60, "size": len(leaf.data)}]}
    return raw, linker, config


class CfgPolicyTests(unittest.TestCase):
    def test_saved_register_phases_edges_and_weighted_bounds(self):
        frames, leaves = synthetic_programs()
        p = verify_cfg_stack_functions({f.base: f.data for f in frames}, {f.base: f.data for f in leaves}, CALLER)[CALLER]
        self.assertEqual(p["saved_registers"], [19, 20, 21])
        self.assertEqual((p["locals_begin"], p["max_depth"], p["max_stack_bytes"], p["max_retired_instructions"]), (40, 2, 144, 53))
        self.assertEqual(p["control_flow"][2]["writable_mask"], 0)
        self.assertEqual(p["control_flow"][4]["writable_mask"], p["saved_mask"])
        tail = next(i for i, s in enumerate(p["steps"]) if s["kind"] == RESTORE)
        self.assertEqual(p["control_flow"][tail]["writable_mask"], (1 << 19) | (1 << 20))
        self.assertEqual(p["control_flow"][tail + 1]["writable_mask"], 0)
        self.assertFalse(p["guest_code_executed"])
        with self.assertRaises(InputError):
            verify_stack_functions({f.base: f.data for f in frames}, {f.base: f.data for f in leaves}, CALLER)

    def test_rejects_branch_to_prologue_restore_middle_ret_external_or_cycle(self):
        frames, leaves = synthetic_programs()
        root = frames[0]
        proof = verify_cfg_stack_functions({f.base: f.data for f in frames}, {f.base: f.data for f in leaves}, CALLER)[CALLER]
        index = next(i for i, s in enumerate(proof["steps"]) if s["kind"] == BRANCH)
        epilogue = next(i for i, s in enumerate(proof["steps"]) if s["kind"] == RESTORE)
        for target in (0, 2, index, epilogue + 1, len(root.words) - 1, len(root.words) + 4):
            words = root.words.copy(); words[index] = 0xB4000000 | (((target - index) & 0x7FFFF) << 5)
            code = {f.base: f.data for f in frames}; code[CALLER] = struct.pack(f"<{len(words)}I", *words)
            with self.subTest(target=target), self.assertRaises(InputError):
                verify_cfg_stack_functions(code, {f.base: f.data for f in leaves}, CALLER)

    def test_rejects_duplicate_mismatched_and_missing_register_saves(self):
        for saves in (((19, 19),), ((19,), (19,)), ((18,),)):
            a = Assembler("invalid", CALLER, 64, saves); a.emit(immediate(0, 1))
            with self.subTest(saves=saves), self.assertRaises(InputError):
                verify_cfg_stack_functions({CALLER: a.finish().data}, {}, CALLER)
        a = Assembler("invalid", CALLER, 32, ((19,),)); a.emit(mov(19, 0)); p = a.finish()
        p.words[-3] = scalar(8, True, 20, 29, 16)
        with self.assertRaisesRegex(InputError, "restore"):
            verify_cfg_stack_functions({CALLER: p.data}, {}, CALLER)
        for rd in (18, 19, 29, 30):
            a = Assembler("unsaved", CALLER, 16); a.emit(mov(rd, 0))
            with self.subTest(rd=rd), self.assertRaises(InputError):
                verify_cfg_stack_functions({CALLER: a.finish().data}, {}, CALLER)

    def test_locals_cannot_read_or_write_saved_slots_or_write_unsaved_registers(self):
        for word in (scalar(8, False, 0, 31, 16), scalar(8, True, 0, 29, 16), scalar(8, True, 20, 31, 24), 0x910007FF):
            a = Assembler("bad_local", CALLER, 48, ((19,),)); a.emit(word)
            with self.subTest(word=hex(word)), self.assertRaises(InputError):
                verify_cfg_stack_functions({CALLER: a.finish().data}, {}, CALLER)
        a = Assembler("valid_local", CALLER, 48, ((19,),)); a.emit(scalar(8, False, 0, 31, 24), scalar(8, True, 19, 29, 24))
        self.assertEqual(verify_cfg_stack_functions({CALLER: a.finish().data}, {}, CALLER)[CALLER]["saved_registers"], [19])

    def test_rejects_unreachable_words_call_recursion_and_excess_depth(self):
        a = Assembler("dead", CALLER, 16); a.branch("epilogue", 0x14000000, 26); a.emit(immediate(0, 1))
        with self.assertRaisesRegex(InputError, "unreachable"):
            verify_cfg_stack_functions({CALLER: a.finish().data}, {}, CALLER)
        a = Assembler("recursive", CALLER, 16); a.bl(CALLER)
        with self.assertRaisesRegex(InputError, "cycle"):
            verify_cfg_stack_functions({CALLER: a.finish().data}, {}, CALLER)
        chain = depth_programs(17)
        with self.assertRaisesRegex(InputError, "depth"):
            verify_cfg_stack_functions({p.base: p.data for p in chain}, {}, CALLER)

    def test_all_ten_saved_registers_and_no_save_conditional_profile(self):
        programs = condition_programs()
        all_saved = programs[-1]
        p = verify_cfg_stack_functions({all_saved.base: all_saved.data}, {}, all_saved.base)[all_saved.base]
        self.assertEqual(p["saved_registers"], list(range(19, 29)))
        self.assertEqual(p["locals_begin"], 96)
        p = programs[0]
        self.assertEqual(verify_cfg_stack_functions({p.base: p.data}, {}, p.base)[p.base]["saved_mask"], 0)


class CfgBundleTests(unittest.TestCase):
    def test_schema_three_factory_proof_hashes_and_previous_policy_rejection(self):
        _, linker, config = bundle_fixture()
        original = bytes(linker.modules[0].image)
        blob, source, manifest = build_bundle(linker, config)
        self.assertEqual((manifest["schema_version"], manifest["profile"]), (3, "cfg-stack-dag"))
        self.assertIn("oot_stack_create_cfg(image", source)
        self.assertEqual(manifest["root"]["verification"]["saved_registers"], [19])
        self.assertEqual(manifest["image"]["body_sha256"], blob[64:96].hex())
        self.assertEqual(bytes(linker.modules[0].image), original)
        previous = deepcopy(config); previous["schema_version"] = 2
        with self.assertRaises(InputError): build_bundle(linker, previous)

    def test_cli_preserves_inputs_source_hash_and_existing_output(self):
        raw, linker, config = bundle_fixture()
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            folder = Path(temporary)
            source, prepared, selection, output = folder / "main", folder / "prepared", folder / "selection.json", folder / "bundle"
            source.write_bytes(raw); prepare(source, prepared)
            selection.write_text(json.dumps(config), encoding="utf-8")
            before = {p.name: p.read_bytes() for p in prepared.iterdir()}
            result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/prepare_registry.py"), str(prepared),
                "--config", str(selection), "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["registry_source_sha256"], hashlib.sha256((output / "registry.c").read_bytes()).hexdigest())
            self.assertEqual({p.name: p.read_bytes() for p in prepared.iterdir()}, before)
            with self.assertRaises(InputError): write_bundle(linker, config, output)


@unittest.skipUnless(os.name == "nt", "native Windows compiler required")
class NativeCfgBundleTests(unittest.TestCase):
    def test_generated_cfg_factory_both_paths_and_retained_image(self):
        _, linker, config = bundle_fixture()
        blob, source, manifest = build_bundle(linker, config)
        lib, _ = compile_library([], os.environ.get("OOT_LIFTER_COMPILER", "cmake"), source)
        bindings(lib)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            path = Path(temporary) / "image.ootmem"; path.write_bytes(blob)
            message, error, report = create_string_buffer(192), c_uint32(), Report()
            image = lib.oot_runtime_open(os.fsencode(path), message, len(message))
            self.assertTrue(image, message.value)
            context = lib.oot_create_bound_registry(image, byref(error))
            self.assertTrue(context, error.value)
            lib.oot_runtime_close(image)
            try:
                for a, b in ((0, 0), (10, 3), ((1 << 64) - 1, 7)):
                    state = State(); state.pc, state.sp, state.x[30] = manifest["root"]["entry"], manifest["image"]["initial_sp"], EXIT
                    state.x[0], state.x[1], state.x[19], state.x[29] = a, b, 0x1234, 0xFEDC
                    self.assertEqual(lib.oot_stack_begin(context, byref(state), EXIT, byref(report)), 0)
                    self.assertEqual(lib.oot_stack_run(context, byref(state), 1000, byref(report)), 2)
                    self.assertEqual((state.x[0], state.x[19], state.x[29], state.pc, state.sp),
                        (42 if a == 0 else (remainder(a, b) + a) & ((1 << 64) - 1), 0x1234, 0xFEDC, EXIT, manifest["image"]["initial_sp"]))
            finally:
                lib.oot_stack_destroy(context)


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "install tools/requirements-lifter.txt for CFG reference tests")
class NativeCfgTests(unittest.TestCase):
    def test_complete_cfg_calls_conditions_prefixes_and_fault_guards(self):
        report, path = run_validation(os.environ.get("OOT_LIFTER_COMPILER", "cmake"))
        self.assertEqual((report["whole_call_cases"], report["condition_and_save_cases"], report["prefix_step_checks"]), (128, 272, 527))
        self.assertEqual((report["weighted_max_steps"], report["max_saved_registers"], report["native_fault_modes"]), (53, 10, 13))
        self.assertFalse(report["game_code_executed"])
        self.assertTrue(path.is_file())


if __name__ == "__main__": unittest.main()
