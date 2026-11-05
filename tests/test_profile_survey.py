"""Synthetic metadata regions, actual profile proofs, and static-only reporting."""

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from input_formats import InputError
from leaf_validation import leaf_programs
from module_linker import Linker, Module
from prepare_exefs import prepare
from profile_survey import PROFILES, metadata_windows, survey_modules
from stack_cfg_validation import Assembler, add, immediate, mov
from stack_layout_validation import LayoutAssembler
from stack_validation import framed
from survey_function_profiles import write_report
from survey_leaf_functions import survey_module as survey_leaves
from test_arm64_analysis import branch, synthetic_module
from test_module_linker import symbol

RET = 0xD65F03C0


def linked(instructions, symbols=(), name="main"):
    m = Module(name, synthetic_module(instructions, symbols=symbols))
    link = Linker([m]); assert link.apply()["link_complete"]
    return m


def programs_module(programs, extra=None):
    words, symbols = {0: branch(0, 0x10)}, []
    for name, offset, data in programs:
        words.update({offset + i: word[0] for i, word in zip(range(0, len(data), 4), struct.iter_unpack("<I", data))})
        symbols.append(symbol(name, value=offset, size=len(data)))
    if extra: words.update(extra)
    return linked(words, symbols)


class ProfileSurveyTests(unittest.TestCase):
    def test_real_verifiers_accept_leaf_and_minimal_framed_caller(self):
        leaf = next(p for p in leaf_programs() if p.name == "leaf_remainder")
        root = Assembler("root", 0x10, 16); root.bl(0x60)
        m = programs_module([("root", 0x10, root.finish().data), ("leaf", 0x60, leaf.data)])
        before = bytes(m.image); report = survey_modules([m], sample_limit=8)
        counts = report["totals"]["profiles"]
        self.assertEqual(counts["register_leaf"]["accepted_regions"], 1)
        for name in PROFILES[1:]:
            self.assertEqual(counts[name]["accepted_regions"], 1, name)
        self.assertEqual(counts["register_leaf"]["accepted_regions"], survey_leaves(m)["accepted_leaf_regions"])
        self.assertEqual(bytes(m.image), before)
        for row in counts.values():
            self.assertEqual(row["considered_candidates"], row["discovery_blocked"] + row["accepted_regions"] + sum(row["rejected"].values()))
        self.assertFalse(report["guest_code_executed"]); self.assertFalse(report["translation_performed"])
        self.assertFalse(report["native_callbacks_registered"]); self.assertFalse(report["function_identity_proven"])

    def test_actual_transitive_frame_closure_including_sparse_layout(self):
        leaf = next(p for p in leaf_programs() if p.name == "leaf_remainder")
        root = LayoutAssembler("root", 0x10, 64, 48, ((32, (19,)),), fp_first=False)
        root.emit(mov(19, 0)); root.bl(0xA0); root.emit(add(0, 0, 19))
        child = LayoutAssembler("child", 0xA0, 32, 0, ((16, (19,)),), split=False, fp_first=False)
        child.emit(mov(19, 0)); child.bl(0xF0); child.emit(add(0, 0, 19))
        m = programs_module([("root", 0x10, root.finish().data), ("child", 0xA0, child.finish().data), ("leaf", 0xF0, leaf.data)])
        r = survey_modules([m])["modules"][0]["profiles"]
        self.assertEqual(r["fixed_layout"]["accepted_regions"], 2)
        root_sample = next(s for s in r["fixed_layout"]["accepted_samples"] if s["offset"] == 0x10)
        self.assertEqual((root_sample["closure_frames"], root_sample["closure_leaves"]), (2, 1))
        self.assertEqual(root_sample["verification"]["max_depth"], 2)
        self.assertEqual(r["cfg_stack"]["accepted_regions"], 0)

    def test_no_stub_or_fabricated_leaf_for_an_unknown_callee(self):
        a = Assembler("root", 0x10, 16); a.bl(0x60)
        m = programs_module([("root", 0x10, a.finish().data)], {0x60: RET})
        r = survey_modules([m])["modules"][0]["profiles"]
        for name in PROFILES[1:]:
            self.assertEqual(r[name]["accepted_regions"], 0)
            self.assertEqual(r[name]["rejected"]["call_dependency"], 1)

    def test_pac_prefix_is_observed_but_never_removed_for_verification(self):
        p = framed("root", 0x10, 32, [immediate(0, 1)])
        data = struct.pack("<I", 0xD503237F) + p.data  # pacibsp; supported-looking frame follows.
        m = programs_module([("pac_region", 0x10, data)])
        r = survey_modules([m])
        self.assertEqual(r["totals"]["first_unsupported_mnemonics"]["pacibsp"], 1)
        self.assertEqual(r["totals"]["first_unsupported_categories"]["pointer_authentication"], 1)
        self.assertEqual(r["totals"]["prefix_observations"]["shapes"]["stp_fp_lr_preindex"], 1)
        self.assertTrue(r["modules"][0]["prefix_observations"]["diagnostic_only"])
        self.assertFalse(r["modules"][0]["prefix_observations"]["hints_removed_for_verification"])
        self.assertTrue(all(p["accepted_regions"] == 0 for p in r["totals"]["profiles"].values()))

    def test_metadata_windows_honor_next_entry_and_smallest_symbol_alias(self):
        m = linked({0: branch(0, 0x40), 0x40: 0x91000400, 0x44: RET, 0x60: RET},
            [symbol("a", value=0x40, size=8), symbol("alias", value=0x40, size=4), symbol("b", value=0x60, size=4)])
        windows = list(metadata_windows(m, 256))
        self.assertEqual([(w[0], w[1]) for w in windows], [(0, 0x40), (0x40, 0x44), (0x60, 0x64)])
        self.assertIn("symbol_size", windows[1][3])
        r = survey_modules([m])
        self.assertEqual(r["totals"]["profiles"]["register_leaf"]["accepted_regions"], 1)
        self.assertEqual(r["totals"]["blocked"]["window_boundary"], 2)

    def test_multiple_returns_cycles_indirect_calls_and_unreachable_words(self):
        diamond = next(p for p in leaf_programs() if p.name == "leaf_diamond")
        m = programs_module([("diamond", 0x10, diamond.data), ("cycle", 0x60, struct.pack("<II", 0x34000000, RET)),
            ("indirect", 0xA0, struct.pack("<II", 0xD63F0000, RET)),
            ("dead", 0xC0, struct.pack("<III", 0x14000002, 0xD503201F, RET))])
        r = survey_modules([m])["totals"]
        self.assertEqual(r["profiles"]["register_leaf"]["accepted_regions"], 1)
        self.assertEqual(r["profiles"]["register_leaf"]["rejected"]["control_cycle"], 1)
        self.assertEqual(r["profiles"]["register_leaf"]["rejected"]["unreachable_words"], 1)
        self.assertEqual(r["blocked"]["indirect_call"], 1)

    def test_sample_limits_zero_samples_and_bounded_word_window(self):
        m = programs_module([("leaf", 0x40, struct.pack("<II", 0x91000400, RET))])
        r = survey_modules([m], sample_limit=0, max_words=1)
        self.assertEqual(r["totals"]["complete_regions"], 0)
        self.assertEqual(r["modules"][0]["discovery"]["samples"], [])
        self.assertTrue(r["modules"][0]["discovery"]["samples_truncated"])
        for options in ({"sample_limit": -1}, {"sample_limit": True}, {"max_words": 0}, {"max_words": 257}):
            with self.subTest(options=options), self.assertRaises(InputError): survey_modules([m], **options)

    def test_shared_call_cycles_fail_actual_profile(self):
        root = Assembler("root", 0x10, 16); root.bl(0x60)
        child = Assembler("child", 0x60, 16); child.bl(0x10)
        m = programs_module([("root", 0x10, root.finish().data), ("child", 0x60, child.finish().data)])
        r = survey_modules([m])["totals"]["profiles"]
        for name in ("linear_stack", "cfg_stack", "fixed_layout"):
            self.assertEqual(r[name]["accepted_regions"], 0)
            self.assertEqual(r[name]["rejected"]["call_cycle"], 2)


class ProfileSurveyCliTests(unittest.TestCase):
    def test_cli_fresh_verified_inputs_output_preservation_and_no_execution(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            folder = Path(temporary); source, prepared, destination = folder / "main", folder / "prepared", folder / "survey.json"
            source.write_bytes(synthetic_module({0: branch(0, 0x40), 0x40: RET}, symbols=[symbol("leaf", value=0x40, size=4)]))
            prepare(source, prepared); before = {p.name: p.read_bytes() for p in prepared.iterdir()}
            args = [sys.executable, "-B", str(ROOT / "tools/survey_function_profiles.py"), str(prepared), "--report", str(destination)]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(destination.read_text()); self.assertTrue(report["offline_link"]["link_complete"])
            self.assertEqual(report["totals"]["profiles"]["register_leaf"]["accepted_regions"], 1)
            self.assertFalse(report["guest_code_executed"]); self.assertFalse(report["translation_performed"])
            self.assertEqual({p.name: p.read_bytes() for p in prepared.iterdir()}, before)
            previous = destination.read_bytes()
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertEqual(destination.read_bytes(), previous)
            with self.assertRaises(InputError): write_report({}, ROOT / "never-write-survey.json")
            self.assertNotEqual(subprocess.run(args[:-1] + [str(prepared / "bad.json")], capture_output=True).returncode, 0)

    def test_tampered_prepared_input_cannot_write_a_report(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            folder = Path(temporary); source, prepared, destination = folder / "main", folder / "prepared", folder / "survey.json"
            source.write_bytes(synthetic_module()); prepare(source, prepared)
            data = bytearray((prepared / "main").read_bytes()); data[-1] ^= 1; (prepared / "main").write_bytes(data)
            result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/survey_function_profiles.py"), str(prepared), "--report", str(destination)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0); self.assertIn("SHA-256", result.stderr); self.assertFalse(destination.exists())


if __name__ == "__main__": unittest.main()
