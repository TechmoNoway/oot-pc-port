"""Artificial closed leaf regions and metadata candidates only."""

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
from leaf_verifier import MAX_LEAF_WORDS, verify_leaf
from module_linker import Linker, Module
from prepare_exefs import prepare
from survey_leaf_functions import survey_module
from test_arm64_analysis import branch, synthetic_module
from test_module_linker import symbol

BASE = 0x1000000
RET = 0xD65F03C0


def code(*words):
    return struct.pack(f"<{len(words)}I", *words)


class LeafPolicyTests(unittest.TestCase):
    def test_return_only_and_multiple_return_diamond(self):
        result = verify_leaf(code(RET), BASE)
        self.assertEqual(result["max_retired_instructions"], 1)
        diamond = next(p for p in leaf_programs() if p.name == "leaf_diamond")
        result = verify_leaf(diamond.data, BASE)
        self.assertEqual((result["return_count"], result["max_retired_instructions"]), (2, 3))
        self.assertTrue(result["all_declared_words_reachable"])
        self.assertFalse(result["guest_code_executed"])
        self.assertIn("X30 is outside the declared range", result["preconditions"])

    def test_complete_examples_have_bounded_mathematical_trials(self):
        for program in leaf_programs():
            result = verify_leaf(program.data, BASE)
            for trial in program.trials:
                if trial.expected_x is not None:
                    self.assertGreaterEqual(trial.budget, result["max_retired_instructions"])
                    self.assertEqual(trial.registers[30], BASE + len(program.data))

    def test_memory_call_dynamic_jump_and_nonstandard_return_rejected(self):
        for words in ((0xF9400020, RET), (0x94000000, RET), (0xD61F0000,), (0xD65F0020,), (0xD503237F, RET)):
            with self.subTest(words=words), self.assertRaises(ValueError):
                verify_leaf(code(*words), BASE)

    def test_protected_register_and_sp_writes_rejected(self):
        for word in (0xD2800012, 0xD2800013, 0xD280001D, 0x5280001E, 0x910003FF, 0x92001C3F):
            with self.subTest(word=hex(word)), self.assertRaisesRegex(InputError, "protected"):
                verify_leaf(code(word, RET), BASE)

    def test_flag_setting_zr_is_allowed(self):
        self.assertEqual(verify_leaf(code(0xEB01001F, RET), BASE)["instruction_count"], 2)

    def test_cycles_external_edges_and_fallthrough_rejected(self):
        for words in ((0x14000000,), (0x14000002, RET), (0xD503201F,), (0x11000400, 0x35FFFFE0, RET)):
            with self.subTest(words=words), self.assertRaises(ValueError):
                verify_leaf(code(*words), BASE)

    def test_unreachable_words_are_not_silently_translated(self):
        for words in ((0x14000002, 0xD503201F, RET), (RET, RET)):
            with self.subTest(words=words), self.assertRaisesRegex(InputError, "unreachable"):
                verify_leaf(code(*words), BASE)

    def test_policy_limit(self):
        longest = code(*([0xD503201F] * (MAX_LEAF_WORDS - 1) + [RET]))
        self.assertEqual(verify_leaf(longest, BASE)["max_retired_instructions"], MAX_LEAF_WORDS)
        with self.assertRaises(InputError):
            verify_leaf(code(*([0xD503201F] * MAX_LEAF_WORDS + [RET])), BASE)


class LeafSurveyTests(unittest.TestCase):
    def fixture(self):
        module = Module("main", synthetic_module({0: branch(0, 0x40), 0x40: 0x9A810000, 0x44: RET, 0x60: RET},
                        symbols=[symbol("one", value=0x40, size=8), symbol("two", value=0x60, size=4)]))
        Linker([module]).apply()
        return module

    def test_metadata_candidates_accounting_samples_and_source_preservation(self):
        module = self.fixture()
        before = bytes(module.image)
        result = survey_module(module, sample_limit=1)
        self.assertEqual((result["accepted_leaf_regions"], len(result["samples"])), (2, 1))
        self.assertTrue(result["samples_truncated"])
        self.assertEqual(result["samples"][0]["offset"], 0x40)
        self.assertEqual(result["metadata_entry_candidates"], result["accepted_leaf_regions"] + sum(result["rejected"].values()))
        self.assertFalse(result["function_identity_proven"])
        self.assertEqual(bytes(module.image), before)

    def test_empty_samples_and_bad_limits(self):
        module = self.fixture()
        self.assertEqual(survey_module(module, sample_limit=0)["samples"], [])
        for kwargs in ({"sample_limit": -1}, {"max_words": 0}, {"max_words": MAX_LEAF_WORDS + 1}):
            with self.assertRaises(InputError):
                survey_module(module, **kwargs)

    def test_cli_uses_verified_prepared_inputs_without_execution(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            folder = Path(temporary)
            source, prepared, report = folder / "main", folder / "prepared", folder / "report.json"
            source.write_bytes(synthetic_module({0: branch(0, 0x40), 0x40: RET}, symbols=[symbol("leaf", size=4)]))
            prepare(source, prepared)
            result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/survey_leaf_functions.py"), str(prepared),
                                     "--report", str(report)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(report.read_text())
            self.assertFalse(data["guest_code_executed"])
            self.assertGreater(data["totals"]["accepted_leaf_regions"], 0)


class LeafTranslationCliTests(unittest.TestCase):
    def test_verified_emission_and_rejection_leave_no_partial_source(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            folder = Path(temporary)
            source, output, report = folder / "code.raw", folder / "code.c", folder / "report.json"
            source.write_bytes(code(0x9A810000, RET))
            args = [sys.executable, "-B", str(ROOT / "tools/lift_arm64.py"), str(source), "--base", hex(BASE),
                    "--output", str(output), "--report", str(report), "--verify-leaf"]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(report.read_text())["leaf_verification"]["instruction_count"], 2)
            source.write_bytes(code(0xF9400020, RET))
            args[args.index(str(output))] = str(folder / "invalid.c")
            args[args.index(str(report))] = str(folder / "invalid.json")
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertFalse((folder / "invalid.c").exists())


if __name__ == "__main__":
    unittest.main()
