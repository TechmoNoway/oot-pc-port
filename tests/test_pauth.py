"""Explicit PAC model boundaries and native PAuth-enabled differential tests."""

import importlib.util
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from arm64_lifter import MAX_WORDS, UnsupportedInstruction, emit_c
from input_formats import InputError
from pauth_lifter import MODEL, WORDS, decode_pauth_block, emit_pauth_c
from pauth_validation import run_validation


class PauthBoundaryTests(unittest.TestCase):
    def test_only_six_exact_forms_are_added_to_separate_abi(self):
        data = struct.pack("<6I", *WORDS)
        self.assertEqual([i.form for i in decode_pauth_block(data, 0x1000)], list(WORDS.values()))
        source, report = emit_pauth_c(data, 0x1000)
        self.assertEqual((report["pauth_abi_version"], report["state_abi_version"], report["model"]), (1, 2, MODEL))
        self.assertFalse(report["registry_compatible"])
        self.assertFalse(report["game_runtime_ready"])
        self.assertIn("const OotPauth *pauth", source)
        self.assertIn("oot_pauth_step(pauth", source)
        for word in WORDS:
            with self.subTest(word=hex(word)), self.assertRaises(UnsupportedInstruction):
                emit_c(struct.pack("<I", word), 0x1000)

    def test_unimplemented_pac_bti_and_invalid_ranges_are_rejected(self):
        for word in (0xD50320FF, 0xD503245F, 0xD65F0BFE, 0xD503231F, 0xDAC10020, 0xFFFFFFFF):
            with self.subTest(word=hex(word)), self.assertRaises(InputError):
                emit_pauth_c(struct.pack("<I", word), 0x1000)
        for data, base in ((b"", 0), (b"123", 0), (b"\0" * (4 * MAX_WORDS + 4), 0),
                           (b"\0" * 4, -4), (b"\0" * 4, 1), (b"\0" * 4, (1 << 64) - 4)):
            with self.subTest(base=base, size=len(data)), self.assertRaises(InputError):
                emit_pauth_c(data, base)
        for name in ("oot_lift_run", "oot_pauth_lift_", "oot_pauth_lift_a;bad()"):
            with self.assertRaises(InputError): emit_pauth_c(struct.pack("<I", 0xD503233F), 0x1000, name)


@unittest.skipUnless(os.name == "nt" and importlib.util.find_spec("unicorn"), "native Windows and pinned Unicorn required")
class NativePauthTests(unittest.TestCase):
    def test_qarma5_signed_bits_authentication_failures_and_nested_frames(self):
        report, path = run_validation(os.environ.get("OOT_LIFTER_COMPILER", "cmake"))
        self.assertEqual(report["primitive_comparisons"], 124928)
        self.assertGreater(report["poisoned_comparisons"], 100000)
        self.assertEqual(report["nested_frame_cases"], 64)
        self.assertGreater(report["frame_prefix_checks"], 1000)
        self.assertEqual(report["rejection_checks"], 15)
        self.assertEqual(report["corrupted_frame_cases"], 16)
        self.assertFalse(report["game_code_executed"])
        self.assertTrue(path.is_file())


if __name__ == "__main__": unittest.main()
