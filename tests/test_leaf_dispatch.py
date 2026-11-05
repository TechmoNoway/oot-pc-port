"""Generated leaf metadata and controlled synthetic native dispatch."""

import importlib.util
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from dispatcher_validation import run_validation
from input_formats import InputError
from leaf_verifier import emit_leaf_descriptor, verify_leaf


class DescriptorTests(unittest.TestCase):
    def test_diamond_metadata_has_exact_successors_and_bounds(self):
        data = struct.pack("<5I", 0x34000060, 0x11000400, 0xD65F03C0, 0x52800540, 0xD65F03C0)
        proof = verify_leaf(data, 0x1000000)
        self.assertEqual(proof["control_flow"], [{"next": [3, 1], "max_steps": 3},
            {"next": [2], "max_steps": 2}, {"next": [], "max_steps": 1},
            {"next": [4], "max_steps": 2}, {"next": [], "max_steps": 1}])
        source = emit_leaf_descriptor(data, 0x1000000, "oot_lift_diamond")
        self.assertIn("oot_leaf_descriptor_diamond(void)", source)
        self.assertIn("OOT_LIFT_ABI_VERSION, OOT_LEAF_POLICY_VERSION, oot_lift_diamond", source)

    def test_descriptor_requires_verified_leaf_and_safe_identifier(self):
        for name in ("main", "oot_lift_x;attack", "oot_lift_"):
            with self.assertRaises(InputError):
                emit_leaf_descriptor(struct.pack("<I", 0xD65F03C0), 0x1000000, name)
        with self.assertRaises(InputError):
            emit_leaf_descriptor(struct.pack("<II", 0xF9400020, 0xD65F03C0), 0x1000000, "oot_lift_memory")


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "install tools/requirements-lifter.txt for dispatcher reference tests")
class NativeDispatchTests(unittest.TestCase):
    def test_generated_leaves_callers_yields_and_rejected_states(self):
        report, path = run_validation(os.environ.get("OOT_LIFTER_COMPILER", "cmake"))
        self.assertEqual(report["result"], "passed")
        self.assertEqual(report["leaf_result_cases"], 768)
        self.assertEqual(report["caller_chain_cases"], 128)
        self.assertGreaterEqual(report["guard_cases"], 17)
        self.assertGreater(report["yield_checks"]["zero_budget_yields"], 0)
        self.assertGreater(report["yield_checks"]["budget_yields"], 0)
        self.assertTrue(path.is_file())


if __name__ == "__main__":
    unittest.main()
