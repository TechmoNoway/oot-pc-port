"""Startup evidence uses synthetic metadata and never executes guest code."""

import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from input_formats import InputError
from module_linker import Linker, Module
from startup_audit import audit_entry, audit_startup, _array
from test_arm64_analysis import branch, synthetic_module, plt_fixture, RET
from test_module_linker import change_memory


def linked(instructions=None):
    linker = Linker([Module("main", synthetic_module(instructions))])
    assert linker.apply()["link_complete"]
    return linker


class StartupAuditTests(unittest.TestCase):
    def test_entry_header_and_exact_original_hashes_without_mutation(self):
        linker = linked({0: branch(0, 0x40), 0x40: RET})
        module = linker.modules[0]
        before = bytes(module.image)
        report = audit_startup(linker)
        self.assertEqual(report["format"], "oot-startup-audit")
        self.assertTrue(report["entry_evidence"]["original_header_branch"])
        self.assertEqual(report["entry_evidence"]["branch_target"], module.base + 0x40)
        self.assertEqual(report["modules"][0]["linked_text_sha256"],
                         hashlib.sha256(before[:256]).hexdigest())
        self.assertEqual([n["offset"] for n in report["entry_graph"]["nodes"]], [0, 0x40])
        self.assertFalse(report["entry_graph"]["runtime_path_proven"])
        self.assertFalse(report["startup_abi_proven"])
        self.assertFalse(report["guest_code_executed"])
        self.assertEqual(bytes(module.image), before)

    def test_direct_calls_both_condition_edges_and_service_stop(self):
        # CBNZ X0,+0x50; caller's possible continuation remains diagnostic.
        linker = linked({0: branch(0, 0x40), 0x40: 0xb5000080,
                         0x44: branch(0x44, 0x60, True), 0x48: RET,
                         0x50: 0xd4000501, 0x54: RET, 0x60: RET})
        report = audit_startup(linker)
        graph = report["entry_graph"]
        nodes = {n["offset"]: n for n in graph["nodes"]}
        self.assertEqual(set(nodes), {0, 0x40, 0x44, 0x48, 0x50, 0x60})
        self.assertEqual(nodes[0x50]["service_immediate"], 0x28)
        self.assertEqual(nodes[0x50]["edges"], [])
        self.assertTrue(nodes[0x44]["continuation_requires_return"])
        self.assertFalse(graph["services"][0]["runtime_path_proven"])
        self.assertEqual(graph["frontier_counts"], {"supervisor_call_boundary": 1})

    def test_indirect_snapshot_is_not_followed_or_approved(self):
        caller, owner = plt_fixture("startup_target")
        linker = Linker([caller, owner])
        linker.applied = True  # plt_fixture already performed this exact offline link.
        graph = audit_startup(linker)["entry_graph"]
        node = next(n for n in graph["nodes"] if n["offset"] == 0xcc)
        self.assertEqual(node["edges"], [])
        self.assertEqual(node["plt_snapshot"]["linked_snapshot_target"], owner.base + 0x40)
        self.assertFalse(node["plt_snapshot"]["live_target_proven"])
        self.assertFalse(any(n["module"] == "sdk" for n in graph["nodes"]))

    def test_initializer_slots_keep_null_sentinel_duplicates_and_order(self):
        linker = linked()
        module = linker.modules[0]
        values = [0, (1 << 64) - 1, module.base + 0x40, module.base + 0x40,
                  module.base + 0x44, module.base + 0x2000]
        module.dynamic[25], module.dynamic[27] = 0x2080, len(values) * 8
        module.image[0x2080:0x2080 + len(values) * 8] = struct.pack("<6Q", *values)
        array = _array(module, linker.modules, 25, 27, "init")
        self.assertEqual([s["value"] for s in array["slots"]], values)
        self.assertEqual(array["classification"],
                         {"null": 1, "sentinel": 1, "code": 3,
                          "non_code": 1, "duplicate_code_slots": 1})
        self.assertEqual(array["unique_code_targets"], 2)
        self.assertFalse(array["execution_order_proven"])
        self.assertTrue(array["slots"][3]["duplicate_code_slot"])
        module.dynamic[27] -= 1
        with self.assertRaises(InputError):
            _array(module, linker.modules, 25, 27, "init")

    def test_raw_entry_allowed_but_raw_initializer_resolution_rejected(self):
        module = Module("main", synthetic_module())
        linker = Linker([module])
        report = audit_entry(linker)
        self.assertEqual(report["image_state"], "raw")
        self.assertEqual(report["entry_graph"]["instruction_count"], 2)
        with self.assertRaises(InputError):
            audit_startup(linker)
        linker.apply()
        self.assertEqual(audit_entry(linker)["image_state"], "offline-linked")

    def test_system_and_unsupported_boundaries_and_limits(self):
        linker = linked({0: branch(0, 0x40), 0x40: 0xd53bd040, 0x44: RET})
        report = audit_startup(linker, max_instructions=1, sample_limit=0)
        self.assertTrue(report["entry_graph"]["truncated"])
        self.assertEqual(report["frontier_samples"], [])
        report = audit_startup(linker)
        self.assertEqual(report["entry_graph"]["frontier_counts"], {"unsupported_semantics": 1})
        self.assertEqual(len(report["entry_graph"]["system_register_boundaries"]), 1)
        for count in (0, 65537, True):
            with self.subTest(count=count), self.assertRaises(InputError):
                audit_startup(linker, max_instructions=count)

    def test_explicit_diagnostic_roots_remain_separate_and_bounded(self):
        linker = linked({0: branch(0, 0x40), 0x40: RET, 0x60: 0xd4000501})
        base = linker.modules[0].base
        report = audit_entry(linker, extra_entries=[base + 0x60])
        graph = report["entry_graph"]
        self.assertEqual(graph["entry"], base)
        self.assertEqual(graph["additional_entries"], [base + 0x60])
        self.assertEqual(set(n["offset"] for n in graph["nodes"]), {0, 0x40, 0x60})
        self.assertIn("diagnostic", graph["root_provenance"][1]["selection"])
        for roots in ([base + 1], [base + 0x2000], [base], [base + 0x60] * 2,
                      [base + 0x60] * 257, [True]):
            with self.subTest(roots=roots[:2]), self.assertRaises(InputError):
                audit_entry(linker, extra_entries=roots)

    def test_cli_rejects_paths_outside_private_build_root(self):
        destination = ROOT / "startup-audit-should-not-exist.json"
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/audit_startup.py"),
                                 "missing", "--report", str(destination)],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Output must be", result.stderr)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
