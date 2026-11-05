"""Artificial ARM64 code and metadata only; no captured game instructions."""

import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from arm64_analysis import analyze_module, plt_stubs, relocated_code_seeds, unwind_entries
from arm64_decode import (CALL, CONDITIONAL, INDIRECT_CALL, INDIRECT_JUMP, JUMP, NORMAL, RETURN,
                          TRAP, Decoder, direct_target, family, flow_kind, literal_reference)
from input_formats import InputError
from module_linker import Linker, Module
from prepare_exefs import prepare
from test_module_linker import change_memory, fixture, symbol

HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None
RET = 0xD65F03C0
NOP = 0xD503201F


def branch(pc, target, call=False):
    return (0x94000000 if call else 0x14000000) | (((target - pc) // 4) & 0x3FFFFFF)


def synthetic_module(instructions=None, **kwargs):
    raw = fixture(**kwargs)
    # This fixture has no unwind table unless a test adds one explicitly.
    raw = change_memory(raw, 0x94, struct.pack("<i", 0x1100 - 0x80))
    for offset, word in (instructions or {0: branch(0, 0x40), 0x40: RET}).items():
        raw = change_memory(raw, offset, struct.pack("<I", word))
    return raw


def plt_fixture(name):
    instructions = {0: branch(0, 0x40), 0x40: branch(0x40, 0xC0, True), 0x44: RET,
                    0xC0: 0xD0000010, 0xC4: 0xF9400211, 0xC8: 0x91000210, 0xCC: 0xD61F0220}
    caller = Module("main", synthetic_module(instructions, symbols=[symbol(name, section=0, value=0, size=0)],
                                             plt=((0x2000, 1026, 1, 0),)))
    owner = Module("sdk", synthetic_module(symbols=[symbol(name)]))
    linker = Linker([caller, owner])
    assert linker.apply()["link_complete"]
    return caller, owner


class EncodingTests(unittest.TestCase):
    def test_signed_direct_branches(self):
        self.assertEqual(flow_kind(branch(0x40, 0x20), "b"), JUMP)
        self.assertEqual(direct_target(branch(0x40, 0x20), 0x40), 0x20)
        self.assertEqual(flow_kind(branch(0x40, 0x80, True), "bl"), CALL)
        self.assertEqual(direct_target(branch(0x40, 0x80, True), 0x40), 0x80)

    def test_compare_and_test_branches(self):
        self.assertEqual(flow_kind(0xB4000080, "cbz"), CONDITIONAL)
        self.assertEqual(direct_target(0xB4000080, 0x44), 0x54)
        self.assertEqual(flow_kind(0x36000040, "tbz"), CONDITIONAL)
        self.assertEqual(direct_target(0x36000040, 0x40), 0x48)

    def test_conditional_branch_negative_offset(self):
        word = 0x54000000 | ((-4 & 0x7FFFF) << 5)
        self.assertEqual(direct_target(word, 0x40), 0x30)

    def test_indirect_return_and_trap(self):
        self.assertEqual(flow_kind(0xD63F0100, "blr"), INDIRECT_CALL)
        self.assertEqual(flow_kind(0xD61F0100, "br"), INDIRECT_JUMP)
        self.assertEqual(flow_kind(RET, "ret"), RETURN)
        self.assertEqual(flow_kind(0xD65F0BFF, "retaa"), RETURN)
        self.assertEqual(flow_kind(0xD4200000, "brk"), TRAP)
        self.assertEqual(flow_kind(0xD4000021, "svc"), NORMAL)

    def test_literal_widths_and_prefetch(self):
        self.assertEqual(literal_reference(0x58000141, 0x48), (0x70, 8))
        self.assertEqual(literal_reference(0x1C000040, 0x40), (0x48, 4))
        self.assertIsNone(literal_reference(0xD8000000, 0))

    def test_families_are_not_semantic_coverage(self):
        self.assertEqual(family(0x91000400, "add", NORMAL), 1)
        self.assertEqual(family(0xC85F7C20, "ldxr", NORMAL), 8)
        self.assertEqual(family(0xD503233F, "paciasp", NORMAL), 7)
        self.assertEqual(family(0x1E222820, "fadd", NORMAL), 4)
        self.assertEqual(family(0xD4000021, "svc", NORMAL), 6)


class MetadataTests(unittest.TestCase):
    def test_unwind_table_entries(self):
        raw = synthetic_module({0: branch(0, 0x40), 0x40: RET, 0x60: RET})
        data = b"\x01\x1b\x03\x3b" + struct.pack("<iI", 0x1B00 - 0x1104, 2)
        data += struct.pack("<4i", 0x40 - 0x1100, 0x1B00 - 0x1100, 0x60 - 0x1100, 0x1B04 - 0x1100)
        raw = change_memory(raw, 0x1100, data)
        raw = change_memory(raw, 0x94, struct.pack("<i", 0x1100 + len(data) - 0x80))
        self.assertEqual(unwind_entries(Module("main", raw)), [0x40, 0x60])

    def test_truncated_unwind_table(self):
        raw = synthetic_module()
        raw = change_memory(raw, 0x1100, b"\x01\x1b\x03\x3b" + struct.pack("<iI", 0x1B00 - 0x1104, 100))
        raw = change_memory(raw, 0x94, struct.pack("<i", 0x1110 - 0x80))
        with self.assertRaisesRegex(InputError, "exceeds"):
            unwind_entries(Module("main", raw))

    def test_plt_name_and_resolved_slot(self):
        caller, owner = plt_fixture("setjmp")
        found = plt_stubs(caller)
        self.assertEqual(found[0xC0]["symbol"], "setjmp")
        self.assertEqual(found[0xC0]["got_offset"], 0x2000)
        self.assertEqual(found[0xC0]["resolved_address"], f"0x{owner.base + 0x40:x}")

    def test_bad_plt_add_is_not_accepted(self):
        raw = synthetic_module({0: branch(0, 0x40), 0x40: RET, 0xC0: 0xD0000010, 0xC4: 0xF9400211,
                                0xC8: 0x91002210, 0xCC: 0xD61F0220},
                               symbols=[symbol("own")], rela=((0x2000, 257, 1, 0),))
        self.assertEqual(plt_stubs(Module("main", raw)), {})

    def test_relocated_code_pointer_candidates(self):
        module = Module("main", synthetic_module({0: branch(0, 0x40), 0x40: RET, 0x60: RET},
                                                 rela=((0x2000, 1027, 0, 0x60),)))
        Linker([module]).apply()
        self.assertEqual(relocated_code_seeds([module]), {"main": {0x60}})


@unittest.skipUnless(HAS_CAPSTONE, "install tools/requirements-analysis.txt for decoder integration tests")
class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()

    def test_cfg_keeps_skipped_literal_pool_out_of_code(self):
        code = {0: branch(0, 0x40), 0x40: branch(0x40, 0x60, True), 0x44: 0xB4000080,
                0x48: 0x58000141, 0x4C: branch(0x4C, 0x58), 0x50: NOP, 0x54: NOP,
                0x58: RET, 0x60: 0x91000400, 0x64: RET, 0x70: NOP, 0x74: NOP}
        module = Module("main", synthetic_module(code))
        Linker([module]).apply()
        result = analyze_module(module, self.decoder)
        self.assertEqual(result["discovered_code_words"], 9)
        self.assertEqual(result["literal_candidate_words"], 2)
        self.assertEqual(result["function_entry_candidate_count"], 3)
        self.assertEqual(result["control_flow"]["direct_call"], 1)
        self.assertFalse(result["all_code_discovered"])
        self.assertEqual(result["lifter_implemented_instruction_count"], 0)

    def test_undecoded_frontier_is_not_silently_skipped(self):
        module = Module("main", synthetic_module({0: branch(0, 0x40), 0x40: 0xFFFFFFFF, 0x44: RET}))
        result = analyze_module(module, self.decoder)
        self.assertEqual(result["undecoded_code_frontiers"], 1)
        self.assertEqual(result["unknown_samples"][0]["offset"], 0x40)
        self.assertEqual(result["discovered_code_words"], 1)

    def test_indirect_jump_stops_while_indirect_call_continues(self):
        jump = Module("main", synthetic_module({0: branch(0, 0x40), 0x40: 0xD61F0100, 0x44: RET}))
        call = Module("main", synthetic_module({0: branch(0, 0x40), 0x40: 0xD63F0100, 0x44: RET}))
        a, b = analyze_module(jump, self.decoder), analyze_module(call, self.decoder)
        self.assertEqual(a["unresolved_indirect_branches"], 1)
        self.assertEqual(a["discovered_code_words"], 2)
        self.assertEqual(b["unresolved_indirect_calls"], 1)
        self.assertEqual(b["discovered_code_words"], 3)

    def test_svc_and_system_registers(self):
        code = {0: branch(0, 0x40), 0x40: 0xD4000021, 0x44: 0xD53BD040, 0x48: RET}
        result = analyze_module(Module("main", synthetic_module(code)), self.decoder)
        self.assertEqual(result["svc_immediates"], {"1": 1})
        self.assertEqual(result["mnemonics"]["mrs"], 1)

    def test_setjmp_call_continuation_is_reported(self):
        caller, _ = plt_fixture("setjmp")
        result = analyze_module(caller, self.decoder)
        self.assertEqual(result["nonlocal_direct_calls"][0]["symbol"], "setjmp")
        self.assertEqual(result["nonlocal_direct_calls"][0]["continuation_offset"], 0x44)
        self.assertEqual(result["control_flow"]["resolved_plt_dispatch"], 1)
        self.assertFalse(result["nonlocal_runtime_implemented"])

    def test_longjmp_has_no_normal_fallthrough(self):
        caller, _ = plt_fixture("longjmp")
        result = analyze_module(caller, self.decoder)
        self.assertIsNone(result["nonlocal_direct_calls"][0]["continuation_offset"])
        self.assertEqual(result["control_flow"].get("return", 0), 0)

    def test_conditional_branch_to_longjmp_keeps_fallthrough(self):
        code = {0: branch(0, 0x40), 0x40: 0x54000400, 0x44: RET,
                0xC0: 0xD0000010, 0xC4: 0xF9400211, 0xC8: 0x91000210, 0xCC: 0xD61F0220}
        caller = Module("main", synthetic_module(code, symbols=[symbol("longjmp", section=0, value=0, size=0)],
                                                 plt=((0x2000, 1026, 1, 0),)))
        owner = Module("sdk", synthetic_module(symbols=[symbol("longjmp")]))
        Linker([caller, owner]).apply()
        result = analyze_module(caller, self.decoder)
        self.assertEqual(result["control_flow"]["conditional_branch"], 1)
        self.assertEqual(result["control_flow"]["return"], 1)

    def test_metadata_candidate_after_indirect_boundary(self):
        code = {0: branch(0, 0x40), 0x40: 0xD61F0100, 0x60: RET}
        module = Module("main", synthetic_module(code, symbols=[symbol("callback", value=0x60)]))
        result = analyze_module(module, self.decoder)
        self.assertEqual(result["discovered_code_words"], 3)
        self.assertEqual(result["candidate_source_counts"]["function_symbol"], 1)

    def test_literal_and_code_conflict_remains_visible(self):
        code = {0: branch(0, 0x40), 0x40: 0x18000040, 0x44: RET, 0x48: RET}
        module = Module("main", synthetic_module(code, symbols=[symbol("callback", value=0x48)]))
        result = analyze_module(module, self.decoder)
        self.assertEqual(result["code_literal_conflict_words"], 1)

    def test_partition_and_determinism(self):
        module = Module("main", synthetic_module())
        a, b = analyze_module(module, self.decoder), analyze_module(module, self.decoder)
        self.assertEqual(a, b)
        self.assertEqual(a["text_words"], a["discovered_code_words"] + a["undecoded_code_frontiers"] +
                         a["literal_candidate_words"] + a["unclassified_words"])

    def test_cli_census_report(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            base = Path(temporary)
            (base / "main").write_bytes(synthetic_module())
            prepared = base / "prepared"
            prepare(base / "main", prepared)
            report = base / "report.json"
            result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/analyze_arm64.py"), str(prepared),
                                     "--report", str(report)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(report.read_text())
            self.assertFalse(data["guest_code_executed"])
            self.assertFalse(data["lifter_implemented"])
            self.assertEqual(len(data["modules"]), 1)


if __name__ == "__main__":
    unittest.main()
