"""Synthetic integer encodings, generated native C, and independent ARM64 reference."""

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
from arm64_lifter import (FORMS, MAX_WORDS, U64, UnsupportedInstruction, decode_block,
                         decode_instruction, emit_c)
from input_formats import InputError
from lifter_validation import BASE, State, run_validation, synthetic_programs


class SemanticDecoderTests(unittest.TestCase):
    def test_known_add_and_compare_aliases(self):
        add = decode_instruction(0x91000420, BASE)  # add x0,x1,#1
        self.assertEqual((add.form, add.width, add.rn, add.rd, add.immediate),
                         ("addsub_immediate", 64, 1, 0, 1))
        compare = decode_instruction(0x7100041F, BASE)  # cmp w0,#1
        self.assertEqual((compare.width, compare.operation, compare.flags, compare.rd), (32, 1, True, 31))

    def test_sp_and_zero_register_context_is_emitted_explicitly(self):
        code, _ = emit_c(struct.pack("<II", 0x910043FF, 0xEB1F03FF), BASE)
        self.assertIn("oot_arm64_read(s, 31, 64, 1)", code)  # add sp,sp,#16
        self.assertIn("oot_arm64_write(s, 31, 64, 1, r)", code)
        self.assertIn("oot_arm64_read(s, 31, 64, 0)", code)  # cmp xzr,xzr
        self.assertIn("oot_arm64_write(s, 31, 64, 0, r)", code)

    def test_move_wide_width_and_upper_half(self):
        ins = decode_instruction(0xF2E24680, BASE)  # movk x0,#0x1234,lsl #48
        self.assertEqual((ins.form, ins.width, ins.operation, ins.amount, ins.immediate),
                         ("move_wide", 64, 3, 48, 0x1234000000000000))

    def test_pc_relative_negative_and_page_relative(self):
        self.assertEqual(decode_instruction(0x10FFFFE0, BASE).target, BASE - 4)  # adr x0,.-4
        self.assertEqual(decode_instruction(0xF0FFFFE0, BASE + 0x234).target, BASE - 0x1000)

    def test_signed_branch_offsets_and_address_wrapping(self):
        self.assertEqual(decode_instruction(0x17FFFFFF, BASE).target, BASE - 4)
        self.assertEqual(decode_instruction(0x17FFFFFF, 0).target, U64 - 3)
        self.assertEqual(decode_instruction(0x5400000F, BASE).operation, 15)

    def test_indirect_link_captures_x30_before_overwrite(self):
        code, _ = emit_c(struct.pack("<I", 0xD63F03C0), BASE)  # blr x30
        self.assertLess(code.index("uint64_t target ="), code.index("s->x[30] ="))

    def test_reserved_and_unimplemented_forms_are_rejected(self):
        unsupported = [0, 0xFFFFFFFF, 0x32800000, 0x52C00000, 0x0BC00000,
                       0x0B008000, 0x0A008000, 0x91800000, 0x54000010,
                       0x8B200000, 0xA9400000, 0xD4000001, 0xD503233F]
        for word in unsupported:
            with self.subTest(word=hex(word)), self.assertRaises(UnsupportedInstruction):
                decode_instruction(word, BASE)

    def test_input_range_and_word_bounds(self):
        for data, base in ((b"", BASE), (b"abc", BASE), (b"\0" * (MAX_WORDS * 4 + 4), BASE),
                           (b"\0" * 4, -4), (b"\0" * 4, BASE + 1), (b"\0" * 4, U64 - 3)):
            with self.subTest(size=len(data), base=base), self.assertRaises(InputError):
                decode_block(data, base)
        for word in (-1, 1 << 32):
            with self.assertRaises(InputError):
                decode_instruction(word, BASE)

    def test_generated_report_and_budget_dispatch_contract(self):
        code, report = emit_c(struct.pack("<II", 0xD503201F, 0xD65F03C0), BASE)
        self.assertEqual(report["forms"], {"nop": 1, "branch_register": 1})
        self.assertFalse(report["guest_memory_access"])
        self.assertFalse(report["game_runtime_ready"])
        self.assertIn("return OOT_LIFT_BUDGET", code)
        self.assertIn("default: *executed = count; return OOT_LIFT_DISPATCH;", code)

    def test_function_name_rejects_c_injection_and_reserved_names(self):
        for name in ("main", "_reserved", "oot_lift_a;bad()", "oot_lift_", "oot_lift_é"):
            with self.subTest(name=name), self.assertRaises(InputError):
                emit_c(struct.pack("<I", 0xD503201F), BASE, name)

    def test_synthetic_programs_cover_every_semantic_form(self):
        forms = {ins.form for p in synthetic_programs() for ins in decode_block(p.data, p.base)}
        self.assertEqual(forms, set(FORMS))

    def test_ctypes_guest_state_layout_matches_c_integer_abi(self):
        self.assertEqual(State.sp.offset, 248)
        self.assertEqual(State.pc.offset, 256)
        self.assertEqual(State.nzcv.offset, 264)


class MemoryDecoderTests(unittest.TestCase):
    def test_unsigned_load_and_store_width_and_scale(self):
        ins = decode_instruction(0xF9400420, BASE)  # ldr x0,[x1,#8]
        self.assertEqual((ins.form, ins.width, ins.access_size, ins.immediate, ins.rn, ins.rd, ins.load),
                         ("loadstore_unsigned", 64, 8, 8, 1, 0, True))
        store = decode_instruction(0x7900043F, BASE)  # strh wzr,[x1,#2]
        self.assertEqual((store.width, store.access_size, store.immediate, store.rd, store.load),
                         (32, 2, 2, 31, False))

    def test_sign_extension_has_explicit_destination_width(self):
        for word, access, width in ((0x39800020, 1, 64), (0x39C00020, 1, 32),
                                    (0x79800020, 2, 64), (0x79C00020, 2, 32), (0xB9800020, 4, 64)):
            with self.subTest(word=hex(word)):
                ins = decode_instruction(word, BASE)
                self.assertEqual((ins.sign_extend, ins.access_size, ins.width), (True, access, width))

    def test_pre_post_and_unscaled_signed_offsets(self):
        for word, immediate, wb, post in ((0xF85F8C20, -8, True, False),
                                         (0xF8408420, 8, True, True), (0xF85F8020, -8, False, False)):
            with self.subTest(word=hex(word)):
                ins = decode_instruction(word, BASE)
                self.assertEqual((ins.immediate, ins.writeback, ins.post_index), (immediate, wb, post))

    def test_register_offset_extension_and_scale(self):
        ins = decode_instruction(0xF8625820, BASE)  # ldr x0,[x1,w2,uxtw #3]
        self.assertEqual((ins.form, ins.rn, ins.rm, ins.extend, ins.amount),
                         ("loadstore_register", 1, 2, 2, 3))

    def test_literal_address_and_load_width(self):
        for word, width, access, signed in ((0x18FFFFE0, 32, 4, False),
                                           (0x58FFFFE0, 64, 8, False), (0x98FFFFE0, 64, 4, True)):
            ins = decode_instruction(word, BASE)
            self.assertEqual((ins.target, ins.width, ins.access_size, ins.sign_extend),
                             (BASE - 4, width, access, signed))

    def test_reject_reserved_unprivileged_vector_atomic_and_overlap_forms(self):
        for word in (0xF9800020, 0xF9C00020, 0xB9C00020, 0xD8000000, 0x3D400020,
                     0xF8620820, 0xF8200020, 0xF8400820, 0xF8400C21, 0xF8000C21, 0xC85F7C20):
            with self.subTest(word=hex(word)), self.assertRaises(UnsupportedInstruction):
                decode_instruction(word, BASE)
        # XZR and SP are distinct architectural registers despite sharing encoding 31.
        self.assertTrue(decode_instruction(0xF8400FFF, BASE).writeback)

    def test_memory_report_records_abi_and_access(self):
        _, report = emit_c(struct.pack("<I", 0xF9400420), BASE)
        self.assertEqual(report["abi_version"], 2)
        self.assertTrue(report["guest_memory_access"])
        self.assertFalse(report["game_runtime_ready"])


class TranslationCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-B", str(ROOT / "tools/lift_arm64.py"), *map(str, args)],
                              capture_output=True, text=True)

    def test_cli_translates_selected_range_and_reports_hash(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build", prefix="lifter-test-") as temporary:
            folder = Path(temporary)
            source, output, report = folder / "code.raw", folder / "code.c", folder / "report.json"
            source.write_bytes(struct.pack("<III", 0, 0xD503201F, 0xD65F03C0))
            result = self.run_cli(source, "--offset", 4, "--size", 8, "--base", hex(BASE),
                                  "--output", output, "--report", report)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(report.read_text())
            self.assertEqual((data["file_offset"], data["instruction_count"]), (4, 2))
            self.assertEqual(len(data["source_sha256"]), 64)
            self.assertFalse(data["guest_code_executed"])
            self.assertIn("oot_lift_run", output.read_text())
            # Never overwrite an existing source/report.
            self.assertNotEqual(self.run_cli(source, "--base", hex(BASE), "--output", output).returncode, 0)

    def test_unsupported_range_leaves_no_partial_output(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build", prefix="lifter-test-") as temporary:
            folder = Path(temporary)
            source, output = folder / "code.raw", folder / "code.c"
            source.write_bytes(struct.pack("<II", 0xD503201F, 0xA9400000))
            result = self.run_cli(source, "--base", hex(BASE), "--output", output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("0xa9400000", result.stderr)
            self.assertFalse(output.exists())

    def test_output_must_stay_under_build(self):
        result = self.run_cli(ROOT / "README.md", "--base", hex(BASE), "--output", ROOT / "never-write.c")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("under the project build", result.stderr)
        self.assertFalse((ROOT / "never-write.c").exists())


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "install tools/requirements-lifter.txt for native differential tests")
class NativeDifferentialTests(unittest.TestCase):
    def test_generated_c_matches_unicorn_state_memory_and_faults(self):
        report, path = run_validation(os.environ.get("OOT_LIFTER_COMPILER", "cmake"))
        self.assertEqual(report["result"], "passed")
        self.assertGreater(report["trial_count"], 18000)
        self.assertGreater(report["memory_trial_count"], 5000)
        self.assertGreater(report["reference_fault_trial_count"], 100)
        self.assertIn("retry_after_mapping", report["memory_policy_checks"])
        self.assertTrue(path.is_file())


if __name__ == "__main__":
    unittest.main()
