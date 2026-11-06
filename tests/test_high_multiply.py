"""High-product encodings, arbitrary-precision math and actual PAC/PLT bundles."""

from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from arm64_lifter import decode_instruction, emit_c, UnsupportedInstruction
from call_validation import LrAssembler
from dispatcher_validation import EXIT, STACK_SIZE
from high_multiply_programs import multiply_high, high_product, MASK64
from input_formats import InputError
from integer_validation import select
from leaf_verifier import verify_leaf
from lifter_validation_types import Program
from module_linker import Linker, Module
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from prepare_registry import build_bundle
from test_arm64_analysis import branch, synthetic_module
from test_module_linker import symbol
import test_multiply_long as long_tests


def bundle_fixture(explicit=False):
    root = LrAssembler("high_root", 0x10, 64, 19, key=int(explicit), explicit_auth=explicit)
    root.emit(multiply_high(True, 19, 0, 1, 5)); root.bl(0x40)
    root.emit(multiply_high(False, 0, 0, 3, 0), select(1, 0, 0, 0, 4, 0))
    child = PauthAssembler("high_child", 0x40, 64, 48, key=1-int(explicit), explicit_auth=not explicit)
    child.emit(multiply_high(False, 0, 19, 5, 19)); child.bl(0xC0)
    child.emit(multiply_high(True, 0, 0, 7), select(1, 0, 0, 0, 9, 6))
    r, c = root.finish(), child.finish()
    leaf = Program("high_leaf", [multiply_high(True, 10, 0, 1, 4), multiply_high(False, 11, 2, 3, 0),
                   multiply_high(False, 0, 10, 11, 11), 0xD65F03C0], [], base=0x40)
    stub = Program("high_stub", [0xD0000010, 0xF9400211, 0x91000210, 0xD61F0220], [], base=0xC0)
    words = {0: branch(0, r.base)}
    for p in (r, c, stub): words.update({p.base+4*i: word for i, word in enumerate(p.words)})
    raw = synthetic_module(words, symbols=[symbol("high_helper", section=0, value=0, size=0),
        symbol(r.name, value=r.base, size=len(r.data)), symbol(c.name, value=c.base, size=len(c.data))],
        plt=((0x2000, 1026, 1, 0),))
    sdk = synthetic_module({0: branch(0, leaf.base), **{leaf.base+4*i: word for i, word in enumerate(leaf.words)}},
                           symbols=[symbol("high_helper", value=leaf.base, size=len(leaf.data))])
    linker = Linker([Module("main", raw), Module("sdk", sdk)])
    assert linker.apply()["link_complete"]
    config = {"schema_version": 8, "pauth_model": MODEL, "root": r.name, "return_sites": [EXIT], "stack_size": STACK_SIZE,
        "frames": [{"name": p.name, "module": "main", "offset": p.base, "size": len(p.data)} for p in (r, c)],
        "leaves": [{"name": leaf.name, "module": "sdk", "offset": leaf.base, "size": len(leaf.data)}],
        "plts": [{"name": stub.name, "module": "main", "offset": stub.base, "leaf": leaf.name}],
        "read_ranges": [{"module": "main", "offset": 0x2100, "size": 8}]}
    programs = [Program(p.name, p.words, [], base=linker.modules[module].base+p.base)
                for p, module in ((r, 0), (c, 0), (stub, 0), (leaf, 1))]
    return linker, config, programs


def expected_call(r, flags):
    saved = high_product(r[0], r[1], True)
    value = high_product(saved, r[5], False)
    value = high_product(high_product(value, r[1], True), high_product(r[2], r[3], False), False)
    value = high_product(value, r[7], True)
    if not flags & (1 << 28): value = r[9]
    value = high_product(value, r[3], False)
    return value if flags & (1 << 30) else r[4]


class HighMultiplyTests(unittest.TestCase):
    def test_known_signed_unsigned_words_and_ignored_ra(self):
        for word, signed, ra in ((0x9B427C20, True, 31), (0x9BC27C20, False, 31), (0x9B420020, True, 0)):
            ins = decode_instruction(word, 0x1000)
            self.assertEqual((ins.form, ins.width, ins.rd, ins.rn, ins.rm, ins.ra, ins.sign_extend, ins.flags),
                             ("multiply_high", 64, 0, 1, 2, ra, signed, False))

    def test_all_source_destination_fields_and_each_ignored_ra_value(self):
        for signed in (False, True):
            for rd in range(32):
                for rn in range(32):
                    for rm in range(32):
                        ra = (rd+rn+rm) % 32
                        ins = decode_instruction(multiply_high(signed, rd, rn, rm, ra), 0x1000)
                        self.assertEqual((ins.rd, ins.rn, ins.rm, ins.ra, ins.width, ins.sign_extend),
                                         (rd, rn, rm, ra, 64, signed))

    def test_fixed_bits_reject_w_flags_and_subtract_without_changing_other_multiply(self):
        for signed in (False, True):
            for bit in (31, 30, 29, 21, 15):
                with self.subTest(signed=signed, bit=bit), self.assertRaises(UnsupportedInstruction):
                    decode_instruction(multiply_high(signed, 0, 1, 2) ^ (1 << bit), 0x1000)
        self.assertEqual(decode_instruction(0x9B027C20, 0x1000).form, "multiply_add")
        self.assertEqual(decode_instruction(0x9B227C20, 0x1000).form, "multiply_long")

    def test_emission_uses_full_x_sources_but_never_uses_an_accumulator_or_sets_flags(self):
        for signed in (False, True):
            code, report = emit_c(struct.pack("<I", multiply_high(signed, 0, 1, 2, 3)), 0x1000)
            self.assertIn("oot_arm64_read(s, 1, 64, 0)", code)
            self.assertIn("oot_arm64_read(s, 2, 64, 0)", code)
            self.assertNotIn("oot_arm64_read(s, 3,", code)
            self.assertNotIn("accumulator", code)
            self.assertNotIn("s->nzcv =", code)
            self.assertFalse(report["guest_memory_access"])

    def test_independent_big_integer_boundary_results(self):
        self.assertEqual(high_product(MASK64, MASK64, False), MASK64-1)
        self.assertEqual(high_product(MASK64, MASK64, True), 0)
        self.assertEqual(high_product(1 << 63, 1 << 63, True), 1 << 62)
        self.assertEqual(high_product(1 << 63, 1, True), MASK64)
        self.assertEqual(high_product(1 << 63, MASK64, True), 0)
        self.assertEqual(high_product(1 << 32, 1 << 32, False), 1)
        self.assertEqual(high_product((1 << 32)-1, (1 << 32)-1, False), 0)

    def test_leaf_destination_and_stack_permissions_stay_unchanged(self):
        for signed in (False, True):
            for rd in range(32):
                code = struct.pack("<II", multiply_high(signed, rd, 29, 30, 18), 0xD65F03C0)
                if 18 <= rd <= 30:
                    with self.assertRaises(InputError): verify_leaf(code, 0x1000)
                else:
                    proof = verify_leaf(code, 0x1000)
                    self.assertEqual(proof["max_retired_instructions"], 2)
                    self.assertFalse(proof["memory_access"])
                    self.assertEqual(proof["protected_registers"], "x18-x30,sp")

    def test_actual_bundles_preserve_original_words_including_ignored_fields(self):
        for explicit in (False, True):
            linker, config, _ = bundle_fixture(explicit)
            before = [bytes(m.image) for m in linker.modules]
            _, source, manifest = build_bundle(linker, config)
            self.assertEqual(manifest["schema_version"], 8)
            self.assertIn("oot_stack_create_plt", source)
            self.assertFalse(manifest["guest_code_executed"])
            self.assertEqual([bytes(m.image) for m in linker.modules], before)


class NativeHighMultiplyTests(long_tests.NativeMultiplyLongTests):
    bundle_fixture = staticmethod(bundle_fixture)
    expected_call = staticmethod(expected_call)
    report_name = "high-multiply"


if __name__ == "__main__": unittest.main()
