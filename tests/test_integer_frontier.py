"""One combined integer-frontier milestone, including actual PAC/PLT factories."""

import binascii
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from arm64_lifter import decode_instruction, UnsupportedInstruction
from call_validation import LrAssembler
from dispatcher_validation import EXIT, STACK_SIZE
from input_formats import InputError
from integer_frontier_programs import extract, crc_word, extract_result, crc_result
from integer_validation import select
from leaf_verifier import verify_leaf
from lifter_validation_types import Program
from module_linker import Linker, Module
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from pauth_validation import Reference
from prepare_registry import build_bundle
from test_arm64_analysis import branch, synthetic_module
from test_module_linker import symbol
import test_multiply_long as call_tests


def bundle_fixture(explicit=False):
    root = LrAssembler("integer_root", 0x10, 64, 19, key=int(explicit), explicit_auth=explicit)
    root.emit(extract(1, 19, 0, 0, 17)); root.bl(0x40)
    root.emit(crc_word(1, 3, 0, 0, 3), select(1, 0, 0, 0, 4, 0))
    child = PauthAssembler("integer_child", 0x40, 64, 48, key=1-int(explicit), explicit_auth=not explicit)
    child.emit(crc_word(0, 3, 0, 19, 5)); child.bl(0xC0)
    child.emit(extract(1, 0, 0, 7, 63), select(1, 0, 0, 0, 9, 6))
    r, c = root.finish(), child.finish()
    leaf = Program("integer_leaf", [crc_word(poly, size, 0, 0, 1+poly*4+size) for poly in (0, 1) for size in range(4)]+
                   [extract(0, 10, 0, 0, 7), extract(1, 0, 10, 0, 13), 0xD65F03C0], [], base=0x40)
    stub = Program("integer_stub", [0xD0000010, 0xF9400211, 0x91000210, 0xD61F0220], [], base=0xC0)
    words = {0: branch(0, r.base)}
    for p in (r, c, stub): words.update({p.base+4*i: word for i, word in enumerate(p.words)})
    raw = synthetic_module(words, symbols=[symbol("integer_helper", section=0, value=0, size=0),
        symbol(r.name, value=r.base, size=len(r.data)), symbol(c.name, value=c.base, size=len(c.data))], plt=((0x2000, 1026, 1, 0),))
    sdk = synthetic_module({0: branch(0, leaf.base), **{leaf.base+4*i: word for i, word in enumerate(leaf.words)}},
                           symbols=[symbol("integer_helper", value=leaf.base, size=len(leaf.data))])
    linker = Linker([Module("main", raw), Module("sdk", sdk)]); assert linker.apply()["link_complete"]
    config = {"schema_version": 8, "pauth_model": MODEL, "root": r.name, "return_sites": [EXIT], "stack_size": STACK_SIZE,
        "frames": [{"name": p.name, "module": "main", "offset": p.base, "size": len(p.data)} for p in (r, c)],
        "leaves": [{"name": leaf.name, "module": "sdk", "offset": leaf.base, "size": len(leaf.data)}],
        "plts": [{"name": stub.name, "module": "main", "offset": stub.base, "leaf": leaf.name}],
        "read_ranges": [{"module": "main", "offset": 0x2100, "size": 8}]}
    programs = [Program(p.name, p.words, [], base=linker.modules[module].base+p.base)
                for p, module in ((r, 0), (c, 0), (stub, 0), (leaf, 1))]
    return linker, config, programs


def expected_call(r, flags):
    saved = extract_result(r[0], r[0], 64, 17)
    value = crc_result(saved, r[5], 64, 0)
    for poly in (0, 1):
        for size in range(4): value = crc_result(value, r[1+poly*4+size], 8 << size, poly)
    rotated = extract_result(value, value, 32, 7)
    value = extract_result(rotated, value, 64, 13)
    value = extract_result(value, r[7], 64, 63)
    if not flags & (1 << 28): value = r[9]
    value = crc_result(value, r[3], 64, 1)
    return value if flags & (1 << 30) else r[4]


class IntegerFrontierTests(unittest.TestCase):
    def test_extract_known_words_and_boundaries(self):
        ins = decode_instruction(0x93C11C20, 0x1000)
        self.assertEqual((ins.form, ins.width, ins.rd, ins.rn, ins.rm, ins.amount), ("extract_register", 64, 0, 1, 1, 7))
        for sf in (0, 1):
            width = 64 if sf else 32
            for amount in range(width):
                for r in range(32):
                    i = decode_instruction(extract(sf, r, 31-r, r, amount), 0x1000)
                    self.assertEqual((i.width, i.rd, i.rn, i.rm, i.amount), (width, r, 31-r, r, amount))
            for word in (extract(sf, 0, 1, 2, 0) ^ (1 << 22), extract(sf, 0, 1, 2, 0) | (1 << 21),
                         extract(sf, 0, 1, 2, 0) | (1 << 29)):
                with self.assertRaises(UnsupportedInstruction): decode_instruction(word, 0x1000)
        with self.assertRaises(UnsupportedInstruction): decode_instruction(extract(0, 0, 1, 2, 32), 0x1000)
        self.assertEqual(extract_result(0x123456789ABCDEF0, 0xFEDCBA9876543210, 64, 0), 0xFEDCBA9876543210)
        self.assertEqual(extract_result(1, 0, 64, 63), 2)

    def test_crc_exact_sizes_polynomials_fields_and_rejected_sf(self):
        for c in (0, 1):
            for size in range(4):
                for r in range(32):
                    i = decode_instruction(crc_word(c, size, r, 31-r, r), 0x1000)
                    self.assertEqual((i.form, i.width, i.rd, i.rn, i.rm, i.access_size, i.operation),
                                     ("crc32", 32, r, 31-r, r, 1 << size, c))
                with self.assertRaises(UnsupportedInstruction): decode_instruction(crc_word(c, size, 0, 1, 2) ^ (1 << 31), 0x1000)
                for bit in (29, 15):
                    with self.assertRaises(UnsupportedInstruction): decode_instruction(crc_word(c, size, 0, 1, 2) ^ (1 << bit), 0x1000)

    def test_crc_polynomial_oracle_known_vectors_and_byte_chaining(self):
        data = b"123456789"
        for poly, expected in ((0, 0xCBF43926), (1, 0xE3069283)):
            acc = 0xFFFFFFFF
            for byte in data: acc = crc_result(acc, byte, 8, poly)
            self.assertEqual(acc ^ 0xFFFFFFFF, expected)
            for size in (16, 32, 64):
                value = 0x0123456789ABCDEF & ((1 << size)-1)
                bytewise = 0xA55ACAFE
                for byte in value.to_bytes(size//8, "little"): bytewise = crc_result(bytewise, byte, 8, poly)
                self.assertEqual(crc_result(0xFFFF0000A55ACAFE, value, size, poly), bytewise)
        self.assertEqual(binascii.crc32(data), 0xCBF43926)

    def test_reference_crc_feature_is_enabled_in_pac_factory_model(self):
        ref = Reference()
        self.assertGreaterEqual((ref.u.cpr_read(3, 0, 0, 6, 0) >> 16) & 15, 1)

    def test_protected_destinations_remain_rejected(self):
        for rd in range(32):
            for word in (extract(1, rd, 29, 30, 0), extract(0, rd, 29, 30, 31), crc_word(1, 3, rd, 29, 30)):
                code = struct.pack("<II", word, 0xD65F03C0)
                if 18 <= rd <= 30:
                    with self.assertRaises(InputError): verify_leaf(code, 0x1000)
                else: self.assertFalse(verify_leaf(code, 0x1000)["memory_access"])

    def test_actual_mixed_factory_keeps_original_words(self):
        for explicit in (False, True):
            linker, config, _ = bundle_fixture(explicit); before = [bytes(m.image) for m in linker.modules]
            _, _, manifest = build_bundle(linker, config)
            self.assertEqual(manifest["schema_version"], 8); self.assertFalse(manifest["guest_code_executed"])
            self.assertEqual([bytes(m.image) for m in linker.modules], before)


class NativeIntegerFrontierTests(call_tests.NativeMultiplyLongTests):
    bundle_fixture = staticmethod(bundle_fixture)
    expected_call = staticmethod(expected_call)
    report_name = "integer-frontier"
    expected_prefixes = 8960


if __name__ == "__main__": unittest.main()
