"""Exact one-source encodings and synthetic mixed W/X PAC/PLT validation."""

from ctypes import byref, c_uint32, c_uint64, create_string_buffer, memset
import importlib.util
from importlib.metadata import version
import json
import os
from pathlib import Path
import random
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from arm64_lifter import decode_instruction, emit_c, UnsupportedInstruction
from bit_programs import bit_word, expected_value, variants, MASK64
from call_validation import LrAssembler
from dispatcher_validation import EXIT, Report, STACK_SIZE
from input_formats import InputError
from integer_validation import select
from leaf_verifier import verify_leaf
from lifter_validation import compile_library
from lifter_validation_types import Program, State
from module_linker import Linker, Module
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from plt_validation import PltReference, bindings
from prepare_registry import build_bundle
from test_arm64_analysis import branch, synthetic_module
from test_module_linker import symbol


def bundle_fixture(sf=1, explicit=False):
    suffix = str(sf)+str(int(explicit))
    reverse = 3 if sf else 2
    root = LrAssembler("bits_root"+suffix, 0x10, 64, 19, key=int(explicit), explicit_auth=explicit)
    root.emit(bit_word(sf, reverse, 19, 0)); root.bl(0x40)
    root.emit(bit_word(sf, 0, 0, 0), select(1, 0, 0, 0, 6, 0))
    child = PauthAssembler("bits_child"+suffix, 0x40, 64, 48, key=1-int(explicit), explicit_auth=not explicit)
    child.emit(bit_word(sf, 1, 0, 19)); child.bl(0xC0)
    child.emit(bit_word(sf, 4, 0, 0), select(1, 0, 0, 0, 7, 6))
    r, c = root.finish(), child.finish()
    leaf = Program("bits_leaf"+suffix, [bit_word(sf, 2, 1, 0), bit_word(sf, 0, 2, 1),
                   bit_word(sf, 5, 3, 2), bit_word(sf, 4, 0, 2), (sf << 31) | 0x0B030000,
                   bit_word(sf, reverse, 4, 4), 0xD65F03C0], [], base=0x40)
    stub = Program("bits_stub"+suffix, [0xD0000010, 0xF9400211, 0x91000210, 0xD61F0220], [], base=0xC0)
    words = {0: branch(0, r.base)}
    for p in (r, c, stub): words.update({p.base+4*i: word for i, word in enumerate(p.words)})
    raw = synthetic_module(words, symbols=[symbol("bits_helper", section=0, value=0, size=0),
        symbol(r.name, value=r.base, size=len(r.data)), symbol(c.name, value=c.base, size=len(c.data))],
        plt=((0x2000, 1026, 1, 0),))
    sdk = synthetic_module({0: branch(0, leaf.base), **{leaf.base+4*i: word for i, word in enumerate(leaf.words)}},
                           symbols=[symbol("bits_helper", value=leaf.base, size=len(leaf.data))])
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


def expected_call(r, flags, sf):
    width, reverse = (64, 3) if sf else (32, 2)
    value = expected_value(r[0], width, reverse)
    value = expected_value(value, width, 1)
    value = expected_value(value, width, 2)
    value = expected_value(value, width, 0)
    value = expected_value(value, width, 5) + expected_value(value, width, 4)
    value = expected_value(value, width, 4)
    if not flags & (1 << 28): value = r[7]
    value = expected_value(value, width, 0)
    return value if flags & (1 << 30) else r[6]


class BitOperationTests(unittest.TestCase):
    def test_known_words_widths_and_containers(self):
        for word, form, width, amount, op in ((0x5AC00020, "bit_reverse", 32, 0, 0),
                (0xDAC00420, "byte_reverse", 64, 16, 0), (0xDAC00820, "byte_reverse", 64, 32, 0),
                (0x5AC00820, "byte_reverse", 32, 32, 0), (0xDAC00C20, "byte_reverse", 64, 64, 0),
                (0x5AC01020, "count_leading", 32, 0, 0), (0xDAC01420, "count_leading", 64, 0, 1)):
            ins = decode_instruction(word, 0x1000)
            self.assertEqual((ins.form, ins.width, ins.rd, ins.rn, ins.amount, ins.operation, ins.flags),
                             (form, width, 0, 1, amount, op, False))

    def test_every_register_field_and_valid_variant(self):
        for sf, op in variants():
            for rd in range(32):
                for rn in range(32):
                    ins = decode_instruction(bit_word(sf, op, rd, rn), 0x1000)
                    self.assertEqual((ins.width, ins.rd, ins.rn), (64 if sf else 32, rd, rn))

    def test_reserved_and_unimplemented_neighbors_do_not_enter_the_new_forms(self):
        for sf in (0, 1):
            for op in (6, 7, 8, 9, 15, 31, 63):
                with self.assertRaises(UnsupportedInstruction): decode_instruction(bit_word(sf, op, 0, 1), 0x1000)
            for bit in (29, 20, 16, 13):
                with self.assertRaises(UnsupportedInstruction): decode_instruction(bit_word(sf, 0, 0, 1) ^ (1 << bit), 0x1000)
        with self.assertRaises(UnsupportedInstruction): decode_instruction(0x5AC00C20, 0x1000)
        self.assertEqual(decode_instruction(0x1AC00820, 0x1000).form, "divide")

    def test_string_and_byte_oracle_boundary_examples(self):
        value = 0x0123456789ABCDEF
        self.assertEqual(expected_value(value, 64, 1), 0x23016745AB89EFCD)
        self.assertEqual(expected_value(value, 64, 2), 0x67452301EFCDAB89)
        self.assertEqual(expected_value(value, 64, 3), 0xEFCDAB8967452301)
        for width in (32, 64):
            self.assertEqual(expected_value(1, width, 0), 1 << (width-1))
            self.assertEqual(expected_value(0, width, 4), width)
            self.assertEqual(expected_value(0, width, 5), width-1)
            self.assertEqual(expected_value(MASK64, width, 5), width-1)
            self.assertEqual(expected_value(1 << (width-1), width, 5), 0)
            self.assertEqual(expected_value(1, width, 5), width-2)

    def test_emission_uses_zr_widths_and_does_not_set_flags(self):
        for sf, op in variants():
            code, report = emit_c(struct.pack("<I", bit_word(sf, op, 31, 31)), 0x1000)
            width = 64 if sf else 32
            self.assertIn(f"oot_arm64_read(s, 31, {width}, 0)", code)
            self.assertIn(f"oot_arm64_write(s, 31, {width}, 0,", code)
            self.assertNotIn("s->nzcv =", code)
            self.assertFalse(report["guest_memory_access"])

    def test_leaf_protection_is_unchanged_for_w_and_x_writes(self):
        for sf, op in variants():
            for rd in range(32):
                code = struct.pack("<II", bit_word(sf, op, rd, 29), 0xD65F03C0)
                if 18 <= rd <= 30:
                    with self.assertRaises(InputError): verify_leaf(code, 0x1000)
                else:
                    proof = verify_leaf(code, 0x1000)
                    self.assertEqual(proof["max_retired_instructions"], 2)
                    self.assertFalse(proof["memory_access"])

    def test_actual_bundles_preserve_original_bytes(self):
        for sf in (0, 1):
            for explicit in (False, True):
                linker, config, _ = bundle_fixture(sf, explicit)
                before = [bytes(m.image) for m in linker.modules]
                _, source, manifest = build_bundle(linker, config)
                self.assertEqual(manifest["schema_version"], 8)
                self.assertIn("oot_stack_create_plt", source)
                self.assertFalse(manifest["guest_code_executed"])
                self.assertEqual([bytes(m.image) for m in linker.modules], before)


@unittest.skipUnless(os.name == "nt" and importlib.util.find_spec("unicorn"), "native Windows/reference required")
class NativeBitOperationTests(unittest.TestCase):
    def test_schema_eight_w_x_saved_destinations_and_every_prefix(self):
        self.assertEqual(version("unicorn"), "2.1.4")
        sources, fixtures = [], []
        for sf in (0, 1):
            for explicit in (False, True):
                linker, config, programs = bundle_fixture(sf, explicit)
                blob, source, manifest = build_bundle(linker, config)
                factory_name = "oot_create_bits"+str(len(fixtures)) if fixtures else "oot_create_bound_registry"
                sources.append(source.replace("oot_create_bound_registry", factory_name))
                fixtures.append((sf, factory_name, blob, manifest, programs))
        mode = os.environ.get("OOT_LIFTER_COMPILER", "cmake")
        lib, build = compile_library([], mode, "\n".join(sources)); bindings(lib)
        args, result_type = lib.oot_create_bound_registry.argtypes, lib.oot_create_bound_registry.restype
        context = lib.oot_pauth_create(1, (c_uint64*4)(*KEYS)); self.assertTrue(context)
        rng, whole, prefixes = random.Random(0xB17CA115), 0, 0
        try:
            for index, (sf, factory_name, blob, manifest, programs) in enumerate(fixtures):
                path = Path(build["directory"]) / f"bits{index}.ootmem"; path.write_bytes(blob)
                message, error, report = create_string_buffer(192), c_uint32(), Report()
                image = lib.oot_runtime_open(os.fsencode(path), message, len(message)); self.assertTrue(image, message.value)
                factory = getattr(lib, factory_name); factory.argtypes, factory.restype = args, result_type
                memory = lib.oot_runtime_memory(image)
                stack_index = next(i for i, r in enumerate(manifest["image"]["regions"]) if r["kind"] == "stack")
                stack = memory.contents.regions[stack_index].data
                dispatcher = factory(image, context, byref(error))
                lib.oot_runtime_close(image); self.assertTrue(dispatcher, error.value)
                ref = PltReference(programs, {manifest["plts"][0]["slot"]: manifest["leaves"][0]["entry"]})
                try:
                    for flags in range(16):
                        for value in (0, 1, 0x80000000, 0xFFFFFFFF, 1 << 63, MASK64, 0x0123456789ABCDEF, rng.getrandbits(64)):
                            s = State(); s.x[:] = [rng.getrandbits(64) for _ in range(31)]; s.x[0] = value
                            s.pc, s.sp, s.x[30], s.nzcv = manifest["root"]["entry"], manifest["image"]["initial_sp"], EXIT, flags << 28
                            expected, saved = expected_call(s.x, s.nzcv, sf), s.x[19]
                            states, stacks = ref.trace(s); memset(stack, 0, STACK_SIZE)
                            self.assertEqual(lib.oot_stack_begin(dispatcher, byref(s), EXIT, byref(report)), 0)
                            for n in range(len(states)):
                                self.assertEqual(lib.oot_stack_run(dispatcher, byref(s), 0, byref(report)), 2 if n == len(states)-1 else 1)
                                self.assertEqual(report.retired_this_call, 0)
                                self.assertEqual(s.values(), states[n].values()); self.assertEqual(s.nzcv, flags << 28)
                                self.assertEqual(bytes(stack[:STACK_SIZE]), stacks[n])
                                if n == len(states)-1: break
                                status = lib.oot_stack_run(dispatcher, byref(s), 1, byref(report))
                                self.assertEqual(status, 2 if n == len(states)-2 else 1)
                                self.assertEqual(report.total_retired, n+1); self.assertEqual(report.retired_this_call, 1)
                                prefixes += 1
                            self.assertEqual((s.x[0], s.x[19]), (expected, saved)); whole += 1
                finally: lib.oot_stack_destroy(dispatcher)
        finally: lib.oot_pauth_destroy(context)
        self.assertEqual((whole, prefixes), (512, 15872))
        report_path = ROOT / f"build/lifter-validation/{mode}-bit-dispatch-report.json"
        report_path.write_text(json.dumps({"whole_call_cases": whole, "prefix_checks": prefixes, "synthetic_only": True,
            "game_code_executed": False, "native_build": build}, indent=2)+"\n", encoding="utf-8")


if __name__ == "__main__": unittest.main()
