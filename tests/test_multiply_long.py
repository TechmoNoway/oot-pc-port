"""Exact widening multiply and synthetic saved-register/PAC/PLT execution."""

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
from call_validation import LrAssembler
from dispatcher_validation import EXIT, Report, STACK_SIZE
from input_formats import InputError
from integer_validation import select
from leaf_verifier import verify_leaf
from lifter_validation import compile_library
from lifter_validation_types import Program, State
from module_linker import Linker, Module
from multiply_programs import multiply_long, mathematical_result, operand32, MASK64
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from plt_validation import PltReference, bindings
from prepare_registry import build_bundle
from test_arm64_analysis import branch, synthetic_module
from test_module_linker import symbol


def bundle_fixture(explicit=False):
    root = LrAssembler("long_root", 0x10, 64, 19, key=int(explicit), explicit_auth=explicit)
    root.emit(multiply_long(True, 0, 19, 0, 1, 2)); root.bl(0x40)
    root.emit(multiply_long(True, 1, 0, 0, 3, 19), select(1, 0, 0, 0, 4, 0))
    child = PauthAssembler("long_child", 0x40, 64, 48, key=1-int(explicit), explicit_auth=not explicit)
    child.emit(multiply_long(False, 0, 0, 19, 5, 6)); child.bl(0xC0)
    child.emit(multiply_long(False, 1, 0, 0, 7, 8), select(1, 0, 0, 0, 9, 6))
    r, c = root.finish(), child.finish()
    leaf = Program("long_leaf", [multiply_long(True, 1, 10, 0, 1, 31),
                   multiply_long(False, 0, 11, 2, 3, 31), multiply_long(True, 0, 0, 10, 11, 0),
                   0xD65F03C0], [], base=0x40)
    stub = Program("long_stub", [0xD0000010, 0xF9400211, 0x91000210, 0xD61F0220], [], base=0xC0)
    words = {0: branch(0, r.base)}
    for p in (r, c, stub):
        words.update({p.base+4*i: word for i, word in enumerate(p.words)})
    raw = synthetic_module(words, symbols=[symbol("long_helper", section=0, value=0, size=0),
        symbol(r.name, value=r.base, size=len(r.data)), symbol(c.name, value=c.base, size=len(c.data))],
        plt=((0x2000, 1026, 1, 0),))
    sdk = synthetic_module({0: branch(0, leaf.base), **{leaf.base+4*i: word for i, word in enumerate(leaf.words)}},
                           symbols=[symbol("long_helper", value=leaf.base, size=len(leaf.data))])
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
    # A whole-call arithmetic formula, independent of decode and native helpers.
    s = lambda v: operand32(v, True)
    u = lambda v: operand32(v, False)
    saved = (r[2] + s(r[0])*s(r[1])) & MASK64
    value = (r[6] + u(saved)*u(r[5])) & MASK64
    negative = (-s(value)*s(r[1])) & MASK64
    product = u(r[2])*u(r[3])
    value = (value + s(negative)*s(product)) & MASK64
    value = (r[8] - u(value)*u(r[7])) & MASK64
    if not flags & (1 << 28): value = r[9]
    value = (saved - s(value)*s(r[3])) & MASK64
    return value if flags & (1 << 30) else r[4]


class MultiplyLongTests(unittest.TestCase):
    def test_known_words_and_aliases(self):
        for word, signed, sub, ra in ((0x9B220C20, True, 0, 3), (0x9BA28C20, False, 1, 3),
                (0x9B227C20, True, 0, 31), (0x9BA27C20, False, 0, 31),
                (0x9B22FC20, True, 1, 31), (0x9BA2FC20, False, 1, 31)):
            ins = decode_instruction(word, 0x1000)
            self.assertEqual((ins.form, ins.width, ins.rd, ins.rn, ins.rm, ins.ra, ins.operation, ins.sign_extend, ins.flags),
                             ("multiply_long", 64, 0, 1, 2, ra, sub, signed, False))

    def test_register_fields_and_fixed_encoding_bits(self):
        for signed in (False, True):
            for sub in (0, 1):
                for rd in range(32):
                    for rn in range(32):
                        rm, ra = 31-rd, 31-rn
                        word = multiply_long(signed, sub, rd, rn, rm, ra)
                        ins = decode_instruction(word, 0x1000)
                        self.assertEqual((ins.rd, ins.rn, ins.rm, ins.ra, ins.width, ins.operation, ins.sign_extend),
                                         (rd, rn, rm, ra, 64, sub, signed))
                for bit in (31, 30, 29, 22):
                    with self.subTest(signed=signed, sub=sub, bit=bit), self.assertRaises(UnsupportedInstruction):
                        decode_instruction(multiply_long(signed, sub, 0, 1, 2, 3) ^ (1 << bit), 0x1000)
        for word in (0x9B42FC20, 0x9BC2FC20):  # High-multiply o0=1 remains unsupported.
            with self.assertRaises(UnsupportedInstruction): decode_instruction(word, 0x1000)
        self.assertEqual(decode_instruction(0x9B020C20, 0x1000).form, "multiply_add")

    def test_emitter_reads_w_sources_full_x_accumulator_and_uses_unsigned_arithmetic(self):
        for signed in (False, True):
            code, report = emit_c(struct.pack("<I", multiply_long(signed, 1, 0, 1, 2, 3)), 0x1000)
            self.assertIn("oot_arm64_read(s, 1, 32, 0)", code)
            self.assertIn("oot_arm64_read(s, 2, 32, 0)", code)
            self.assertIn("oot_arm64_read(s, 3, 64, 0)", code)
            self.assertEqual("oot_arm64_sign_extend" in code, signed)
            self.assertIn("oot_arm64_write(s, 0, 64, 0, accumulator - (a * b))", code)
            self.assertNotIn("s->nzcv =", code)
            self.assertNotIn("int64_t ", code.replace("uint64_t ", ""))
            self.assertFalse(report["guest_memory_access"])

    def test_independent_arithmetic_boundaries(self):
        r = [0]*31
        r[1], r[2], r[3] = 0xFFFFFFFF, 0xFFFFFFFF, MASK64
        self.assertEqual(mathematical_result(r, False, 0, 1, 2, 3), 0xFFFFFFFE00000000)
        self.assertEqual(mathematical_result(r, True, 0, 1, 2, 3), 0)
        r[1], r[2], r[3] = 0xDEADBEEF80000000, 0x12345678FFFFFFFF, 0x100000000
        self.assertEqual(mathematical_result(r, True, 0, 1, 2, 3), 0x180000000)
        self.assertEqual(mathematical_result(r, True, 1, 1, 2, 31), MASK64 ^ 0x7FFFFFFF)

    def test_leaf_destination_policy_stays_explicit_and_zr_is_not_sp(self):
        for rd in range(32):
            code = struct.pack("<II", multiply_long(True, 0, rd, 29, 30, 18), 0xD65F03C0)
            if 18 <= rd <= 30:
                with self.assertRaises(InputError): verify_leaf(code, 0x1000)
            else:
                proof = verify_leaf(code, 0x1000)
                self.assertEqual(proof["max_retired_instructions"], 2)
                self.assertEqual(proof["protected_registers"], "x18-x30,sp")
                self.assertFalse(proof["memory_access"])

    def test_actual_bundle_keeps_original_bytes_and_saved_register_policy(self):
        for explicit in (False, True):
            linker, config, _ = bundle_fixture(explicit)
            before = [bytes(m.image) for m in linker.modules]
            _, source, manifest = build_bundle(linker, config)
            self.assertEqual(manifest["schema_version"], 8)
            self.assertIn("oot_stack_create_plt", source)
            self.assertFalse(manifest["guest_code_executed"])
            self.assertEqual([bytes(m.image) for m in linker.modules], before)


@unittest.skipUnless(os.name == "nt" and importlib.util.find_spec("unicorn"), "native Windows/reference required")
class NativeMultiplyLongTests(unittest.TestCase):
    bundle_fixture = staticmethod(bundle_fixture)
    expected_call = staticmethod(expected_call)
    report_name = "multiply"
    expected_prefixes = 7168

    def test_schema_eight_saved_registers_aliases_flags_and_every_prefix(self):
        self.assertEqual(version("unicorn"), "2.1.4")
        sources, fixtures = [], []
        for explicit in (False, True):
            linker, config, programs = self.bundle_fixture(explicit)
            blob, source, manifest = build_bundle(linker, config)
            if explicit:
                source = source.replace("oot_create_bound_registry", "oot_create_long1")
                for name in [r['name'] for kind in ('frames', 'leaves', 'plts') for r in config[kind]]:
                    source = source.replace(name, name+"1")
            sources.append(source); fixtures.append((blob, manifest, programs))
        mode = os.environ.get("OOT_LIFTER_COMPILER", "cmake")
        lib, build = compile_library([], mode, "\n".join(sources)); bindings(lib)
        context = lib.oot_pauth_create(1, (c_uint64*4)(*KEYS)); self.assertTrue(context)
        rng, whole, prefixes = random.Random(0x10A64CA1), 0, 0
        try:
            for index, (blob, manifest, programs) in enumerate(fixtures):
                path = Path(build["directory"]) / f"{self.report_name}{index}.ootmem"; path.write_bytes(blob)
                message, error, report = create_string_buffer(192), c_uint32(), Report()
                image = lib.oot_runtime_open(os.fsencode(path), message, len(message)); self.assertTrue(image, message.value)
                factory = lib.oot_create_long1 if index else lib.oot_create_bound_registry
                factory.argtypes, factory.restype = lib.oot_create_bound_registry.argtypes, lib.oot_create_bound_registry.restype
                memory = lib.oot_runtime_memory(image)
                stack_index = next(i for i, r in enumerate(manifest["image"]["regions"]) if r["kind"] == "stack")
                stack = memory.contents.regions[stack_index].data
                dispatcher = factory(image, context, byref(error))
                lib.oot_runtime_close(image); self.assertTrue(dispatcher, error.value)
                ref = PltReference(programs, {manifest["plts"][0]["slot"]: manifest["leaves"][0]["entry"]})
                try:
                    for flags in range(16):
                        for value in (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 1 << 63, MASK64, rng.getrandbits(64)):
                            s = State(); s.x[:] = [rng.getrandbits(64) for _ in range(31)]
                            s.x[0], s.x[1], s.x[2], s.x[3] = value, value ^ 0xFFFFFFFF, value ^ (1 << 63), value
                            s.pc, s.sp, s.x[30], s.nzcv = manifest["root"]["entry"], manifest["image"]["initial_sp"], EXIT, flags << 28
                            expected, protected = self.expected_call(s.x, s.nzcv), s.x[19]
                            states, stacks = ref.trace(s); memset(stack, 0, STACK_SIZE)
                            self.assertEqual(lib.oot_stack_begin(dispatcher, byref(s), EXIT, byref(report)), 0)
                            for n in range(len(states)):
                                self.assertEqual(lib.oot_stack_run(dispatcher, byref(s), 0, byref(report)), 2 if n == len(states)-1 else 1)
                                self.assertEqual(report.retired_this_call, 0)
                                self.assertEqual(s.values(), states[n].values())
                                self.assertEqual(s.nzcv, flags << 28)
                                self.assertEqual(bytes(stack[:STACK_SIZE]), stacks[n])
                                if n == len(states)-1: break
                                status = lib.oot_stack_run(dispatcher, byref(s), 1, byref(report))
                                self.assertEqual(status, 2 if n == len(states)-2 else 1)
                                self.assertEqual(report.total_retired, n+1); self.assertEqual(report.retired_this_call, 1)
                                prefixes += 1
                            self.assertEqual((s.x[0], s.x[19]), (expected, protected)); whole += 1
                finally: lib.oot_stack_destroy(dispatcher)
        finally: lib.oot_pauth_destroy(context)
        self.assertEqual((whole, prefixes), (256, self.expected_prefixes))
        report_path = ROOT / f"build/lifter-validation/{mode}-{self.report_name}-dispatch-report.json"
        report_path.write_text(json.dumps({"whole_call_cases": whole, "prefix_checks": prefixes, "synthetic_only": True,
            "game_code_executed": False, "native_build": build}, indent=2)+"\n", encoding="utf-8")


if __name__ == "__main__": unittest.main()
