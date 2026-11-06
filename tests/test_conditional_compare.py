"""Exact conditional comparisons and synthetic PAC/PLT flag propagation."""

from ctypes import byref, c_uint32, c_uint64, create_string_buffer, memset
import importlib.util
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
from conditional_programs import compare, compare_flags, arithmetic_flags, condition_holds
from dispatcher_validation import EXIT, Report, STACK_SIZE
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


def bundle_fixture(explicit=False):
    root = LrAssembler("compare_root", 0x10, 64, 19, key=int(explicit), explicit_auth=explicit)
    root.emit(compare(1, 1, 0, 1, 4, 2)); root.bl(0x40)
    root.emit(compare(0, 1, 0, 31, 2, 1, True), select(1, 0, 0, 10, 11, 3))
    child = PauthAssembler("compare_child", 0x40, 64, 48, key=1-int(explicit), explicit_auth=not explicit)
    child.emit(compare(0, 0, 2, 31, 1, 0, True)); child.bl(0xC0)
    child.emit(compare(1, 0, 0, 7, 0, 15), select(1, 0, 0, 8, 9, 6))
    r, c = root.finish(), child.finish()
    leaf = Program("compare_leaf", [compare(1, 1, 3, 4, 8, 3), select(0, 0, 0, 5, 6, 1), 0xD65F03C0], [], base=0x40)
    stub = Program("compare_stub", [0xD0000010, 0xF9400211, 0x91000210, 0xD61F0220], [], base=0xC0)
    words = {0: branch(0, r.base)}
    for p in (r, c, stub):
        words.update({p.base+4*i: word for i, word in enumerate(p.words)})
    raw = synthetic_module(words, symbols=[symbol("compare_helper", section=0, value=0, size=0),
        symbol(r.name, value=r.base, size=len(r.data)), symbol(c.name, value=c.base, size=len(c.data))],
        plt=((0x2000, 1026, 1, 0),))
    sdk = synthetic_module({0: branch(0, leaf.base), **{leaf.base+4*i: word for i, word in enumerate(leaf.words)}},
                           symbols=[symbol("compare_helper", value=leaf.base, size=len(leaf.data))])
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


def expected_call(registers, flags):
    r = list(registers)
    flags = compare_flags(r, flags, 1, 1, 0, 1, 4, 2)
    flags = compare_flags(r, flags, 0, 0, 2, 31, 1, 0, True)
    flags = compare_flags(r, flags, 1, 1, 3, 4, 8, 3)
    r[0] = r[5 if condition_holds(flags, 1) else 6] & 0xFFFFFFFF
    flags = compare_flags(r, flags, 1, 0, 0, 7, 0, 15)
    r[0] = r[8 if condition_holds(flags, 6) else 9]
    flags = compare_flags(r, flags, 0, 1, 0, 31, 2, 1, True)
    return r[10 if condition_holds(flags, 3) else 11], flags


class ConditionalCompareTests(unittest.TestCase):
    def test_known_words_have_no_destination_and_separate_fallback_flags(self):
        ins = decode_instruction(0xFA410000, 0x1000)  # CCMP X0,X1,#0,EQ
        self.assertEqual((ins.form, ins.width, ins.rd, ins.rn, ins.rm, ins.condition, ins.nzcv, ins.operation, ins.flags),
                         ("conditional_compare_register", 64, 31, 0, 1, 0, 0, 1, True))
        ins = decode_instruction(0x3A5FE825, 0x1000)  # CCMN W1,#31,#5,AL
        self.assertEqual((ins.form, ins.width, ins.rd, ins.rn, ins.immediate, ins.condition, ins.nzcv, ins.operation),
                         ("conditional_compare_immediate", 32, 31, 1, 31, 14, 5, 0))

    def test_all_source_fields_conditions_and_fallbacks(self):
        for sf in (0, 1):
            for sub in (0, 1):
                for imm in (False, True):
                    for reg in range(32):
                        for cond in range(16):
                            for flags in range(16):
                                ins = decode_instruction(compare(sf, sub, reg, 31-reg, flags, cond, imm), 0x1000)
                                self.assertEqual((ins.width, ins.rd, ins.rn, ins.immediate if imm else ins.rm,
                                                  ins.condition, ins.nzcv, ins.operation, ins.flags),
                                                 (64 if sf else 32, 31, reg, 31-reg, cond, flags, sub, True))

    def test_reserved_s_o2_o3_bits_are_rejected(self):
        for sf in (0, 1):
            for sub in (0, 1):
                for imm in (False, True):
                    word = compare(sf, sub, 0, 1, 0, 0, imm)
                    for bit in (29, 10, 4):
                        with self.subTest(word=hex(word), bit=bit), self.assertRaises(UnsupportedInstruction):
                            decode_instruction(word ^ (1 << bit), 0x1000)

    def test_emission_reads_zr_and_never_writes_any_register_or_sp(self):
        for imm in (False, True):
            code, report = emit_c(struct.pack("<I", compare(1, 0, 31, 31, 15, 15, imm)), 0x1000)
            self.assertIn("oot_arm64_read(s, 31, 64, 0)", code)
            self.assertIn("oot_arm64_condition(s->nzcv, 15)", code)
            self.assertIn("s->nzcv = UINT32_C(0xf0000000);", code)
            self.assertNotIn("oot_arm64_write", code)
            self.assertFalse(report["guest_memory_access"])

    def test_leaf_policy_explicitly_allows_flag_only_protected_sources(self):
        words = [compare(1, sub, rn, rm, flags, 14) for sub in (0, 1)
                 for rn, rm in ((18, 30), (29, 31), (31, 19)) for flags in range(16)] + [0xD65F03C0]
        proof = verify_leaf(struct.pack(f"<{len(words)}I", *words), 0x1000)
        self.assertEqual(proof["max_retired_instructions"], len(words))
        self.assertEqual(proof["protected_registers"], "x18-x30,sp")
        self.assertFalse(proof["memory_access"])

    def test_independent_math_oracle_boundary_examples(self):
        self.assertEqual(arithmetic_flags(0, 0, 64, True), 0x60000000)
        self.assertEqual(arithmetic_flags(0, 1, 32, True), 0x80000000)
        self.assertEqual(arithmetic_flags(0xFFFFFFFF, 1, 32, False), 0x60000000)
        self.assertEqual(arithmetic_flags(0x7FFFFFFF, 1, 32, False), 0x90000000)
        self.assertEqual(arithmetic_flags(0x8000000000000000, 1, 64, True), 0x30000000)
        for flags in range(16):
            self.assertTrue(condition_holds(flags << 28, 14))
            self.assertTrue(condition_holds(flags << 28, 15))

    def test_real_bundle_proves_both_frame_layouts_and_retains_original_bytes(self):
        for explicit in (False, True):
            linker, config, _ = bundle_fixture(explicit)
            before = [bytes(m.image) for m in linker.modules]
            _, source, manifest = build_bundle(linker, config)
            self.assertEqual(manifest["schema_version"], 8)
            self.assertIn("oot_stack_create_plt", source)
            self.assertFalse(manifest["guest_code_executed"])
            self.assertEqual([bytes(m.image) for m in linker.modules], before)


@unittest.skipUnless(os.name == "nt" and importlib.util.find_spec("unicorn"), "native Windows/reference required")
class NativeConditionalCompareTests(unittest.TestCase):
    def test_schema_eight_factories_every_prefix_flags_and_stack(self):
        sources, fixtures = [], []
        for explicit in (False, True):
            linker, config, programs = bundle_fixture(explicit)
            blob, source, manifest = build_bundle(linker, config)
            sources.append(source.replace("oot_create_bound_registry", "oot_create_compare1") if explicit else source)
            fixtures.append((blob, manifest, programs))
        # Each factory has private static descriptor names in its own translation
        # unit in real builds; give the second fixture distinct names here too.
        sources[1] = sources[1].replace("compare_root", "compare_root1").replace("compare_child", "compare_child1").replace(
            "compare_leaf", "compare_leaf1").replace("compare_stub", "compare_stub1")
        mode = os.environ.get("OOT_LIFTER_COMPILER", "cmake")
        lib, build = compile_library([], mode, "\n".join(sources)); bindings(lib)
        context = lib.oot_pauth_create(1, (c_uint64*4)(*KEYS))
        self.assertTrue(context)
        rng, whole, prefixes = random.Random(0xCC4D15A7), 0, 0
        try:
            for index, (blob, manifest, programs) in enumerate(fixtures):
                path = Path(build["directory"]) / f"compare{index}.ootmem"; path.write_bytes(blob)
                message, error, report = create_string_buffer(192), c_uint32(), Report()
                image = lib.oot_runtime_open(os.fsencode(path), message, len(message)); self.assertTrue(image, message.value)
                factory = lib.oot_create_compare1 if index else lib.oot_create_bound_registry
                factory.argtypes, factory.restype = lib.oot_create_bound_registry.argtypes, lib.oot_create_bound_registry.restype
                memory = lib.oot_runtime_memory(image)
                stack_index = next(i for i, r in enumerate(manifest["image"]["regions"]) if r["kind"] == "stack")
                stack = memory.contents.regions[stack_index].data
                dispatcher = factory(image, context, byref(error))
                lib.oot_runtime_close(image); self.assertTrue(dispatcher, error.value)
                ref = PltReference(programs, {manifest["plts"][0]["slot"]: manifest["leaves"][0]["entry"]})
                try:
                    for flags in range(16):
                        for value in (0, 1, 30, 31, 0xFFFFFFFF, 1 << 63, (1 << 64)-1, rng.getrandbits(64)):
                            s = State(); s.x[:] = [rng.getrandbits(64) for _ in range(31)]
                            s.x[0], s.x[1], s.x[2], s.x[3], s.x[4], s.x[7], s.x[8], s.x[9] = value, value^1, value, value, 31, value, 30, 31
                            s.pc, s.sp, s.x[30], s.nzcv = manifest["root"]["entry"], manifest["image"]["initial_sp"], EXIT, flags << 28
                            result, final_flags = expected_call(s.x, s.nzcv)
                            states, stacks = ref.trace(s)
                            memset(stack, 0, STACK_SIZE)
                            self.assertEqual(lib.oot_stack_begin(dispatcher, byref(s), EXIT, byref(report)), 0)
                            for n in range(len(states)):
                                self.assertEqual(lib.oot_stack_run(dispatcher, byref(s), 0, byref(report)), 2 if n == len(states)-1 else 1)
                                self.assertEqual(report.retired_this_call, 0)
                                self.assertEqual(s.values(), states[n].values())
                                self.assertEqual(bytes(stack[:STACK_SIZE]), stacks[n])
                                if n == len(states)-1: break
                                status = lib.oot_stack_run(dispatcher, byref(s), 1, byref(report))
                                self.assertEqual(status, 2 if n == len(states)-2 else 1)
                                self.assertEqual(report.total_retired, n+1); self.assertEqual(report.retired_this_call, 1)
                                prefixes += 1
                            self.assertEqual((s.x[0], s.nzcv), (result, final_flags))
                            whole += 1
                finally: lib.oot_stack_destroy(dispatcher)
        finally: lib.oot_pauth_destroy(context)
        self.assertEqual(whole, 256)
        report_path = ROOT / f"build/lifter-validation/{mode}-conditional-dispatch-report.json"
        report_path.write_text(json.dumps({"whole_call_cases": whole, "prefix_checks": prefixes, "synthetic_only": True,
            "game_code_executed": False, "native_build": build}, indent=2)+"\n", encoding="utf-8")


if __name__ == "__main__": unittest.main()
