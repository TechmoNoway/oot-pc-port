"""Application-only SIMD conversion and bit operations, independently checked."""
from ctypes import byref, cast, POINTER, sizeof
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]

import test_application_integer_float as integer_float
import test_sdk_init_vectors as fixtures
from input_formats import InputError
from lifter_validation_types import State
from sdk_init_instructions import decode_sdk_init_instruction, sdk_init_vector_kind


def simd_integer_fp(width, unsigned, rn, rd):
    return (0x5e21d800 | ((width == 64) << 22) |
            (unsigned << 29) | (rn << 5) | rd)


def orr(q, rm, rn, rd):
    return 0x0ea01c00 | q << 30 | rm << 16 | rn << 5 | rd


def dup_element(imm5, rn, rd):
    return 0x5e000400 | imm5 << 16 | rn << 5 | rd


def ins_element(imm5, imm4, rn, rd):
    return 0x6e000400 | imm5 << 16 | imm4 << 11 | rn << 5 | rd


def cmeq(q, size, rm, rn, rd):
    return 0x2e208c00 | q << 30 | size << 22 | rm << 16 | rn << 5 | rd


def bif(q, rm, rn, rd):
    return 0x2ee01c00 | q << 30 | rm << 16 | rn << 5 | rd


class ApplicationSimdDecodeTests(unittest.TestCase):
    def test_literal_register_bit_operations_and_reserved_siblings(self):
        cases = ((0x4ea21c20, orr(1, 2, 1, 0), 'simd_orr', 26),
                 (0x5e180423, dup_element(24, 1, 3), 'simd_dup_element', 27),
                 (0x6e180420, ins_element(24, 0, 1, 0), 'simd_ins_element', 28),
                 (0x6e228c20, cmeq(1, 0, 2, 1, 0), 'simd_cmeq', 29),
                 (0x6ee21c20, bif(1, 2, 1, 0), 'simd_bif', 30))
        for word, encoded, family, operation in cases:
            with self.subTest(word=hex(word)):
                self.assertEqual(word, encoded)
                self.assertIsNone(sdk_init_vector_kind(word))
                with self.assertRaises(InputError):
                    decode_sdk_init_instruction(word, fixtures.BASE)
                self.assertEqual(sdk_init_vector_kind(word, application=True), family)
                self.assertEqual(decode_sdk_init_instruction(word, fixtures.BASE, True).operation, operation)
        for word in (dup_element(0, 0, 0), dup_element(16, 0, 0),
                     ins_element(0, 0, 0, 0), ins_element(16, 0, 0, 0), cmeq(0, 3, 0, 0, 0)):
            self.assertIsNone(sdk_init_vector_kind(word, application=True))

    def test_literal_scalar_encodings_are_application_only(self):
        # Literal words check the generator independently, including vector Q31.
        cases = ((0x7e21d808, 32, 1, 0, 8),
                 (0x5e21d841, 32, 0, 2, 1),
                 (0x5e61dbff, 64, 0, 31, 31),
                 (0x7e61d83f, 64, 1, 1, 31))
        for word, width, unsigned, rn, rd in cases:
            with self.subTest(word=hex(word)):
                self.assertEqual(simd_integer_fp(width, unsigned, rn, rd), word)
                self.assertIsNone(sdk_init_vector_kind(word))
                with self.assertRaises(InputError):
                    decode_sdk_init_instruction(word, fixtures.BASE)
                self.assertEqual(sdk_init_vector_kind(word, application=True), 'simd_integer_fp')
                decoded = decode_sdk_init_instruction(word, fixtures.BASE, application=True)
                self.assertEqual((decoded.form, decoded.operation, decoded.width,
                                  decoded.immediate, decoded.condition, decoded.rn, decoded.rd),
                                 ('sdk_init_vector', 25, width, width, unsigned, rn, rd))

    def test_fixed_bit_mutations_do_not_enter_the_new_family(self):
        word, mask = 0x7e21d808, 0xdfbffc00
        for bit in range(32):
            if mask & (1 << bit):
                self.assertNotEqual(sdk_init_vector_kind(word ^ (1 << bit), application=True),
                                    'simd_integer_fp', bit)
        # Vector and fixed-point forms are separate instructions, not this family.
        for word in (0x6e21d808, 0x7f21e408):
            self.assertIsNone(sdk_init_vector_kind(word, application=True))
        for word in (True, -1, 1 << 32):
            self.assertIsNone(sdk_init_vector_kind(word, application=True))
            with self.assertRaises(InputError):
                decode_sdk_init_instruction(word, fixtures.BASE, application=True)


class ApplicationSimdConversionTests(unittest.TestCase):
    fixture = fixtures.SdkInitVectorTests.fixture
    reference_start = fixtures.SdkInitVectorTests.reference_start
    reference_vectors = fixtures.SdkInitVectorTests.reference_vectors

    @classmethod
    def setUpClass(cls):
        # Reuse setup through its module, without importing/discovering its tests.
        integer_float.ApplicationIntegerFloatTests.setUpClass.__func__(cls)

    def compare_conversion(self, width, unsigned, rn, rd, value, fpcr=0, fpsr=0):
        vectors, state, memory, backing, table = self.fixture()
        word = simd_integer_fp(width, unsigned, rn, rd)
        encoded = value & ((1 << width) - 1)
        vectors.q[rn][:width // 8] = encoded.to_bytes(width // 8, 'little')
        vectors.fpcr, vectors.fpsr = fpcr, fpsr
        self.assertEqual(self.kind(word), 3)
        self.assertEqual(self.lib.oot_startup_vector_kind(word), 0)
        self.reference_start(vectors, state, backing, [word])
        expected = self.reference.step(state, word)
        expected_vectors = self.reference_vectors()
        before = (bytes(vectors), bytes(state), bytes(memory), bytes(backing), bytes(table))
        out, result, write = fixtures.VectorState(), State(), fixtures.VectorWrite()
        self.assertEqual(self.prepare_fn(byref(vectors), word, byref(state), byref(memory),
                                         byref(out), byref(result), byref(write)), 0, hex(word))
        self.assertEqual(result.values(), expected.values(), hex(word))
        self.assertEqual(bytes(out), expected_vectors, (hex(word), value))
        self.assertEqual((bytes(vectors), bytes(state), bytes(memory), bytes(backing), bytes(table)), before)
        self.assertEqual(bytes(self.reference.u.mem_read(fixtures.STACK, len(backing))), bytes(backing))
        self.assertEqual((write.address, write.size, bytes(write.bytes)), (0, 0, bytes(64)))
        # Exact rational distances catch double rounding independently of ARM/native code.
        signed_value = encoded
        if not unsigned and encoded & (1 << (width - 1)):
            signed_value -= 1 << width
        bits, flags = integer_float.oracle(signed_value, width)
        self.assertEqual(bytes(out.q[rd]), bits.to_bytes(width // 8, 'little') + bytes(16 - width // 8))
        self.assertEqual(out.fpsr, fpsr | flags)
        self.assertEqual(out.fpcr, fpcr)
        self.assertEqual(result.pc, state.pc + 4)
        return out

    def test_literal_native_kind_and_q31_conversion(self):
        self.assertEqual(self.kind(0x7e21d808), 3)
        out = self.compare_conversion(32, 1, 0, 8, 17)
        self.assertEqual(bytes(out.q[8]), bytes.fromhex('00008841') + bytes(12))
        out = self.compare_conversion(64, 0, 31, 31, -(1 << 63))
        self.assertEqual(bytes(out.q[31]), bytes.fromhex('000000000000e0c3') + bytes(8))

    def test_all_register_fields_signedness_widths_and_full_reference_state(self):
        values = (0, 1, -1, 0xffffffff, 0xffffffffffffffff,
                  0x80000000, 0x8000000000000000, (1 << 24) + 1,
                  (1 << 24) + 3, (1 << 53) + 1, (1 << 53) + 3,
                  (1 << 63) + (1 << 39) + 1)
        for width in (32, 64):
            for unsigned in (0, 1):
                for rn in range(32):
                    for rd in range(32):
                        self.compare_conversion(width, unsigned, rn, rd,
                            values[(rn + rd) % len(values)], ((rn + rd) & 1) << 24, 0x08000001)

    def test_boundary_and_tie_values_for_every_variant_and_alias(self):
        for width in (32, 64):
            values = (0, 1, -1, (1 << width) - 1, -(1 << (width - 1)),
                      (1 << (width - 1)) - 1, (1 << 24) - 1, (1 << 24) + 1,
                      (1 << 24) + 3, -((1 << 24) + 1), -((1 << 24) + 3))
            if width == 64:
                values += ((1 << 53) - 1, (1 << 53) + 1, (1 << 53) + 3,
                           -((1 << 53) + 1), -((1 << 53) + 3),
                           (1 << 63) + (1 << 39) + 1)
            for unsigned in (0, 1):
                for value in values:
                    for fpcr in (0, 1 << 24):
                        for fpsr in (0, 0x0800009f):
                            for rd in (0, 31):
                                self.compare_conversion(width, unsigned, 31, rd, value, fpcr, fpsr)

    def test_native_profile_fixed_bits_and_unsupported_siblings(self):
        word, mask = 0x7e21d808, 0xdfbffc00
        for bit in range(32):
            if mask & (1 << bit):
                self.assertNotEqual(self.kind(word ^ (1 << bit)), 3, bit)
        vectors, state, memory, backing, table = self.fixture()
        for instruction in (word, 0x6e21d808, 0x7f21e408):
            out = fixtures.VectorState.from_buffer_copy(bytes([0xa5]) * sizeof(fixtures.VectorState))
            result = State.from_buffer_copy(bytes([0xb6]) * sizeof(State))
            write = fixtures.VectorWrite.from_buffer_copy(bytes([0xc7]) * sizeof(fixtures.VectorWrite))
            before = (bytes(vectors), bytes(state), bytes(memory), bytes(backing), bytes(table),
                      bytes(out), bytes(result), bytes(write))
            fn = self.lib.oot_startup_vector_prepare if instruction == word else self.prepare_fn
            self.assertEqual(fn(byref(vectors), instruction, byref(state), byref(memory),
                                byref(out), byref(result), byref(write)), 1)
            self.assertEqual((bytes(vectors), bytes(state), bytes(memory), bytes(backing), bytes(table),
                              bytes(out), bytes(result), bytes(write)), before)

    def test_invalid_states_and_overlapping_outputs_do_not_publish(self):
        for mutation in ('pc', 'pc_limit', 'sp', 'nzcv', 'fpcr_rounding', 'fpcr_unknown',
                         'fpsr', 'alias_vector', 'alias_registers', 'alias_outputs'):
            with self.subTest(mutation=mutation):
                vectors, state, memory, backing, table = self.fixture()
                if mutation == 'pc': state.pc += 1
                if mutation == 'pc_limit': state.pc = (1 << 39) - 4
                if mutation == 'sp': state.sp += 8
                if mutation == 'nzcv': state.nzcv |= 1
                if mutation == 'fpcr_rounding': vectors.fpcr = 1 << 22
                if mutation == 'fpcr_unknown': vectors.fpcr = 1 << 19
                if mutation == 'fpsr': vectors.fpsr = 1 << 28
                out = fixtures.VectorState.from_buffer_copy(bytes([0xa5]) * sizeof(fixtures.VectorState))
                result = State.from_buffer_copy(bytes([0xb6]) * sizeof(State))
                write = fixtures.VectorWrite.from_buffer_copy(bytes([0xc7]) * sizeof(fixtures.VectorWrite))
                before = (bytes(vectors), bytes(state), bytes(memory), bytes(backing), bytes(table),
                          bytes(out), bytes(result), bytes(write))
                out_ptr = byref(vectors if mutation == 'alias_vector' else out)
                result_ptr = byref(state if mutation == 'alias_registers' else result)
                write_ptr = cast(byref(out), POINTER(fixtures.VectorWrite)) if mutation == 'alias_outputs' else byref(write)
                self.assertEqual(self.prepare_fn(byref(vectors), 0x7e21d808, byref(state), byref(memory),
                                                 out_ptr, result_ptr, write_ptr), 2)
                self.assertEqual((bytes(vectors), bytes(state), bytes(memory), bytes(backing), bytes(table),
                                  bytes(out), bytes(result), bytes(write)), before)


class ApplicationSimdBitTests(unittest.TestCase):
    fixture = fixtures.SdkInitVectorTests.fixture
    reference_start = fixtures.SdkInitVectorTests.reference_start
    reference_vectors = fixtures.SdkInitVectorTests.reference_vectors
    setUpClass = classmethod(ApplicationSimdConversionTests.setUpClass.__func__)

    def compare_bits(self, word, kind, pattern=0):
        vectors, state, memory, backing, table = self.fixture(seed=7)
        rn, rd, rm = word >> 5 & 31, word & 31, word >> 16 & 31
        # Includes NaN-shaped bits, high-bit lane differences and equality mixtures.
        for reg in range(32):
            vectors.q[reg][:] = bytes.fromhex('0100807f0100c0ff5555aaaa00000080')
            vectors.q[reg][reg % 16] ^= 128
        if kind == 8:
            vectors.q[rm][:] = bytes(([0, 255, 0x55, 0xaa][pattern % 4],)) * 16
        vectors.fpcr, vectors.fpsr = (pattern & 1) << 24, 0x0800009f
        old, n, m = bytes(vectors.q[rd]), bytes(vectors.q[rn]), bytes(vectors.q[rm])
        size, count = 1 << (word >> 22 & 3), 16 if word >> 30 & 1 else 8
        decoded = decode_sdk_init_instruction(word, fixtures.BASE, True)
        self.assertEqual(decoded.operation, kind + 22)
        self.assertEqual((decoded.rd, decoded.rn), (rd, rn))
        if kind in (4, 7, 8):
            self.assertEqual((decoded.width, decoded.rm), (count * 8, rm))
            if kind == 4: expected = bytes(a | b for a, b in zip(n[:count], m))
            elif kind == 8: expected = bytes((d & mask) | (a & (255 ^ mask))
                                            for d, a, mask in zip(old[:count], n, m))
            else:
                self.assertEqual(decoded.access_size, size)
                expected = b''.join(bytes([255 if n[i:i+size] == m[i:i+size] else 0]) * size
                                    for i in range(0, count, size))
            expected += bytes(16-count)
        else:
            imm5 = word >> 16 & 31
            size = imm5 & -imm5
            dest = imm5 // (2 * size)
            source = dest if kind == 5 else (word >> 11 & 15) // size
            self.assertEqual((decoded.width, decoded.access_size, decoded.immediate),
                             (size*8 if kind == 5 else 128, size, dest))
            if kind == 5: expected = n[source*size:(source+1)*size] + bytes(16-size)
            else:
                self.assertEqual(decoded.condition, source)
                expected = old[:dest*size] + n[source*size:(source+1)*size] + old[(dest+1)*size:]
        self.assertEqual(self.kind(word), kind)
        self.assertEqual(self.lib.oot_startup_vector_kind(word), 0)
        self.reference_start(vectors, state, backing, [word])
        reference = self.reference.step(state, word)
        reference_vectors = self.reference_vectors()
        before = tuple(bytes(x) for x in (vectors, state, memory, backing, table))
        out, result, write = fixtures.VectorState(), State(), fixtures.VectorWrite()
        self.assertEqual(self.prepare_fn(byref(vectors), word, byref(state), byref(memory),
                                         byref(out), byref(result), byref(write)), 0, hex(word))
        self.assertEqual(bytes(out.q[rd]), expected, hex(word))
        self.assertEqual(bytes(out), reference_vectors, hex(word))
        self.assertEqual(result.values(), reference.values(), hex(word))
        self.assertEqual(tuple(bytes(x) for x in (vectors, state, memory, backing, table)), before)
        self.assertEqual(bytes(self.reference.u.mem_read(fixtures.STACK, len(backing))), bytes(backing))
        self.assertEqual(bytes(write), bytes(sizeof(write)))

    def test_orr_and_bif_all_fields_and_three_way_aliases(self):
        for kind, encode in ((4, orr), (8, bif)):
            for q in (0, 1):
                for rn in range(32):
                    for rd in range(32):
                        self.compare_bits(encode(q, (rn+rd) % 32, rn, rd), kind, rn+rd)
                for rm in range(32):
                    for rn, rd in ((1, 2), (2, 2), (1, rm), (rm, 2), (rm, rm), (31, 31)):
                        for pattern in range(4):
                            self.compare_bits(encode(q, rm, rn, rd), kind, pattern)

    def test_dup_and_ins_every_lane_ignored_bit_and_alias(self):
        for size in (1, 2, 4, 8):
            for dest in range(16 // size):
                imm5 = size * (2*dest+1)
                for rn, rd in ((1, 2), (31, 31), (31, 0)):
                    self.compare_bits(dup_element(imm5, rn, rd), 5)
                    # All 16 imm4 values include every source lane and ignored low bits.
                    for imm4 in range(16):
                        self.compare_bits(ins_element(imm5, imm4, rn, rd), 6, imm4)
            for rn in range(32):
                for rd in range(32):
                    self.compare_bits(dup_element(size, rn, rd), 5)
                    self.compare_bits(ins_element(size, 0, rn, rd), 6)

    def test_cmeq_every_size_and_register_fields(self):
        for q in (0, 1):
            for size in range(4):
                if not q and size == 3: continue
                for rn in range(32):
                    for rd in range(32):
                        self.compare_bits(cmeq(q, size, (rn+rd) % 32, rn, rd), 7)
                for rm in range(32):
                    for rn, rd in ((1, 2), (2, 2), (1, rm), (rm, 2), (rm, rm), (31, 31)):
                        self.compare_bits(cmeq(q, size, rm, rn, rd), 7)

    def test_new_families_do_not_admit_fixed_bit_siblings_or_publish_faults(self):
        for word in (dup_element(0,0,0),dup_element(16,0,0),ins_element(0,0,0,0),
                     ins_element(16,0,0,0),cmeq(0,3,0,0,0)):
            self.assertEqual(self.kind(word),0)
            vectors,state,memory,backing,table=self.fixture()
            out=fixtures.VectorState.from_buffer_copy(bytes([0xa5])*sizeof(fixtures.VectorState))
            result=State.from_buffer_copy(bytes([0xb6])*sizeof(State))
            write=fixtures.VectorWrite.from_buffer_copy(bytes([0xc7])*sizeof(fixtures.VectorWrite))
            objects=(vectors,state,memory,backing,table,out,result,write)
            before=tuple(bytes(x) for x in objects)
            self.assertEqual(self.prepare_fn(byref(vectors),word,byref(state),byref(memory),
                byref(out),byref(result),byref(write)),1)
            self.assertEqual(tuple(bytes(x) for x in objects),before)
        for word, kind, mask in ((orr(1, 2, 1, 0), 4, 0xbfe0fc00),
                                 (dup_element(24, 31, 31), 5, 0xffe0fc00),
                                 (ins_element(24, 7, 31, 31), 6, 0xffe08400),
                                 (cmeq(1, 3, 31, 31, 31), 7, 0xbf20fc00),
                                 (bif(1, 31, 31, 31), 8, 0xbfe0fc00)):
            family = sdk_init_vector_kind(word, True)
            for bit in range(32):
                if mask & (1 << bit):
                    sibling = word ^ (1 << bit)
                    self.assertNotEqual(sdk_init_vector_kind(sibling, True), family)
                    self.assertNotEqual(self.kind(sibling), kind)
            for mode in ('init', 'fpcr', 'fpsr', 'alias'):
                vectors, state, memory, backing, table = self.fixture()
                if mode == 'fpcr': vectors.fpcr = 1 << 22
                if mode == 'fpsr': vectors.fpsr = 1 << 28
                out, result, write = fixtures.VectorState(), State(), fixtures.VectorWrite()
                before = tuple(bytes(x) for x in (vectors, state, memory, backing, table, out, result, write))
                fn = self.lib.oot_startup_vector_prepare if mode == 'init' else self.prepare_fn
                self.assertEqual(fn(byref(vectors), word, byref(state), byref(memory),
                                    byref(vectors if mode == 'alias' else out), byref(result), byref(write)),
                                 1 if mode == 'init' else 2)
                self.assertEqual(tuple(bytes(x) for x in (vectors, state, memory, backing, table, out, result, write)), before)


if __name__ == '__main__':
    unittest.main()
