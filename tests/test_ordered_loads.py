"""Exact no-offset RCpc encodings, unchanged function policies, native ordering."""

import importlib.util
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from arm64_lifter import decode_instruction,emit_c,UnsupportedInstruction
from input_formats import InputError
from ordered_programs import rcpc
from ordered_validation import run_validation
from pauth_stack_validation import PauthAssembler
from stack_layout_verifier import verify_pauth_stack_functions
from leaf_verifier import verify_leaf


class OrderedDecoderTests(unittest.TestCase):
    def test_all_registers_sizes_and_exact_encoding_fields(self):
        for size in range(4):
            for rn in range(32):
                for rt in range(32):
                    ins=decode_instruction(rcpc(size,rt,rn),0x1000)
                    self.assertEqual((ins.form,ins.width,ins.access_size,ins.rd,ins.rn,ins.load,ins.writeback),
                                     ('load_acquire_rcpc',64 if size==3 else 32,1<<size,rt,rn,True,False))

    def test_nearby_atomic_ordered_and_postindex_encodings_stay_rejected(self):
        for word in (0xC8DFFC20,0xF8A00020,0x38BFC420,0x38B7C020,0xF8BFC420,0xD5033BBF):
            with self.subTest(word=hex(word)),self.assertRaises(UnsupportedInstruction):decode_instruction(word,0x1000)
        for word in (0x38DFC020,0x38BFC820):  # Valid ordinary scalar encodings in the neighboring space.
            self.assertNotEqual(decode_instruction(word,0x1000).form,'load_acquire_rcpc')

    def test_emitter_keeps_access_for_zr_and_reads_sp_explicitly(self):
        source,report=emit_c(struct.pack('<I',rcpc(0,31,31)),0x1000)
        self.assertIn('oot_arm64_read(s, 31, 64, 1)',source)
        self.assertIn('oot_memory_load_rcpc(memory, address, 1, 1, &value)',source)
        self.assertIn('oot_arm64_write(s, 31, 32, 0, value)',source)
        self.assertTrue(report['guest_memory_access'])

    def test_existing_function_profiles_do_not_gain_memory_permissions(self):
        code=struct.pack('<II',rcpc(0),0xD65F03C0)
        with self.assertRaises(InputError):verify_leaf(code,0x1000)
        a=PauthAssembler('rcpc_frame',0x1000,32);a.emit(rcpc(0));p=a.finish()
        with self.assertRaises(InputError):verify_pauth_stack_functions({p.base:p.data},{},p.base)


@unittest.skipUnless(os.name=='nt' and importlib.util.find_spec('unicorn'),'native Windows and pinned reference required')
class NativeOrderedTests(unittest.TestCase):
    def test_values_faults_pac_frames_and_native_publication(self):
        report,path=run_validation(os.environ.get('OOT_LIFTER_COMPILER','cmake'))
        self.assertEqual(report['value_fault_comparisons'],1647)
        self.assertGreaterEqual(report['policy_checks'],28)
        self.assertEqual((report['pac_frame_cases'],report['pac_prefix_checks']),(20,96))
        self.assertEqual(report['native_publication_rounds'],40000)
        self.assertFalse(report['weak_memory_outcome_equivalence_claimed']);self.assertTrue(path.is_file())


if __name__=='__main__':unittest.main()
