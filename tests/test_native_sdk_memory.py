"""Whole native-SDK input captures preserve earlier operand limits and faults."""
from ctypes import POINTER,byref,c_int,c_uint8,c_uint32,c_uint64
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from lifter_validation import compile_library
from lifter_validation_types import Memory,Region


class NativeSdkMemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib,cls.metadata=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),
            extra_source='int oot_native_memory_fixture;')
        cls.lib.oot_memory_init.argtypes=[POINTER(Memory),POINTER(Region),c_uint64]
        cls.lib.oot_memory_init.restype=c_int
        for name in ('oot_memory_load_native_input','oot_memory_load_record'):
            function=getattr(cls.lib,name)
            function.argtypes=[POINTER(Memory),c_uint64,POINTER(c_uint8),c_uint32];function.restype=c_int
        cls.lib.oot_memory_probe.argtypes=[POINTER(Memory),c_uint64,c_uint32,c_uint32]
        cls.lib.oot_memory_probe.restype=c_int

    def test_complete_capture_and_trailing_permission_fault(self):
        base=0x10000000;raw=bytes((i*13+7)%256 for i in range(4096))
        for tail_permission in (0,1,2,3):
            first=(c_uint8*4095).from_buffer_copy(raw[:-1]);last=(c_uint8*1)(raw[-1])
            table=(Region*2)(Region(base,4095,first,1),Region(base+4095,1,last,tail_permission))
            memory=Memory();self.assertTrue(self.lib.oot_memory_init(byref(memory),table,2))
            out=(c_uint8*4096)(*([0xa5]*4096));before=bytes(out)
            ok=self.lib.oot_memory_load_native_input(byref(memory),base,out,4096)
            self.assertEqual(ok,bool(tail_permission&1))
            self.assertEqual(bytes(out),raw if ok else before)
            self.assertEqual(bytes(first)+bytes(last),raw)
            if not ok:self.assertEqual((memory.fault.address,memory.fault.failing_address,memory.fault.size,memory.fault.access,memory.fault.reason),
                (base,base+4095,4096,1,2))

    def test_bounds_wrap_and_unchanged_legacy_limits(self):
        base=0x10000000;backing=(c_uint8*4096)(*range(256),*([0]*3840))
        table=(Region*1)(Region(base,4096,backing,3));memory=Memory()
        self.assertTrue(self.lib.oot_memory_init(byref(memory),table,1))
        for address,size in ((base,0),(base,4097),(base+1,4096),((1<<64)-4,8)):
            out=(c_uint8*4097)(*([0xcc]*4097));before=bytes(out)
            self.assertFalse(self.lib.oot_memory_load_native_input(byref(memory),address,out,size))
            self.assertEqual(bytes(out),before)
        out=(c_uint8*65)(*([0x7a]*65))
        self.assertFalse(self.lib.oot_memory_load_record(byref(memory),base,out,65))
        self.assertEqual(bytes(out),bytes([0x7a]*65))
        self.assertFalse(self.lib.oot_memory_probe(byref(memory),base,17,1))
        self.assertTrue(self.lib.oot_memory_load_native_input(byref(memory),base+1,out,65))
        self.assertEqual(bytes(out),bytes(backing)[1:66])


if __name__=='__main__':unittest.main()
