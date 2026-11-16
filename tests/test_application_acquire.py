"""Application-only LDAR/B/H, independent bytes and pinned Arm state oracle.

Arm encoding/operation: https://documentation-service.arm.com/static/60df18dc0320e92fa40b7e59
The backend supplies a stronger serialized Normal-memory order, not exhaustive
weak-memory equivalence. All images and instructions here are synthetic.
"""
from ctypes import POINTER,byref,c_int,c_uint32,c_uint,c_uint64,c_char_p
import os,struct,sys,unittest
from unittest.mock import patch
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import test_sdk_init_atomics as fixtures
from lifter_validation_types import Memory,State
from arm64_lifter import decode_instruction
from sdk_instructions import decode_sdk_instruction
from sdk_init_instructions import decode_sdk_init_instruction,sdk_init_atomic_kind
from input_formats import InputError

def ldar(size,rt,rn):return 0x08dffc00|({1:0,2:1,4:2,8:3}[size]<<30)|(rn<<5)|rt

class ApplicationAcquireTests(unittest.TestCase):
    memory=fixtures.SdkInitAtomicTests.memory;state=fixtures.SdkInitAtomicTests.state
    @classmethod
    def setUpClass(cls):
        fixtures.SdkInitAtomicTests.setUpClass.__func__(cls)
        cls.step=cls.lib.oot_startup_application_atomic_step
        cls.step.argtypes=[c_uint32,POINTER(State),POINTER(Memory)];cls.step.restype=c_int
        cls.kind=cls.lib.oot_startup_application_atomic_kind;cls.kind.argtypes=[c_uint32];cls.kind.restype=c_int
    def test_all_widths_registers_aliases_zr_and_readonly_match_reference(self):
        memory,backing,keep=self.memory(permissions=1)
        for size in (1,2,4,8):
            for rn in range(32):
                for rt in range(32):
                    state=self.state(rn);word=ldar(size,rt,rn)
                    value=(0xdeadbeef800080ff^((rn<<9)|rt))&((1<<(size*8))-1)
                    backing[256:256+size]=value.to_bytes(size,'little')
                    self.reference.code(struct.pack('<I',word));self.reference.u.mem_write(fixtures.STACK,bytes(backing))
                    expected=self.reference.step(state,word);actual=State.from_buffer_copy(state)
                    self.assertEqual(self.step(word,byref(actual),byref(memory)),0)
                    self.assertEqual(actual.values(),expected.values())
                    if rt!=31:self.assertEqual(actual.x[rt],value)
                    self.assertEqual(bytes(backing),bytes(self.reference.u.mem_read(fixtures.STACK,len(backing))))
                    i=decode_sdk_init_instruction(word,fixtures.BASE,application=True)
                    self.assertEqual((i.width,i.access_size,i.rd,i.rn),(64 if size==8 else 32,size,rt,rn))
                    self.assertEqual(self.kind(word),9)
    def test_faults_and_discarded_results_still_read_without_state_or_memory_effects(self):
        for size in (1,2,4,8):
            for permission in (0,1,2,3):
                for offset in (0,1,4096-256,(1<<39)-fixtures.STACK-256):
                    memory,backing,keep=self.memory(permissions=permission);state=self.state();state.x[2]+=offset
                    word=ldar(size,31,2);before=(state.values(),bytes(backing))
                    status=self.step(word,byref(state),byref(memory))
                    fault=not(permission&1)or offset>=4096-256 or bool(offset%size)
                    self.assertEqual(status,2 if fault else 0)
                    if fault:self.assertEqual((state.values(),bytes(backing)),before)
                    self.assertEqual(bytes(backing),before[1])
                    if fault:self.assertEqual(memory.fault.access,1)
    def test_legacy_domains_and_neighbor_encodings_remain_closed(self):
        for size in (1,2,4,8):
            word=ldar(size,0,1)
            for decode in (decode_instruction,decode_sdk_instruction,decode_sdk_init_instruction):
                with self.assertRaises(InputError):decode(word,fixtures.BASE)
            self.assertIsNone(sdk_init_atomic_kind(word));self.assertEqual(self.lib.oot_startup_init_atomic_kind(word),0)
            state=self.state();memory,backing,keep=self.memory();before=state.values()
            self.assertEqual(self.lib.oot_startup_init_atomic_step(word,byref(state),byref(memory)),1)
            self.assertEqual(state.values(),before)
            for bit in (10,15,16,21,22,23,24,25,26,27,28,29):
                neighbor=word^(1<<bit)
                self.assertNotEqual(self.kind(neighbor),9)
                self.assertNotEqual(sdk_init_atomic_kind(neighbor,True),'ldar')
    def test_generated_dispatch_full_vectors_quanta_and_crossed_metadata(self):
        import test_application_boot as boot
        from test_host_boot import mov64
        from test_sdk_init_vectors import VectorState
        from lifter_validation import compile_library
        value=0x11223344800080ff
        words=[0xd10083ff,boot.simd.fixtures.movi(1,0,14,0x5a,0),boot.simd.fixtures.movi(1,0,14,0xa5,31),
            *mov64(8,value),0xf90003e8,*[ldar(size,n,31)for n,size in enumerate((1,2,4,8))],
            ldar(8,31,31),0x910003e9,ldar(8,9,9),0x910083ff,0xd4200000]
        with patch.object(boot,'simd_program',return_value=(words,[])):
            blob,sources,_=boot.package(2,True,simd_cohort=True)
        source='\n'.join(sources.values())+boot.SNAPSHOT_SOURCE.replace('UINT32_C(0x7e21d81f)',f'UINT32_C({ldar(8,9,9)})')
        lib,build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),extra_source=source,startup=True)
        fn=lib.oot_test_simd_snapshot
        fn.argtypes=[c_char_p,c_uint64,c_uint64,c_uint,POINTER(VectorState),POINTER(c_uint),POINTER(State)];fn.restype=c_int
        path=Path(build['directory'])/'acquire.ootmem';path.write_bytes(blob);states=[]
        for quantum in (1,2,1000):
            history=(VectorState*1024)();count=c_uint();state=State()
            self.assertEqual(fn(os.fsencode(path),quantum,1000,0,history,byref(count),byref(state)),1)
            self.assertEqual(list(state.x[:4]),[0xff,0x80ff,0x800080ff,value]);self.assertEqual(state.x[9],value)
            expected=[bytes(16)for _ in range(32)];expected[0]=bytes([0x5a])*16;expected[31]=bytes([0xa5])*16
            self.assertEqual(bytes(history[count.value-1]),b''.join(expected)+bytes(8));states.append(state.values())
        self.assertEqual(states[0],states[1]);self.assertEqual(states[1],states[2])
        count=c_uint();history=(VectorState*1024)();state=State()
        self.assertEqual(fn(os.fsencode(path),1,1000,1,history,byref(count),byref(state)),0);self.assertEqual(count.value,0)

if __name__=='__main__':unittest.main()
