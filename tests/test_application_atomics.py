"""Application-only A/R additions against the enabled pinned ARM reference."""
from ctypes import POINTER,byref,c_int,c_uint32
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import test_sdk_init_atomics as fixtures
from lifter_validation_types import Memory,State
from sdk_init_instructions import decode_sdk_init_instruction,sdk_init_atomic_kind
from input_formats import InputError
from startup_audit import StartupDecodeCache,audit_entry
from test_startup_audit import linked
from test_arm64_analysis import branch,RET

class ApplicationAtomicTests(unittest.TestCase):
    memory=fixtures.SdkInitAtomicTests.memory;state=fixtures.SdkInitAtomicTests.state
    @classmethod
    def setUpClass(cls):
        fixtures.SdkInitAtomicTests.setUpClass.__func__(cls)
        cls.step=cls.lib.oot_startup_application_atomic_step;cls.step.argtypes=[c_uint32,POINTER(State),POINTER(Memory)];cls.step.restype=c_int
        cls.kind=cls.lib.oot_startup_application_atomic_kind;cls.kind.argtypes=[c_uint32];cls.kind.restype=c_int
    def test_all_fields_aliases_wrapping_and_zero_register_match_reference(self):
        memory,backing,keep=self.memory()
        edge=(0,1,0xffffffff,0xffffffffffffffff,0x80000000,0x8000000000000000)
        for size in (4,8):
            for order in (1,2):
                for rs in range(32):
                    for rt in range(32):
                        rn=(rs+rt)%32;state=self.state(rn)
                        word=fixtures.ldadd(size,rs=rs,rt=rt,rn=rn)|(order<<22)
                        self.assertEqual(self.kind(word),7 if order==1 else 6)
                        self.assertEqual(self.lib.oot_startup_init_atomic_kind(word),0)
                        self.assertIsNone(sdk_init_atomic_kind(word))
                        with self.assertRaises(InputError):decode_sdk_init_instruction(word,fixtures.BASE)
                        self.assertEqual(decode_sdk_init_instruction(word,fixtures.BASE,application=True).form,'sdk_init_atomic')
                        old=edge[(rs+rt)%len(edge)]&((1<<(size*8))-1)
                        backing[256:256+size]=old.to_bytes(size,'little')
                        self.reference.code(struct.pack('<I',word));self.reference.u.mem_write(fixtures.STACK,bytes(backing))
                        expected=self.reference.step(state,word);actual=State.from_buffer_copy(state)
                        self.assertEqual(self.step(word,byref(actual),byref(memory)),0)
                        self.assertEqual(actual.values(),expected.values())
                        self.assertEqual(bytes(backing),bytes(self.reference.u.mem_read(fixtures.STACK,len(backing))))
    def test_faults_and_legacy_rejections_preserve_full_state_and_backing(self):
        for permissions in (0,1,2,3):
            for offset in (0,1,4096-256):
                memory,backing,keep=self.memory(permissions=permissions);state=self.state();state.x[2]+=offset
                word=fixtures.ldadd(8)|(1<<22);before=(state.values(),bytes(backing))
                old=State.from_buffer_copy(state)
                self.assertEqual(self.lib.oot_startup_init_atomic_step(word,byref(old),byref(memory)),1)
                self.assertEqual((old.values(),bytes(backing)),before)
                status=self.step(word,byref(state),byref(memory))
                if permissions!=3 or offset:self.assertEqual(status,2);self.assertEqual((state.values(),bytes(backing)),before)
                else:self.assertEqual(status,0)
    def test_decode_memo_keeps_application_and_initialization_domains_separate(self):
        raw=linked({0:branch(0,0x40),0x40:0xb8600041,0x44:RET});cache=StartupDecodeCache()
        for app in (False,True,False,True):
            report=audit_entry(raw,sdk=True,sdk_init=True,application=app,decode_cache=cache)
            node=next(n for n in report['entry_graph']['nodes']if n['offset']==0x40)
            self.assertEqual(node['semantic_supported'],app)
            self.assertEqual(report,audit_entry(raw,sdk=True,sdk_init=True,application=app))
