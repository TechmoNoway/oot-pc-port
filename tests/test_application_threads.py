"""Owned main-thread metadata must agree across setters and every query."""
from ctypes import POINTER,Structure,byref,c_int,c_uint32,c_uint64,c_void_p
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import test_sdk_init_context as fixtures
from startup_validation import State,ServiceReport
from application_audit import audit_thread_wrappers
from module_linker import Module,Linker
from test_arm64_analysis import synthetic_module,branch,RET
from input_formats import InputError

class ThreadState(Structure):
    _fields_=[('priority',c_uint32),('core',c_uint32),('affinity',c_uint64),('priority_updates',c_uint64),('affinity_updates',c_uint64),('ideal_core',c_uint32),('reserved',c_uint32)]

class ApplicationThreadTests(unittest.TestCase):
    image=fixtures.SdkInitContextTests.image;config=fixtures.SdkInitContextTests.config;create=fixtures.SdkInitContextTests.create;state=fixtures.SdkInitContextTests.state
    @classmethod
    def setUpClass(cls):
        fixtures.SdkInitContextTests.setUpClass.__func__(cls)
        f=cls.lib.oot_startup_context_application_thread;f.argtypes=[c_void_p,POINTER(ThreadState)];f.restype=c_int
    def owned(self,context):
        out=ThreadState();self.assertTrue(self.lib.oot_startup_context_application_thread(context,byref(out)));return out
    def call(self,context,service,args,status=0):
        s=self.state()
        for n,value in args.items():s.x[n]=value
        before=State.from_buffer_copy(s);report=ServiceReport()
        self.assertEqual(self.lib.oot_startup_context_service(context,service,byref(s),byref(report)),status)
        if status:self.assertEqual(s.values(),before.values())
        else:
            expected=State.from_buffer_copy(before);expected.pc+=4
            if service in (13,15):expected.x[0]=0;self.assertEqual(s.values(),expected.values())
        return s
    def context(self):
        cfg,sdk=self.config(flags=1|2|8|128|256|512,capacity=0x200000)
        sdk.priority_mask=(1<<31)|(1<<44)|(1<<63);sdk.core_mask=0b1011
        error=c_uint32();c=self.lib.oot_startup_context_create_sdk(self.image(),byref(cfg),byref(sdk),byref(error))
        self.assertTrue(c,error.value);self.addCleanup(self.lib.oot_startup_context_destroy,c);return c,cfg
    def test_all_priority_values_handles_and_queries_preserve_rejected_state(self):
        context,cfg=self.context();updates=0;priority=44
        for handle in (cfg.main_thread_handle,0xffff8000,0x1234):
            for value in range(65):
                good=handle!=0x1234 and value in (31,44,63)
                before=bytes(self.owned(context));self.call(context,13,{0:handle,1:value},0 if good else 1)
                if good:updates+=1;priority=value
                else:self.assertEqual(bytes(self.owned(context)),before)
                state=self.owned(context);self.assertEqual((state.priority,state.priority_updates),(priority,updates))
                query=self.call(context,12,{1:cfg.main_thread_handle});self.assertEqual((query.x[0],query.x[1]),(0,priority))
        self.call(context,13,{0:cfg.main_thread_handle,1:0x10000002c})
        self.assertEqual(self.owned(context).priority,44)
    def test_concrete_affinity_masks_query_current_core_and_failures_are_atomic(self):
        context,cfg=self.context();updates=0
        for core in (0,1,2,3,63,64,0xffffffff,0xfffffffe):
            for mask in (0,1,2,3,8,9,11,15,1<<63):
                good=bool(mask) and not(mask&~0b1011) and (core==0xffffffff or (core<64 and bool(mask&(1<<core))))
                previous_core=self.owned(context).core
                before=bytes(self.owned(context));self.call(context,15,{0:cfg.main_thread_handle,1:core,2:mask},0 if good else 1)
                if good:
                    updates+=1;state=self.owned(context)
                    active=core if core<64 else (previous_core if mask&(1<<previous_core) else mask.bit_length()-1)
                    self.assertEqual((state.core,state.ideal_core,state.affinity,state.affinity_updates),(active,core,mask,updates))
                    query=self.call(context,14,{2:cfg.main_thread_handle});self.assertEqual((query.x[0],query.x[1],query.x[2]),(0,core,mask))
                    self.assertEqual(self.call(context,16,{}).x[0],active)
                else:self.assertEqual(bytes(self.owned(context)),before)
        before=bytes(self.owned(context));self.call(context,15,{0:0x1234,1:0,2:1},1);self.assertEqual(bytes(self.owned(context)),before)
    def test_older_profiles_keep_both_setters_unsupported(self):
        for flags in (1|2|8|128,1|2|8|128|256):
            c,cfg,_=self.create(flags=flags,capacity=0x200000)
            out=ThreadState(priority=0xa5);self.assertFalse(self.lib.oot_startup_context_application_thread(c,byref(out)))
            self.assertEqual(out.priority,0xa5)
            self.call(c,13,{0:cfg.main_thread_handle,1:44},1);self.call(c,15,{0:cfg.main_thread_handle,1:0,2:1},1)
    def test_original_wrappers_must_be_unique_exact_aligned_text(self):
        words={0:branch(0,0x40),0x40:0xd40001a1,0x44:RET,0x50:0xd40001e1,0x54:RET}
        l=Linker([Module('sdk',synthetic_module(words))]);l.apply()
        report=audit_thread_wrappers(l);self.assertEqual([r['service']for r in report],[13,15])
        l.modules[0].image[0x50]^=1
        with self.assertRaises(InputError):audit_thread_wrappers(l)
