"""Graphics profile admission is independent of GPU availability."""
from ctypes import Structure,POINTER,byref,c_char,c_int,c_uint32,c_uint64,c_void_p
import unittest
import test_sdk_init_context as context_fixture
from test_native_sdk_runtime import NativeReport

class GraphicsReport(Structure):
    _fields_=[(n,c_uint32) for n in ('version','ready','api_version','driver_version','vendor_id','device_id','queue_family','reserved')]+[
        (n,c_uint64) for n in ('calls','boots','checks','working_memory','working_size')]+[('device_name',c_char*256)]

class GraphicsContextTests(unittest.TestCase):
    image=context_fixture.SdkInitContextTests.image
    config=context_fixture.SdkInitContextTests.config
    create=context_fixture.SdkInitContextTests.create
    state=context_fixture.SdkInitContextTests.state
    native_call=context_fixture.SdkInitContextTests.native_call
    providers=context_fixture.SdkInitContextTests.providers
    @classmethod
    def setUpClass(cls):
        context_fixture.SdkInitContextTests.setUpClass.__func__(cls)
        for name,args in (
            ('oot_startup_context_graphics_enabled',[c_void_p]),
            ('oot_startup_context_graphics_report',[c_void_p,POINTER(GraphicsReport)])):
            f=getattr(cls.lib,name);f.argtypes=args;f.restype=c_int

    def test_opt_in_and_preboot_check_create_no_gpu_readiness(self):
        for flags,enabled in ((context_fixture.INIT_FLAGS,False),
            (context_fixture.INIT_FLAGS|512,False),(context_fixture.INIT_FLAGS|512|1024,True)):
            c,_,_=self.create(flags=flags,capacity=0x200000)
            self.assertEqual(bool(self.lib.oot_startup_context_graphics_enabled(c)),enabled)
            self.assertEqual(bool(self.lib.oot_startup_context_handler_valid(c,448)),enabled)
            self.assertEqual(bool(self.lib.oot_startup_context_handler_valid(c,449)),enabled)
            self.assertFalse(self.lib.oot_startup_context_returns_value(c,448))
            r=GraphicsReport();self.assertEqual(bool(self.lib.oot_startup_context_graphics_report(c,byref(r))),enabled)
            if enabled:
                self.assertEqual((r.version,r.ready,r.calls),(1,0,0))
                self.native_call(c,449,self.state(),expected=1)
                self.assertEqual(self.lib.oot_startup_context_native(c).contents.calls,0)

    def test_graphics_flag_requires_application_and_native_overflow_precedes_boot(self):
        cfg,sdk=self.config(flags=context_fixture.INIT_FLAGS|1024,capacity=0x200000)
        error=c_uint32()
        self.assertFalse(self.lib.oot_startup_context_create_sdk(self.image(),byref(cfg),byref(sdk),byref(error)))
        c,_,_=self.create(flags=context_fixture.INIT_FLAGS|512|1024,capacity=0x200000)
        self.native_call(c,64,self.state(),expected=0)
        self.lib.oot_startup_context_native(c).contents.calls=(1<<64)-1
        state=self.state();old=state.values();report=NativeReport()
        self.assertEqual(self.lib.oot_startup_context_native_call(c,448,byref(state),byref(report)),2)
        self.assertEqual(state.values(),old)
        r=GraphicsReport();self.assertTrue(self.lib.oot_startup_context_graphics_report(c,byref(r)))
        self.assertEqual((r.ready,r.calls,r.boots),(0,0,0))

if __name__=='__main__':unittest.main()
