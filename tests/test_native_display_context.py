"""The display provider is explicitly gated and cold contexts create no HWND."""
from ctypes import Structure,POINTER,byref,c_int,c_uint32,c_uint64,c_void_p
import unittest
import test_sdk_init_context as fixture
from test_native_sdk_runtime import NativeReport

class DisplayReport(Structure):
    _fields_=[(n,c_uint32) for n in ('version','ready','presentation_supported','reserved')]+[
        (n,c_uint64) for n in ('calls','initializations')]

class DisplayContextTests(unittest.TestCase):
    image=fixture.SdkInitContextTests.image
    config=fixture.SdkInitContextTests.config
    create=fixture.SdkInitContextTests.create
    state=fixture.SdkInitContextTests.state
    native_call=fixture.SdkInitContextTests.native_call
    providers=fixture.SdkInitContextTests.providers
    @classmethod
    def setUpClass(cls):
        fixture.SdkInitContextTests.setUpClass.__func__(cls)
        for name,args in (
            ('oot_startup_context_display_enabled',[c_void_p]),
            ('oot_startup_context_display_report',[c_void_p,POINTER(DisplayReport)])):
            f=getattr(cls.lib,name);f.argtypes=args;f.restype=c_int

    def test_only_explicit_profile_admits_void_initializer_and_remains_cold(self):
        for flags,enabled in ((fixture.INIT_FLAGS,False),(fixture.INIT_FLAGS|512,False),
            (fixture.INIT_FLAGS|512|1024,False),(fixture.INIT_FLAGS|512|1024|2048,True)):
            c,_,_=self.create(flags=flags,capacity=0x200000)
            self.assertEqual(bool(self.lib.oot_startup_context_display_enabled(c)),enabled)
            self.assertEqual(bool(self.lib.oot_startup_context_handler_valid(c,450)),enabled)
            self.assertFalse(self.lib.oot_startup_context_returns_value(c,450))
            r=DisplayReport();self.assertEqual(bool(self.lib.oot_startup_context_display_report(c,byref(r))),enabled)
            if enabled:
                self.assertEqual((r.version,r.ready,r.calls,r.initializations),(1,0,0,0))
                self.native_call(c,450,self.state(),expected=1)
                self.assertEqual(self.lib.oot_startup_context_native(c).contents.calls,0)

    def test_requires_graphics_and_aggregate_overflow_precedes_resources(self):
        cfg,sdk=self.config(flags=fixture.INIT_FLAGS|512|2048,capacity=0x200000);error=c_uint32()
        self.assertFalse(self.lib.oot_startup_context_create_sdk(self.image(),byref(cfg),byref(sdk),byref(error)))
        c,_,_=self.create(flags=fixture.INIT_FLAGS|512|1024|2048,capacity=0x200000)
        self.native_call(c,64,self.state(),expected=0)
        self.lib.oot_startup_context_native(c).contents.calls=(1<<64)-1
        state=self.state();old=state.values();report=NativeReport()
        self.assertEqual(self.lib.oot_startup_context_native_call(c,450,byref(state),byref(report)),2)
        self.assertEqual(state.values(),old)
        r=DisplayReport();self.assertTrue(self.lib.oot_startup_context_display_report(c,byref(r)))
        self.assertEqual((r.ready,r.calls,r.initializations),(0,0,0))

if __name__=='__main__':unittest.main()
