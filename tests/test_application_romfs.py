"""RomFS ownership and availability through the actual startup context."""
from ctypes import POINTER,byref,c_char_p,c_int,c_uint8,c_uint32,c_void_p
import hashlib,os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import test_sdk_init_context as fixtures
from test_romfs_preparation import fixture,PROGRAM_ID
from test_native_romfs import Stats
from test_native_sdk_runtime import NativeReport
from prepare_romfs import prepare

class ApplicationRomFsTests(unittest.TestCase):
    image=fixtures.SdkInitContextTests.image
    config=fixtures.SdkInitContextTests.config
    state=fixtures.SdkInitContextTests.state
    @classmethod
    def setUpClass(cls):
        fixtures.SdkInitContextTests.setUpClass.__func__(cls)
        for name,args,result in (
            ('oot_startup_context_set_romfs',[c_void_p,c_char_p,POINTER(c_uint8)],c_int),
            ('oot_startup_context_romfs_stats',[c_void_p,POINTER(Stats)],c_int),
            ('oot_startup_context_retain',[c_void_p],c_int)):
            fn=getattr(cls.lib,name);fn.argtypes=args;fn.restype=result
    def test_only_fresh_application_context_can_bind_exact_program_and_seal(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);source,prepared=fixture(root);prepare(prepared,root/'romfs')
            index=root/'romfs/romfs.index';seal=(c_uint8*32).from_buffer_copy(hashlib.sha256(index.read_bytes()).digest())
            for flags,program in ((1|2|8|128,PROGRAM_ID),(1|2|8|128|256,PROGRAM_ID),
                (1|2|8|128|256|512,PROGRAM_ID+1),(1|2|8|128|256|512,PROGRAM_ID)):
                cfg,sdk=self.config(flags,0x200000);sdk.program_id=program;error=c_uint32()
                context=self.lib.oot_startup_context_create_sdk(self.image(),byref(cfg),byref(sdk),byref(error));self.assertTrue(context)
                try:
                    app=bool(flags&512);r=self.state();before=r.values();report=NativeReport()
                    self.assertEqual(self.lib.oot_startup_context_native_call(context,384,byref(r),byref(report)),1)
                    self.assertEqual(r.values(),before)
                    self.assertEqual(bool(self.lib.oot_startup_context_handler_valid(context,384)),app)
                    stats=Stats();self.assertFalse(self.lib.oot_startup_context_romfs_stats(context,byref(stats)))
                    wrong=(c_uint8*32)(*([0x33]*32));self.assertFalse(self.lib.oot_startup_context_set_romfs(context,os.fsencode(index),wrong))
                    success=app and program==PROGRAM_ID
                    self.assertEqual(bool(self.lib.oot_startup_context_set_romfs(context,os.fsencode(index),seal)),success)
                    if success:
                        self.assertTrue(self.lib.oot_startup_context_romfs_stats(context,byref(stats)))
                        self.assertEqual((stats.files,stats.directories,stats.mount_calls),(3,2,0))
                        self.assertFalse(self.lib.oot_startup_context_set_romfs(context,os.fsencode(index),seal))
                        # Invalid guest output cannot count a native call or publish mount state.
                        r=self.state();r.x[0]=0;before=r.values();calls=self.lib.oot_startup_context_native(context).contents.calls
                        self.assertEqual(self.lib.oot_startup_context_native_call(context,384,byref(r),byref(report)),2)
                        self.assertEqual(r.values(),before);self.assertEqual(self.lib.oot_startup_context_native(context).contents.calls,calls)
                finally:self.lib.oot_startup_context_destroy(context)
            cfg,sdk=self.config(1|2|8|128|256|512,0x200000);sdk.program_id=PROGRAM_ID;error=c_uint32()
            context=self.lib.oot_startup_context_create_sdk(self.image(),byref(cfg),byref(sdk),byref(error));self.assertTrue(context)
            try:
                self.assertTrue(self.lib.oot_startup_context_retain(context))
                self.assertFalse(self.lib.oot_startup_context_set_romfs(context,os.fsencode(index),seal))
                self.lib.oot_startup_context_destroy(context)
                self.assertTrue(self.lib.oot_startup_context_set_romfs(context,os.fsencode(index),seal))
            finally:self.lib.oot_startup_context_destroy(context)

if __name__=='__main__':unittest.main()
