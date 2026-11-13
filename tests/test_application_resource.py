"""Owned process resource metadata; synthetic inputs and native providers only."""
from ctypes import POINTER,byref,c_int,c_uint64,c_void_p,sizeof,cast
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from lifter_validation_types import State
import test_sdk_init_context as contexts
import test_native_platform as platforms
from test_native_sdk_runtime import NativeReport


class ApplicationResourceTests(unittest.TestCase):
    image=contexts.SdkInitContextTests.image
    config=contexts.SdkInitContextTests.config
    create=contexts.SdkInitContextTests.create
    state=contexts.SdkInitContextTests.state

    @classmethod
    def setUpClass(cls):
        contexts.SdkInitContextTests.setUpClass.__func__(cls)
        fn=cls.lib.oot_native_platform_init
        fn.argtypes=[POINTER(platforms.PlatformState),POINTER(platforms.PlatformConfig)];fn.restype=c_int

    def owner(self,pid=1,active=True):
        state=platforms.PlatformState();config=platforms.PlatformConfig(1,0,0,1,0,0,pid,7)
        self.assertTrue(self.lib.oot_native_platform_init(byref(state),byref(config)))
        # Valid provider state after initialization; its lifetime is already
        # tested separately through the real platform initialization handler.
        if active:state.initialized=1;state.generations=1
        return state

    def query(self,owner,calls,registers,out_count=None,result=None):
        fn=self.lib.oot_application_resource_prepare
        fn.argtypes=[POINTER(platforms.PlatformState),c_uint64,POINTER(State),POINTER(c_uint64),POINTER(State)]
        fn.restype=c_int
        out_count=c_uint64(0xa5a5a5a5a5a5a5a5) if out_count is None else out_count
        result=State.from_buffer_copy(bytes([0xb6])*sizeof(State)) if result is None else result
        before=(bytes(owner),bytes(registers));outputs=(out_count.value,bytes(result))
        status=fn(byref(owner),calls,byref(registers),byref(out_count),byref(result))
        self.assertEqual((bytes(owner),bytes(registers)),before)
        if status:self.assertEqual((out_count.value,bytes(result)),outputs)
        return status,out_count,result

    def count(self,context):
        fn=self.lib.oot_startup_context_application_resource_queries
        fn.argtypes=[c_void_p];fn.restype=c_uint64
        return fn(context)

    def test_exact_handler_only_in_initialized_application_profile(self):
        for flags in (1|2|8|128,1|2|8|128|256,1|2|8|128|256|512):
            context,_,_=self.create(flags=flags,capacity=0x200000)
            enabled=bool(flags&512)
            self.assertEqual(bool(self.lib.oot_startup_context_handler_valid(context,322)),enabled)
            self.assertEqual(bool(self.lib.oot_startup_context_returns_value(context,322)),enabled)
            r=self.state();before=r.values();report=NativeReport()
            self.assertEqual(self.lib.oot_startup_context_native_call(context,322,byref(r),byref(report)),1)
            self.assertEqual(r.values(),before)
            r=self.state()
            self.assertEqual(self.lib.oot_startup_context_native_call(context,64,byref(r),byref(report)),0 if flags&256 else 1)
            for query_index in range(3):
                r=self.state();before=State.from_buffer_copy(r)
                self.assertEqual(self.lib.oot_startup_context_native_call(context,322,byref(r),byref(report)),0 if enabled else 1)
                if enabled:
                    before.x[0]=1;before.pc=before.x[30]
                    self.assertEqual(r.values(),before.values());self.assertEqual(self.count(context),query_index+1)
                else:self.assertEqual(r.values(),before.values())
            if enabled:
                r=self.state();self.assertEqual(self.lib.oot_startup_context_native_call(context,65,byref(r),byref(report)),0)
                r=self.state();before=r.values();calls=self.count(context)
                self.assertEqual(self.lib.oot_startup_context_native_call(context,322,byref(r),byref(report)),1)
                self.assertEqual((r.values(),self.count(context)),(before,calls))
                r=self.state();self.assertEqual(self.lib.oot_startup_context_native_call(context,64,byref(r),byref(report)),0)
                r=self.state();self.assertEqual(self.lib.oot_startup_context_native_call(context,322,byref(r),byref(report)),0)
                self.assertEqual((r.x[0],self.count(context)),(1,calls+1))

    def test_full_width_owner_identity_preserves_every_other_register(self):
        for pid in (1,0xffffffff,0x100000001,0xfedcba9876543210,(1<<64)-1):
            owner=self.owner(pid);r=self.state();r.nzcv=0xd0000000
            for calls in (0,1,(1<<64)-2):
                status,count,result=self.query(owner,calls,r)
                self.assertEqual(status,0);self.assertEqual(count.value,calls+1)
                expected=State.from_buffer_copy(r);expected.x[0]=pid;expected.pc=expected.x[30]
                self.assertEqual(result.values(),expected.values())

    def test_inactive_invalid_owner_counter_and_register_faults_preserve_outputs(self):
        for mutation in ('inactive','owner_version','owner_reserved','pid_zero','active_invalid','generation',
                         'counter','pc_zero','pc_alignment','pc_limit','sp','nzcv','return_zero','return_alignment','return_limit'):
            owner=self.owner();r=self.state();calls=0
            if mutation=='inactive':owner=self.owner(active=False)
            if mutation=='owner_version':owner.version=2
            if mutation=='owner_reserved':owner.reserved=1
            if mutation=='pid_zero':owner.config.process_id=0
            if mutation=='active_invalid':owner.initialized=2
            if mutation=='generation':owner.generations=0
            if mutation=='counter':calls=(1<<64)-1
            if mutation=='pc_zero':r.pc=0
            if mutation=='pc_alignment':r.pc+=1
            if mutation=='pc_limit':r.pc=1<<39
            if mutation=='sp':r.sp+=8
            if mutation=='nzcv':r.nzcv|=1
            if mutation=='return_zero':r.x[30]=0
            if mutation=='return_alignment':r.x[30]+=1
            if mutation=='return_limit':r.x[30]=1<<39
            with self.subTest(mutation=mutation):self.assertEqual(self.query(owner,calls,r)[0],1 if mutation=='inactive' else 2)

    def test_null_and_overlapping_live_outputs_reject_before_publication(self):
        owner=self.owner();r=self.state();count=c_uint64(0x123456789abcdef0)
        out=State.from_buffer_copy(bytes([0xa5])*sizeof(State))
        # Bind the signature through one ordinary call first.
        self.query(owner,0,r)
        fn=self.lib.oot_application_resource_prepare
        normal=[byref(owner),0,byref(r),byref(count),byref(out)]
        cases=[]
        for index in (0,2,3,4):
            args=list(normal);args[index]=None;cases.append(args)
        args=list(normal);args[4]=byref(r);cases.append(args)
        args=list(normal);args[3]=cast(byref(r),POINTER(c_uint64));cases.append(args)
        args=list(normal);args[3]=cast(byref(out),POINTER(c_uint64));cases.append(args)
        before=(bytes(owner),bytes(r),count.value,bytes(out))
        for args in cases:
            self.assertEqual(fn(*args),2)
            self.assertEqual((bytes(owner),bytes(r),count.value,bytes(out)),before)

    def test_aggregate_native_overflow_does_not_commit_resource_query(self):
        context,_,_=self.create(flags=1|2|8|128|256|512,capacity=0x200000)
        report=NativeReport();r=self.state()
        self.assertEqual(self.lib.oot_startup_context_native_call(context,64,byref(r),byref(report)),0)
        native=self.lib.oot_startup_context_native(context).contents
        native.calls=(1<<64)-1
        r=self.state();before=(r.values(),self.count(context),bytes(native))
        self.assertEqual(self.lib.oot_startup_context_native_call(context,322,byref(r),byref(report)),2)
        self.assertEqual((r.values(),self.count(context),bytes(native)),before)


if __name__=='__main__':unittest.main()
