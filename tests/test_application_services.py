"""Application policy ownership, full ABI preservation and exact audit extension."""
from copy import deepcopy
from ctypes import POINTER,Structure,byref,c_int,c_uint32,c_uint64,c_void_p,sizeof
import os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from application_audit import CONTRACTS,extend_application_audit
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import State

class Services(Structure):
    _fields_=[('version',c_uint32),('graphics_notifications',c_uint32),('reserved',c_uint32*2),('policy_calls',c_uint64),('language_code',c_uint64),('language_calls',c_uint64)]

class ApplicationServicesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source=f'#include "{(ROOT/"src/application_services.c").as_posix()}"\n'
        cls.lib,_=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),extra_source=source)
        cls.prepare=cls.lib.oot_application_services_prepare
        cls.prepare.argtypes=[POINTER(Services),c_uint32,c_uint32,POINTER(State),POINTER(Services),POINTER(State)]
        cls.prepare.restype=c_int

    def test_owned_language_preference_returns_original_eight_byte_value_only(self):
        code=int.from_bytes(b'en-US\0\0\0','little')
        for supplied in (0,code,code+1):
            service=Services(version=1,language_code=supplied)
            state=State();state.pc=0x1000040;state.sp=0x700001000;state.x[30]=0x1000080
            for n in range(30):state.x[n]=0x9988776600000000+n
            out=Services();result=State();before=State.from_buffer_copy(state)
            status=self.prepare(byref(service),321,1,byref(state),byref(out),byref(result))
            self.assertEqual(status,0 if supplied==code else 1)
            if not status:
                before.x[0]=code;before.pc=before.x[30]
                self.assertEqual(result.values(),before.values());self.assertEqual(out.language_calls,1)
                self.assertEqual((out.language_code,out.policy_calls),(code,0))
        service=Services(version=1,language_code=code,language_calls=(1<<64)-1)
        before=(bytes(out),bytes(result));self.assertEqual(self.prepare(byref(service),321,1,byref(state),byref(out),byref(result)),2)
        self.assertEqual((bytes(out),bytes(result)),before)

    def test_policy_requires_platform_and_preserves_full_abi_on_all_inputs(self):
        service=Services(version=1);registers=State();registers.pc=0x1000040;registers.sp=0x700001000;registers.nzcv=0xd0000000
        for n in range(31):registers.x[n]=0x8877665500000000+n
        registers.x[30]=0x1000080
        for platform in (0,1,2):
            for handler in (31,320,321):
                for value in (0,1,2,0xffffffff,0x100000001):
                    registers.x[0]=value;next_state=Services.from_buffer_copy(bytes([0xa5])*sizeof(Services));result=State.from_buffer_copy(bytes([0xb6])*sizeof(State))
                    inputs=(bytes(service),bytes(registers));outputs=(bytes(next_state),bytes(result))
                    status=self.prepare(byref(service),handler,platform,byref(registers),byref(next_state),byref(result))
                    expected=2 if platform==2 else (0 if platform==1 and handler==320 and value&0xffffffff<=1 else 1)
                    self.assertEqual(status,expected);self.assertEqual((bytes(service),bytes(registers)),inputs)
                    if status:self.assertEqual((bytes(next_state),bytes(result)),outputs)
                    else:
                        wanted=State.from_buffer_copy(registers);wanted.pc=registers.x[30]
                        self.assertEqual(result.values(),wanted.values());self.assertEqual(next_state.policy_calls,1)
                        self.assertEqual(next_state.graphics_notifications,value&0xffffffff)

    def test_alias_overflow_bad_state_and_invalid_registers_preserve_outputs(self):
        for mutation in ('alias','overflow','version','reserved','sp','nzcv','pc','return'):
            state=Services(version=1);r=State();r.pc=0x1000040;r.sp=0x700001000;r.x[30]=0x1000080
            if mutation=='overflow':state.policy_calls=(1<<64)-1
            if mutation=='version':state.version=2
            if mutation=='reserved':state.reserved[0]=1
            if mutation=='sp':r.sp+=8
            if mutation=='nzcv':r.nzcv=1
            if mutation=='pc':r.pc+=1
            if mutation=='return':r.x[30]=1<<39
            out=Services.from_buffer_copy(bytes([0xa5])*sizeof(Services));result=State.from_buffer_copy(bytes([0xb6])*sizeof(State))
            before=(bytes(state),bytes(r),bytes(out),bytes(result))
            self.assertEqual(self.prepare(byref(state),320,1,byref(r),byref(state if mutation=='alias' else out),byref(result)),2)
            self.assertEqual((bytes(state),bytes(r),bytes(out),bytes(result)),before)

    def test_exact_guard_extension_does_not_mutate_the_initialization_registry(self):
        symbol=CONTRACTS[0][2]
        original=dict(functions=[dict(symbol=c[2],names=[c[2]],handler_id=31,module='sdk',entry=0x100040+i*128,size=68,body_sha256='11'*32) for i,c in enumerate(CONTRACTS)])
        before=deepcopy(original);report=extend_application_audit(original)
        self.assertEqual(original,before);self.assertEqual(report['functions'][0]['handler_id'],320)
        self.assertEqual(report['functions'][0]['body_sha256'],'11'*32)
        self.assertEqual(len(report['application_providers']),14)
        for contract,row in zip(CONTRACTS,report['functions']):
            self.assertEqual((row['handler_id'],row['returns_value'],row['return_register']),
                (contract[0],contract[4],'X0' if contract[4] else None))
        for index in range(1,len(CONTRACTS)):
            bad=deepcopy(original);bad['functions'].pop(index)
            with self.subTest(missing=CONTRACTS[index][1]),self.assertRaises(InputError):extend_application_audit(bad)
        for change in ('missing','alias','handler','module'):
            bad=deepcopy(original)
            if change=='missing':bad['functions']=[]
            if change=='alias':bad['functions'][0]['names'].append('other')
            if change=='handler':bad['functions'][0]['handler_id']=64
            if change=='module':bad['functions'][0]['module']='main'
            with self.assertRaises(InputError):extend_application_audit(bad)

class ApplicationContextTests(unittest.TestCase):
    from test_sdk_init_context import SdkInitContextTests as Fixture
    image=Fixture.image;config=Fixture.config;create=Fixture.create;state=Fixture.state
    @classmethod
    def setUpClass(cls):
        cls.Fixture.setUpClass.__func__(cls)
        for name,args,result in (
            ('oot_startup_context_application_enabled',[c_void_p],c_int),
            ('oot_startup_context_application_services',[c_void_p],POINTER(Services))):
            fn=getattr(cls.lib,name);fn.argtypes=args;fn.restype=result

    def test_application_policy_is_unavailable_to_every_earlier_context(self):
        from test_native_sdk_runtime import NativeReport
        for flags in (1|2|8|128,1|2|8|128|256,1|2|8|128|256|512):
            context,_,_=self.create(flags=flags,capacity=0x200000)
            enabled=bool(flags&512)
            self.assertEqual(bool(self.lib.oot_startup_context_application_enabled(context)),enabled)
            self.assertEqual(bool(self.lib.oot_startup_context_application_services(context)),enabled)
            self.assertEqual(bool(self.lib.oot_startup_context_handler_valid(context,320)),enabled)
            report=NativeReport();r=self.state();r.x[0]=1;before=r.values()
            # Even the new profile needs a real initialized platform provider.
            self.assertEqual(self.lib.oot_startup_context_native_call(context,320,byref(r),byref(report)),1)
            self.assertEqual(r.values(),before)
            self.assertEqual(self.lib.oot_startup_context_native_call(context,64,byref(r),byref(report)),0 if flags&256 else 1)
            r=self.state();r.x[0]=1;before=State.from_buffer_copy(r)
            self.assertEqual(self.lib.oot_startup_context_native_call(context,320,byref(r),byref(report)),0 if enabled else 1)
            if enabled:
                before.pc=before.x[30];self.assertEqual(r.values(),before.values())
                service=self.lib.oot_startup_context_application_services(context).contents
                self.assertEqual((service.graphics_notifications,service.policy_calls),(1,1))

    def test_application_context_requires_initialization(self):
        from ctypes import c_uint32
        context,_,_=self.create(flags=1|2|8|128|256|512,capacity=0x200000)
        self.assertTrue(self.lib.oot_startup_context_application_enabled(context))
        cfg,sdk=self.config(flags=1|2|8|128|512,capacity=0x200000);error=c_uint32()
        self.assertFalse(self.lib.oot_startup_context_create_sdk(self.image(),byref(cfg),byref(sdk),byref(error)))
