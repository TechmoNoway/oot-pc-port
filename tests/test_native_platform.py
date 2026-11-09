"""Synthetic owned platform lifetimes, scalar ABI and transactional isolation."""

from ctypes import (POINTER, Structure, byref, c_int, c_size_t, c_uint8,
                    c_uint32, c_uint64, cast, sizeof)
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from lifter_validation import compile_library
from lifter_validation_types import Memory, Region, State

BASE=0x200000000


class PlatformConfig(Structure):
    _fields_=[(name,c_uint32) for name in ('version','operation_mode','performance_mode',
        'focus_state','graphics_scale','reserved')]+[('process_id',c_uint64),('main_thread_id',c_uint64)]


class PlatformState(Structure):
    _fields_=[(name,c_uint32) for name in ('version','initialized','cpu_boost_mode',
        'focus_handling_mode','resume_notification_enabled','operation_notification_enabled',
        'performance_notification_enabled','reserved')]+[('config',PlatformConfig)]+[
        (name,c_uint64) for name in ('calls','initialization_calls','finalization_calls',
        'generations','boost_updates','focus_updates','notification_updates','queries')]


class PlatformWrite(Structure):
    _fields_=[('address',c_uint64),('size',c_uint32),('bytes',c_uint8*64)]


class PlatformReport(Structure):
    _fields_=[(name,c_uint32) for name in ('status','handler','error','size')]


class NativePlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This independent provider needs only the checked memory backend. It
        # deliberately does not execute or register an original game function.
        cls.lib,_=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),
            extra_source='#include "native_platform.c"\n'
                'OOT_LIFT_EXPORT size_t oot_test_platform_size(unsigned n) {\n'
                'switch(n) { case 0:return sizeof(OotNativePlatformConfig);\n'
                'case 1:return sizeof(OotNativePlatform); case 2:return sizeof(OotNativePlatformWrite);\n'
                'default:return sizeof(OotNativePlatformReport); } }\n')
        signatures={
            'oot_native_platform_init':([POINTER(PlatformState),POINTER(PlatformConfig)],c_int),
            'oot_native_platform_valid':([POINTER(PlatformState)],c_int),
            'oot_native_platform_handler_valid':([c_uint32],c_int),
            'oot_native_platform_returns_value':([c_uint32],c_int),
            'oot_native_platform_prepare':([POINTER(PlatformState),c_uint32,POINTER(State),
                POINTER(Memory),POINTER(PlatformState),POINTER(State),POINTER(PlatformWrite),
                POINTER(PlatformReport)],c_int),
            'oot_memory_init':([POINTER(Memory),POINTER(Region),c_size_t],c_int),
            'oot_test_platform_size':([c_uint32],c_size_t)}
        for name,(arguments,result) in signatures.items():
            function=getattr(cls.lib,name);function.argtypes=arguments;function.restype=result
        for n,kind in enumerate((PlatformConfig,PlatformState,PlatformWrite,PlatformReport)):
            if cls.lib.oot_test_platform_size(n)!=sizeof(kind):
                raise AssertionError(f'{kind.__name__} native layout differs')

    def fixture(self,initialized=True,config=None):
        backing=(c_uint8*1024)(*[n%256 for n in range(1024)])
        table=(Region*1)(Region(BASE,len(backing),backing,1))
        memory=Memory();self.assertTrue(self.lib.oot_memory_init(byref(memory),table,1))
        state=PlatformState()
        if config is None:config=PlatformConfig(1,0,0,1,0,0,1,1)
        self.assertTrue(self.lib.oot_native_platform_init(byref(state),byref(config)))
        registers=State()
        for n in range(31):registers.x[n]=0xfedcba9800001000+n
        registers.pc=0x1000040;registers.x[30]=0x1000080
        registers.sp=0x7000001000;registers.nzcv=0xb0000000
        if initialized:state=self.prepare(state,64,registers,memory)[0]
        return state,registers,memory,backing,table

    def prepare(self,state,handler,registers,memory,status=0,value=None,error=None):
        next_state=PlatformState.from_buffer_copy(bytes([0xa5])*sizeof(PlatformState))
        result=State.from_buffer_copy(bytes([0xb6])*sizeof(State))
        write=PlatformWrite.from_buffer_copy(bytes([0xc7])*sizeof(PlatformWrite))
        report=PlatformReport()
        before=(bytes(state),bytes(registers))
        outputs=(bytes(next_state),bytes(result),bytes(write))
        returned=self.lib.oot_native_platform_prepare(byref(state),handler,byref(registers),
            byref(memory),byref(next_state),byref(result),byref(write),byref(report))
        self.assertEqual(returned,status)
        self.assertEqual((bytes(state),bytes(registers)),before)
        self.assertEqual((report.status,report.handler,report.size),(status,handler,0))
        if error is not None:self.assertEqual(report.error,error)
        if status:
            self.assertEqual((bytes(next_state),bytes(result),bytes(write)),outputs)
        else:
            expected=State.from_buffer_copy(registers);expected.pc=registers.x[30]
            if value is not None:expected.x[0]=value
            self.assertEqual(result.values(),expected.values())
            self.assertEqual((write.address,write.size,bytes(write.bytes)),(0,0,bytes(64)))
            self.assertTrue(self.lib.oot_native_platform_valid(byref(next_state)))
        return next_state,result,write,report

    def test_configuration_is_validated_and_owned(self):
        config=PlatformConfig(1,1,1,3,2,0,5,9)
        state,registers,memory,backing,keep=self.fixture(False,config)
        config.operation_mode=0;config.main_thread_id=99
        self.assertEqual((state.config.operation_mode,state.config.main_thread_id),(1,9))
        self.assertEqual((state.initialized,state.generations,state.calls),(0,0,0))
        invalid=(('version',0),('operation_mode',2),('performance_mode',2),('focus_state',0),
            ('focus_state',4),('graphics_scale',3),('reserved',1),('process_id',0),('main_thread_id',0))
        for field,value in invalid:
            config=PlatformConfig.from_buffer_copy(state.config);setattr(config,field,value)
            before=bytes(state)
            self.assertFalse(self.lib.oot_native_platform_init(byref(state),byref(config)))
            self.assertEqual(bytes(state),before)

    def test_handler_contract_has_explicit_scalar_getters(self):
        for handler in list(range(128))+[0xffffffff]:
            self.assertEqual(bool(self.lib.oot_native_platform_handler_valid(handler)),64<=handler<=74)
            self.assertEqual(bool(self.lib.oot_native_platform_returns_value(handler)),handler in (66,67,68,74))

    def test_queries_setters_and_finalize_require_initialized_lifetime(self):
        state,registers,memory,backing,keep=self.fixture(False)
        for handler in range(65,75):self.prepare(state,handler,registers,memory,1,error=2)
        for handler in (0,16,63,75,127,0xffffffff):self.prepare(state,handler,registers,memory,1,error=0)

    def test_initialize_is_idempotent_and_finalize_starts_new_lifetime(self):
        state,registers,memory,backing,keep=self.fixture()
        registers.x[0]=1
        state=self.prepare(state,69,registers,memory)[0]
        state=self.prepare(state,70,registers,memory)[0]
        for handler in (71,72,73):state=self.prepare(state,handler,registers,memory)[0]
        duplicate=self.prepare(state,64,registers,memory)[0]
        self.assertEqual((duplicate.initialization_calls,duplicate.generations),(2,1))
        self.assertEqual((duplicate.cpu_boost_mode,duplicate.focus_handling_mode,
            duplicate.resume_notification_enabled,duplicate.operation_notification_enabled,
            duplicate.performance_notification_enabled),(1,1,1,1,1))
        final=self.prepare(duplicate,65,registers,memory)[0]
        self.assertEqual((final.initialized,final.finalization_calls,final.generations),(0,1,1))
        self.assertEqual((final.cpu_boost_mode,final.focus_handling_mode,final.resume_notification_enabled,
            final.operation_notification_enabled,final.performance_notification_enabled),(0,0,0,0,0))
        restarted=self.prepare(final,64,registers,memory)[0]
        self.assertEqual((restarted.initialized,restarted.generations,restarted.initialization_calls),(1,2,3))
        self.assertEqual(bytes(restarted.config),bytes(state.config))

    def test_each_getter_returns_declared_model_and_only_x0_changes(self):
        for operation,performance,focus,graphics in ((0,0,1,0),(1,1,3,2),(0,1,2,1)):
            state,registers,memory,backing,keep=self.fixture(config=PlatformConfig(
                1,operation,performance,focus,graphics,0,1,1))
            for handler,value in ((66,operation),(67,performance),(68,focus),(74,graphics)):
                state=self.prepare(state,handler,registers,memory,value=value)[0]
            self.assertEqual((state.queries,state.calls),(4,5))

    def test_setters_own_advisory_policy_and_preserve_all_registers(self):
        state,registers,memory,backing,keep=self.fixture()
        before=bytes(backing)
        for mode in (0,1,1,0):
            registers.x[0]=0xabcdef0100000000|mode
            state=self.prepare(state,69,registers,memory)[0]
            self.assertEqual(state.cpu_boost_mode,mode)
        for mode in (3,2,1,0):
            registers.x[0]=mode;state=self.prepare(state,70,registers,memory)[0]
            self.assertEqual(state.focus_handling_mode,mode)
        for handler,field in ((71,'resume_notification_enabled'),(72,'operation_notification_enabled'),
                              (73,'performance_notification_enabled')):
            for enabled in (1,0,1):
                registers.x[0]=enabled;state=self.prepare(state,handler,registers,memory)[0]
                self.assertEqual(getattr(state,field),enabled)
        self.assertEqual((state.boost_updates,state.focus_updates,state.notification_updates),(4,4,9))
        self.assertEqual((state.config.operation_mode,state.config.performance_mode,state.config.focus_state),(0,0,1))
        self.assertEqual(bytes(backing),before)

    def test_bad_enum_inputs_leave_all_candidates_unchanged(self):
        state,registers,memory,backing,keep=self.fixture()
        for handler,values in ((69,(2,3,0xffffffff)),(70,(4,0xffffffff)),
                              (71,(2,256)),(72,(2,0xffffffff)),(73,(2,0xffffffff))):
            for value in values:
                registers.x[0]=value;self.prepare(state,handler,registers,memory,1,error=4)

    def test_counter_overflow_never_partially_prepares_state(self):
        original,registers,memory,backing,keep=self.fixture()
        for handler,field in ((64,'calls'),(64,'initialization_calls'),(65,'finalization_calls'),
            (66,'queries'),(69,'boost_updates'),(70,'focus_updates'),(71,'notification_updates')):
            state=PlatformState.from_buffer_copy(original);setattr(state,field,2**64-1)
            registers.x[0]=1;self.prepare(state,handler,registers,memory,2,error=5)
        state=self.prepare(original,65,registers,memory)[0]
        state.generations=2**64-1
        self.prepare(state,64,registers,memory,2,error=5)

    def test_invalid_state_fields_and_lifetimes_are_rejected(self):
        original,registers,memory,backing,keep=self.fixture()
        for field,value in (('version',0),('initialized',2),('cpu_boost_mode',2),
            ('focus_handling_mode',4),('resume_notification_enabled',2),
            ('operation_notification_enabled',2),('performance_notification_enabled',2),
            ('reserved',1),('generations',0)):
            state=PlatformState.from_buffer_copy(original);setattr(state,field,value)
            self.assertFalse(self.lib.oot_native_platform_valid(byref(state)))
            self.prepare(state,66,registers,memory,2,error=2)
        state=self.prepare(original,65,registers,memory)[0];state.cpu_boost_mode=1
        self.assertFalse(self.lib.oot_native_platform_valid(byref(state)))
        self.prepare(state,64,registers,memory,2,error=2)

    def test_bad_register_protocol_preserves_entire_transaction(self):
        state,original,memory,backing,keep=self.fixture()
        cases=(('pc',0),('pc',0x1000001),('pc',1<<39),('sp',original.sp+8),('nzcv',1))
        for field,value in cases:
            registers=State.from_buffer_copy(original);setattr(registers,field,value)
            self.prepare(state,64,registers,memory,2,error=1)
        for lr in (0,3,(1<<39),0x1000081):
            registers=State.from_buffer_copy(original);registers.x[30]=lr
            self.prepare(state,64,registers,memory,2,error=1)

    def test_aliasing_outputs_and_report_cannot_corrupt_input_or_guest_bytes(self):
        state,registers,memory,backing,keep=self.fixture()
        next_state=PlatformState();result=State();write=PlatformWrite();report=PlatformReport()
        before=(bytes(state),bytes(registers),bytes(backing),bytes(next_state),bytes(result),bytes(write))
        cases=(
            (byref(state),byref(result),byref(write),byref(report)),
            (byref(next_state),byref(registers),byref(write),byref(report)),
            (byref(next_state),byref(result),cast(byref(state),POINTER(PlatformWrite)),byref(report)),
            (byref(next_state),byref(result),byref(write),cast(byref(state),POINTER(PlatformReport))),
            (cast(backing,POINTER(PlatformState)),byref(result),byref(write),byref(report)),
            (byref(next_state),byref(result),byref(write),cast(backing,POINTER(PlatformReport))))
        for next_pointer,result_pointer,write_pointer,report_pointer in cases:
            self.assertEqual(self.lib.oot_native_platform_prepare(byref(state),64,byref(registers),
                byref(memory),next_pointer,result_pointer,write_pointer,report_pointer),2)
            self.assertEqual((bytes(state),bytes(registers),bytes(backing),bytes(next_state),
                bytes(result),bytes(write)),before)

    def test_candidate_state_has_no_borrowed_config_or_guest_storage(self):
        state,registers,memory,backing,keep=self.fixture()
        copied=PlatformState.from_buffer_copy(state)
        state.config.focus_state=3;backing[:]=bytes(len(backing))
        candidate=self.prepare(copied,68,registers,memory,value=1)[0]
        self.assertEqual(candidate.config.focus_state,1)


if __name__=='__main__':unittest.main()
