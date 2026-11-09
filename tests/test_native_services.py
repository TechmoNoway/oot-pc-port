"""Synthetic provider ownership and ABI tests; no original game code runs."""
from ctypes import (POINTER, Structure, byref, c_char, c_int, c_size_t,
                    c_uint8, c_uint32, c_uint64, sizeof)
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from lifter_validation import compile_library
from lifter_validation_types import Memory, Region, State

BASE=0x200000000
INITIALIZERS=(128,144,160,176,192,208)
HANDLERS=(*INITIALIZERS,129,193,194)


class Config(Structure):
    _fields_=[(name,c_uint32) for name in ('version','aoc_catalog_mode','parental_policy','reserved')]+[
        (name,c_uint64) for name in ('clock_frequency','clock_ticks','clock_unix_seconds')]


class Observer(Structure):
    _fields_=[('kind',c_uint32),('active',c_uint32),('captures',c_uint64)]


class Mount(Structure):
    _fields_=[('name',c_char*16),('provider_id',c_uint32),('active',c_uint32)]


class Services(Structure):
    _fields_=[(name,c_uint32) for name in (
        'version','aoc_initialized','err_initialized','diag_initialized','pctl_initialized',
        'fs_mode','local_access_log','result_handled','aoc_count','aoc_references','context_capacity','context_size',
        'observer_count','mount_count','parental_policy','clock_initialized','clock_references')]+[
        ('config',Config)]+[(name,c_uint64) for name in (
        'calls','aoc_initializations','aoc_finalizations','err_initializations','diag_initializations',
        'pctl_initializations','fs_initializations','access_log_updates','result_handled_updates',
        'clock_initializations')]+[('context',c_uint8*1024),('observers',Observer*4),('mounts',Mount*8)]


class Write(Structure):
    _fields_=[('address',c_uint64),('size',c_uint32),('bytes',c_uint8*64)]


class Report(Structure):
    _fields_=[(name,c_uint32) for name in ('status','handler','error','log_size')]


class NativeServicesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Include this separately owned provider in the generated synthetic TU;
        # startup=False keeps the test independent of the constructor registry.
        source=f'#include "{(ROOT/"src/native_services.c").as_posix()}"\n'
        source+='OOT_LIFT_EXPORT size_t oot_services_size(void) { return sizeof(OotNativeServices); }\n'
        source+='OOT_LIFT_EXPORT size_t oot_services_write_size(void) { return sizeof(OotNativeServicesWrite); }\n'
        cls.lib,_=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),extra_source=source)
        signatures={
            'oot_native_services_init':([POINTER(Services),POINTER(Config)],c_int),
            'oot_native_services_handler_valid':([c_uint32],c_int),
            'oot_native_services_returns_value':([c_uint32],c_int),
            'oot_native_services_prepare':([POINTER(Services),c_uint32,POINTER(State),POINTER(Memory),
                POINTER(Services),POINTER(State),POINTER(Write),POINTER(Report)],c_int),
            'oot_memory_init':([POINTER(Memory),POINTER(Region),c_size_t],c_int),
            'oot_services_size':([],c_size_t),'oot_services_write_size':([],c_size_t)}
        for name,(args,result) in signatures.items():
            function=getattr(cls.lib,name);function.argtypes=args;function.restype=result
        if cls.lib.oot_services_size()!=sizeof(Services):raise AssertionError('services ABI differs')
        if cls.lib.oot_services_write_size()!=sizeof(Write):raise AssertionError('write ABI differs')

    def fixture(self,policy=0,clock=True):
        backing=(c_uint8*4096)(*[n%251 for n in range(4096)])
        table=(Region*1)(Region(BASE,len(backing),backing,3))
        memory=Memory();self.assertTrue(self.lib.oot_memory_init(byref(memory),table,1))
        state=Services();config=Config(1,1,policy,0,19200000 if clock else 0,
            38400000 if clock else 0,1700000000 if clock else 0)
        self.assertTrue(self.lib.oot_native_services_init(byref(state),byref(config)))
        registers=State()
        for n in range(31):registers.x[n]=0x8877665500000000+n
        registers.pc=0x1000040;registers.x[30]=0x1000080
        registers.sp=0x7000001000;registers.nzcv=0xd0000000
        return state,registers,memory,backing,table

    def prepare(self,state,handler,registers,memory,expected=0):
        candidate=Services.from_buffer_copy(b'\xa5'*sizeof(Services))
        result=State.from_buffer_copy(b'\xb6'*sizeof(State))
        write=Write.from_buffer_copy(b'\xc7'*sizeof(Write))
        report=Report()
        unchanged=(bytes(candidate),bytes(result),bytes(write))
        inputs=(bytes(state),bytes(registers))
        status=self.lib.oot_native_services_prepare(byref(state),handler,byref(registers),
            byref(memory),byref(candidate),byref(result),byref(write),byref(report))
        self.assertEqual(status,expected)
        self.assertEqual((bytes(state),bytes(registers)),inputs)
        self.assertEqual((report.status,report.handler),(status,handler))
        if status:
            self.assertEqual((bytes(candidate),bytes(result),bytes(write)),unchanged)
        else:
            wanted=State.from_buffer_copy(registers);wanted.pc=registers.x[30]
            if handler==208:wanted.x[0]=0
            self.assertEqual(result.values(),wanted.values())
            self.assertEqual((write.address,write.size,bytes(write.bytes)),(0,0,bytes(64)))
        return candidate,report

    def test_complete_declared_sequence_owns_all_provider_readiness(self):
        state,registers,memory,backing,keep=self.fixture(policy=1)
        untouched=bytes(backing)
        for handler in INITIALIZERS:state=self.prepare(state,handler,registers,memory)[0]
        registers.x[0]=1
        for handler in (193,194):state=self.prepare(state,handler,registers,memory)[0]
        self.assertEqual((state.aoc_initialized,state.err_initialized,state.diag_initialized,
            state.pctl_initialized,state.fs_mode,state.clock_initialized),(1,1,1,1,1,1))
        self.assertEqual((state.calls,state.aoc_initializations,state.err_initializations,
            state.diag_initializations,state.pctl_initializations,state.fs_initializations,
            state.clock_initializations,state.access_log_updates,state.result_handled_updates),
            (8,1,1,1,1,1,1,1,1))
        self.assertEqual((state.local_access_log,state.result_handled,state.parental_policy),(1,1,1))
        self.assertEqual((state.context_capacity,state.context_size,bytes(state.context)),(1024,0,bytes(1024)))
        self.assertEqual((state.observer_count,state.observers[0].kind,state.observers[0].active),(1,1,1))
        self.assertEqual((state.aoc_count,state.mount_count,state.clock_references),(0,0,1))
        self.assertEqual(bytes(state.mounts),bytes(sizeof(Mount)*8))
        self.assertEqual(bytes(backing),untouched)

    def test_config_is_explicit_copied_and_rejection_preserves_state(self):
        state,registers,memory,backing,keep=self.fixture()
        self.assertEqual(state.parental_policy,0)
        config=Config(1,1,1,0,1000,20,1700000000)
        self.assertTrue(self.lib.oot_native_services_init(byref(state),byref(config)))
        config.parental_policy=0;config.clock_ticks=999
        self.assertEqual((state.parental_policy,state.config.clock_ticks),(1,20))
        for field,value in (('version',0),('aoc_catalog_mode',0),('aoc_catalog_mode',2),
                ('parental_policy',2),('reserved',1),('clock_frequency',1000000001)):
            invalid=Config.from_buffer_copy(state.config);setattr(invalid,field,value)
            original=bytes(state)
            self.assertFalse(self.lib.oot_native_services_init(byref(state),byref(invalid)))
            self.assertEqual(bytes(state),original)
        invalid=Config(1,1,0,0,0,1,0)
        self.assertFalse(self.lib.oot_native_services_init(byref(state),byref(invalid)))

    def test_only_audited_handlers_and_time_result_are_exposed(self):
        state,registers,memory,backing,keep=self.fixture()
        for handler in range(256):
            self.assertEqual(bool(self.lib.oot_native_services_handler_valid(handler)),handler in HANDLERS)
            self.assertEqual(bool(self.lib.oot_native_services_returns_value(handler)),handler==208)
        for handler in (0,31,130,145,161,177,195,209,0xffffffff):
            self.prepare(state,handler,registers,memory,1)

    def test_empty_addon_catalogue_has_balanced_owned_lifetime(self):
        state,registers,memory,backing,keep=self.fixture()
        self.prepare(state,129,registers,memory,1)
        for handler in (128,128,129):state=self.prepare(state,handler,registers,memory)[0]
        self.assertEqual((state.aoc_initialized,state.aoc_references,state.aoc_count),(1,1,0))
        state=self.prepare(state,129,registers,memory)[0]
        self.assertEqual((state.aoc_initialized,state.aoc_references,state.aoc_initializations,
            state.aoc_finalizations),(0,0,2,2))
        self.prepare(state,129,registers,memory,1)
        state=self.prepare(state,128,registers,memory)[0]
        self.assertEqual((state.aoc_initialized,state.aoc_references),(1,1))

    def test_filesystem_controls_require_application_mode_and_store_bool(self):
        state,registers,memory,backing,keep=self.fixture()
        registers.x[0]=1
        for handler in (193,194):self.prepare(state,handler,registers,memory,1)
        state=self.prepare(state,192,registers,memory)[0]
        for value in (1,0,1):
            registers.x[0]=(0x12345678<<32)|value
            for handler in (193,194):state=self.prepare(state,handler,registers,memory)[0]
            self.assertEqual((state.local_access_log,state.result_handled),(value,value))
        self.assertEqual((state.access_log_updates,state.result_handled_updates),(3,3))
        for value in (2,255,256,0xffffffff):
            registers.x[0]=value
            for handler in (193,194):self.prepare(state,handler,registers,memory,1)

    def test_time_requires_calibration_and_returns_result_without_guest_objects(self):
        state,registers,memory,backing,keep=self.fixture(clock=False)
        self.prepare(state,208,registers,memory,1)
        state,registers,memory,backing,keep=self.fixture()
        for n in range(3):
            state=self.prepare(state,208,registers,memory)[0]
            self.assertEqual((state.clock_references,state.clock_initializations),(n+1,n+1))
        self.assertEqual((state.config.clock_frequency,state.config.clock_ticks,state.config.clock_unix_seconds),
            (19200000,38400000,1700000000))

    def test_repeated_idempotent_mode_and_writer_init_preserve_storage(self):
        state,registers,memory,backing,keep=self.fixture()
        for handler in (144,192,144,192):state=self.prepare(state,handler,registers,memory)[0]
        self.assertEqual((state.calls,state.err_initializations,state.fs_initializations),(4,1,1))
        self.assertEqual((state.context_capacity,state.context_size,bytes(state.context)),(1024,0,bytes(1024)))
        state=self.prepare(state,160,registers,memory)[0]
        # A second registration is outside the admitted bounded lifecycle;
        # it must not insert the same observer twice.
        self.prepare(state,160,registers,memory,1)

    def test_invalid_original_return_and_state_are_transactional(self):
        state,registers,memory,backing,keep=self.fixture()
        for field,value in (('pc',0),('pc',0x1000041),('sp',1),('nzcv',1)):
            invalid=State.from_buffer_copy(registers);setattr(invalid,field,value)
            self.prepare(state,128,invalid,memory,2)
        for value in (0,2,0x1000041,1<<39,(1<<64)-1):
            invalid=State.from_buffer_copy(registers);invalid.x[30]=value
            self.prepare(state,128,invalid,memory,2)
        for field,value in (('version',0),('aoc_initialized',2),('err_initialized',2),
                ('diag_initialized',2),('pctl_initialized',2),('fs_mode',2),('aoc_count',1),('aoc_references',1),
                ('context_capacity',1024),('observer_count',1),('mount_count',1),
                ('parental_policy',1),('clock_initialized',1),('clock_references',1),('local_access_log',1)):
            invalid=Services.from_buffer_copy(state);setattr(invalid,field,value)
            self.prepare(invalid,128,registers,memory,2)
        invalid=Services.from_buffer_copy(state);invalid.context[0]=1
        self.prepare(invalid,128,registers,memory,2)
        invalid=Services.from_buffer_copy(state);invalid.mounts[0].active=1
        self.prepare(invalid,128,registers,memory,2)
        state=self.prepare(state,160,registers,memory)[0]
        state.observers[0].kind=0
        self.prepare(state,128,registers,memory,2)

    def test_all_effect_counters_reject_overflow_before_commit(self):
        state,registers,memory,backing,keep=self.fixture()
        for field,handler in (('calls',128),('aoc_initializations',128),('err_initializations',144),
                ('diag_initializations',160),('pctl_initializations',176),('fs_initializations',192),
                ('clock_initializations',208)):
            invalid=Services.from_buffer_copy(state);setattr(invalid,field,(1<<64)-1)
            self.prepare(invalid,handler,registers,memory,2)
        state=self.prepare(state,192,registers,memory)[0];registers.x[0]=1
        for field,handler in (('access_log_updates',193),('result_handled_updates',194)):
            invalid=Services.from_buffer_copy(state);setattr(invalid,field,(1<<64)-1)
            self.prepare(invalid,handler,registers,memory,2)
        state=self.prepare(state,208,registers,memory)[0];state.clock_references=0xffffffff
        self.prepare(state,208,registers,memory,2)
        state,registers,memory,backing,keep=self.fixture()
        state=self.prepare(state,128,registers,memory)[0]
        invalid=Services.from_buffer_copy(state);invalid.aoc_references=0xffffffff
        self.prepare(invalid,128,registers,memory,2)
        state.aoc_finalizations=(1<<64)-1
        self.prepare(state,129,registers,memory,2)

    def test_aliasing_and_bad_memory_configuration_reject_without_effects(self):
        state,registers,memory,backing,keep=self.fixture()
        result=State();write=Write();report=Report();before=bytes(state)
        self.assertEqual(self.lib.oot_native_services_prepare(byref(state),128,byref(registers),
            byref(memory),byref(state),byref(result),byref(write),byref(report)),2)
        self.assertEqual(bytes(state),before)
        memory.valid=0
        self.prepare(state,128,registers,memory,2)


if __name__=='__main__':unittest.main()
