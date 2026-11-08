"""Synthetic native logging state, owned captures and precise read failures."""
from ctypes import (POINTER, Structure, byref, c_int, c_size_t, c_uint8, c_uint32,
                    c_uint64, c_char, cast, string_at)
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from lifter_validation import compile_library
from lifter_validation_types import Memory, Region, State

BASE=0x200000000


class NativeConfig(Structure):
    _fields_=[('version',c_uint32),('operation_mode',c_uint32),('performance_mode',c_uint32),
              ('process_id',c_uint64),('main_thread_id',c_uint64)]


class NativeState(Structure):
    _fields_=[(name,c_uint32) for name in ('version','logging_initialized','platform_initialized','destination',
        'cpu_boost_mode','last_log_size','last_metadata_size')]+[('config',NativeConfig)]+[
        (name,c_uint64) for name in ('calls','logging_initializations','logging_finalizations',
        'platform_initializations','platform_finalizations','destination_updates','log_records','log_bytes')]+[
        ('last_log',c_uint8*4096),('last_metadata',c_uint8*64)]+[
        (name,c_uint32) for name in ('default_observer_enabled','last_log_head','last_log_tail')]+[
        ('observer_updates',c_uint64),('log_attempts',c_uint64),('last_filename',c_char*256),
        ('last_function',c_char*256),('last_module',c_char*256)]


class NativeReport(Structure):
    _fields_=[(name,c_uint32) for name in ('status','handler','error','log_size')]


class NativeSdkRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib,_=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),startup=True,
            extra_source='#include "sdk_native.h"\nOOT_LIFT_EXPORT size_t oot_test_native_size(void) { return sizeof(OotSdkNative); }\n')
        signatures={
            'oot_sdk_native_init':([POINTER(NativeState),POINTER(NativeConfig)],c_int),
            'oot_sdk_native_handler_valid':([c_uint32],c_int),
            'oot_sdk_native_returns_value':([c_uint32],c_int),
            'oot_sdk_native_prepare':([POINTER(NativeState),c_uint32,POINTER(State),POINTER(Memory),
                POINTER(NativeState),POINTER(State),POINTER(NativeReport)],c_int),
            'oot_memory_init':([POINTER(Memory),POINTER(Region),c_size_t],c_int),
            'oot_test_native_size':([],c_size_t)}
        for name,(args,result) in signatures.items():
            function=getattr(cls.lib,name);function.argtypes=args;function.restype=result
        from ctypes import sizeof
        if cls.lib.oot_test_native_size()!=sizeof(NativeState):raise AssertionError('native state ABI differs')

    def fixture(self,initialized=True):
        backing=(c_uint8*8192)()
        table=(Region*1)(Region(BASE,len(backing),backing,3))
        memory=Memory();self.assertTrue(self.lib.oot_memory_init(byref(memory),table,1))
        state=NativeState();config=NativeConfig(1,0,0,1,7)
        self.assertTrue(self.lib.oot_sdk_native_init(byref(state),byref(config)))
        registers=State()
        for n in range(31):registers.x[n]=0x1234567800000000+n
        registers.pc=0x1000040;registers.x[30]=0x1000080
        registers.sp=0x7000001000;registers.nzcv=0xa0000000
        if initialized:state=self.prepare(state,1,registers,memory)[1]
        return state,registers,memory,backing,table

    def prepare(self,state,handler,registers,memory,expected=0):
        next_state=NativeState.from_buffer_copy(bytes([0xa5])*len(bytes(state)))
        result=State.from_buffer_copy(bytes([0xb6])*len(bytes(registers)))
        before_next,before_result=bytes(next_state),bytes(result)
        before_state,before_registers=bytes(state),bytes(registers)
        report=NativeReport()
        status=self.lib.oot_sdk_native_prepare(byref(state),handler,byref(registers),byref(memory),
            byref(next_state),byref(result),byref(report))
        self.assertEqual(status,expected)
        self.assertEqual((bytes(state),bytes(registers)),(before_state,before_registers))
        if status:
            self.assertEqual((bytes(next_state),bytes(result)),(before_next,before_result))
        else:
            expected_registers=State.from_buffer_copy(registers);expected_registers.pc=registers.x[30]
            self.assertEqual(result.values(),expected_registers.values())
        self.assertEqual((report.status,report.handler),(status,handler))
        return report,next_state,result

    def log_data(self,registers,backing,payload=b'hello\0binary\xff'):
        strings=(b'file.cpp\0',b'Function\0',b'Module\0')
        positions=(6000,6400,6800)
        for position,value in zip(positions,strings):backing[position:position+len(value)]=value
        metadata=struct.pack('<I4xQQQII',42,*[BASE+n for n in positions],3,7)
        backing[:40]=metadata
        backing[128:152]=struct.pack('<QQBB6x',BASE+256,len(payload),1,0)
        backing[256:256+len(payload)]=payload
        registers.x[0]=BASE;registers.x[1]=BASE+128
        return payload

    def test_explicit_configuration_handlers_and_guard_do_not_invent_effects(self):
        state,registers,memory,backing,keep=self.fixture(False)
        self.assertEqual((state.logging_initialized,state.destination,state.default_observer_enabled),(0,0xffff,1))
        for handler in range(64):
            self.assertEqual(bool(self.lib.oot_sdk_native_handler_valid(handler)),handler in (1,3,5,6,31))
            self.assertFalse(self.lib.oot_sdk_native_returns_value(handler))
        self.prepare(state,5,registers,memory,1)
        self.prepare(state,3,registers,memory,1)
        for handler in (0,2,4,7,16,20,31,0xffffffff):
            self.prepare(state,handler,registers,memory,1)
        for version,operation,performance,pid,tid in ((0,0,0,1,1),(1,2,0,1,1),(1,0,2,1,1),(1,0,0,0,1),(1,0,0,1,0)):
            before=bytes(state)
            self.assertFalse(self.lib.oot_sdk_native_init(byref(state),byref(NativeConfig(version,operation,performance,pid,tid))))
            self.assertEqual(bytes(state),before)

    def test_log_capture_owns_bytes_metadata_strings_and_preserves_guest(self):
        state,registers,memory,backing,keep=self.fixture()
        payload=self.log_data(registers,backing)
        original=bytes(backing)
        report,next_state,result=self.prepare(state,5,registers,memory)
        self.assertEqual(report.log_size,len(payload))
        self.assertEqual((next_state.log_attempts,next_state.log_records,next_state.log_bytes),(1,1,len(payload)))
        self.assertEqual(bytes(next_state.last_log[:len(payload)]),payload)
        self.assertEqual(bytes(next_state.last_log[len(payload):]),bytes(4096-len(payload)))
        self.assertEqual((next_state.last_filename,next_state.last_function,next_state.last_module),(b'file.cpp',b'Function',b'Module'))
        self.assertEqual((next_state.last_log_head,next_state.last_log_tail,next_state.last_metadata_size),(1,0,40))
        normalized=bytearray(64);normalized[:4]=struct.pack('<I',42);normalized[32:40]=struct.pack('<II',3,7)
        self.assertEqual(bytes(next_state.last_metadata),bytes(normalized))
        self.assertEqual(bytes(backing),original)
        backing[:]=bytes(len(backing))
        self.assertEqual(bytes(next_state.last_log[:len(payload)]),payload)
        self.assertEqual(next_state.last_filename,b'file.cpp')

    def test_destination_and_default_observer_control_have_real_owned_effects(self):
        state,registers,memory,backing,keep=self.fixture()
        self.log_data(registers,backing)
        state=self.prepare(state,5,registers,memory)[1]
        for destination in (0,1,2,3,4,7,0xffff):
            registers.x[0]=destination | (0xabcdef00<<32)
            candidate=self.prepare(state,3,registers,memory)[1]
            self.assertEqual((candidate.destination,candidate.destination_updates),(destination,1))
        for destination in (8,0x10000,0xfffffffe):
            registers.x[0]=destination;self.prepare(state,3,registers,memory,1)
        registers.x[0]=0;state=self.prepare(state,6,registers,memory)[1]
        self.assertEqual((state.default_observer_enabled,state.observer_updates),(0,1))
        registers.x[0]=0x1234;registers.x[1]=0xffffffffffffffff
        report,candidate,_=self.prepare(state,5,registers,memory)
        self.assertEqual((candidate.log_records,candidate.log_attempts,report.log_size),(1,2,0))
        self.assertEqual(bytes(candidate.last_log),bytes(state.last_log))
        registers.x[0]=1;state=self.prepare(state,6,registers,memory)[1]
        self.assertEqual(state.default_observer_enabled,1)
        for bad in (2,255,256,0xffffffff):registers.x[0]=bad;self.prepare(state,6,registers,memory,1)

    def test_exact_record_prefix_and_null_metadata_strings_are_supported(self):
        state,registers,memory,backing,keep=self.fixture()
        self.log_data(registers,backing,b'')
        backing[:40]=struct.pack('<I4xQQQII',0xffffffff,0,0,0,4,0xffffffff)
        backing[128:152]=struct.pack('<QQBB6x',0,0,0,1)
        table=(Region*2)(Region(BASE,40,backing,1),Region(BASE+128,24,cast(byref(backing,128),POINTER(c_uint8)),1))
        self.assertTrue(self.lib.oot_memory_init(byref(memory),table,2))
        report,candidate,_=self.prepare(state,5,registers,memory)
        self.assertEqual((candidate.last_log_size,candidate.last_log_head,candidate.last_log_tail),(0,0,1))
        self.assertEqual((candidate.last_filename,candidate.last_function,candidate.last_module),(b'',b'',b''))
        self.assertEqual(report.log_size,0)

    def test_payload_limit_strings_page_edges_and_read_faults_are_transactional(self):
        state,registers,memory,backing,keep=self.fixture()
        self.log_data(registers,backing,b'x'*4096)
        candidate=self.prepare(state,5,registers,memory)[1]
        self.assertEqual(candidate.last_log_size,4096)
        backing[128+8:128+16]=struct.pack('<Q',4097)
        self.prepare(state,5,registers,memory,1)
        self.log_data(registers,backing)
        for offset,value in ((128+16,2),(128+17,255),(32,5)):
            old=backing[offset];backing[offset]=value
            self.prepare(state,5,registers,memory,1);backing[offset]=old
        for field,address in ((0,BASE+8192),(1,BASE+8192-23),(0,(1<<39)-39),(1,(1<<39)-23)):
            old=registers.x[field];registers.x[field]=address
            self.prepare(state,5,registers,memory,2);registers.x[field]=old
        backing[128:136]=struct.pack('<Q',BASE+8192-2)
        self.prepare(state,5,registers,memory,2)
        self.log_data(registers,backing)
        for position in (6000,6400,6800):
            old=bytes(backing[position:position+256]);backing[position:position+256]=b'x'*256
            self.prepare(state,5,registers,memory,2);backing[position:position+256]=old
        # A NUL at the last mapped byte needs no speculative read past it.
        backing[8191]=0;backing[8:16]=struct.pack('<Q',BASE+8191)
        self.assertEqual(self.prepare(state,5,registers,memory)[1].last_filename,b'')

    def test_invalid_state_return_registers_aliases_and_counter_overflow_reject(self):
        state,registers,memory,backing,keep=self.fixture()
        for name,value in (('pc',0),('pc',0x1000001),('sp',registers.sp+1),('nzcv',1)):
            altered=State.from_buffer_copy(registers);setattr(altered,name,value)
            self.prepare(state,1,altered,memory,2)
        for lr in (0,2,0x1000001,1<<39,0xffffffffffffffff):
            altered=State.from_buffer_copy(registers);altered.x[30]=lr
            self.prepare(state,1,altered,memory,2)
        for name,value in (('version',2),('logging_initialized',2),('last_log_size',4097),('default_observer_enabled',2),('destination',8)):
            altered=NativeState.from_buffer_copy(state);setattr(altered,name,value)
            self.prepare(altered,1,registers,memory,2)
        for name,handler in (('calls',1),('logging_initializations',1),('observer_updates',6),('destination_updates',3)):
            altered=NativeState.from_buffer_copy(state);setattr(altered,name,(1<<64)-1);registers.x[0]=1
            self.prepare(altered,handler,registers,memory,2)
        self.log_data(registers,backing)
        for name in ('log_records','log_bytes','log_attempts'):
            altered=NativeState.from_buffer_copy(state);setattr(altered,name,(1<<64)-1)
            self.prepare(altered,5,registers,memory,2)
        report=NativeReport();result=State();before=bytes(state)
        self.assertEqual(self.lib.oot_sdk_native_prepare(byref(state),1,byref(registers),byref(memory),
            byref(state),byref(result),byref(report)),2)
        self.assertEqual(bytes(state),before)


if __name__=='__main__':unittest.main()
