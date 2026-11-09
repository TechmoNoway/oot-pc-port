"""Synthetic SDK-init constructor, provider transactions and reserved heap."""
from ctypes import (POINTER, byref, c_int, c_uint32, c_uint64, c_void_p,
                    create_string_buffer, string_at)
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from lifter_validation import compile_library
from startup_validation import Config,ServiceReport,State,bindings,snapshot
from prepare_startup import CONTEXT
from test_sdk_instructions import SdkConfig,make_fixture,BASE
from test_native_platform import PlatformState
from test_native_services import Services
from test_native_sdk_runtime import NativeState,NativeReport

ALIGN=0x200000
INIT_FLAGS=1|2|8|128|256


class SdkInitContextTests(unittest.TestCase):
    def test_live_system_tick_requires_declared_rate_and_preserves_full_abi(self):
        context,cfg,sdk=self.create(capacity=ALIGN)
        self.native_call(context,224,self.state(),expected=1)
        cfg,sdk=self.config(capacity=ALIGN);cfg.tick_frequency=31250000;error=c_uint32()
        context=self.lib.oot_startup_context_create_sdk(self.image(),byref(cfg),byref(sdk),byref(error))
        self.assertTrue(context,error.value);self.addCleanup(self.lib.oot_startup_context_destroy,context)
        last=0
        for _ in range(16):
            state=self.state();before=State.from_buffer_copy(state);report=NativeReport()
            self.assertEqual(self.lib.oot_startup_context_native_call(context,224,byref(state),byref(report)),0)
            self.assertGreaterEqual(state.x[0],last);self.assertLess(state.x[0],cfg.tick_frequency*30)
            last=state.x[0];before.x[0]=last;before.pc=before.x[30]
            self.assertEqual(state.values(),before.values());self.assertEqual(report.status,0)
        self.assertEqual(self.lib.oot_startup_context_native(context).contents.calls,16)
    @classmethod
    def setUpClass(cls):
        cls.lib,cls.build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),
            startup=True,extra_source='int oot_sdk_init_context_fixture;')
        bindings(cls.lib)
        signatures={
            'oot_startup_context_create_sdk':([c_void_p,POINTER(Config),POINTER(SdkConfig),POINTER(c_uint32)],c_void_p),
            'oot_startup_context_init_enabled':([c_void_p],c_int),
            'oot_startup_context_native_enabled':([c_void_p],c_int),
            'oot_startup_context_handler_valid':([c_void_p,c_uint32],c_int),
            'oot_startup_context_returns_value':([c_void_p,c_uint32],c_int),
            'oot_startup_context_platform':([c_void_p],POINTER(PlatformState)),
            'oot_startup_context_services':([c_void_p],POINTER(Services)),
            'oot_startup_context_native':([c_void_p],POINTER(NativeState)),
            'oot_startup_context_native_call':([c_void_p,c_uint32,POINTER(State),POINTER(NativeReport)],c_int),
            'oot_memory_store':([c_void_p,c_uint64,c_uint32,c_uint64],c_int),
            'oot_memory_load':([c_void_p,c_uint64,c_uint32,POINTER(c_uint64)],c_int)}
        for name,(args,result) in signatures.items():
            function=getattr(cls.lib,name);function.argtypes=args;function.restype=result

    def image(self):
        blob,*_=make_fixture([])
        path=Path(self.build['directory'])/'sdk-init-context.ootmem';path.write_bytes(blob)
        message=create_string_buffer(192)
        image=self.lib.oot_runtime_open(os.fsencode(path),message,len(message))
        self.assertTrue(image,message.value)
        self.addCleanup(self.lib.oot_runtime_close,image)
        return image

    def config(self,flags=INIT_FLAGS,capacity=0x80000000):
        cfg=Config(**dict(CONTEXT,heap_capacity=capacity))
        sdk=SdkConfig(version=1,flags=flags,entropy=(c_uint64*4)(1,2,3,4),
            core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,
            alias_base=0x5000000000,alias_size=ALIGN,program_id=0x1000,is_application=1,
            total_memory=(1<<32),main_thread_id=7,main_thread_priority=44,main_thread_core=0)
        return cfg,sdk

    def create(self,flags=INIT_FLAGS,capacity=0x80000000):
        cfg,sdk=self.config(flags,capacity);error=c_uint32()
        context=self.lib.oot_startup_context_create_sdk(self.image(),byref(cfg),byref(sdk),byref(error))
        self.assertTrue(context,error.value)
        self.addCleanup(self.lib.oot_startup_context_destroy,context)
        return context,cfg,sdk

    def state(self):
        registers=State()
        for n in range(31):registers.x[n]=0x9988776600000000+n
        registers.pc=BASE;registers.x[30]=BASE+8
        registers.sp=0x7000001000;registers.nzcv=0x90000000
        return registers

    def providers(self,context):
        return tuple(bytes(getattr(self.lib,'oot_startup_context_'+name)(context).contents)
            for name in ('native','platform','services'))

    def native_call(self,context,handler,registers,expected=0,value=None):
        before=State.from_buffer_copy(registers);providers=self.providers(context)
        memory=snapshot(self.lib,context);report=NativeReport()
        status=self.lib.oot_startup_context_native_call(context,handler,byref(registers),byref(report))
        self.assertEqual(status,expected)
        if expected:
            self.assertEqual(registers.values(),before.values())
            self.assertEqual(self.providers(context),providers)
        else:
            before.pc=before.x[30]
            if value is not None:before.x[0]=value
            self.assertEqual(registers.values(),before.values())
        self.assertEqual(snapshot(self.lib,context),memory)
        return report

    def region_metadata(self,context):
        memory=self.lib.oot_startup_context_memory(context).contents
        return tuple((r.base,r.size,r.permissions) for r in memory.regions[:memory.count])

    def heap(self,context,size,expected=0):
        registers=self.state();registers.x[1]=size
        old_state=registers.values();old_size=self.lib.oot_startup_context_heap_size(context)
        old_regions=self.region_metadata(context);report=ServiceReport()
        status=self.lib.oot_startup_context_service(context,1,byref(registers),byref(report))
        self.assertEqual(status,expected)
        if expected:
            self.assertEqual(registers.values(),old_state)
            self.assertEqual(self.lib.oot_startup_context_heap_size(context),old_size)
            self.assertEqual(self.region_metadata(context),old_regions)
        else:
            self.assertEqual((registers.x[0],registers.pc),(0,BASE+4))
            self.assertEqual(self.lib.oot_startup_context_heap_size(context),size)

    def test_constructor_requires_native_process_and_thread_flags(self):
        image=self.image()
        for flags in (256,1|256,1|2|8|256,1|128|256,1|2|128|256,1|8|128|256):
            cfg,sdk=self.config(flags,ALIGN);error=c_uint32()
            context=self.lib.oot_startup_context_create_sdk(image,byref(cfg),byref(sdk),byref(error))
            self.assertFalse(context,flags)
            self.assertEqual(error.value,1)
        context,cfg,sdk=self.create()
        self.assertTrue(self.lib.oot_startup_context_init_enabled(context))
        self.assertTrue(self.lib.oot_startup_context_native_enabled(context))
        self.assertFalse(self.lib.oot_startup_context_init_enabled(None))
        self.assertFalse(self.lib.oot_startup_context_handler_valid(None,64))
        platform=self.lib.oot_startup_context_platform(context).contents
        services=self.lib.oot_startup_context_services(context).contents
        self.assertEqual((platform.config.graphics_scale,platform.config.main_thread_id),(0,7))
        self.assertGreater(services.config.clock_frequency,0)
        self.assertGreater(services.config.clock_ticks,0)
        self.assertGreater(services.config.clock_unix_seconds,0)

    def test_providers_commit_void_getter_result_and_aggregate_calls(self):
        context,cfg,sdk=self.create(capacity=ALIGN);registers=self.state()
        for handler in (1,64,128,144,160,176,192):self.native_call(context,handler,registers)
        for handler in (193,194):
            registers.x[0]=1;self.native_call(context,handler,registers)
        for handler,value in ((66,0),(67,0),(68,1),(74,0),(208,0)):
            registers.x[0]=0xffffffffffffffff
            self.assertTrue(self.lib.oot_startup_context_returns_value(context,handler))
            self.native_call(context,handler,registers,value=value)
        for handler in (64,128,129,144,160,176,192,193,194):
            self.assertFalse(self.lib.oot_startup_context_returns_value(context,handler))
        native=self.lib.oot_startup_context_native(context).contents
        platform=self.lib.oot_startup_context_platform(context).contents
        services=self.lib.oot_startup_context_services(context).contents
        self.assertEqual((native.calls,platform.calls,services.calls),(14,5,8))
        self.assertEqual((services.aoc_initialized,services.err_initialized,services.diag_initialized,
            services.pctl_initialized,services.fs_mode,services.clock_initialized),(1,1,1,1,1,1))

    def test_guard_failures_and_aggregate_overflow_preserve_all_owned_effects(self):
        context,cfg,sdk=self.create(capacity=ALIGN);registers=self.state()
        self.native_call(context,66,registers,1)
        for handler in (31,0,127,255):self.native_call(context,handler,registers,1)
        self.native_call(context,64,registers)
        native=self.lib.oot_startup_context_native(context).contents
        native.calls=(1<<64)-1
        self.native_call(context,128,registers,2)
        self.native_call(context,66,registers,2)

    def test_heap_reserves_two_gib_without_mapping_and_regrowth_is_zeroed(self):
        context,cfg,sdk=self.create()
        self.assertEqual(self.lib.oot_startup_context_heap_size(context),0)
        self.assertNotIn(cfg.heap_base,[r[0] for r in self.region_metadata(context)])
        self.heap(context,2*ALIGN)
        memory=self.lib.oot_startup_context_memory(context)
        for offset in (0,ALIGN-8,ALIGN,2*ALIGN-8):
            self.assertTrue(self.lib.oot_memory_store(memory,cfg.heap_base+offset,8,0xfedcba9876543210))
        self.heap(context,ALIGN)
        value=c_uint64()
        self.assertFalse(self.lib.oot_memory_load(memory,cfg.heap_base+ALIGN,8,byref(value)))
        self.heap(context,2*ALIGN)
        self.assertTrue(self.lib.oot_memory_load(memory,cfg.heap_base,8,byref(value)))
        self.assertEqual(value.value,0xfedcba9876543210)
        for offset in (ALIGN,2*ALIGN-8):
            self.assertTrue(self.lib.oot_memory_load(memory,cfg.heap_base+offset,8,byref(value)))
            self.assertEqual(value.value,0)
        self.heap(context,0);self.heap(context,ALIGN)
        self.assertTrue(self.lib.oot_memory_load(memory,cfg.heap_base,8,byref(value)))
        self.assertEqual(value.value,0)

    def test_invalid_heap_capacity_or_request_preserves_live_mapping(self):
        image=self.image()
        for capacity in (0,ALIGN+1,0x80000000+ALIGN):
            cfg,sdk=self.config(capacity=capacity);error=c_uint32()
            context=self.lib.oot_startup_context_create_sdk(image,byref(cfg),byref(sdk),byref(error))
            self.assertFalse(context)
        context,cfg,sdk=self.create(capacity=2*ALIGN);self.heap(context,ALIGN)
        original=snapshot(self.lib,context)
        for size in (1,ALIGN-1,ALIGN+1,3*ALIGN,(1<<64)-1):
            self.heap(context,size,2)
            self.assertEqual(snapshot(self.lib,context),original)

    def test_previous_native_profile_keeps_one_gib_capacity_and_provider_guards(self):
        context,cfg,sdk=self.create(flags=INIT_FLAGS&~256,capacity=1<<30)
        self.assertFalse(self.lib.oot_startup_context_init_enabled(context))
        self.assertFalse(self.lib.oot_startup_context_platform(context))
        self.assertFalse(self.lib.oot_startup_context_services(context))
        for handler in (64,128,208):self.assertFalse(self.lib.oot_startup_context_handler_valid(context,handler))
        registers=self.state();before=registers.values();report=NativeReport()
        self.assertEqual(self.lib.oot_startup_context_native_call(context,128,byref(registers),byref(report)),1)
        self.assertEqual(registers.values(),before)
        self.heap(context,ALIGN)
        memory=self.lib.oot_startup_context_memory(context)
        self.assertTrue(self.lib.oot_memory_store(memory,cfg.heap_base,8,1234))
        self.heap(context,0);self.heap(context,ALIGN)
        value=c_uint64()
        self.assertTrue(self.lib.oot_memory_load(memory,cfg.heap_base,8,byref(value)))
        self.assertEqual(value.value,0)


if __name__=='__main__':unittest.main()
