"""Native-SDK DMB subset: exact words, serialized order and precise prefixes."""
from ctypes import (POINTER, byref, c_int, c_size_t, c_uint8, c_uint32,
                    c_uint64, c_void_p, cast, create_string_buffer)
import hashlib
import os
from pathlib import Path
import random
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from arm64_lifter import decode_instruction
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import Memory,Region,State
from pauth_lifter import decode_pauth_instruction
from pauth_validation import KEYS,Reference
from prepare_runtime import pack_regions
from prepare_startup import CONTEXT
from sdk_instructions import DMB_OPTIONS,decode_sdk_instruction,sdk_barrier_kind,sdk_system_kind
from startup_validation import Config,Instruction,Program,Report,Span,TRACE,bindings,snapshot
from test_sdk_instructions import SdkConfig
from test_native_sdk_dispatch import NativeFunction

BASE,STACK=0x1000000,0x7000000000
STOP=0xd4200000


def dmb(option):return 0xd50330bf|(option<<8)


STRESS=r'''
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "guest_memory.h"
typedef struct BarrierWorker {
 OotGuestMemory memory;HANDLE start;volatile LONG *failed;
 uint64_t base;unsigned option,rounds,consumer;
} BarrierWorker;
static DWORD WINAPI barrier_worker(void *arg) {
 BarrierWorker *w=arg;ULONGLONG deadline=GetTickCount64()+15000;
 if(WaitForSingleObject(w->start,15000)!=WAIT_OBJECT_0)goto failed;
 for(unsigned n=1;n<=w->rounds;++n) {
  uint64_t value;
  do {
   if(GetTickCount64()>deadline||InterlockedCompareExchange(w->failed,0,0))goto failed;
   if(!oot_memory_load(&w->memory,w->base+(w->consumer?8:16),8,&value))goto failed;
   if(value!=(w->consumer?n:n-1))SwitchToThread();
  }while(value!=(w->consumer?n:n-1));
  if(w->consumer) {
   if(!oot_memory_barrier(&w->memory,w->option)||!oot_memory_load(&w->memory,w->base,8,&value)||
      value!=(UINT64_C(0x9e3779b97f4a7c15)*(uint64_t)n)||
      !oot_memory_store(&w->memory,w->base+16,8,n))goto failed;
  } else {
   if(!oot_memory_store(&w->memory,w->base,8,UINT64_C(0x9e3779b97f4a7c15)*(uint64_t)n)||
      !oot_memory_barrier(&w->memory,w->option)||!oot_memory_store(&w->memory,w->base+8,8,n))goto failed;
  }
 }
 return 0;
failed:InterlockedExchange(w->failed,1);return 1;
}
OOT_MEMORY_API int oot_test_barrier_publication(unsigned before,unsigned after,unsigned rounds) {
 uint8_t bytes[24]={0};OotGuestRegion regions[2];BarrierWorker w[2]={0};
 HANDLE threads[2]={0},start;volatile LONG failed=0;DWORD code;
 if(!rounds||rounds>10000)return 0;
 start=CreateEventW(NULL,TRUE,FALSE,NULL);if(!start)return 0;
 for(unsigned n=0;n<2;++n) {
  regions[n]=(OotGuestRegion){UINT64_C(0x200000000)+(uint64_t)n*0x10000,24,bytes,3};
  if(!oot_memory_init(&w[n].memory,&regions[n],1)){CloseHandle(start);return 0;}
  w[n].start=start;w[n].failed=&failed;w[n].base=regions[n].base;
  w[n].rounds=rounds;w[n].consumer=n;w[n].option=n?after:before;
  threads[n]=CreateThread(NULL,0,barrier_worker,&w[n],0,NULL);
  if(!threads[n]){InterlockedExchange(&failed,1);break;}
 }
 SetEvent(start);
 for(unsigned n=0;n<2;++n)if(threads[n]) {
  if(WaitForSingleObject(threads[n],30000)!=WAIT_OBJECT_0)ExitProcess(1);
  if(!GetExitCodeThread(threads[n],&code)||code)InterlockedExchange(&failed,1);
  CloseHandle(threads[n]);
 }
 CloseHandle(start);return !failed;
}
'''


class BarrierDecoderTests(unittest.TestCase):
    def test_exact_named_options_fixed_bits_and_legacy_boundaries(self):
        self.assertEqual(DMB_OPTIONS,frozenset((1,2,3,5,6,7,9,10,11,13,14,15)))
        for option in range(16):
            word=dmb(option)
            self.assertEqual(sdk_barrier_kind(word),'dmb' if option in DMB_OPTIONS else None)
            self.assertIsNone(sdk_system_kind(word))
            if option in DMB_OPTIONS:
                instruction=decode_sdk_instruction(word,BASE)
                self.assertEqual((instruction.form,instruction.operation),('sdk_barrier',option))
            else:
                with self.assertRaises(InputError):decode_sdk_instruction(word,BASE)
            for decoder in (decode_instruction,decode_pauth_instruction):
                with self.assertRaises(InputError):decoder(word,BASE)
            for bit in range(32):
                if 0xfffff0ff&(1<<bit):self.assertIsNone(sdk_barrier_kind(word^(1<<bit)))
        for word in (None,True,-1,1<<32,'word',0xd5033b9f,0xd5033fdf,0xd503201f):
            self.assertIsNone(sdk_barrier_kind(word))
        for pc in (True,-4,2,1<<64):
            with self.assertRaises(InputError):decode_sdk_instruction(dmb(9),pc)


class NativeBarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib,cls.build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),STRESS,startup=True)
        bindings(cls.lib)
        signatures={
            'oot_memory_barrier':([POINTER(Memory),c_uint32],c_int),
            'oot_test_barrier_publication':([c_uint32,c_uint32,c_uint32],c_int),
            'oot_startup_context_create_sdk':([c_void_p,POINTER(Config),POINTER(SdkConfig),POINTER(c_uint32)],c_void_p),
            'oot_startup_context_system':([c_void_p,c_uint32,POINTER(State)],c_int),
            'oot_startup_dispatch_create_sdk':([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_create_native':([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_set_native_functions':([c_void_p,POINTER(NativeFunction),c_size_t,POINTER(c_uint32)],c_int)}
        for name,(arguments,result) in signatures.items():
            function=getattr(cls.lib,name);function.argtypes=arguments;function.restype=result

    def session(self,native=True,options=None,limit=1000):
        options=sorted(DMB_OPTIONS) if options is None else list(options)
        words=[dmb(option) for option in options]
        data=bytearray(4096)
        for n,word in enumerate(words+[STOP]):struct.pack_into('<I',data,n*4,word)
        guard=BASE+len(words)*4+16
        struct.pack_into('<I',data,guard-BASE,0xd65f03c0)
        module=SimpleNamespace(name='barrier_fixture',base=BASE,ranges=((0,4096),(4096,4096),(4096,4096)),
            bss_start=4096,bss_end=4096,image=data)
        blob,manifest=pack_regions([module],{'synthetic_raw':True},STACK,4096)
        path=Path(self.build['directory'])/'native-barriers.ootmem';path.write_bytes(blob)
        message=create_string_buffer(192);error=c_uint32()
        image=self.lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
        config=Config(**dict(CONTEXT,heap_capacity=0x200000))
        sdk=SdkConfig(version=1,flags=1|2|8|(128 if native else 0),entropy=(c_uint64*4)(1,2,3,4),
            core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,
            alias_base=0x5000000000,alias_size=0x200000,program_id=0x1000,is_application=1,
            total_memory=manifest['backing_bytes']+config.tls_size+config.heap_capacity,
            main_thread_id=1,main_thread_priority=44,main_thread_core=0)
        context=self.lib.oot_startup_context_create_sdk(image,byref(config),byref(sdk),byref(error))
        self.assertTrue(context,error.value)
        keys=self.lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));self.assertTrue(keys)
        rows=[Instruction(BASE+4*n,word,5 if option in DMB_OPTIONS else 4,
            BASE+4*n+(4 if option in DMB_OPTIONS else 0),BASE+4*n+(4 if option in DMB_OPTIONS else 0),None)
            for n,(word,option) in enumerate(zip(words,options))]
        end=BASE+4*len(words)
        rows += [Instruction(end,STOP,4,end,end,None),Instruction(guard,0xd65f03c0,4,guard,guard,None)]
        instructions=(Instruction*len(rows))(*rows)
        size=guard-BASE+4
        spans=(Span*1)(Span(BASE,size,(c_uint8*32).from_buffer_copy(hashlib.sha256(data[:size]).digest())))
        program=Program(1,7 if native else 3,BASE,(c_uint8*32).from_buffer_copy(bytes.fromhex(manifest['body_sha256'])),
            instructions,len(rows),spans,1)
        create=self.lib.oot_startup_dispatch_create_native if native else self.lib.oot_startup_dispatch_create_sdk
        dispatcher=create(image,context,keys,byref(program),limit,byref(error));self.assertTrue(dispatcher,error.value)
        if native:
            descriptor=NativeFunction(1,31,guard,4,(c_uint8*32).from_buffer_copy(hashlib.sha256(data[guard-BASE:guard-BASE+4]).digest()))
            self.assertTrue(self.lib.oot_startup_dispatch_set_native_functions(dispatcher,byref(descriptor),1,byref(error)),error.value)
        state=State();self.assertTrue(self.lib.oot_startup_context_initial_state(context,BASE,byref(state)))
        for n in range(31):state.x[n]=0xa123456789abcdef^n
        state.nzcv=0xb0000000
        self.addCleanup(self.lib.oot_runtime_close,image)
        self.addCleanup(self.lib.oot_startup_context_destroy,context)
        self.addCleanup(self.lib.oot_pauth_destroy,keys)
        self.addCleanup(self.lib.oot_startup_dispatch_destroy,dispatcher)
        return context,dispatcher,state,words

    def test_backend_clears_only_fault_and_rejects_bad_domains_without_mutation(self):
        backing=(c_uint8*32)(*range(32));table=(Region*1)(Region(BASE,32,backing,0))
        memory=Memory();self.assertTrue(self.lib.oot_memory_init(byref(memory),table,1))
        original=bytes(backing);metadata=bytes(table)
        for option in (*range(20),0xffffffff):
            memory.fault.address=0xabcdef;memory.fault.reason=3
            self.assertEqual(bool(self.lib.oot_memory_barrier(byref(memory),option)),option in DMB_OPTIONS)
            self.assertEqual(bytes(backing),original);self.assertEqual(bytes(table),metadata)
            self.assertEqual(memory.fault.values(),(0,0,0,0,0 if option in DMB_OPTIONS else 4))
        for value in (0,2,0xffffffff):
            memory.valid=value;self.assertFalse(self.lib.oot_memory_barrier(byref(memory),9))
            self.assertEqual(memory.fault.values(),(0,0,0,0,4))
        self.assertFalse(self.lib.oot_memory_barrier(None,9))
        self.assertTrue(self.lib.oot_memory_init(byref(memory),None,0))
        self.assertTrue(self.lib.oot_memory_barrier(byref(memory),15))

    def test_full_state_matches_unicorn_and_old_sdk_rejects_barriers(self):
        context,dispatcher,initial,words=self.session()
        reference=Reference();rng=random.Random(1709)
        for word in words:
            reference.code(struct.pack('<I',word))
            for flags in range(16):
                state=State.from_buffer_copy(initial)
                for n in range(31):state.x[n]=rng.getrandbits(64)
                state.nzcv=flags<<28
                expected=reference.step(state,word)
                self.assertEqual(self.lib.oot_startup_context_system(context,word,byref(state)),0)
                self.assertEqual(state.values(),expected.values())
        old_context,_,state,_=self.session(native=False)
        before=state.values()
        for word in words+[dmb(0),dmb(4),dmb(8),dmb(12),0xd5033f9f,0xd5033fdf]:
            self.assertEqual(self.lib.oot_startup_context_system(old_context,word,byref(state)),1)
            self.assertEqual(state.values(),before)
        for word in [dmb(0),dmb(4),dmb(8),dmb(12),0xd5033f9f,0xd5033fdf]:
            state=State.from_buffer_copy(initial);before=state.values()
            self.assertEqual(self.lib.oot_startup_context_system(context,word,byref(state)),1)
            self.assertEqual(state.values(),before)
        for field,value in (('pc',BASE+1),('nzcv',1),('pc',(1<<39)-4)):
            state=State.from_buffer_copy(initial);setattr(state,field,value);before=state.values()
            self.assertEqual(self.lib.oot_startup_context_system(context,dmb(9),byref(state)),2)
            self.assertEqual(state.values(),before)

    def test_dispatch_prefixes_quota_and_unsupported_options_retire_precisely(self):
        for native,options,expected in ((True,sorted(DMB_OPTIONS),12),(False,[9],0),(True,[0],0)):
            for quantum in (1,3,100):
                context,dispatcher,state,words=self.session(native,options)
                initial=State.from_buffer_copy(state);memory=snapshot(self.lib,context);report=Report();events=[]
                @TRACE
                def trace(row,_):events.append((row.contents.pc,row.contents.retired,row.contents.event))
                self.assertEqual(self.lib.oot_startup_dispatch_begin(dispatcher,byref(state),byref(report)),0)
                self.assertEqual(self.lib.oot_startup_dispatch_run(dispatcher,byref(state),0,None,None,byref(report)),1)
                self.assertEqual((report.retired,state.values()),(0,initial.values()))
                while True:
                    status=self.lib.oot_startup_dispatch_run(dispatcher,byref(state),quantum,cast(trace,c_void_p),None,byref(report))
                    prediction=State.from_buffer_copy(initial);prediction.pc+=report.retired*4
                    self.assertEqual(state.values(),prediction.values());self.assertEqual(snapshot(self.lib,context),memory)
                    if status!=1:break
                self.assertEqual((status,report.error,report.retired),(2,8,expected))
                self.assertEqual(len(events),expected+1)
                self.assertEqual(events[-1],(BASE+4*expected,expected,2))
        context,dispatcher,state,words=self.session(options=[9,9],limit=1)
        initial=State.from_buffer_copy(state);report=Report();memory=snapshot(self.lib,context)
        self.assertEqual(self.lib.oot_startup_dispatch_begin(dispatcher,byref(state),byref(report)),0)
        self.assertEqual(self.lib.oot_startup_dispatch_run(dispatcher,byref(state),100,None,None,byref(report)),2)
        initial.pc+=4
        self.assertEqual((report.error,report.retired,state.values()),(12,1,initial.values()))
        self.assertEqual(snapshot(self.lib,context),memory)

    def test_serialized_barriers_publish_across_distinct_alias_views(self):
        for before,after in ((2,1),(6,5),(10,9),(14,13),(3,15),(7,11)):
            self.assertEqual(self.lib.oot_test_barrier_publication(before,after,2000),1)


if __name__=='__main__':unittest.main()
