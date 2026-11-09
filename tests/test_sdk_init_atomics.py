"""Synthetic INIT LDADD/STLR semantics, full faults and native alias contention.

Independent reference: pinned Unicorn 2.1.4 MAX CPU, with enabled QARMA5
configuration checked by the existing reference. Encoding reference:
https://github.com/llvm/llvm-project/blob/main/llvm/test/MC/AArch64/armv8.1a-atomic.s
No original game instructions or data are used.
"""
from ctypes import (POINTER,byref,c_int,c_size_t,c_uint8,c_uint32,c_uint64,
                    c_void_p,create_string_buffer,cast)
import hashlib
from importlib.metadata import version
import os
from pathlib import Path
import random
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from arm64_lifter import U64,decode_instruction
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import Memory,Region,State
from pauth_lifter import decode_pauth_instruction
from pauth_validation import Reference,KEYS,BASE,STACK
from sdk_instructions import decode_sdk_instruction
from sdk_init_instructions import decode_sdk_init_instruction,sdk_init_atomic_kind
from prepare_runtime import pack_regions
from prepare_startup import CONTEXT
from startup_validation import Config,Instruction,Program,Span,Report,bindings,snapshot
from test_sdk_instructions import SdkConfig
from test_native_sdk_dispatch import NativeFunction


def ldadd(size,al=False,rs=0,rt=1,rn=2):
    return (0xf8200000 if size==8 else 0xb8200000)|(0xc00000 if al else 0)|(rs<<16)|(rn<<5)|rt


def stlr(size,rt=0,rn=2):
    return 0x089ffc00|({1:0,2:1,4:2,8:3}[size]<<30)|(rn<<5)|rt

def ldset(size,order=0,rs=0,rt=1,rn=2):
    return ldadd(size,False,rs,rt,rn)|0x3000|(order<<22)

def ldclr(size,order=0,rs=0,rt=1,rn=2):
    return ldadd(size,False,rs,rt,rn)|0x1000|(order<<22)


SOURCE=r'''
#include "startup_init_atomic.h"
#include <windows.h>
#include <stdlib.h>
typedef struct InitAddWorker {
 OotGuestMemory memory;uint64_t address;unsigned size,count;uint64_t *seen;LONG failed;
} InitAddWorker;
static DWORD WINAPI init_add_worker(LPVOID opaque) {
 InitAddWorker *worker=opaque;
 for(unsigned n=0;n<worker->count;++n)
  if(!oot_memory_fetch_add(&worker->memory,worker->address,worker->size,0,1,&worker->seen[n])) {
   InterlockedExchange(&worker->failed,1);break;
  }
 return 0;
}
OOT_LIFT_EXPORT int oot_init_add_stress(unsigned size) {
 uint8_t bytes[8]={0};const unsigned count=30000;
 OotGuestRegion regions[2]={{UINT64_C(0x200000000),8,bytes,3},{UINT64_C(0x200000100),8,bytes,3}};
 InitAddWorker workers[2]={0};HANDLE threads[2]={0};uint8_t *unique=NULL;int ok=0;
 if(size!=4&&size!=8)return 0;
 unique=calloc(count*2,1);if(!unique)return 0;
 for(unsigned n=0;n<2;++n) {
  workers[n].address=regions[n].base;workers[n].size=size;workers[n].count=count;
  workers[n].seen=calloc(count,sizeof(uint64_t));
  if(!workers[n].seen||!oot_memory_init(&workers[n].memory,regions,2))goto cleanup;
 }
 for(unsigned n=0;n<2;++n) {
  threads[n]=CreateThread(NULL,0,init_add_worker,workers+n,0,NULL);
  if(!threads[n])goto cleanup;
 }
 if(WaitForMultipleObjects(2,threads,TRUE,30000)!=WAIT_OBJECT_0)goto cleanup;
 for(unsigned n=0;n<2;++n) {
  if(workers[n].failed)goto cleanup;
  for(unsigned k=0;k<count;++k) {
   uint64_t value=workers[n].seen[k];
   if(value>=count*2||unique[value])goto cleanup;
   unique[value]=1;
  }
 }
 {uint64_t value;if(!oot_memory_load(&workers[0].memory,regions[0].base,size,&value)||value!=count*2)goto cleanup;}
 ok=1;
cleanup:
 for(unsigned n=0;n<2;++n)if(threads[n]) {WaitForSingleObject(threads[n],INFINITE);CloseHandle(threads[n]);}
 for(unsigned n=0;n<2;++n)free(workers[n].seen);
 free(unique);return ok;
}
'''


class SdkInitAtomicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if version('unicorn')!='2.1.4':raise AssertionError('pinned Unicorn is required')
        cls.lib,cls.build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),
            startup=True,extra_source=SOURCE)
        bindings(cls.lib)
        signatures={
            'oot_startup_init_atomic_kind':([c_uint32],c_int),
            'oot_startup_init_atomic_step':([c_uint32,POINTER(State),POINTER(Memory)],c_int),
            'oot_memory_init':([POINTER(Memory),POINTER(Region),c_size_t],c_int),
            'oot_memory_fetch_add':([POINTER(Memory),c_uint64,c_uint32,c_uint32,c_uint64,POINTER(c_uint64)],c_int),
            'oot_memory_fetch_or':([POINTER(Memory),c_uint64,c_uint32,c_uint32,c_uint64,POINTER(c_uint64)],c_int),
            'oot_memory_fetch_clear':([POINTER(Memory),c_uint64,c_uint32,c_uint32,c_uint64,POINTER(c_uint64)],c_int),
            'oot_memory_store_release':([POINTER(Memory),c_uint64,c_uint32,c_uint32,c_uint64],c_int),
            'oot_init_add_stress':([c_uint32],c_int),
            'oot_startup_context_create_sdk':([c_void_p,POINTER(Config),POINTER(SdkConfig),POINTER(c_uint32)],c_void_p),
            'oot_startup_context_system':([c_void_p,c_uint32,POINTER(State)],c_int),
            'oot_startup_dispatch_create_init':([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_create_native':([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_create_sdk':([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_set_native_functions':([c_void_p,POINTER(NativeFunction),c_size_t,POINTER(c_uint32)],c_int)}
        for name,(args,result) in signatures.items():
            function=getattr(cls.lib,name);function.argtypes=args;function.restype=result
        cls.reference=Reference();cls.reference.keys(KEYS)
        if (cls.reference.u.cpr_read(3,0,0,6,0)>>20)&15<2:
            raise AssertionError('reference must declare Arm LSE atomics')

    def memory(self,permissions=3,size=4096):
        backing=(c_uint8*size)(*([0xa5]*size))
        table=(Region*1)(Region(STACK,size,backing,permissions));memory=Memory()
        self.assertTrue(self.lib.oot_memory_init(byref(memory),table,1))
        return memory,backing,table

    def state(self,rn=2):
        state=State();state.pc=BASE;state.sp=STACK+256;state.nzcv=0xb0000000
        for n in range(31):state.x[n]=0x12345678ff00aa55+n
        if rn!=31:state.x[rn]=STACK+256
        return state

    def compare(self,word,state,memory,backing):
        self.reference.code(struct.pack('<I',word))
        self.reference.u.mem_write(STACK,bytes(backing))
        expected=self.reference.step(state,word)
        actual=State.from_buffer_copy(state)
        self.assertEqual(self.lib.oot_startup_init_atomic_step(word,byref(actual),byref(memory)),0)
        self.assertEqual(actual.values(),expected.values())
        self.assertEqual(bytes(backing),bytes(self.reference.u.mem_read(STACK,len(backing))))

    def test_ldadd_fields_aliases_modular_values_and_zero_register_match_reference(self):
        memory,backing,keep=self.memory();edge=(0,1,0xffffffff,0xffffffffffffffff,0x80000000,0x8000000000000000)
        for size in (4,8):
            for al in (False,True):
                for rs in range(32):
                    for rt in range(32):
                        rn=(rs+rt)%32;state=self.state(rn)
                        old=edge[(rs+rt)%len(edge)]&((1<<(size*8))-1)
                        backing[256:256+size]=old.to_bytes(size,'little')
                        state.nzcv=((rs+rt)%16)<<28
                        self.compare(ldadd(size,al,rs,rt,rn),state,memory,backing)
                for rn in range(32):
                    for rs,rt in ((rn,rn),(31,rn),(rn,31)):
                        self.compare(ldadd(size,al,rs,rt,rn),self.state(rn),memory,backing)

    def test_stlr_widths_sources_sp_and_truncation_match_reference(self):
        memory,backing,keep=self.memory()
        for size in (1,2,4,8):
            for rt in range(32):
                for rn in (0,rt,31):
                    state=self.state(rn);state.nzcv=(rt%16)<<28
                    self.compare(stlr(size,rt,rn),state,memory,backing)

    def test_ldset_all_orderings_and_aliases_match_original_reference_semantics(self):
        for make,kind in ((ldset,4),(ldclr,5)):self._bitwise_reference(make,kind)

    def _bitwise_reference(self,make,kind):
        memory,backing,keep=self.memory()
        for size in (4,8):
            for order in range(4):
                for rs in range(32):
                    for rt in range(32):
                        rn=(rs+rt)%32;state=self.state(rn)
                        word=make(size,order,rs,rt,rn)
                        self.assertEqual(self.lib.oot_startup_init_atomic_kind(word),kind)
                        self.assertEqual(decode_sdk_init_instruction(word,BASE).form,'sdk_init_atomic')
                        backing[256:256+size]=(0xa55a00ff88552211&((1<<(size*8))-1)).to_bytes(size,'little')
                        self.compare(word,state,memory,backing)
                        if rs==0 and rt==0:
                            for legacy in (decode_instruction,decode_pauth_instruction,decode_sdk_instruction):
                                with self.assertRaises(InputError):legacy(word,BASE)

    def test_exact_scope_and_decoder_fields_preserve_earlier_policies(self):
        for size in (4,8):
            for al in (False,True):
                word=ldadd(size,al,30,29,31);decoded=decode_sdk_init_instruction(word,BASE)
                self.assertEqual((decoded.form,decoded.rd,decoded.rm,decoded.rn,decoded.access_size),
                    ('sdk_init_atomic',29,30,31,size))
                self.assertEqual(self.lib.oot_startup_init_atomic_kind(word),2 if al else 1)
        for size in (1,2,4,8):
            word=stlr(size,30,31);decoded=decode_sdk_init_instruction(word,BASE)
            self.assertEqual((decoded.form,decoded.rd,decoded.rn,decoded.access_size),('sdk_init_atomic',30,31,size))
            self.assertEqual(self.lib.oot_startup_init_atomic_kind(word),3)
        for word in (ldadd(4),ldadd(8,True),stlr(1),stlr(2),stlr(4),stlr(8)):
            for legacy in (decode_instruction,decode_pauth_instruction,decode_sdk_instruction):
                with self.assertRaises(InputError):legacy(word,BASE)
        for word in (0xb8a00041,0xb8600041,0x38200041,0x78200041,0xb8202041,0x889f7c40,0x885ffc40):
            self.assertEqual(self.lib.oot_startup_init_atomic_kind(word),0)
            self.assertIsNone(sdk_init_atomic_kind(word))

    def test_fetch_add_full_faults_output_preservation_and_read_write_requirement(self):
        for function in (self.lib.oot_memory_fetch_add,self.lib.oot_memory_fetch_or,self.lib.oot_memory_fetch_clear):self._fetch_faults(function)

    def _fetch_faults(self,function):
        for size in (4,8):
            for permissions in (0,1,2):
                memory,backing,keep=self.memory(permissions);out=c_uint64(0x1122334455667788);before=bytes(backing)
                self.assertFalse(function(byref(memory),STACK+256,size,0,1,byref(out)))
                self.assertEqual((bytes(backing),out.value),(before,0x1122334455667788))
            memory,backing,keep=self.memory();out=c_uint64(0x1122334455667788)
            for address,width,sp in ((STACK+1,size,0),(STACK+8,size,1),(STACK,size,2),
                    (STACK,1,0),(STACK,2,0),(STACK,16,0),(STACK+4096,size,0),((1<<64)-size+1,size,0)):
                before=bytes(backing)
                self.assertFalse(function(byref(memory),address,width,sp,1,byref(out)))
                self.assertEqual((bytes(backing),out.value),(before,0x1122334455667788))
            # A naturally aligned operand can span separately backed regions;
            # the last byte must be checked before any write or output change.
            table=(Region*2)(Region(STACK,size-1,backing,3),
                Region(STACK+size-1,1,cast(byref(backing,size-1),POINTER(c_uint8)),1))
            self.assertTrue(self.lib.oot_memory_init(byref(memory),table,2));before=bytes(backing)
            self.assertFalse(function(byref(memory),STACK,size,0,7,byref(out)))
            self.assertEqual((bytes(backing),out.value),(before,0x1122334455667788))
            self.assertEqual((memory.fault.address,memory.fault.failing_address,memory.fault.size,memory.fault.access),
                (STACK,STACK+size-1,size,3))

    def test_release_store_write_only_permissions_alignment_and_instruction_faults(self):
        memory,backing,keep=self.memory(2)
        for size in (1,2,4,8):
            self.assertTrue(self.lib.oot_memory_store_release(byref(memory),STACK,size,0,0xfedcba9876543210))
            self.assertEqual(bytes(backing[:size]),(0xfedcba9876543210&((1<<(size*8))-1)).to_bytes(size,'little'))
            for address in (STACK+4096,STACK+1 if size>1 else STACK+4096):
                before=bytes(backing)
                self.assertFalse(self.lib.oot_memory_store_release(byref(memory),address,size,0,U64))
                self.assertEqual(bytes(backing),before)
        for word in (ldadd(4),ldadd(8,True),ldset(4),ldset(8,3),stlr(1),stlr(2),stlr(4),stlr(8)):
            for address in (STACK+4096,1<<39,U64):
                state=self.state();state.x[2]=address;before=state.values();guest=bytes(backing)
                self.assertEqual(self.lib.oot_startup_init_atomic_step(word,byref(state),byref(memory)),2)
                self.assertEqual((state.values(),bytes(backing)),(before,guest))
            state=self.state();state.pc+=1;before=state.values()
            self.assertEqual(self.lib.oot_startup_init_atomic_step(word,byref(state),byref(memory)),2)
            self.assertEqual(state.values(),before)

    def test_native_two_thread_alias_views_observe_each_old_value_exactly_once(self):
        for size in (4,8):self.assertTrue(self.lib.oot_init_add_stress(size))

    def test_dispatcher_prefixes_retire_atomically_and_older_profiles_reject(self):
        for first in (ldadd(4,True),ldset(4),ldclr(4)):self._dispatch_prefixes(first)

    def _dispatch_prefixes(self,first):
        words=(first,stlr(4,1,2),0xd4200000)
        data=bytearray(8192);struct.pack_into('<3I',data,0,*words);struct.pack_into('<I',data,64,0xd65f03c0)
        struct.pack_into('<I',data,4096,0xfffffffe)
        module=SimpleNamespace(name='init_atomic',base=BASE,ranges=((0,4096),(4096,4096),(4096,8192)),
            bss_start=8192,bss_end=8192,image=data)
        blob,manifest=pack_regions([module],{'synthetic_raw':True},0x7000000000,4096)
        path=Path(self.build['directory'])/'init-atomic.ootmem';path.write_bytes(blob)
        rows=(Instruction*3)(*[Instruction(BASE+4*n,word,5 if n<2 else 4,
            BASE+4*(n+1) if n<2 else BASE+8,BASE+4*(n+1) if n<2 else BASE+8,None) for n,word in enumerate(words)])
        spans=(Span*1)(Span(BASE,12,(c_uint8*32).from_buffer_copy(hashlib.sha256(data[:12]).digest())))
        for flags,mode in ((1|2|8,'sdk'),(1|2|8|128,'native'),(1|2|8|128|256,'init')):
            message=create_string_buffer(192);image=self.lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
            context=keys=dispatcher=None
            try:
                config=Config(**dict(CONTEXT,heap_capacity=0x200000))
                sdk=SdkConfig(version=1,flags=flags,entropy=(c_uint64*4)(1,2,3,4),core_mask=1,priority_mask=U64,
                    aslr_base=0,aslr_size=1<<39,alias_base=0x5000000000,alias_size=0x200000,
                    program_id=1,is_application=1,total_memory=1<<30,main_thread_id=1,main_thread_priority=44,main_thread_core=0)
                error=c_uint32();context=self.lib.oot_startup_context_create_sdk(image,byref(config),byref(sdk),byref(error));self.assertTrue(context,error.value)
                keys=self.lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));self.assertTrue(keys)
                program=Program(1,15 if mode=='init' else 7 if mode=='native' else 3,BASE,
                    (c_uint8*32).from_buffer_copy(bytes.fromhex(manifest['body_sha256'])),rows,3,spans,1)
                dispatcher=getattr(self.lib,'oot_startup_dispatch_create_'+mode)(image,context,keys,byref(program),100,byref(error))
                if mode!='init':
                    self.assertFalse(dispatcher)
                    state=self.state();before=state.values()
                    self.assertEqual(self.lib.oot_startup_context_system(context,words[0],byref(state)),1)
                    self.assertEqual(state.values(),before)
                    continue
                self.assertTrue(dispatcher,error.value)
                guard=NativeFunction(1,31,BASE+64,4,(c_uint8*32).from_buffer_copy(hashlib.sha256(data[64:68]).digest()))
                self.assertTrue(self.lib.oot_startup_dispatch_set_native_functions(dispatcher,byref(guard),1,byref(error)))
                state=State();self.assertTrue(self.lib.oot_startup_context_initial_state(context,BASE,byref(state)))
                state.x[0]=3;state.x[1]=0xabcdef0000000000;state.x[2]=BASE+4096;report=Report()
                self.assertEqual(self.lib.oot_startup_dispatch_begin(dispatcher,byref(state),byref(report)),0)
                self.assertEqual(self.lib.oot_startup_dispatch_run(dispatcher,byref(state),1,None,None,byref(report)),1)
                self.assertEqual((report.retired,state.pc,state.x[0],state.x[1]),(1,BASE+4,3,0xfffffffe))
                wanted=1 if first==ldadd(4,True) else 0xffffffff if first==ldset(4) else 0xfffffffc
                self.assertEqual(struct.unpack('<I',snapshot(self.lib,context)[BASE+4096][:4])[0],wanted)
                self.assertEqual(self.lib.oot_startup_dispatch_run(dispatcher,byref(state),1,None,None,byref(report)),1)
                self.assertEqual((report.retired,state.pc),(2,BASE+8))
                self.assertEqual(struct.unpack('<I',snapshot(self.lib,context)[BASE+4096][:4])[0],0xfffffffe)
                self.assertEqual(self.lib.oot_startup_dispatch_run(dispatcher,byref(state),1,None,None,byref(report)),2)
                self.assertEqual((report.retired,report.error),(2,8))
            finally:
                if dispatcher:self.lib.oot_startup_dispatch_destroy(dispatcher)
                if keys:self.lib.oot_pauth_destroy(keys)
                if context:self.lib.oot_startup_context_destroy(context)
                self.lib.oot_runtime_close(image)


if __name__=='__main__':unittest.main()
