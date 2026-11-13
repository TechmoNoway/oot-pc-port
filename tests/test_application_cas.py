"""Application-only byte/halfword CAS against independent ARM state/memory."""
from ctypes import POINTER,byref,c_int,c_uint32,c_uint64
import os
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import test_sdk_init_atomics as fixtures
from input_formats import InputError
from lifter_validation_types import Memory,State
from sdk_instructions import decode_sdk_instruction,sdk_atomic_kind
from sdk_init_instructions import decode_sdk_init_instruction,sdk_init_atomic_kind
from lifter_validation import compile_library


def narrow_cas(size,order,rs,rt,rn):
    return 0x08a07c00|((size==2)<<30)|((order>>1)<<22)|((order&1)<<15)|rs<<16|rn<<5|rt


class ApplicationCasDecodeTests(unittest.TestCase):
    def test_literal_application_only_metadata(self):
        for word,size,order,rs,rt,rn in ((0x08e87d2a,1,2,8,10,9),
                                       (0x48a07fff,2,0,0,31,31),
                                       (0x08ffffff,1,3,31,31,31)):
            self.assertEqual(narrow_cas(size,order,rs,rt,rn),word)
            self.assertIsNone(sdk_atomic_kind(word))
            self.assertIsNone(sdk_init_atomic_kind(word))
            for decode in (decode_sdk_instruction,decode_sdk_init_instruction):
                with self.assertRaises(InputError):decode(word,fixtures.BASE)
            self.assertEqual(sdk_init_atomic_kind(word,True),'compare_exchange_narrow')
            i=decode_sdk_init_instruction(word,fixtures.BASE,True)
            self.assertEqual((i.form,i.width,i.access_size,i.rd,i.rm,i.rn,i.operation),
                             ('sdk_atomic',32,size,rs,rt,rn,order))


class ApplicationCasTests(unittest.TestCase):
    memory=fixtures.SdkInitAtomicTests.memory
    state=fixtures.SdkInitAtomicTests.state

    @classmethod
    def setUpClass(cls):
        fixtures.SdkInitAtomicTests.setUpClass.__func__(cls)
        cls.kind=cls.lib.oot_startup_application_atomic_kind
        cls.kind.argtypes=[c_uint32];cls.kind.restype=c_int
        cls.step=cls.lib.oot_startup_application_atomic_step
        cls.step.argtypes=[c_uint32,POINTER(State),POINTER(Memory)];cls.step.restype=c_int

    def compare(self,size,order,rs,rt,rn,match,operands=None,offset=256):
        memory,backing,table=self.memory();state=self.state(rn)
        if rn==31:state.sp=fixtures.STACK+offset
        else:state.x[rn]=fixtures.STACK+offset
        if operands is not None:
            assert rs!=rt and rn not in (rs,rt) and 31 not in (rs,rt)
            state.x[rs],state.x[rt]=operands
        word=narrow_cas(size,order,rs,rt,rn);mask=(1<<(size*8))-1
        expected=0 if rs==31 else state.x[rs]&mask
        desired=0 if rt==31 else state.x[rt]&mask
        old=expected if match else expected^(1<<(size*8-1))
        backing[offset:offset+size]=old.to_bytes(size,'little')
        expected_bytes=bytearray(backing)
        if match:expected_bytes[offset:offset+size]=desired.to_bytes(size,'little')
        wanted=State.from_buffer_copy(state);wanted.pc+=4
        if rs!=31:wanted.x[rs]=old
        self.reference.code(struct.pack('<I',word));self.reference.u.mem_write(fixtures.STACK,bytes(backing))
        reference=self.reference.step(state,word)
        self.assertEqual(self.kind(word),8)
        self.assertEqual(self.lib.oot_startup_init_atomic_kind(word),0)
        before=bytes(state);actual=State.from_buffer_copy(state)
        self.assertEqual(self.step(word,byref(actual),byref(memory)),0,hex(word))
        self.assertEqual(actual.values(),wanted.values(),hex(word))
        self.assertEqual(actual.values(),reference.values(),hex(word))
        self.assertEqual(bytes(backing),bytes(expected_bytes),hex(word))
        self.assertEqual(bytes(backing),bytes(self.reference.u.mem_read(fixtures.STACK,len(backing))))
        self.assertEqual(bytes(state),before)

    def test_literal_native_kind_and_original_old_profile_rejection(self):
        self.assertEqual(self.kind(0x08e87d2a),8)
        for size in (1,2):
            for order in range(4):
                word=narrow_cas(size,order,8,10,9)
                memory,backing,table=self.memory();state=self.state(9)
                before=(bytes(state),bytes(backing))
                self.assertEqual(self.lib.oot_startup_init_atomic_step(word,byref(state),byref(memory)),1)
                self.assertEqual((bytes(state),bytes(backing)),before)

    def test_all_compare_result_and_desired_fields_success_failure_and_aliases(self):
        for size in (1,2):
            for order in range(4):
                for rs in range(32):
                    for rt in range(32):self.compare(size,order,rs,rt,(rs+rt)%32,(rs+rt)&1)
                for rn in range(32):
                    for rs,rt in ((1,2),(rn,2),(1,rn),(rn,rn),(31,2),(1,31),(31,31)):
                        for match in (False,True):self.compare(size,order,rs,rt,rn,match)

    def test_boundaries_use_only_low_source_bits_and_zero_extend_high_old_values(self):
        for size in (1,2):
            mask=(1<<(size*8))-1
            edges=(0,1,(1<<(size*8-1))-1,1<<(size*8-1),mask)
            for order in range(4):
                for expected in edges:
                    for desired in edges:
                        for match in (False,True):
                            operands=(0xfedcba98ffffffff & ~mask | expected,
                                      0x12345678ffffffff & ~mask | desired)
                            self.compare(size,order,8,10,9,match,operands)

    def test_last_mapped_byte_or_halfword_does_not_require_a_wider_access(self):
        for size in (1,2):
            for order in range(4):
                for match in (False,True):self.compare(size,order,8,10,9,match,offset=4096-size)

    def test_fixed_bit_neighbors_cannot_enter_narrow_cas(self):
        word,mask=0x08e87d2a,0xbfa07c00
        for bit in range(32):
            if mask&(1<<bit):
                self.assertNotEqual(self.kind(word^(1<<bit)),8)
                self.assertNotEqual(sdk_init_atomic_kind(word^(1<<bit),True),'compare_exchange_narrow')

    def test_bad_state_permissions_alignment_and_address_faults_preserve_effects(self):
        for size in (1,2):
            for mutation in ('pc','sp','nzcv','pc_limit','address_limit','ro','unmapped','half_unaligned'):
                if mutation=='half_unaligned' and size==1:continue
                memory,backing,table=self.memory(permissions=1 if mutation=='ro' else 3)
                state=self.state(9)
                if mutation=='pc':state.pc+=1
                if mutation=='sp':state.sp+=8
                if mutation=='nzcv':state.nzcv|=1
                if mutation=='pc_limit':state.pc=(1<<39)-4
                if mutation=='address_limit':state.x[9]=1<<39
                if mutation=='unmapped':state.x[9]=fixtures.STACK+8192
                if mutation=='half_unaligned':state.x[9]+=1
                before=(bytes(state),bytes(backing))
                self.assertEqual(self.step(narrow_cas(size,3,8,10,9),byref(state),byref(memory)),2,mutation)
                self.assertEqual((bytes(state),bytes(backing)),before,mutation)

    def test_narrow_and_old_backend_width_domains_preserve_output_sentinels(self):
        old=self.lib.oot_memory_compare_exchange
        new=self.lib.oot_memory_compare_exchange_narrow
        for fn in (old,new):
            fn.argtypes=[POINTER(Memory),c_uint64,c_uint32,c_uint32,c_uint64,c_uint64,POINTER(c_uint64)]
            fn.restype=c_int
        for fn,sizes in ((old,(1,2)),(new,(0,3,4,8,16,0xffffffff))):
            for size in sizes:
                memory,backing,table=self.memory();before=bytes(backing);out=c_uint64(0xdeadbeef12345678)
                self.assertEqual(fn(byref(memory),fixtures.STACK+256,size,0,0xa5,0,byref(out)),0)
                self.assertEqual(out.value,0xdeadbeef12345678)
                self.assertEqual(bytes(backing),before)


    def test_backend_complete_permissions_split_spans_and_invalid_configuration(self):
        from ctypes import c_uint8,cast
        from lifter_validation_types import Region
        fn=self.lib.oot_memory_compare_exchange_narrow
        fn.argtypes=[POINTER(Memory),c_uint64,c_uint32,c_uint32,c_uint64,c_uint64,POINTER(c_uint64)]
        fn.restype=c_int
        base=fixtures.STACK
        sentinel=0xdeadbeef12345678
        for size in (1,2):
            for permissions in range(4):
                for match in (False,True):
                    memory,backing,table=self.memory(permissions)
                    before=bytes(backing);old=int.from_bytes(before[:size],'little')
                    out=c_uint64(sentinel)
                    ok=fn(byref(memory),base,size,0,old^(not match),0x11223344,byref(out))
                    self.assertEqual(ok,permissions==3)
                    if ok:
                        wanted=(0x11223344&((1<<(8*size))-1)).to_bytes(size,'little') if match else before[:size]
                        self.assertEqual(bytes(backing),wanted+before[size:])
                        self.assertEqual(out.value,old)
                        self.assertEqual(memory.fault.reason,0)
                    else:
                        self.assertEqual((bytes(backing),out.value),(before,sentinel))
                        self.assertEqual(memory.fault.values(),(base,base,size,3,2))
            for sp,address,reason in ((1,base+8,5),(2,base,4)):
                memory,backing,table=self.memory();before=bytes(backing);out=c_uint64(sentinel)
                self.assertFalse(fn(byref(memory),address,size,sp,0,0,byref(out)))
                self.assertEqual((bytes(backing),out.value),(before,sentinel))
                self.assertEqual(memory.fault.values(),(address,address,size,3,reason))
            memory,backing,table=self.memory();before=bytes(backing)
            self.assertFalse(fn(byref(memory),base,size,0,0,0,None))
            self.assertEqual(bytes(backing),before);self.assertEqual(memory.fault.reason,4)
            memory.valid=0;out=c_uint64(sentinel)
            self.assertFalse(fn(byref(memory),base,size,0,0,0,byref(out)))
            self.assertEqual((bytes(backing),out.value),(before,sentinel))
            self.assertFalse(fn(None,base,size,0,0,0,byref(out)))
            self.assertEqual(out.value,sentinel)
        # Halfword may cross two legitimate regions. A missing/unreadable second
        # byte must leave the first byte and returned-value output untouched.
        for permission in (None,0,1,2,3):
            for match in (False,True):
                backing=(c_uint8*2)(0x81,0xfe);before=bytes(backing)
                regions=[Region(base,1,backing,3)]
                if permission is not None:
                    regions.append(Region(base+1,1,cast(byref(backing,1),POINTER(c_uint8)),permission))
                table=(Region*len(regions))(*regions);memory=Memory()
                self.assertTrue(self.lib.oot_memory_init(byref(memory),table,len(table)))
                out=c_uint64(sentinel)
                self.assertEqual(fn(byref(memory),base,2,0,0xfe81^(not match),0x1234,byref(out)),permission==3)
                if permission==3:
                    self.assertEqual(out.value,0xfe81)
                    self.assertEqual(bytes(backing),b'\x34\x12' if match else before)
                else:
                    self.assertEqual((bytes(backing),out.value),(before,sentinel))
                    self.assertEqual(memory.fault.values(),(base,base+1,2,3,1 if permission is None else 2))
        # Malformed tables enter through memory_init, never forged live pointers.
        backing=(c_uint8*2)(0x81,0xfe)
        for bad in (Region(base,0,backing,3),Region(base,2,backing,4),
                    Region(base,2,None,3),Region((1<<64)-1,2,backing,3)):
            table=(Region*1)(bad);memory=Memory();out=c_uint64(sentinel)
            self.assertFalse(self.lib.oot_memory_init(byref(memory),table,1))
            self.assertFalse(fn(byref(memory),base,1,0,0,0,byref(out)))
            self.assertEqual((bytes(backing),out.value),(b'\x81\xfe',sentinel))


ORDER_SOURCE=r'''
#include "arm64_lift.h"
#include <windows.h>
typedef struct CasOrderWorker {
 OotGuestMemory memory;uint64_t base;unsigned size,rounds;HANDLE start;volatile LONG *failed;
} CasOrderWorker;
static int cas_order_acquire(CasOrderWorker *w) {
 ULONGLONG deadline=GetTickCount64()+15000;unsigned spins=0;
 for(;;){uint64_t old;
  if(InterlockedCompareExchange(w->failed,0,0) || GetTickCount64()>deadline)return 0;
  if(!oot_memory_compare_exchange_narrow(&w->memory,w->base,w->size,0,0,1,&old))return 0;
  if(!old)return 1;
  if(++spins%64==0)SwitchToThread();
 }
}
static DWORD WINAPI cas_order_worker(void *opaque) {
 CasOrderWorker *w=opaque;
 if(WaitForSingleObject(w->start,15000)!=WAIT_OBJECT_0)goto failed;
 for(unsigned i=0;i<w->rounds;++i){uint64_t a,b,old;
  if(!cas_order_acquire(w) || !oot_memory_load(&w->memory,w->base+8,8,&a) ||
     !oot_memory_load(&w->memory,w->base+16,8,&b) || b!=~a)goto failed;
  if(i%32==0)SwitchToThread();
  if(!oot_memory_store(&w->memory,w->base+8,8,a+1) ||
     !oot_memory_store(&w->memory,w->base+16,8,~(a+1)) ||
     !oot_memory_compare_exchange_narrow(&w->memory,w->base,w->size,0,1,0,&old) || old!=1)goto failed;
 }
 return 0;
failed:
 InterlockedExchange(w->failed,1);return 1;
}
OOT_LIFT_EXPORT int oot_test_cas_order(unsigned size) {
 uint8_t bytes[64]={0};volatile LONG failed=0;unsigned started=0;int ok=0;
 const unsigned rounds=5000;uint64_t count=0,flag=1;
 OotGuestRegion regions[2]={{UINT64_C(0x200000000),64,bytes,3},{UINT64_C(0x200000100),64,bytes,3}};
 CasOrderWorker workers[2]={0};HANDLE threads[2]={0};HANDLE start=NULL;
 if(size!=1 && size!=2)return 0;
 start=CreateEventW(NULL,TRUE,FALSE,NULL);if(!start)return 0;
 for(unsigned n=0;n<2;++n){
  workers[n].base=regions[n].base;workers[n].size=size;workers[n].rounds=rounds;
  workers[n].start=start;workers[n].failed=&failed;
  if(!oot_memory_init(&workers[n].memory,regions,2))goto cleanup;
 }
 if(!oot_memory_store(&workers[0].memory,workers[0].base+16,8,UINT64_MAX))goto cleanup;
 for(unsigned n=0;n<2;++n){threads[n]=CreateThread(NULL,0,cas_order_worker,workers+n,0,NULL);if(!threads[n])goto cleanup;++started;}
 SetEvent(start);
 if(WaitForMultipleObjects(2,threads,TRUE,30000)!=WAIT_OBJECT_0 || failed)goto cleanup;
 if(!oot_memory_load(&workers[0].memory,workers[0].base+8,8,&count) || count!=rounds*2 ||
    !oot_memory_load(&workers[0].memory,workers[0].base,size,&flag) || flag)goto cleanup;
 ok=1;
cleanup:
 if(!ok)InterlockedExchange(&failed,1);
 SetEvent(start);
 /* Workers have a bounded wait and observe failure before acquiring again.
  * Join before stack-backed views/metadata can leave scope. */
 if(started)WaitForMultipleObjects(started,threads,TRUE,INFINITE);
 for(unsigned n=0;n<started;++n)CloseHandle(threads[n]);
 CloseHandle(start);return ok;
}
'''


class ApplicationCasOrderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib,cls.build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),
                                          extra_source=ORDER_SOURCE,startup=True)
        cls.stress=cls.lib.oot_test_cas_order
        cls.stress.argtypes=[c_uint32];cls.stress.restype=c_int

    def test_two_native_alias_views_publish_payload_and_preserve_atomic_exclusion(self):
        # Real native workers, not guest threads or exhaustive weak-memory proof.
        for size in (1,2):
            with self.subTest(size=size):self.assertEqual(self.stress(size),1)


if __name__=='__main__':unittest.main()
