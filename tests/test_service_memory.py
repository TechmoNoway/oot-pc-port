"""Separate bulk service transactions retain instruction-transfer limits."""
from ctypes import POINTER,Structure,byref,c_int,c_uint8,c_uint32,c_uint64,sizeof
import os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from lifter_validation import compile_library
from lifter_validation_types import Memory,Region

class Write(Structure):
    _fields_=[('address',c_uint64),('bytes',POINTER(c_uint8)),('size',c_uint32)]

class ServiceMemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source=r'''
#include <windows.h>
#include "guest_memory.h"
#include "arm64_lift.h"
typedef struct ServiceStress {OotGuestMemory memory;uint64_t address,value;int error;} ServiceStress;
static DWORD WINAPI service_writer(LPVOID opaque){
    ServiceStress *s=opaque;
    OotServiceWrite rows[2]={{s->address,(const uint8_t *)&s->value,8},{s->address+8,(const uint8_t *)&s->value,8}};
    for(unsigned n=0;n<50000;++n)if(!oot_memory_store_service(&s->memory,rows,2)){s->error=1;break;}
    return 0;
}
static DWORD WINAPI service_reader(LPVOID opaque){
    ServiceStress *s=opaque;uint64_t a,b;
    for(unsigned n=0;n<100000;++n)if(!oot_memory_load_pair(&s->memory,s->address,8,&a,&b)||a!=b){s->error=1;break;}
    return 0;
}
OOT_LIFT_EXPORT int oot_service_publication_stress(void){
    uint8_t data[16]={0};OotGuestRegion table[2]={{0x1000,16,data,3},{0x2000,16,data,3}};
    ServiceStress workers[3]={0};HANDLE threads[3]={0};int ok=1;unsigned started=0;
    for(unsigned n=0;n<3;++n){
        if(!oot_memory_init(&workers[n].memory,table,2))return 0;
        workers[n].address=n==1 ? 0x2000:0x1000;
        workers[n].value=n==1 ? UINT64_C(0xaabbccddeeff0011):UINT64_C(0x1122334455667788);
    }
    for(unsigned n=0;n<3;++n){
        threads[n]=CreateThread(NULL,0,n==2 ? service_reader:service_writer,workers+n,0,NULL);
        if(!threads[n]){ok=0;break;}++started;
    }
    if(started && WaitForMultipleObjects(started,threads,TRUE,INFINITE)!=WAIT_OBJECT_0)ok=0;
    for(unsigned n=0;n<started;++n){CloseHandle(threads[n]);if(workers[n].error)ok=0;}
    return ok;
}
'''
        cls.lib,_=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),extra_source=source)
        for name,args in (
            ('oot_memory_init',[POINTER(Memory),POINTER(Region),c_uint64]),
            ('oot_memory_store_service',[POINTER(Memory),POINTER(Write),c_uint32]),
            ('oot_memory_load_service_path',[POINTER(Memory),c_uint64,POINTER(c_uint8),c_uint32,POINTER(c_uint32)]),
            ('oot_memory_store_record',[POINTER(Memory),c_uint64,POINTER(c_uint8),c_uint32]),
            ('oot_memory_load_native_input',[POINTER(Memory),c_uint64,POINTER(c_uint8),c_uint32])):
            fn=getattr(cls.lib,name);fn.argtypes=args;fn.restype=c_int
        cls.lib.oot_service_publication_stress.argtypes=[];cls.lib.oot_service_publication_stress.restype=c_int
    def test_joint_outputs_publish_together_across_native_alias_views(self):
        self.assertTrue(self.lib.oot_service_publication_stress())
    def memory(self,permissions=3,gap=0,size=8192):
        a=(c_uint8*size)(*([0xa5]*size));b=(c_uint8*size)(*([0xb6]*size))
        regions=(Region*2)(Region(0x1000,size,a,3),Region(0x1000+size+gap,size,b,permissions));m=Memory()
        self.assertTrue(self.lib.oot_memory_init(byref(m),regions,2));return m,a,b,regions
    def test_joint_outputs_preflight_all_ranges_before_any_write(self):
        source=(c_uint8*96)(*range(96))
        for permissions,gap in ((3,0),(1,0),(3,16)):
            m,a,b,regions=self.memory(permissions,gap);before=(bytes(a),bytes(b))
            rows=(Write*2)(Write(0x1000,source,8),Write(0x2fe0,source,96))
            self.assertEqual(self.lib.oot_memory_store_service(byref(m),rows,2),int(permissions==3 and not gap))
            if permissions!=3 or gap:self.assertEqual((bytes(a),bytes(b)),before)
            else:self.assertEqual(bytes(a[-32:])+bytes(b[:64]),bytes(source))
        m,a,b,regions=self.memory()
        for count,rows in ((0,(Write*1)(Write(0x1000,source,8))),
            (3,(Write*3)(*[Write(0x1000+i*8,source,8) for i in range(3)])),
            (2,(Write*2)(Write(0x1000,source,16),Write(0x1008,source,8))),
            (1,(Write*1)(Write((1<<64)-4,source,8))),
            (1,(Write*1)(Write(0x1000,source,0)))):
            before=(bytes(a),bytes(b));self.assertFalse(self.lib.oot_memory_store_service(byref(m),rows,count))
            self.assertEqual((bytes(a),bytes(b)),before)
    def test_bulk_caps_and_earlier_record_and_input_limits(self):
        cap=8*1024*1024;m,a,b,regions=self.memory(size=cap//2+64)
        source=(c_uint8*cap)();source[0]=17;source[-1]=99
        rows=(Write*2)(Write(0x1000,source,cap),Write(0x1000+cap,source,64))
        self.assertTrue(self.lib.oot_memory_store_service(byref(m),rows,2))
        self.assertEqual((a[0],b[cap-len(a)-1]),(17,99))
        for size,count in ((cap+1,1),(cap,2)):
            rows[0].size=size;rows[1].size=65
            before=(bytes(a),bytes(b));self.assertFalse(self.lib.oot_memory_store_service(byref(m),rows,count))
            self.assertEqual((bytes(a),bytes(b)),before)
        self.assertFalse(self.lib.oot_memory_store_record(byref(m),0x1000,source,65))
        output=(c_uint8*4097)(*([0xdd]*4097))
        self.assertFalse(self.lib.oot_memory_load_native_input(byref(m),0x1000,output,4097))
        self.assertEqual(bytes(output),bytes([0xdd])*4097)
    def test_path_snapshots_stop_at_nul_and_preserve_both_outputs_on_fault(self):
        m,a,b,regions=self.memory(gap=16)
        output=(c_uint8*4097)(*([0xcc]*4097));length=c_uint32(0xa5a5)
        a[-4:]=b'abc\0'
        self.assertTrue(self.lib.oot_memory_load_service_path(byref(m),0x1000+len(a)-4,output,4097,byref(length)))
        self.assertEqual((bytes(output[:4]),length.value),(b'abc\0',3))
        for address,capacity in ((0x1000+len(a)-3,2),(0x1000+len(a),4097),(0x1000,4098),(0x1000,0)):
            before=(bytes(output),length.value)
            self.assertFalse(self.lib.oot_memory_load_service_path(byref(m),address,output,capacity,byref(length)))
            self.assertEqual((bytes(output),length.value),before)

if __name__=='__main__':unittest.main()
