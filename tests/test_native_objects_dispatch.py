"""Actual generated source/factory calls over synthetic image and host peers."""
from ctypes import CDLL,POINTER,byref,c_char_p,c_int,c_uint,c_uint64
import hashlib,os,struct,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_application_boot as boot
from test_host_boot import mov64
from test_arm64_analysis import branch
from test_sdk_init_vectors import VectorState
from lifter_validation_types import State
from object_cache import SharedCompiler
ROOT=boot.ROOT

def objects_package():
    real_make=boot.make_boot;real_emit=boot.emit_startup;extra=[];declaration={};table_records=[]
    def make(raw,*args,**kwargs):
        sdk=raw.modules[2];main=raw.modules[1];base=sdk.base
        declaration.update(version=1,flags=0,width=1920,height=1080,display=base+0x1500,display_size=64,
            layer=base+0x1600,layer_size=128,native_window=base+0x1618,
            vptr_address=[base+x for x in(0x1500,0x1600,0x1610,0x1618,0x1620)],
            vptr_value=[base+0x1410+n*24 for n in range(5)],anchor=base+0xe40,anchor_size=4,
            anchor_sha256=hashlib.sha256(struct.pack('<I',0xd65f03c0)).hexdigest())
        for n in range(8):
            at=0x1400+n*24;data=struct.pack('<QQQ',0,base+0x17f0,base+0xe40)
            sdk.image[at:at+24]=data;table_records.append(dict(address=base+at,size=24,sha256=hashlib.sha256(data).hexdigest()))
        declaration['tables']=table_records
        for at,value in zip(declaration['vptr_address'],declaration['vptr_value']):struct.pack_into('<Q',sdk.image,at-base,value)
        for at in(0xe40,0xe50,0xe60,0xe70,0xe80):struct.pack_into('<I',sdk.image,at,0xd65f03c0)
        start=main.base+0x900;words=[];out=base+0x1900
        def append(values):words.extend(values)
        def call(offset):words.append(branch(start+len(words)*4,base+offset,True))
        append(mov64(0,out));call(0xe40)
        append(mov64(0,out));append(mov64(1,declaration['display']));call(0xe50)
        append(mov64(0,out));append(mov64(1,declaration['layer']));call(0xe60)
        append(mov64(16,out));words.append(0xf9400211) # Independent X17 <- [X16].
        append(mov64(0,declaration['layer']));call(0xe70)
        append(mov64(0,declaration['display']));call(0xe80)
        words.append(0xd4200000)
        struct.pack_into('<I',main.image,0x824,branch(main.base+0x824,start))
        struct.pack_into('<'+str(len(words))+'I',main.image,0x900,*words)
        for n,word in enumerate(words):
            row=dict(address=start+n*4,word=word,semantic_supported=word!=0xd4200000)
            if word==0xd4200000:row['selection_stop']='synthetic object boundary'
            extra.append(row)
        return real_make(raw,*args,**kwargs)
    def emit(raw,nodes,manifest,*args,**kwargs):
        sdk=raw.modules[2]
        for offset,handler in((0xe40,451),(0xe50,453),(0xe60,455),(0xe70,454),(0xe80,452)):
            kwargs['native_functions'].append(dict(handler_id=handler,entry=sdk.base+offset,size=4,
                body_sha256=hashlib.sha256(sdk.read(offset,4)).hexdigest()))
        kwargs.update(objects=True,object_declaration=declaration)
        return real_emit(raw,sorted([*nodes,*extra],key=lambda n:n['address']),manifest,*args,**kwargs)
    with patch.object(boot,'make_boot',make),patch.object(boot,'emit_startup',emit):
        blob,sources,goal=boot.package(2,True,graphics=True,graphics_calls=True,display=True)
    return blob,sources,goal,declaration

class NativeObjectsDispatchTests(unittest.TestCase):
    def test_bound_factory_return_quota_full_vectors_and_old_profile_rejection(self):
        blob,sources,_,declaration=objects_package()
        observer=boot.SNAPSHOT_SOURCE.replace('oot_startup_dispatch_create_application','oot_startup_dispatch_create_objects')
        observer=observer.replace('if(!context || !keys)goto done;',
            'if(!context || !keys)goto done;\n'
            '    OotStartupDispatcher *cold=oot_startup_dispatch_create_objects(image,context,keys,&program,limit,&error);'
            'if(cold)goto done;\n'
            '    thread_id=object_fixture_thread();oot_graphics_destroy(context->graphics);context->graphics=parent_graphics();\n'
            '    context->graphics->report.working_memory=0;context->graphics->report.working_size=0;\n'
            '    if(!oot_startup_context_bind_objects(context,oot_startup_compiled_objects()))goto done;\n'
            '    OotStartupProgram older=program;older.flags&=~OOT_STARTUP_OBJECTS;\n'
            '    if(oot_startup_dispatch_create_display(image,context,keys,&older,limit,&error))goto done;\n')
        observer=observer.replace('*count=used;*final=state;ok=1;',
            '*count=used;*final=state;oot_startup_context_objects_report(context,&last_objects);'
            'last_calls=oot_startup_dispatch_native_calls(dispatch);ok=1;')
        text=('#include <windows.h>\nstatic DWORD object_fixture_thread(void){return GetCurrentThreadId();}\n'
            '#define failure graphics_fixture_failure\n#define OOT_PEER_FIXTURE_ONLY\n#include "native_graphics_peer_test.c"\n#undef failure\n'
            '#include "startup_context.c"\nstatic OotObjectsReport last_objects;static uint64_t last_calls;\n'
            +'\n'.join(sources.values())+observer+
            '\nOOT_LIFT_EXPORT void oot_test_object_counts(uint64_t *out){'
            'out[0]=last_calls;out[1]=last_objects.calls;out[2]=last_objects.opens;out[3]=last_objects.creates;'
            'out[4]=last_objects.window_getters;out[5]=last_objects.destroys;out[6]=last_objects.closes;'
            'out[7]=last_objects.references;out[8]=windows;out[9]=surfaces;out[10]=instances;out[11]=devices;}\n')
        parent=ROOT/'build/object-dispatch-tests';parent.mkdir(parents=True,exist_ok=True)
        folder=Path(tempfile.mkdtemp(dir=parent));source=folder/'fixture.c';source.write_text(text)
        names=('guest_memory','runtime_image','host_win32','leaf_dispatch','frame_dispatch','stack_dispatch',
            'pauth','checked_read','plt_bridge','startup_dispatch','sdk_native','native_platform','native_services',
            'native_math','startup_vector','startup_float','startup_init_atomic','application_services','native_romfs','native_objects','native_vblank')
        compiler=SharedCompiler(os.environ.get('OOT_LIFTER_COMPILER','cmake'),log=folder/'build.log')
        flags=(compiler.defines({'OOT_MEMORY_SHARED_EXPORTS':None,'_CRT_SECURE_NO_WARNINGS':None,'_WIN32_WINNT':'0x0A00'})+
            compiler.includes([ROOT/'src',ROOT/'tests',ROOT/'third_party/vulkan/include']))
        library=folder/'objects-fixture.dll'
        compiler.build([source,*[ROOT/'src'/(n+'.c')for n in names]],library,flags,shared=True,libraries=['bcrypt','user32'])
        lib=CDLL(str(library));run=lib.oot_test_simd_snapshot
        run.argtypes=[c_char_p,c_uint64,c_uint64,c_uint,POINTER(VectorState),POINTER(c_uint),POINTER(State)];run.restype=c_int
        counts=lib.oot_test_object_counts;counts.argtypes=[POINTER(c_uint64)];counts.restype=None
        path=folder/'synthetic.ootmem';path.write_bytes(blob)
        for quantum in(1,2,1000):
            history=(VectorState*1024)();count=c_uint();final=State();values=(c_uint64*12)()
            self.assertEqual(run(os.fsencode(path),quantum,1000,0,history,byref(count),byref(final)),1)
            counts(values);self.assertEqual(tuple(values),(9,5,1,1,1,1,1,0,0,0,0,0))
            self.assertEqual(final.x[17],declaration['native_window'])
            self.assertEqual(bytes(history[count.value-1].q[0]),bytes([0x5a]*16))
            self.assertEqual(bytes(history[count.value-1].q[31]),bytes([0xa5]*16))

if __name__=='__main__':unittest.main()
