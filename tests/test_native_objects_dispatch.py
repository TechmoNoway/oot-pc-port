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

def objects_package(events=False,refresh=False,nvn=False,layout=False,resources=False):
    real_make=boot.make_boot;real_emit=boot.emit_startup;extra=[];declaration={};table_records=[]
    def make(raw,*args,**kwargs):
        sdk=raw.modules[2];main=raw.modules[1];base=sdk.base
        declaration.update(version=1,flags=int(events)|(2 if refresh else 0)|(4 if nvn else 0)|(8 if layout else 0)|(16 if resources else 0),width=1920,height=1080,display=base+0x1500,display_size=64,
            layer=base+0x1600,layer_size=128,native_window=base+0x1618,
            vptr_address=[base+x for x in(0x1500,0x1600,0x1610,0x1618,0x1620)],
            vptr_value=[base+0x1410+n*24 for n in range(5)],anchor=base+0xe40,anchor_size=4,
            anchor_sha256=hashlib.sha256(struct.pack('<I',0xd65f03c0)).hexdigest())
        for n in range(8):
            at=0x1400+n*24;data=struct.pack('<QQQ',0,base+0x17f0,base+0xe40)
            sdk.image[at:at+24]=data;table_records.append(dict(address=base+at,size=24,sha256=hashlib.sha256(data).hexdigest()))
        declaration['tables']=table_records
        for at,value in zip(declaration['vptr_address'],declaration['vptr_value']):struct.pack_into('<Q',sdk.image,at-base,value)
        for at in(0xe40,0xe50,0xe60,0xe70,0xe80,0xe90,0xea0):struct.pack_into('<I',sdk.image,at,0xd65f03c0)
        if nvn:
            for at in(0xeb0,0xec0,0xed0,0xee0,0xef0,0xf00,0xf10,0xf20,0xf30):struct.pack_into('<I',sdk.image,at,0xd65f03c0)
            struct.pack_into('<8Q',sdk.image,0x1840,*[base+at for at in(0xed0,0xf20,0xee0,0xeb0,0xf00,0xec0,0xf10,0xef0)])
            sdk.image[0x1a00:0x1a14]=b'nvnDeviceInitialize\0'
        start=main.base+0x900;words=[];out=base+0x1900
        def append(values):words.extend(values)
        def call(offset):words.append(branch(start+len(words)*4,base+offset,True))
        append(mov64(0,out));call(0xe40)
        append(mov64(0,out));append(mov64(1,declaration['display']));call(0xe50)
        append(mov64(0,out));append(mov64(1,declaration['layer']));call(0xe60)
        append(mov64(16,out));words.append(0xf9400211) # Independent X17 <- [X16].
        if refresh:
            for receiver,value in ((declaration['display'],1),(declaration['display'],2),
                (declaration['display']+8,1),(declaration['display'],0x123400000001)):
                append(mov64(0,receiver));append(mov64(1,value));call(0xea0)
        if nvn:
            append(mov64(0,0));append(mov64(1,base+0x1a00));call(0xeb0)
            words.append(0xaa0003f9) # X25: the original bound procedure, never a host pointer.
            append(mov64(0,base+0x1a80));append(mov64(1,base+0x1ac0));words.append(0xd63f0320)
            words.append(0xaa0003f8) # X24: actual initialize result.
            for query in(0,1):
                append(mov64(0,base+0x1a80));append(mov64(1,query));append(mov64(2,base+0x1b00));call(0xee0)
                append(mov64(16,base+0x1b00));words.append(0xb940021a+query) # W26/W27: independent loaded ABI versions.
            if layout:
                for n,query in enumerate((15,16)):
                    append(mov64(0,base+0x1a80));append(mov64(1,query));append(mov64(2,base+0x1b00));call(0xee0)
                    append(mov64(16,base+0x1b00));words.append(0xb940021a+n)
            for at in(0xef0,0xf10):
                append(mov64(0,base+0x1a80));append(mov64(1,1));call(at)
            append(mov64(0,base+0x1a80));call(0xf00);words.append(0xaa0003fc) # X28: origin.
            append(mov64(0,base+0x1a80));call(0xf20);words.append(0xaa0003f7) # X23: depth.
            if resources:
                append(mov64(0,base+0x1b80));append(mov64(1,0));call(0xf30)
            append(mov64(0,base+0x1a80));call(0xed0)
        if events:
            event_out=out+0x40
            append(mov64(0,event_out));append(mov64(1,declaration['display']));call(0xe90)
            # Synthetic service caller, independently encoded from the OS SDK.
            # X21 points at the real registered token in the published record.
            append(mov64(21,event_out+20));append(mov64(1,event_out+20));append(mov64(2,1));append(mov64(3,(1<<64)-1))
            words.append(0xd4000001|(0x18<<5))
            words.append(0xb94002a0);words.append(0xd4000001|(0x17<<5))
            words.append(0xb94002a0);words.append(0xd4000001|(0x17<<5));words.append(0xaa0003f4) # X20 <- reset miss.
            words.append(0xb94002a0);words.append(0xd4000001|(0x12<<5))
            words.append(0xb94002a0);words.append(0xd4000001|(0x16<<5))
            append(mov64(22,event_out+40));words.append(0x390002df) # Original destroy shape: clear the tag.
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
        if events:kwargs['native_functions'].append(dict(handler_id=456,entry=sdk.base+0xe90,size=4,
            body_sha256=hashlib.sha256(sdk.read(0xe90,4)).hexdigest()))
        if refresh:kwargs['native_functions'].append(dict(handler_id=457,entry=sdk.base+0xea0,size=4,
            body_sha256=hashlib.sha256(sdk.read(0xea0,4)).hexdigest()))
        if nvn:
            for offset,handler in((0xeb0,458),(0xec0,459),(0xed0,460),(0xee0,461),(0xef0,462),(0xf00,463),(0xf10,464),(0xf20,465)):
                kwargs['native_functions'].append(dict(handler_id=handler,entry=sdk.base+offset,size=4,
                    body_sha256=hashlib.sha256(sdk.read(offset,4)).hexdigest()))
            if resources:kwargs['native_functions'].append(dict(handler_id=466,entry=sdk.base+0xf30,size=4,body_sha256=hashlib.sha256(sdk.read(0xf30,4)).hexdigest()))
            kwargs['nvn_declaration']=dict(table=sdk.base+0x1840,table_sha256=hashlib.sha256(sdk.read(0x1840,64)).hexdigest(),
                procedures=[dict(name=name,entry=sdk.base+offset)for name,offset in
                    (('nvnDeviceFinalize',0xed0),('nvnDeviceGetDepthMode',0xf20),('nvnDeviceGetInteger',0xee0),
                     ('nvnDeviceGetProcAddress',0xeb0),('nvnDeviceGetWindowOriginMode',0xf00),('nvnDeviceInitialize',0xec0),
                     ('nvnDeviceSetDepthMode',0xf10),('nvnDeviceSetWindowOriginMode',0xef0))])
        kwargs.update(objects=True,object_declaration=declaration)
        return real_emit(raw,sorted([*nodes,*extra],key=lambda n:n['address']),manifest,*args,**kwargs)
    with patch.object(boot,'make_boot',make),patch.object(boot,'emit_startup',emit):
        blob,sources,goal=boot.package(2,True,graphics=True,graphics_calls=True,display=True)
    return blob,sources,goal,declaration

class NativeObjectsDispatchTests(unittest.TestCase):
    def test_bound_factory_return_quota_full_vectors_and_old_profile_rejection(self):
        self.check_dispatch(False)
    def test_published_event_svc_wait_reset_clear_close_and_quanta(self):
        self.check_dispatch(True)
    def test_refresh_void_returns_full_vectors_and_quanta(self):
        self.check_dispatch(True,True)
    def test_nvn_lookup_indirect_call_owned_device_finalization_and_quanta(self):
        self.check_dispatch(True,True,True)
    def test_nvn_fixed_descriptor_layout_full_dispatch_and_quanta(self):
        self.check_dispatch(True,True,True,True)
    def test_resource_optin_factory_fault_preserves_vectors_gprs_and_quanta(self):
        self.check_dispatch(True,True,True,True,True)
    def check_dispatch(self,events,refresh=False,nvn=False,layout=False,resources=False):
        blob,sources,_,declaration=objects_package(events,refresh,nvn,layout,resources)
        observer=boot.SNAPSHOT_SOURCE.replace('oot_startup_dispatch_create_application','oot_startup_dispatch_create_objects')
        observer=observer.replace('if(!context || !keys)goto done;',
            'if(!context || !keys)goto done;\n'
            '    OotStartupDispatcher *cold=oot_startup_dispatch_create_objects(image,context,keys,&program,limit,&error);'
            'if(cold)goto done;\n'
            '    thread_id=object_fixture_thread();oot_graphics_destroy(context->graphics);context->graphics=parent_graphics();\n'
            '    context->graphics->report.working_memory=0;context->graphics->report.working_size=0;\n'
            '    if(!oot_startup_context_bind_objects(context,oot_startup_compiled_objects()))goto done;\n'
            '    if(oot_startup_compiled_nvn() && !oot_startup_context_bind_nvn(context,oot_startup_compiled_nvn()))goto done;\n'
            '    OotStartupProgram older=program;older.flags&=~OOT_STARTUP_OBJECTS;\n'
            '    if(oot_startup_dispatch_create_display(image,context,keys,&older,limit,&error))goto done;\n')
        observer=observer.replace('*count=used;*final=state;ok=1;',
            '*count=used;*final=state;oot_startup_context_objects_report(context,&last_objects);'
            'oot_startup_context_refresh_report(context,&last_refresh);'
            'last_calls=oot_startup_dispatch_native_calls(dispatch);ok=1;')
        text=('#include <windows.h>\nstatic DWORD object_fixture_thread(void){return GetCurrentThreadId();}\n'
            '#define failure graphics_fixture_failure\n#define OOT_PEER_FIXTURE_ONLY\n#include "native_graphics_peer_test.c"\n#undef failure\n'
            '#include "startup_context.c"\n'
            +('#include "native_vblank.h"\nOotVblankSource *oot_test_object_vblank_create(HMONITOR);\n#define oot_vblank_create oot_test_object_vblank_create\n#include "native_objects.c"\n#undef oot_vblank_create\n'if events else'')+
            'static OotObjectsReport last_objects;static OotRefreshReport last_refresh;static uint64_t last_calls;\n'
            +'\n'.join(sources.values())+observer+
            '\nOOT_LIFT_EXPORT void oot_test_object_counts(uint64_t *out){'
            'out[0]=last_calls;out[1]=last_objects.calls;out[2]=last_objects.opens;out[3]=last_objects.creates;'
            'out[4]=last_objects.window_getters;out[5]=last_objects.destroys;out[6]=last_objects.closes;'
            'out[7]=last_objects.references;out[8]=windows;out[9]=surfaces;out[10]=instances;out[11]=devices;'
            'out[12]=last_objects.vsync_events;out[13]=last_objects.waits;out[14]=last_objects.resets;'
            'out[15]=last_objects.clears;out[16]=last_objects.handle_closes;out[17]=last_objects.event_open;'
            'out[18]=last_refresh.capability_bits;out[19]=last_refresh.update_mask;'
            'out[20]=last_refresh.updates;out[21]=last_refresh.ignored;}\n')
        parent=ROOT/'build/object-dispatch-tests';parent.mkdir(parents=True,exist_ok=True)
        folder=Path(tempfile.mkdtemp(dir=parent));source=folder/'fixture.c';source.write_text(text)
        names=('guest_memory','runtime_image','host_win32','leaf_dispatch','frame_dispatch','stack_dispatch',
            'pauth','checked_read','plt_bridge','startup_dispatch','sdk_native','native_platform','native_services',
            'native_math','startup_vector','startup_float','startup_init_atomic','application_services','native_romfs','native_objects','native_gpu','native_nvn_resources','native_vblank')
        names=tuple(n for n in names if not events or n not in('native_objects','native_vblank'))
        compiler=SharedCompiler(os.environ.get('OOT_LIFTER_COMPILER','cmake'),log=folder/'build.log')
        flags=(compiler.defines({'OOT_MEMORY_SHARED_EXPORTS':None,'_CRT_SECURE_NO_WARNINGS':None,'_WIN32_WINNT':'0x0A00'})+
            compiler.includes([ROOT/'src',ROOT/'tests',ROOT/'third_party/vulkan/include']))
        library=folder/'objects-fixture.dll'
        compiler.build([source,*[ROOT/'src'/(n+'.c')for n in names],*([ROOT/'tests/objects_vblank_fixture.c']if events else[])],library,flags,shared=True,libraries=['bcrypt','user32'])
        lib=CDLL(str(library));run=lib.oot_test_simd_snapshot
        run.argtypes=[c_char_p,c_uint64,c_uint64,c_uint,POINTER(VectorState),POINTER(c_uint),POINTER(State)];run.restype=c_int
        counts=lib.oot_test_object_counts;counts.argtypes=[POINTER(c_uint64)];counts.restype=None
        path=folder/'synthetic.ootmem';path.write_bytes(blob)
        for quantum in(1,2,1000):
            history=(VectorState*1024)();count=c_uint();final=State();values=(c_uint64*22)()
            self.assertEqual(run(os.fsencode(path),quantum,1000,0,history,byref(count),byref(final)),1)
            counts(values)
            if resources:
                self.assertEqual(final.pc,declaration['display']-0x1500+0xf30)
                self.assertEqual((final.x[0],final.x[1]),(declaration['display']-0x1500+0x1b80,0))
                self.assertEqual((values[0],values[1]),(21,17))
                self.assertEqual(bytes(history[count.value-1].q[0]),bytes([0x5a]*16))
                self.assertEqual(bytes(history[count.value-1].q[31]),bytes([0xa5]*16))
                if quantum==1:resource_state=final.values()
                else:self.assertEqual(final.values(),resource_state)
                continue
            self.assertEqual(tuple(values),((10 if events else 9)+(4 if refresh else 0)+(9 if nvn else 0)+(2 if layout else 0),
                (6 if events else 5)+(4 if refresh else 0)+(9 if nvn else 0)+(2 if layout else 0),1,1,1,1,1,0,0,0,0,0,
                *([1,1,2,1,1,0]if events else[0]*6),*([2,2,3,1]if refresh else[0]*4)))
            if nvn:
                self.assertEqual(final.x[24],1);self.assertEqual(final.x[25],declaration['display']-0x1500+0xec0)
                self.assertEqual((final.x[26],final.x[27]),(32,32)if layout else(231,40))
                self.assertEqual((final.x[28],final.x[23]),(1,1))
            if events:self.assertEqual(final.x[20],0xfa01)
            self.assertEqual(final.x[17],declaration['native_window'])
            self.assertEqual(bytes(history[count.value-1].q[0]),bytes([0x5a]*16))
            self.assertEqual(bytes(history[count.value-1].q[31]),bytes([0xa5]*16))

if __name__=='__main__':unittest.main()
