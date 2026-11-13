"""Application entry is a separate opt-in after the unchanged original goal."""
import hashlib,json,os,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from test_host_boot import fixture
from host_boot import make_boot
from prepare_runtime import pack_regions,STACK_BASE
from prepare_startup import CONTEXT,emit_startup
from startup_sources import write_sources
from build_startup import build_native,execute
from input_formats import InputError
from test_arm64_analysis import branch
import test_application_simd as simd
import test_application_cas as cas

# Test-owned observer: the product CLI deliberately exposes no vector dump.
SNAPSHOT_SOURCE=r'''
#include "startup_dispatch.h"
#include "startup_vector.h"
#include <string.h>
OOT_LIFT_EXPORT int oot_test_simd_snapshot(const char *path,uint64_t quantum,uint64_t limit,
    unsigned mutate,OotStartupVectorState *history,unsigned *count,OotArm64State *final) {
    char message[192];uint32_t error=0;int ok=0;size_t n=0;
    OotRuntimeImage *image=oot_runtime_open(path,message,sizeof(message));
    OotStartupContext *context=NULL;OotPauth *keys=NULL;OotStartupDispatcher *dispatch=NULL;
    OotArm64State state={0};OotStartupReport report={0};
    OotStartupProgram program=*oot_startup_compiled_program();
    OotStartupInstruction rows[1024];unsigned used=0;
    if(!image || program.instruction_count>1024)goto done;
    if(mutate){
        memcpy(rows,program.instructions,program.instruction_count*sizeof(*rows));
        for(size_t i=0;i<program.instruction_count;++i)if(rows[i].word==UINT32_C(0x7e21d81f))rows[i].word^=1;
        program.instructions=rows;
    }
    context=oot_startup_context_create_sdk(image,oot_startup_compiled_config(),oot_startup_compiled_sdk_config(),&error);
    keys=oot_pauth_create(OOT_PAUTH_QARMA5_VA39,NULL);
    if(!context || !keys)goto done;
    dispatch=oot_startup_dispatch_create_application(image,context,keys,&program,limit,&error);
    if(!dispatch)goto done;
    const OotNativeFunction *functions=oot_startup_compiled_native_functions(&n);
    if(!oot_startup_dispatch_set_native_functions(dispatch,functions,n,&error) ||
        !oot_startup_dispatch_set_sdk_goal(dispatch,oot_startup_compiled_sdk_goal(),&error))goto done;
    const OotStartupConstructor *constructors=oot_startup_compiled_constructors(&n);
    if(!oot_startup_dispatch_set_constructors(dispatch,constructors,n) ||
        !oot_startup_context_initial_state(context,program.entry,&state))goto done;
    (void)oot_startup_dispatch_begin(dispatch,&state,&report);
    if(report.status!=OOT_STARTUP_READY)goto done;
    do {
        (void)oot_startup_dispatch_run(dispatch,&state,quantum,NULL,NULL,&report);
        if(used==1024)goto done;
        history[used++]=*oot_startup_context_vectors(context);
    }while(report.status==OOT_STARTUP_YIELDED);
    *count=used;*final=state;ok=1;
done:
    if(dispatch)oot_startup_dispatch_destroy(dispatch);
    if(keys)oot_pauth_destroy(keys);
    if(context)oot_startup_context_destroy(context);
    if(image)oot_runtime_close(image);
    return ok;
}
'''

def simd_program():
    # Stack-backed synthetic vectors: Q0=(17,85), Q1=(170,255).
    words=[0xd10083ff,0xd2800228,0xd2800aa9,0xa90027e8,
           0xd2801548,0xd2801fe9,0xa90127e8,0x3dc003e0,0x3dc007e1,
           simd.simd_integer_fp(32,1,0,31),simd.orr(1,1,0,2),
           simd.dup_element(24,2,3),simd.ins_element(24,0,31,3),
           simd.cmeq(1,3,0,0,4),simd.bif(1,0,1,3),
           0x1e2603e0,0x9e660041,0x9e660062,
           simd.dup_element(24,3,5),0x9e6600a3,0x9e660084,
           0x910083ff,0xd4200000]
    # Conversion is exact: float32(17)=0x41880000. ORR=(187,255).
    # BIF oldD=(255,0x41880000), N=(170,255), mask=(17,85).
    result=(255 & 17) | (170 & ((1<<64)-1 ^ 17))
    high=(0x41880000 & 85) | (255 & ((1<<64)-1 ^ 85))
    return words,[0x41880000,187,result,high,(1<<64)-1]


def narrow_cas_program():
    words=[0xd10043ff,0x910003e9,simd.fixtures.movi(1,0,14,0x5a,0),
           simd.fixtures.movi(1,0,14,0xa5,31)]
    for size in (1,2):
        for order in range(4):
            rd=(size-1)*4+order
            words += [0x52800228,0x72a00028,0x5280054a,
                      (0x79000128 if size==2 else 0x39000128),
                      cas.narrow_cas(size,order,8,10,9),
                      (0x79400120 if size==2 else 0x39400120)|rd,
                      0x0b080000|rd<<5|rd]
    return words+[0x910043ff,0xd4200000],[59]*8


def package(completed,application,atomic=False,integer_fp=False,simd_cohort=False,narrow_cas=False,resource=False,graphics=False,graphics_calls=False,display=False):
    raw,goal,audit=fixture(completed)
    main=raw.modules[1];sdk=raw.modules[2]
    struct.pack_into('<III',main.image,0x804,0x910004a5,0x910008c6,0xd4200000)
    if atomic:struct.pack_into('<7I',main.image,0x804,0xd10043ff,0x52800069,0xb90003e9,0xb86903e0,0xb94003e1,0x910043ff,0xd4200000)
    if integer_fp:struct.pack_into('<5I',main.image,0x804,0x52800228,0x1e230108,0x9e380101,0x1e260100,0xd4200000)
    if simd_cohort:
        words,_=simd_program()
        struct.pack_into('<'+'I'*len(words),main.image,0x804,*words)
    if narrow_cas:
        words,_=narrow_cas_program()
        struct.pack_into('<'+'I'*len(words),main.image,0x804,*words)
    if resource:
        words=[simd.fixtures.movi(1,0,14,0x5a,0),simd.fixtures.movi(1,0,14,0xa5,31),
            branch(main.base+0x80c,sdk.base+0xe10,True),branch(main.base+0x810,sdk.base+0xe20,True),
            0xaa0003f3,branch(main.base+0x818,sdk.base+0xe30,True),0x8b130000,0xd4200000]
        struct.pack_into('<'+'I'*len(words),main.image,0x804,*words)
        for offset in (0xe10,0xe20,0xe30):struct.pack_into('<I',sdk.image,offset,0xd65f03c0)
    if graphics_calls:
        words=[simd.fixtures.movi(1,0,14,0x5a,0),simd.fixtures.movi(1,0,14,0xa5,31),
            branch(main.base+0x80c,sdk.base+0xe10,True),0xaa1f03e0,0xaa1f03e1,
            branch(main.base+0x818,sdk.base+0xe20,True),branch(main.base+0x81c,sdk.base+0xe30,True),
            branch(main.base+0x820,sdk.base+0xe20,True),0xd4200000]
        struct.pack_into('<'+'I'*len(words),main.image,0x804,*words)
        for offset in (0xe10,0xe20,0xe30):struct.pack_into('<I',sdk.image,offset,0xd65f03c0)
    boot,boot_nodes,report=make_boot(raw,goal,audit,32768)
    nodes=list(boot_nodes)
    for module,lo,hi in [(main,0x100,0x150),(main,0x200,0x214),(sdk,0x100,0x150),
                        (sdk,0x500,0x528),(main,0x700,0x73c),(main,0x780,0x788),
                        (main,0x800,0x804+len(words)*4 if simd_cohort or narrow_cas or resource or graphics_calls else 0x820 if atomic or integer_fp else 0x810)]:
        for off in range(lo,hi,4):
            word=module.unpack('<I',off)[0]
            if not word:continue
            row=dict(address=module.base+off,word=word,semantic_supported=word!=0xd4200000)
            if word==0xd4200000:row['selection_stop']='synthetic application boundary'
            if word==0xb86903e0 and not application:row.update(semantic_supported=False,selection_stop='application-only addition')
            if word in (0x1e230108,0x9e380101) and not application:row.update(semantic_supported=False,selection_stop='application-only conversion')
            if simd_cohort and not application and simd.sdk_init_vector_kind(word,True)!=simd.sdk_init_vector_kind(word):
                row.update(semantic_supported=False,selection_stop='application-only SIMD')
            if narrow_cas and not application and cas.sdk_init_atomic_kind(word,True)=='compare_exchange_narrow':
                row.update(semantic_supported=False,selection_stop='application-only narrow CAS')
            if word&0xffe0001f==0xd4000001:row['service_immediate']=word>>5&65535
            nodes.append(row)
    if resource or graphics_calls:
        for offset in (0xe10,0xe20,0xe30):
            nodes.append(dict(address=sdk.base+offset,word=0xd65f03c0,semantic_supported=False,
                              native_boundary=True,selection_stop='synthetic resource provider boundary'))
    raw.modules.append(boot)
    blob,manifest=pack_regions(raw.modules,{'synthetic':True},STACK_BASE,4096)
    config=dict(CONTEXT,heap_capacity=0x200000)
    model=dict(core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,alias_base=0x5000000000,
        alias_size=0x200000,program_id=1,is_application=1,total_memory=manifest['backing_bytes']+config['tls_size']+config['heap_capacity'],
        main_thread_id=1,main_thread_priority=44,main_thread_core=0)
    natives=[dict(handler_id=31,entry=sdk.base+0xe00,size=8,body_sha256=hashlib.sha256(sdk.read(0xe00,8)).hexdigest())]
    if resource:
        for offset,handler in ((0xe10,64),(0xe20,322 if application else 31),(0xe30,322 if application else 31)):
            natives.append(dict(handler_id=handler,entry=sdk.base+offset,size=4,
                                body_sha256=hashlib.sha256(sdk.read(offset,4)).hexdigest()))
    if graphics_calls:
        for offset,handler in ((0xe10,64),(0xe20,448),(0xe30,450 if display else 449)):
            natives.append(dict(handler_id=handler,entry=sdk.base+offset,size=4,
                                body_sha256=hashlib.sha256(sdk.read(offset,4)).hexdigest()))
    units={};source,summary=emit_startup(raw,sorted(nodes,key=lambda n:n['address']),manifest,config,
        sdk_config=model,sdk_goal=goal,native_functions=natives,sdk_init=True,units=units,entry_override=boot.base,
        host_linked=True,host_constructors=report['module_order'],application=application,graphics=graphics,display=display)
    return blob,dict(units,**{'startup.c':source}),goal

class ApplicationBootTests(unittest.TestCase):
    def test_narrow_cas_dispatch_yields_full_vectors_and_crossed_word(self):
        from ctypes import POINTER,byref,c_char_p,c_uint,c_uint64,c_int
        from lifter_validation import compile_library
        from lifter_validation_types import State
        from test_sdk_init_vectors import VectorState
        words,wanted=narrow_cas_program()
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);compiler=os.environ.get('OOT_LIFTER_COMPILER','cmake');outcomes=[]
            for app in (False,True):
                blob,sources,_=package(2,app,narrow_cas=True)
                folder=root/str(app);folder.mkdir();write_sources(folder,sources)
                (folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,compiler,root/'cache')
                outcomes.append(execute(exe,folder,1000,1000,'full'))
            self.assertEqual(outcomes[0]['error'],15)
            whole=outcomes[1];self.assertEqual(whole['error'],8)
            self.assertTrue(whole['sdk_initialization_completed'])
            self.assertEqual(whole['post_entry_retired'],len(words)-1)
            self.assertEqual(whole['application_stop_arguments'],wanted)
            rows=[json.loads(line) for line in Path(whole['trace_file']).read_text().splitlines()]
            quotas={r['retired']+delta for r in rows if r['word']&0xbfa07c00==0x08a07c00 and r['event']==0
                    for delta in (-1,0)}
            for limit in [1000,*sorted(quotas)]:
                folder=root/f'prefix-{limit}';folder.mkdir();(folder/'startup.ootmem').write_bytes(blob)
                prefix=execute(exe,folder,limit,1,'full')
                actual=[json.loads(line) for line in Path(prefix['trace_file']).read_text().splitlines()]
                self.assertEqual(actual[:-1],[r for r in rows[:-1] if r['retired']<=prefix['retired']])
                if limit==1000:
                    self.assertEqual(prefix['trace_sha256'],whole['trace_sha256'])
                    self.assertEqual(prefix['application_stop_arguments'],wanted)
                else:self.assertEqual(prefix['retired'],limit)
            # Independent full Q-bank observation also covers nonzero sentinels.
            source='\n'.join(sources.values())+SNAPSHOT_SOURCE.replace('UINT32_C(0x7e21d81f)','UINT32_C(0x08e87d2a)')
            lib,build=compile_library([],compiler,extra_source=source,startup=True)
            fn=lib.oot_test_simd_snapshot
            fn.argtypes=[c_char_p,c_uint64,c_uint64,c_uint,POINTER(VectorState),POINTER(c_uint),POINTER(State)];fn.restype=c_int
            path=Path(build['directory'])/'cas.ootmem';path.write_bytes(blob)
            history=(VectorState*1024)();count=c_uint();state=State()
            self.assertEqual(fn(os.fsencode(path),1,1000,0,history,byref(count),byref(state)),1)
            expected=[bytes(16) for _ in range(32)];expected[0]=bytes([0x5a])*16;expected[31]=bytes([0xa5])*16
            self.assertEqual(bytes(history[count.value-1]),b''.join(expected)+bytes(8))
            count.value=0
            self.assertEqual(fn(os.fsencode(path),1,1000,1,history,byref(count),byref(state)),0)
            self.assertEqual(count.value,0)

    def test_simd_complete_vector_bank_survives_yields_and_crossed_word_rejects(self):
        from ctypes import POINTER,byref,c_char_p,c_uint,c_uint64,c_int
        from lifter_validation import compile_library
        from lifter_validation_types import State
        from test_sdk_init_vectors import VectorState
        blob,sources,_=package(2,True,simd_cohort=True)
        lib,build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),
            extra_source='\n'.join(sources.values())+SNAPSHOT_SOURCE,startup=True)
        fn=lib.oot_test_simd_snapshot
        fn.argtypes=[c_char_p,c_uint64,c_uint64,c_uint,POINTER(VectorState),POINTER(c_uint),POINTER(State)]
        fn.restype=c_int
        path=Path(build['directory'])/'application.ootmem';path.write_bytes(blob)
        def run(quantum,limit=1000,mutate=0):
            history=(VectorState*1024)();count=c_uint();state=State()
            ok=fn(os.fsencode(path),quantum,limit,mutate,history,byref(count),byref(state))
            return ok,[bytes(v) for v in history[:count.value]],state
        ok,whole,state=run(1000);self.assertEqual(ok,1)
        ok,steps,single=run(1);self.assertEqual(ok,1)
        self.assertEqual(whole[-1],steps[-1]);self.assertEqual(state.values(),single.values())
        expected=[bytes(16) for _ in range(32)]
        pair=lambda lo,hi:struct.pack('<QQ',lo,hi)
        expected[0]=pair(17,85);expected[1]=pair(170,255);expected[2]=pair(187,255)
        expected[3]=pair(187,170);expected[4]=bytes([255])*16;expected[5]=pair(170,0)
        expected[31]=pair(0x41880000,0)
        self.assertEqual(whole[-1],b''.join(expected)+bytes(8))
        # Every suspension is identical to an independent run stopped at that quota.
        for quota in range(len(steps)-len(simd_program()[0]),len(steps)):
            ok,prefix,_=run(1000,quota);self.assertEqual(ok,1)
            self.assertEqual(prefix[-1],steps[quota-1])
        ok,history,_=run(1,mutate=1)
        self.assertEqual((ok,history),(0,[]))

    def test_simd_cohort_dispatch_yields_and_every_instruction_quota(self):
        words,expected=simd_program()
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);compiler=os.environ.get('OOT_LIFTER_COMPILER','cmake')
            outcomes=[]
            for app in (False,True):
                blob,sources,goal=package(2,app,simd_cohort=True)
                folder=root/str(app);folder.mkdir()
                write_sources(folder,sources);(folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,compiler,root/'cache')
                outcomes.append(execute(exe,folder,1000,1000,'full'))
            self.assertEqual(outcomes[0]['error'],15)
            full=outcomes[1]
            self.assertEqual(full['error'],8)
            self.assertTrue(full['sdk_initialization_completed'])
            self.assertEqual(full['post_entry_retired'],len(words)-1)
            self.assertEqual(full['application_stop_arguments'][:5],expected)
            rows=[json.loads(line) for line in Path(full['trace_file']).read_text().splitlines()]
            # The six families are consecutive in this synthetic program.
            boundaries={r['retired']+delta for r in rows if r['word'] in words[9:15] and r['event']==0
                        for delta in (-1,0)}
            for limit in [1000,*sorted(boundaries)]:
                folder=root/f'prefix-{limit}';folder.mkdir();(folder/'startup.ootmem').write_bytes(blob)
                prefix=execute(exe,folder,limit,1,'full')
                actual=[json.loads(line) for line in Path(prefix['trace_file']).read_text().splitlines()]
                self.assertEqual(actual[:-1],[r for r in rows[:-1] if r['retired']<=prefix['retired']])
                if limit==1000:
                    self.assertEqual(prefix['trace_sha256'],full['trace_sha256'])
                    self.assertEqual(prefix['application_stop_arguments'],full['application_stop_arguments'])
                else:self.assertEqual(prefix['retired'],limit)

    def test_integer_float_dispatch_preserves_old_goal_and_publishes_real_vector_value(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);outcomes=[]
            for app in (False,True):
                blob,sources,goal=package(2,app,integer_fp=True);folder=root/str(app);folder.mkdir()
                write_sources(folder,sources);(folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,os.environ.get('OOT_LIFTER_COMPILER','cmake'),root/'cache')
                outcomes.append(execute(exe,folder,1000,1,'full'))
            self.assertEqual(outcomes[0]['error'],15)
            self.assertEqual(outcomes[1]['post_entry_retired'],4)
            self.assertEqual(outcomes[1]['application_stop_arguments'][:2],[0x41880000,17])
    def test_application_atomic_dispatch_preserves_init_endpoint_and_real_memory_effect(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);outcomes=[]
            for app in (False,True):
                blob,sources,goal=package(2,app,atomic=True);folder=root/str(app);folder.mkdir()
                write_sources(folder,sources);(folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,os.environ.get('OOT_LIFTER_COMPILER','cmake'),root/'cache')
                outcomes.append(execute(exe,folder,1000,1,'full'))
            self.assertEqual(outcomes[0]['error'],15)
            self.assertEqual(outcomes[1]['post_entry_retired'],6)
            self.assertEqual(outcomes[1]['application_stop_arguments'][:2],[3,6])
    def test_entry_requires_full_initialization_and_preserves_old_stop(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);compiler=os.environ.get('OOT_LIFTER_COMPILER','cmake')
            for completed in (1,2,3,4):
                outcomes=[]
                for application in (False,True):
                    blob,sources,goal=package(completed,application)
                    folder=root/f'{completed}-{application}';folder.mkdir()
                    write_sources(folder,sources);(folder/'startup.ootmem').write_bytes(blob)
                    exe,_=build_native(folder,compiler,root/'cache')
                    report=execute(exe,folder,1000,1,'full');outcomes.append(report)
                    valid=completed in (1,2)
                    self.assertEqual(report['sdk_initialization_completed'],valid)
                    if application:
                        self.assertTrue(report['application_runtime'])
                        self.assertEqual(report['application_entry_retired'],valid)
                        self.assertEqual(report['post_entry_retired'],2 if valid else 0)
                        self.assertEqual(report['error'],8 if valid else 16)
                    else:self.assertEqual(report['error'],15 if valid else 16)
                if completed in (1,2):
                    self.assertEqual(outcomes[1]['retired']-outcomes[0]['retired'],2)
                    old=Path(outcomes[0]['trace_file']).read_text().splitlines()[:-1]
                    new=Path(outcomes[1]['trace_file']).read_text().splitlines()
                    self.assertEqual(new[:len(old)],old)
                    # Every quota boundary before, at and after the goal.
                    for limit in range(outcomes[0]['retired']-1,outcomes[0]['retired']+4):
                        run=root/f'prefix-{completed}-{limit}';run.mkdir();(run/'startup.ootmem').write_bytes(blob)
                        prefix=execute(exe,run,limit,1,'full')
                        delta=max(0,min(2,limit-outcomes[0]['retired']))
                        self.assertEqual(prefix['post_entry_retired'],delta)
                        self.assertEqual(prefix['application_entry_retired'],delta>0)
                        self.assertEqual(prefix['sdk_initialization_completed'],limit>=outcomes[0]['retired'])

    def test_application_emission_cannot_select_an_older_profile(self):
        with self.assertRaises(InputError):emit_startup(None,[],{},application=True)

    def test_crossed_program_context_flags_and_missing_goal_reject_before_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            root=Path(tmp);blob,sources,goal=package(2,True,simd_cohort=True)
            for mutation in ('program','context','goal'):
                changed=dict(sources)
                if mutation=='program':changed['startup.c']=changed['startup.c'].replace('OOT_STARTUP_APPLICATION | ','',1)
                elif mutation=='context':changed['startup.c']=changed['startup.c'].replace(' | OOT_SDK_APPLICATION','',1)
                else:changed['startup.c']=changed['startup.c'].replace('return &oot_sdk_goal;','(void)oot_sdk_goal;return NULL;',1)
                self.assertNotEqual(changed['startup.c'],sources['startup.c'])
                folder=root/mutation;folder.mkdir();write_sources(folder,changed);(folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,os.environ.get('OOT_LIFTER_COMPILER','cmake'),root/'cache')
                result=subprocess.run([str(exe),'--boot-images',str(folder/'startup.ootmem'),
                    '--trace',str(folder/'trace.jsonl'),'--limit','1000'],capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,'')
                self.assertFalse((folder/'trace.jsonl').exists())
