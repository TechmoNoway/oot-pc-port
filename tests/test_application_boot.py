"""Application entry is a separate opt-in after the unchanged original goal."""
import hashlib,os,struct,subprocess,sys,tempfile,unittest
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

def package(completed,application,atomic=False,integer_fp=False):
    raw,goal,audit=fixture(completed)
    main=raw.modules[1];sdk=raw.modules[2]
    struct.pack_into('<III',main.image,0x804,0x910004a5,0x910008c6,0xd4200000)
    if atomic:struct.pack_into('<7I',main.image,0x804,0xd10043ff,0x52800069,0xb90003e9,0xb86903e0,0xb94003e1,0x910043ff,0xd4200000)
    if integer_fp:struct.pack_into('<5I',main.image,0x804,0x52800228,0x1e230108,0x9e380101,0x1e260100,0xd4200000)
    boot,boot_nodes,report=make_boot(raw,goal,audit,32768)
    nodes=list(boot_nodes)
    for module,lo,hi in [(main,0x100,0x150),(main,0x200,0x214),(sdk,0x100,0x150),
                        (sdk,0x500,0x528),(main,0x700,0x73c),(main,0x780,0x788),(main,0x800,0x820 if atomic or integer_fp else 0x810)]:
        for off in range(lo,hi,4):
            word=module.unpack('<I',off)[0]
            if not word:continue
            row=dict(address=module.base+off,word=word,semantic_supported=word!=0xd4200000)
            if word==0xd4200000:row['selection_stop']='synthetic application boundary'
            if word==0xb86903e0 and not application:row.update(semantic_supported=False,selection_stop='application-only addition')
            if word in (0x1e230108,0x9e380101) and not application:row.update(semantic_supported=False,selection_stop='application-only conversion')
            if word&0xffe0001f==0xd4000001:row['service_immediate']=word>>5&65535
            nodes.append(row)
    raw.modules.append(boot)
    blob,manifest=pack_regions(raw.modules,{'synthetic':True},STACK_BASE,4096)
    config=dict(CONTEXT,heap_capacity=0x200000)
    model=dict(core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,alias_base=0x5000000000,
        alias_size=0x200000,program_id=1,is_application=1,total_memory=manifest['backing_bytes']+config['tls_size']+config['heap_capacity'],
        main_thread_id=1,main_thread_priority=44,main_thread_core=0)
    natives=[dict(handler_id=31,entry=sdk.base+0xe00,size=8,body_sha256=hashlib.sha256(sdk.read(0xe00,8)).hexdigest())]
    units={};source,summary=emit_startup(raw,sorted(nodes,key=lambda n:n['address']),manifest,config,
        sdk_config=model,sdk_goal=goal,native_functions=natives,sdk_init=True,units=units,entry_override=boot.base,
        host_linked=True,host_constructors=report['module_order'],application=application)
    return blob,dict(units,**{'startup.c':source}),goal

class ApplicationBootTests(unittest.TestCase):
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
            root=Path(tmp);blob,sources,goal=package(2,True)
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
