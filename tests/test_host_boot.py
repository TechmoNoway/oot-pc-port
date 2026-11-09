"""Project-owned synthetic host boot, original callbacks and deferred-init guard."""
import hashlib,os,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from host_boot import BootModule,make_boot,mov64
from prepare_runtime import pack_regions,STACK_BASE
from prepare_startup import CONTEXT,emit_startup
from sdk_init_instructions import decode_sdk_init_instruction
from startup_sources import write_sources
from build_startup import build_native,execute
from input_formats import InputError
from test_arm64_analysis import branch

def adrp(rd,pc,target):
 v=((target&~4095)-(pc&~4095))>>12;return 0x90000000|((v&3)<<29)|(((v>>2)&0x7ffff)<<5)|rd

def fixture(completed=2):
 mods=[]
 for name,base in [('rtld',0x100000000),('main',0x100200000),('sdk',0x101000000)]:
  m=BootModule([]);m.name=name;m.base=base;mods.append(m)
 rtld,main,sdk=mods
 target=rtld.base+8192;pc=rtld.base+0x78;imm=target-pc
 recipe=[0x2a1303e0,0xd503201f,0x10000001|((imm&3)<<29)|(((imm>>2)&0x7ffff)<<5),0xaa1403e2,0xaa1503e3,0xaa1603e4]
 struct.pack_into('<6I',rtld.image,0x70,*recipe)
 struct.pack_into('<I',rtld.image,0x58,branch(rtld.base+0x58,rtld.base+0x200,True))
 delta=0x300-0x204;adr=0x10000000|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5)
 struct.pack_into('<3I',rtld.image,0x200,0xd503201f,adr,0xd65f03c0)
 delta=4096-0x30c;adr=0x10000002|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5)
 struct.pack_into('<9I',rtld.image,0x300,0xd503237f,0xaa1e03e0,0xd503201f,adr,0x52800021,0xb9000041,0xaa0003fe,0xd50323ff,0xd65f03c0)

 for m in (main,sdk):
  p=m.base+0x100
  registration=(1 if m.name=='sdk' else 2) if completed==4 else completed
  words=[0xd503237f,0xd10243ff,0xa9077bfd,0xa9084ff4,0x9101c3fd,adrp(19,p+20,m.base+4096),0xb9400268,
   0x350000c8,0x52800000|(registration<<5),0xb9000260,0xb9400268,0x7100051f,0x54000080,0xb9400660,0x11000400,0xb9000660,0xa9484ff4,0xa9477bfd,0x910243ff,0xd65f0fff]
  struct.pack_into('<'+str(len(words))+'I',m.image,0x100,*words)
 start=[0xd503237f,0xa9be7bfd,0xf9000bf3,0x910003fd,0xaa0303f3,0xd63f0260,0xf9400bf3,0xa8c27bfd,0xd50323ff,branch(sdk.base+0x524,main.base+0x700)]
 struct.pack_into('<10I',sdk.image,0x500,*start)
 if completed==1:
  # Main registration invokes the deferred SDK DT_INIT itself; a host second
  # pass would increment the SDK constructor counter twice and fail the goal.
  struct.pack_into('<I',main.image,0x120,branch(main.base+0x120,main.base+0x200,True))
  helper=[0xa9bf7bfd,branch(main.base+0x204,sdk.base+0x100,True),0x52800040,0xa8c17bfd,0xd65f03c0]
  struct.pack_into('<5I',main.image,0x200,*helper)
 struct.pack_into('<II',sdk.image,0xe00,0xd503237f,0xd65f03c0)
 checks=[]
 for m in ((main,) if completed==4 else (main,sdk)):
  checks+=mov64(16,m.base+4100)+[0xb9400200,0x7100041f]
  branch_pc=main.base+0x700+len(checks)*4
  checks.append(0x54000001|(((main.base+0x780-branch_pc)//4)<<5))
 checks.append(branch(main.base+0x700+len(checks)*4,main.base+0x800))
 struct.pack_into('<'+str(len(checks))+'I',main.image,0x700,*checks)
 struct.pack_into('<II',main.image,0x780,0xd400ff81,0xd4200000)
 struct.pack_into('<II',main.image,0x800,branch(main.base+0x800,main.base+0x804),0xd4200000)
 goal=dict(stages=[dict(symbol='_ZN2nn4init5StartEmmPFvvES2_S2_',entry=sdk.base+0x500)],mandatory_stage_entries=[sdk.base+0x500],
  goal_entry=dict(thunk_entry=main.base+0x800,entry=main.base+0x804,thunk_word=branch(main.base+0x800,main.base+0x804)))
 audit=dict(modules=[dict(name=m.name,dynamic_functions=dict(init=None if m.name=='rtld' else dict(address=m.base+0x100)))for m in mods])
 return SimpleNamespace(modules=mods),goal,audit

class HostBootTests(unittest.TestCase):
 def test_original_argument_recipe_and_constructor_state_are_required(self):
  raw,goal,audit=fixture();m,n,report=make_boot(raw,goal,audit,32768)
  self.assertEqual([r['module']for r in report['module_order']],['sdk','main'])
  self.assertFalse(report['original_rtld_execution_allowed'])
  raw.modules[0].image[0x70]^=1
  with self.assertRaises(InputError):make_boot(raw,goal,audit,32768)
 def test_callbacks_complete_or_stop_before_original_goal(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
   root=Path(tmp)
   for completed in (0,1,2,3,4):
    raw,goal,audit=fixture(completed);boot,boot_nodes,boot_report=make_boot(raw,goal,audit,32768)
    sdk=raw.modules[2];nodes=list(boot_nodes)
    for m,lo,hi in [(raw.modules[1],0x100,0x150),(raw.modules[1],0x200,0x214),(sdk,0x100,0x150),(sdk,0x500,0x528),(raw.modules[1],0x700,0x73c),(raw.modules[1],0x780,0x788),(raw.modules[1],0x800,0x808)]:
     for off in range(lo,hi,4):
      w=m.unpack('<I',off)[0];pc=m.base+off
      if w&0xffe0001f==0xd4000001:nodes.append(dict(address=pc,word=w,semantic_supported=True,service_immediate=w>>5&65535))
      elif w==0xd4200000:nodes.append(dict(address=pc,word=w,semantic_supported=False,selection_stop='goal'))
      elif w:decode_sdk_init_instruction(w,pc);nodes.append(dict(address=pc,word=w,semantic_supported=True))
    raw.modules.append(boot);package,manifest=pack_regions(raw.modules,{'synthetic_host_link':True},STACK_BASE,4096)
    cfg=dict(CONTEXT,heap_capacity=0x200000)
    model=dict(core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,alias_base=0x5000000000,alias_size=0x200000,
     program_id=1,is_application=1,total_memory=manifest['backing_bytes']+cfg['tls_size']+cfg['heap_capacity'],main_thread_id=1,main_thread_priority=44,main_thread_core=0)
    funcs=[dict(handler_id=31,entry=sdk.base+0xe00,size=8,body_sha256=hashlib.sha256(sdk.read(0xe00,8)).hexdigest())]
    units={};source,_=emit_startup(raw,sorted(nodes,key=lambda n:n['address']),manifest,cfg,sdk_config=model,sdk_goal=goal,native_functions=funcs,
     sdk_init=True,units=units,entry_override=boot.base,host_linked=True,host_constructors=boot_report['module_order'])
    bundle=root/str(completed);bundle.mkdir();write_sources(bundle,dict(units,**{'startup.c':source}));(bundle/'startup.ootmem').write_bytes(package)
    exe,_=build_native(bundle,os.environ.get('OOT_LIFTER_COMPILER','cmake'),root/'cache')
    result=execute(exe,bundle,1000,1000,'full')
    self.assertTrue(result['host_linked']);self.assertGreater(result['host_scaffold_retired'],0)
    self.assertEqual(result['original_retired']+result['host_scaffold_retired'],result['retired'])
    self.assertEqual(result['sdk_initialization_completed'],completed in (1,2))
    self.assertEqual(result['error'],15 if completed in (1,2) else 16)
    if completed in (1,2):self.assertEqual(result['constructors_completed'],2)
    if completed==2:
     # Host-linked startup rejects loader execution, loader interceptions and
     # forged constructor evidence before producing any execution report.
     for mutation in ('rtld-row','rtld-native','constructor-hash'):
      altered_nodes=list(nodes);altered_functions=list(funcs)
      constructors=[dict(c) for c in boot_report['module_order']]
      if mutation=='rtld-row':
       altered_nodes.append(dict(address=raw.modules[0].base,word=0,semantic_supported=False,selection_stop='forbidden rtld'))
      elif mutation=='rtld-native':
       altered_functions=[dict(funcs[0],entry=raw.modules[0].base+0xe00,
        body_sha256=hashlib.sha256(raw.modules[0].read(0xe00,8)).hexdigest())]
      else:constructors[0]['body_sha256']='00'*32
      parts={};bad_source,_=emit_startup(raw,sorted(altered_nodes,key=lambda n:n['address']),manifest,cfg,
       sdk_config=model,sdk_goal=goal,native_functions=altered_functions,sdk_init=True,units=parts,
       entry_override=boot.base,host_linked=True,host_constructors=constructors)
      bad=root/mutation;bad.mkdir();write_sources(bad,dict(parts,**{'startup.c':bad_source}))
      (bad/'startup.ootmem').write_bytes(package)
      executable,_=build_native(bad,os.environ.get('OOT_LIFTER_COMPILER','cmake'),root/'cache')
      rejected=subprocess.run([str(executable),'--boot-images',str(bad/'startup.ootmem'),
       '--trace',str(bad/'trace.jsonl'),'--limit','1000','--quantum','1000'],capture_output=True,text=True)
      self.assertNotEqual(rejected.returncode,0,mutation)
      self.assertEqual(rejected.stdout,'',mutation)
      self.assertIn({'rtld-row':'Startup selection rejected','rtld-native':'Native SDK bindings rejected',
       'constructor-hash':'Constructor observers rejected'}[mutation],rejected.stderr)

if __name__=='__main__':unittest.main()
