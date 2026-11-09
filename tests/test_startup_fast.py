"""Whole-leaf acceleration must preserve every original trace row and quota prefix."""
import hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from module_linker import Linker,Module
from prepare_startup import CONTEXT,prepare_bundle,selection,emit_startup
from startup_sources import write_sources
from build_startup import build_native,execute
from test_arm64_analysis import branch,synthetic_module,symbol

class StartupFastTests(unittest.TestCase):
 def test_accelerated_leaf_matches_full_trace_and_all_budget_prefixes(self):
  words={0:branch(0,0x40),0x40:branch(0x40,0xc0,True),0x44:branch(0x44,0xd0,True),0x48:branch(0x48,0x4c),0x4c:0xd4200000,
   0xc0:0xd503237f,0xc4:0xd65f03c0,0xd0:0x91000421,0xd4:0x91000842,0xd8:0xd65f03c0}
  raw=Linker([Module('main',synthetic_module(words,symbols=[symbol('leaf',value=0xd0,size=12)]))]);base=raw.modules[0].base
  with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
   folder=Path(tmp);bundle=folder/'bundle';report=prepare_bundle(raw,bundle)
   _,nodes=selection(raw,sdk=True,native_entries=(base+0xc0,),sdk_init=True)
   cfg=dict(CONTEXT,heap_capacity=0x200000)
   sdk=dict(core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,alias_base=0x5000000000,alias_size=0x200000,
    program_id=1,is_application=1,total_memory=report['package']['backing_bytes']+cfg['tls_size']+cfg['heap_capacity'],main_thread_id=1,main_thread_priority=44,main_thread_core=0)
   goal=dict(mandatory_stage_entries=[base+0x40],goal_entry=dict(thunk_entry=base+0x48,entry=base+0x4c,thunk_word=words[0x48]))
   native=[dict(handler_id=1,entry=base+0xc0,size=8,body_sha256=hashlib.sha256(raw.modules[0].read(0xc0,8)).hexdigest())]
   units={};source,_=emit_startup(raw,nodes,report['package'],cfg,sdk_config=sdk,sdk_goal=goal,native_functions=native,sdk_init=True,units=units)
   self.assertIn('oot_fast_leaf_',source);write_sources(bundle,dict(units,**{'startup.c':source}))
   exe,_=build_native(bundle,os.environ.get('OOT_LIFTER_COMPILER','cmake'))
   for limit in range(1,12):
    outcomes=[]
    for fast in (False,True):
     run=folder/f'run-{limit}-{fast}';run.mkdir();(run/'startup.ootmem').write_bytes((bundle/'startup.ootmem').read_bytes())
     outcomes.append(execute(exe,run,limit,100,'full',fast_functions=fast))
    self.assertEqual(outcomes[0]['trace_sha256'],outcomes[1]['trace_sha256'])
    self.assertEqual(outcomes[0]['retired'],outcomes[1]['retired'])
   self.assertTrue(outcomes[1]['sdk_initialization_completed']);self.assertEqual(outcomes[1]['fast_function_calls'],1)
   # A faulty trusted callback still cannot publish protected-register changes.
   bad=folder/'bad';bad.mkdir();(bad/'startup.ootmem').write_bytes((bundle/'startup.ootmem').read_bytes())
   name=f'oot_fast_leaf_{base+0xd0:x}'
   broken=dict(units)
   unit=next(k for k,v in broken.items() if 'int '+name+'(' in v)
   broken[unit]=broken[unit].replace('int '+name+'(','int '+name+'_original(',1)+f'''
int {name}(OotArm64State *s,OotGuestMemory *m,const OotPauth *p,uint64_t b,uint64_t *n) {{
 int result={name}_original(s,m,p,b,n);s->x[18]^=1;return result;
}}
'''
   write_sources(bad,dict(broken,**{'startup.c':source}))
   exe,_=build_native(bad,os.environ.get('OOT_LIFTER_COMPILER','cmake'))
   fault=execute(exe,bad,100,100,'full',fast_functions=True)
   self.assertEqual((fault['status'],fault['error'],fault['pc'],fault['fast_function_calls']),(4,13,hex(base+0xd0),0))

if __name__=='__main__':unittest.main()
