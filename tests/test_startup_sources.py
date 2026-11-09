"""Stable split sources preserve execution and reject altered build inputs."""
import json,os,sys,tempfile,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from input_formats import InputError
from module_linker import Linker,Module
from prepare_startup import prepare_bundle,selection,emit_startup
from startup_sources import cached_sources,write_sources
from build_startup import build_native,execute
from test_arm64_analysis import synthetic_module,branch

class StartupSourcesTests(unittest.TestCase):
 def test_seals_mtime_and_path_rejection(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
   root=Path(tmp);bundle=root/'bundle';bundle.mkdir();cache=root/'cache'
   write_sources(bundle,{'startup.c':'int a;','lift_100.c':'int b;'})
   first,_=cached_sources(bundle,cache);times=[p.stat().st_mtime_ns for p in first]
   again,_=cached_sources(bundle,cache);self.assertEqual(times,[p.stat().st_mtime_ns for p in again])
   (bundle/'lift_100.c').write_text('tampered')
   with self.assertRaises(InputError):cached_sources(bundle,cache)
   m=json.loads((bundle/'sources.json').read_text());m['files'][0]['path']='../escape.c'
   (bundle/'sources.json').write_text(json.dumps(m))
   with self.assertRaises(InputError):cached_sources(bundle,cache)
 def test_split_flat_full_prefix_and_incremental_units(self):
  words={0:branch(0,0x40),0x40:0xd2803e80,0x44:0x91000421,0x48:0xf1000400,0x4c:0x54ffffc1,0x50:0xd4000fe1}
  with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
   root=Path(tmp);raw=Linker([Module('main',synthetic_module(words))]);flat=root/'flat'
   manifest=prepare_bundle(raw,flat);_,nodes=selection(raw);units={}
   source,_=emit_startup(raw,nodes,manifest['package'],units=units)
   split=root/'split';split.mkdir();write_sources(split,dict(units,**{'startup.c':source}))
   (split/'startup.ootmem').write_bytes((flat/'startup.ootmem').read_bytes())
   results=[]
   for bundle in (flat,split):
    exe,_=build_native(bundle,os.environ.get('OOT_LIFTER_COMPILER','cmake'))
    results.append(execute(exe,bundle,10000,1000,'full'))
   build_native(split,os.environ.get('OOT_LIFTER_COMPILER','cmake'))
   cached=json.loads((split/'build.json').read_text())
   self.assertEqual(cached['changed_units'],0)
   self.assertEqual(cached['compiled_objects'],0)
   self.assertGreater(cached['reused_objects'],0)
   self.assertEqual(results[0]['retired'],1502)
   self.assertEqual(results[0]['trace_sha256'],results[1]['trace_sha256'])
   before=dict(units)
   other=Module('other',synthetic_module({0:branch(0,0x40),0x40:0xd65f03c0},symbols=[]))
   expanded=Linker([raw.modules[0],other]);report2=prepare_bundle(expanded,root/'extra')
   _,more=selection(expanded,extra_entries=(other.base+0x40,));new_units={}
   emit_startup(expanded,more,report2['package'],units=new_units)
   for name,data in before.items():self.assertEqual(new_units[name],data)
   self.assertGreater(len(new_units),len(before))


if __name__=='__main__':unittest.main()
