"""Synthetic initialization CLI: providers cannot retire original goal rows."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from build_startup import build_native,execute
from module_linker import Linker,Module
from prepare_startup import CONTEXT,prepare_bundle,selection,emit_startup
from test_arm64_analysis import branch,synthetic_module


class SdkInitCliTests(unittest.TestCase):
    def test_unselected_providers_typed_result_original_goal_and_trace_modes(self):
        words={0:branch(0,0x40),0x40:branch(0x40,0xc0,True),
            0x44:branch(0x44,0xd0,True),0x48:0xd2800020,
            0x4c:branch(0x4c,0xe0,True),0x50:branch(0x50,0xf0,True),
            0x54:branch(0x54,0x58),0x58:0xd4200000}
        handlers={0xc0:64,0xd0:66,0xe0:69,0xf0:208}
        for pc in handlers:words.update({pc:0xd503237f,pc+4:0xd65f03c0})
        raw=Linker([Module('main',synthetic_module(words))]);base=raw.modules[0].base
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='sdk-init-cli-') as temporary:
            folder=Path(temporary);bundle=folder/'bundle'
            report=prepare_bundle(raw,bundle)
            _,nodes=selection(raw,sdk=True,native_entries=tuple(base+x for x in handlers),sdk_init=True)
            nodes=[n for n in nodes if n['address'] not in {base+x for x in handlers}]
            cfg=dict(CONTEXT,heap_capacity=0x200000)
            sdk=dict(core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,
                alias_base=0x5000000000,alias_size=0x200000,program_id=0x1000,is_application=1,
                total_memory=report['package']['backing_bytes']+cfg['tls_size']+cfg['heap_capacity'],
                main_thread_id=1,main_thread_priority=44,main_thread_core=0)
            goal=dict(mandatory_stage_entries=[base+0x40],goal_entry=dict(
                thunk_entry=base+0x54,entry=base+0x58,thunk_word=words[0x54]))
            functions=[dict(handler_id=handler,entry=base+pc,size=8,
                body_sha256=hashlib.sha256(raw.modules[0].read(pc,8)).hexdigest()) for pc,handler in handlers.items()]
            source,summary=emit_startup(raw,nodes,report['package'],cfg,sdk_config=sdk,
                sdk_goal=goal,native_functions=functions,sdk_init=True)
            self.assertIn('OOT_STARTUP_INIT_RUNTIME',source)
            self.assertIn('OOT_SDK_INITIALIZATION',source)
            (bundle/'startup.c').write_text(source,encoding='utf-8')
            exe,_=build_native(bundle,os.environ.get('OOT_LIFTER_COMPILER','cmake'))
            original=(bundle/'startup.ootmem').read_bytes();results=[]
            for mode,quantum in [('full',1),('compact',100)]:
                run=folder/mode;run.mkdir();(run/'startup.ootmem').write_bytes(original)
                result=execute(exe,run,100,quantum,mode)
                self.assertTrue(result['sdk_initialization_completed'])
                self.assertTrue(result['sdk_init_providers'])
                self.assertEqual(result['error'],15)
                self.assertEqual(result['sdk_stages_completed'],1)
                self.assertEqual(result['native_calls'],4)
                self.assertEqual(result['native_stats']['calls'],4)
                self.assertEqual(result['init_stats']['platform_calls'],3)
                self.assertEqual(result['init_stats']['service_calls'],1)
                self.assertEqual(result['init_stats']['cpu_boost_mode'],1)
                self.assertEqual(result['init_stats']['clock_initialized'],1)
                self.assertEqual(result['pc'],hex(base+0x58))
                self.assertFalse(result['original_oe_initialize_entered'])
                rows=[json.loads(line) for line in (run/'trace.jsonl').read_text().splitlines()]
                self.assertFalse(any(row['event']==0 and row['pc'] in {hex(base+x) for x in handlers} for row in rows))
                results.append(result)
            self.assertEqual(results[0]['trace_sha256'],results[1]['trace_sha256'])
            self.assertEqual((bundle/'startup.ootmem').read_bytes(),original)


if __name__=='__main__':unittest.main()
