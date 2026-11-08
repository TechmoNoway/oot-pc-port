"""Synthetic hybrid CLI: native calls are separate from retired original words."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from build_startup import build_native,execute
from module_linker import Linker,Module
from prepare_startup import CONTEXT,prepare_bundle,selection,emit_startup
from test_arm64_analysis import branch,synthetic_module


class NativeSdkCliTests(unittest.TestCase):
    def test_native_entry_body_binding_trace_counts_quota_and_goal(self):
        words={0:branch(0,0x40),0x40:0x910004a5,0x44:branch(0x44,0xc0,True),
               0x48:0xd2800161,0x4c:0xd2800002,0x50:0xd2800003,0x54:0xd4000521,
               0x58:0x36000081,0x5c:branch(0x5c,0xd0,True),0x60:0xd4200000,
               0x68:0x910004c6,0x6c:branch(0x6c,0x70),0x70:0xd4200000,
               0xc0:0xd503237f,0xc4:0xd65f03c0,0xd0:0xd503237f,0xd4:0xd65f03c0}
        raw=Linker([Module('main',synthetic_module(words))]);base=raw.modules[0].base
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='native-sdk-cli-') as temporary:
            folder=Path(temporary);bundle=folder/'bundle'
            report=prepare_bundle(raw,bundle)
            _,nodes=selection(raw,sdk=True,native_entries=(base+0xc0,base+0xd0))
            config=dict(CONTEXT,heap_capacity=0x200000)
            sdk=dict(core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,
                alias_base=0x5000000000,alias_size=0x200000,program_id=0x1000,is_application=1,
                total_memory=report['package']['backing_bytes']+config['tls_size']+config['heap_capacity'],
                main_thread_id=1,main_thread_priority=44,main_thread_core=0)
            goal=dict(mandatory_stage_entries=[base+0x40],goal_entry=dict(
                thunk_entry=base+0x6c,entry=base+0x70,thunk_word=words[0x6c]))
            functions=[dict(handler_id=1,entry=base+0xc0,size=8,
                body_sha256=hashlib.sha256(raw.modules[0].read(0xc0,8)).hexdigest()),
                dict(handler_id=31,entry=base+0xd0,size=8,
                body_sha256=hashlib.sha256(raw.modules[0].read(0xd0,8)).hexdigest())]
            source,_=emit_startup(raw,nodes,report['package'],config,sdk_config=sdk,
                sdk_goal=goal,native_functions=functions,original_oe_entry=base+0x40)
            (bundle/'startup.c').write_text(source,encoding='utf-8')
            exe,_=build_native(bundle,os.environ.get('OOT_LIFTER_COMPILER','cmake'))
            original=(bundle/'startup.ootmem').read_bytes();results={}
            for mode,quantum,limit in (('full',1,11),('compact',100,11),('quota',1,10),('guard',100,100)):
                run=folder/mode;run.mkdir()
                # execute() consumes a fresh bundle path; retain the same sealed package.
                (run/'startup.ootmem').write_bytes(original)
                entropy=run/'entropy.bin';entropy.write_bytes(struct.pack('<4Q',1 if mode=='guard' else 0,0,0,0))
                result=execute(exe,run,limit,quantum,mode if mode in ('full','compact') else 'full',entropy)
                results[mode]=result
                self.assertEqual(result['native_calls'],1)
                self.assertTrue(result['native_sdk'])
                self.assertTrue(result['original_oe_initialize_entered'])
                self.assertEqual((result['native_stats']['calls'],result['native_stats']['logging_initializations']),(1,1))
                rows=[json.loads(line) for line in (run/'trace.jsonl').read_text().splitlines()]
                native=[row for row in rows if row['event']==3]
                self.assertEqual(len(native),1)
                self.assertEqual(native[0],dict(pc=hex(base+0xc0),next_pc=hex(base+0x48),retired=3,
                    word=words[0xc0],event=3,error=0,service=1))
                self.assertEqual((result['retired'],result['trace_steps'],result['trace_rows']),
                    (9,10,11) if mode in ('quota','guard') else (10,11,12))
                self.assertEqual(result['error'],9 if mode=='guard' else 12 if mode=='quota' else 15)
                self.assertEqual(result['sdk_initialization_completed'],mode in ('full','compact'))
                self.assertEqual(result['exit_code'],0 if mode in ('full','compact') else 3)
                self.assertEqual(result['native_handler_stop'],mode=='guard')
                if mode=='guard':
                    self.assertEqual(result['service'],31)
                    self.assertNotIn('named_port',result)
            self.assertEqual(results['full']['trace_sha256'],results['compact']['trace_sha256'])
            self.assertEqual((bundle/'startup.ootmem').read_bytes(),original)


if __name__=='__main__':unittest.main()
