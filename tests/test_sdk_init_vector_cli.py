"""Generated synthetic resolver frame: Q transfers, PAC, XPACLRI and native ABI."""
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
from input_formats import InputError
from module_linker import Linker,Module
from prepare_startup import CONTEXT,prepare_bundle,selection,emit_startup
from sdk_init_instructions import decode_sdk_init_instruction
from sdk_instructions import decode_sdk_instruction
from pauth_lifter import decode_pauth_instruction
from test_arm64_analysis import branch,synthetic_module
from pair_validation import pair


def vector_pair(load,mode,rn,immediate):
    return 0x2c000000|(2<<30)|(mode<<23)|(int(load)<<22)|((immediate&127)<<15)|(1<<10)|(rn<<5)


class SdkInitVectorCliTests(unittest.TestCase):
    def words(self,fault=False):
        # Q0/Q1 initially contain zero. A nonzero sentinel in the future Q
        # frame must be replaced by the store and remain zero after restore.
        return {0:branch(0,0x40),0x40:branch(0x40,0x68,True),0x44:branch(0x44,0xa0,True),
            0x48:0x350000c0,0x4c:branch(0x4c,0x54),0x54:branch(0x54,0x58),
            0x58:0xd4200000,0x60:0xd4200000,
            0x68:0xd503237f,0x6c:0xd65f03c0,0x78:0xd503237f,0x7c:0xd65f03c0,
            0xa0:0xd503237f,0xa4:pair(2,False,29,30,31,3,-2),0xa8:0x910003fd,
            0xac:0xd2800005|(0x1234<<5),0xb0:0xf8000000|((-8&511)<<12)|(31<<5)|5,
            0xb4:vector_pair(False,2,5,0) if fault else vector_pair(False,3,31,-2),
            0xb8:0x52800006|(100<<5),0xbc:0x710004c6,0xc0:0x54ffffe1,
            0xc4:branch(0xc4,0x78,True),0xc8:vector_pair(True,1,31,2),
            0xcc:0xf8400000|((-8&511)<<12)|(31<<5)|5,
            0xd0:0xb5000005|((((0x60-0xd0)//4)&0x7ffff)<<5),
            0xd4:pair(2,True,29,30,31,1,2),0xd8:0xd50323ff,0xdc:0xd50320ff,0xe0:0xd65f03c0}

    def build(self,folder,fault=False):
        words=self.words(fault);raw=Linker([Module('main',synthetic_module(words))]);base=raw.modules[0].base
        bundle=folder/'bundle';prepared=prepare_bundle(raw,bundle)
        handlers={0x68:64,0x78:66}
        _,nodes=selection(raw,sdk=True,native_entries=tuple(base+x for x in handlers),sdk_init=True)
        # Exact provider entries are intentionally outside the compiled table.
        nodes=[node for node in nodes if node['address'] not in {base+x for x in handlers}]
        config=dict(CONTEXT,heap_capacity=0x200000)
        sdk=dict(core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,
            alias_base=0x5000000000,alias_size=0x200000,program_id=0x1000,is_application=1,
            total_memory=prepared['package']['backing_bytes']+config['tls_size']+config['heap_capacity'],
            main_thread_id=1,main_thread_priority=44,main_thread_core=0)
        functions=[dict(handler_id=handler,entry=base+pc,size=8,
            body_sha256=hashlib.sha256(raw.modules[0].read(pc,8)).hexdigest()) for pc,handler in handlers.items()]
        goal=dict(mandatory_stage_entries=[base+0x40,base+0xa0],goal_entry=dict(
            thunk_entry=base+0x54,entry=base+0x58,thunk_word=words[0x54]))
        source,summary=emit_startup(raw,nodes,prepared['package'],config,sdk_config=sdk,
            sdk_goal=goal,native_functions=functions,sdk_init=True)
        self.assertIn('OOT_STARTUP_INIT_RUNTIME',source)
        self.assertIn(f'UINT64_C(0x{base+0xb4:x}), UINT32_C(0x{words[0xb4]:08x}), 6,',source)
        for word in (words[0xb4],words[0xc8],words[0xdc]):
            self.assertIn(decode_sdk_init_instruction(word,base).form,('sdk_init_vector','sdk_pointer'))
            for legacy in (decode_sdk_instruction,decode_pauth_instruction):
                with self.assertRaises(InputError):legacy(word,base)
        with self.assertRaises(InputError):emit_startup(raw,nodes,prepared['package'],config,
            sdk_config=sdk,sdk_goal=goal,native_functions=functions)
        (bundle/'startup.c').write_text(source,encoding='utf-8')
        exe,_=build_native(bundle,os.environ.get('OOT_LIFTER_COMPILER','cmake'))
        return exe,bundle,base

    def run_case(self,folder,bundle,exe,name,quantum=1000,limit=1000,mode='full'):
        run=folder/name;run.mkdir();(run/'startup.ootmem').write_bytes((bundle/'startup.ootmem').read_bytes())
        result=execute(exe,run,limit,quantum,mode)
        rows=[json.loads(line) for line in (run/'trace.jsonl').read_text().splitlines()]
        self.assertEqual((result['trace_steps'],result['trace_rows']),
            (result['retired']+result['native_calls'],result['retired']+result['native_calls']+1))
        return result,rows

    def test_resolver_vector_frame_typed_getter_and_exact_goal_match_full_compact(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='sdk-init-vector-cli-') as temporary:
            folder=Path(temporary);exe,bundle,base=self.build(folder);original=(bundle/'startup.ootmem').read_bytes()
            full,rows=self.run_case(folder,bundle,exe,'full',quantum=1)
            compact,stored=self.run_case(folder,bundle,exe,'compact',mode='compact')
            for result in (full,compact):
                self.assertEqual((result['error'],result['retired'],result['native_calls'],result['sdk_stages_completed']),(15,221,2,2))
                self.assertTrue(result['sdk_initialization_completed'])
                self.assertEqual(result['pc'],hex(base+0x58))
                self.assertEqual((result['native_stats']['calls'],result['init_stats']['platform_calls']),(2,2))
            self.assertLess(len(stored),len(rows))
            self.assertEqual(full['trace_sha256'],compact['trace_sha256'])
            for pc in (0xb4,0xc8,0xdc):
                retired=[row for row in rows if row['pc']==hex(base+pc) and row['event']==0]
                self.assertEqual(len(retired),1)
            self.assertEqual([row['service'] for row in rows if row['event']==3],[64,66])
            self.assertEqual((bundle/'startup.ootmem').read_bytes(),original)
            for limit,retired,pc in ((9,8,0xb4),(10,9,0xb8),(212,211,0x78),(213,211,0xc8)):
                result,prefix=self.run_case(folder,bundle,exe,'quota-'+str(limit),quantum=1,limit=limit)
                self.assertEqual((result['error'],result['retired'],result['pc']),(12,retired,hex(base+pc)))
                self.assertFalse(result['sdk_initialization_completed'])
                self.assertEqual(prefix[:-1],rows[:len(prefix)-1])

    def test_faulting_q_pair_retires_nothing_and_never_calls_the_getter(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='sdk-init-vector-fault-') as temporary:
            folder=Path(temporary);exe,bundle,base=self.build(folder,True)
            full,rows=self.run_case(folder,bundle,exe,'full',quantum=1)
            compact,stored=self.run_case(folder,bundle,exe,'compact',mode='compact')
            for result in (full,compact):
                self.assertEqual((result['error'],result['retired'],result['pc'],result['native_calls']),(11,8,hex(base+0xb4),1))
                self.assertFalse(result['sdk_initialization_completed'])
                self.assertEqual(result['init_stats']['platform_calls'],1)
            self.assertEqual(rows[-1]['retired'],rows[-2]['retired'])
            self.assertFalse(any(row['event']==0 and row['pc']==hex(base+0xb4) for row in rows))
            self.assertEqual(full['trace_sha256'],compact['trace_sha256'])


if __name__=='__main__':unittest.main()
