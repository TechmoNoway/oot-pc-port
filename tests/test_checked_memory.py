"""Policy-8/schema-9 checked stores and original-byte callee closures."""
from copy import deepcopy
from ctypes import byref,c_uint32,c_uint64,create_string_buffer,memset,memmove
import importlib.util
import json
import os
from pathlib import Path
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from call_validation import LrAssembler
from checked_memory_validation import bindings, matrix_programs, graph_programs, run_validation
from dispatcher_validation import EXIT,STACK_SIZE,Report
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import Program,State
from memory_validation import transfer
from module_linker import Module,Linker
from pair_validation import pair
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from plt_validation import PltReference
from prepare_registry import build_bundle
from profile_survey import survey_modules
from run_milestone import compare_memory
from stack_cfg_validation import add_immediate,mov
from stack_layout_verifier import WRITE,READ,verify_memory_stack_functions,verify_plt_stack_functions,verify_call_stack_functions
from test_arm64_analysis import synthetic_module,branch,RET
from test_module_linker import symbol


def bundle_fixture(explicit=False):
    r=LrAssembler('memory_bundle'+str(int(explicit)),0x10,64,19,key=int(explicit),explicit_auth=explicit)
    r.emit(mov(19,0),transfer(3,0,0,1));r.bl(0x50);r.bl(0xc0);root=r.finish()
    c=PauthAssembler('memory_helper'+str(int(explicit)),0x50,64,48,key=1-int(explicit),explicit_auth=not explicit)
    c.emit(transfer(3,1,0,1),add_immediate(0,0,5),transfer(3,0,0,1,immediate=1));child=c.finish()
    assert root.base+len(root.data)<=0x50 and child.base+len(child.data)<=0x80
    words={0:branch(0,0x10),0xc0:0xd0000010,0xc4:0xf9400211,0xc8:0x91000210,0xcc:0xd61f0220}
    for p in (root,child):words.update({p.base+i:w for i,w in zip(range(0,len(p.data),4),p.words)})
    raw=synthetic_module(words,symbols=[symbol('store_helper',section=0,value=0,size=0),
        symbol(root.name,value=root.base,size=len(root.data)),symbol(child.name,value=child.base,size=len(child.data))],plt=((0x2000,1026,1,0),))
    leaf=Program('memory_bundle_leaf'+str(int(explicit)),[add_immediate(0,0,7),RET],[],base=0x40)
    sdk=synthetic_module({0:branch(0,0x40),0x40:leaf.words[0],0x44:RET},symbols=[symbol('store_helper',value=0x40,size=8)])
    linker=Linker([Module('main',raw),Module('sdk',sdk)]);assert linker.apply()['link_complete']
    config=dict(schema_version=9,pauth_model=MODEL,root=root.name,return_sites=[EXIT],stack_size=STACK_SIZE,
        frames=[dict(name=p.name,module='main',offset=p.base,size=len(p.data)) for p in (root,child)],
        leaves=[dict(name=leaf.name,module='sdk',offset=leaf.base,size=len(leaf.data))],
        plts=[dict(name='memory_bundle_bridge'+str(int(explicit)),module='main',offset=0xc0,leaf=leaf.name)],
        read_ranges=[dict(module='main',offset=0x2100,size=32)],write_ranges=[dict(module='main',offset=0x2100,size=32)])
    programs=[Program(p.name,p.words,[],base=linker.modules[n].base+p.base) for p,n in ((root,0),(child,0),(leaf,1))]
    programs.append(Program(config['plts'][0]['name'],[words[k] for k in (0xc0,0xc4,0xc8,0xcc)],[],base=linker.modules[0].base+0xc0))
    return linker,config,programs


class CheckedMemoryPolicyTests(unittest.TestCase):
    def test_original_byte_proofs_and_prior_constructor_boundaries(self):
        frames,leaf,(stub,record)=graph_programs();codes={p.base:p.data for p in frames};leaves={leaf.base:leaf.data}
        before=deepcopy(codes)
        proofs=verify_memory_stack_functions(codes,leaves,frames[0].base,{stub.base:record})
        self.assertEqual(codes,before)
        self.assertEqual(proofs[frames[0].base]['policy'],'checked-memory-stack-dag-v8')
        self.assertEqual(sum(p['checked_write_count'] for p in proofs.values()),3)
        self.assertEqual(proofs[frames[0].base]['max_depth'],3)
        for p in proofs.values():self.assertTrue(all(bool(w)==(s['kind'] in (READ,WRITE)) for w,s in zip(p['read_words'],p['steps'])))
        with self.assertRaises(InputError):verify_plt_stack_functions(codes,leaves,frames[0].base,{stub.base:record})
        for p,_,_,_,label in matrix_programs():
            proof=verify_memory_stack_functions({p.base:p.data},{},p.base)[p.base]
            self.assertEqual(proof['checked_write_count'],1)
            if label != 'local':
                with self.assertRaises(InputError):verify_call_stack_functions({p.base:p.data},{},p.base)

    def test_writeback_reserved_local_vector_atomic_and_unsaved_loads_stay_rejected(self):
        for word in (transfer(3,0,0,1,'pre',8),transfer(3,0,0,1,'post',8),pair(2,False,0,1,2,3,2),
                     transfer(3,0,0,31),transfer(3,0,0,29),transfer(3,1,18,1),0x3d800020,0xf8200020):
            a=PauthAssembler('denied',0x1000,64,0,split=False);a.emit(word);p=a.finish()
            with self.subTest(word=hex(word)),self.assertRaises(InputError):verify_memory_stack_functions({p.base:p.data},{},p.base)

    def test_bundle_ranges_permissions_lifetimes_and_no_input_mutation(self):
        linker,config,_=bundle_fixture();before=[bytes(m.image) for m in linker.modules]
        _,source,m=build_bundle(linker,config)
        self.assertEqual((m['schema_version'],m['profile']),(9,'checked-memory-stack-dag'))
        self.assertIn('oot_stack_create_memory',source);self.assertTrue(m['write_addresses_checked_at_runtime'])
        self.assertEqual([bytes(x.image) for x in linker.modules],before)
        for change in (dict(schema_version=8),dict(write_ranges=None),dict(write_ranges=[dict(module='main',offset=0x1000,size=8)]),
                dict(write_ranges=[dict(module='main',offset=0x21ff,size=2)]),dict(write_ranges=config['write_ranges']*2),
                dict(write_ranges=[dict(module='stack',offset=0,size=8)]),dict(write_ranges=[dict(module='main',offset=True,size=8)])):
            bad=deepcopy(config);bad.update(change)
            with self.subTest(change=change),self.assertRaises(InputError):build_bundle(linker,bad)
        local=deepcopy(config);local['write_ranges']=[]
        self.assertEqual(build_bundle(linker,local)[2]['write_ranges'],[])
        local['plts']=[]
        with self.assertRaises(InputError):build_bundle(linker,local) # actual stub BL stays unresolved

    def test_survey_reports_real_upgraded_callee_cluster_and_remaining_frontier(self):
        linker,_,_=bundle_fixture();before=[bytes(x.image) for x in linker.modules]
        r=survey_modules(linker.modules,memory=True)
        self.assertEqual(r['totals']['profiles']['plt_leaf']['accepted_regions'],0)
        self.assertEqual(r['totals']['profiles']['checked_memory']['accepted_regions'],2)
        clusters=r['memory_clusters']
        self.assertEqual((clusters['newly_accepted_roots'],clusters['unique_frames_in_upgraded_closures'],clusters['unique_frame_call_edges']),(2,2,1))
        self.assertEqual(clusters['connected_component_sizes'],{'2':1})
        self.assertFalse(r['runtime_write_ranges_supplied']);self.assertFalse(r['translation_performed'])
        self.assertEqual([bytes(x.image) for x in linker.modules],before)

    def test_memory_evidence_requires_same_shared_policy_and_no_runtime_grants(self):
        linker,_,_=bundle_fixture()
        old=survey_modules(linker.modules,plt=True);new=survey_modules(linker.modules,memory=True)
        self.assertTrue(compare_memory(old,new)['shared_policy_outcomes_match'])
        for key in ('source_sha256','linked_text_sha256'):
            bad=deepcopy(new);bad['modules'][0][key]='changed'
            with self.assertRaises(InputError):compare_memory(old,bad)
        bad=deepcopy(new);bad['runtime_write_ranges_supplied']=True
        with self.assertRaises(InputError):compare_memory(old,bad)
        bad=deepcopy(new);bad['modules'][0]['profiles']['plt_leaf']['accepted_regions']+=1
        with self.assertRaises(InputError):compare_memory(old,bad)

    def test_missing_callee_keeps_original_metadata_failure_window(self):
        a=PauthAssembler('blocked_root',0x10,32);a.bl(0xc0);root=a.finish()
        words={0:branch(0,0x10),0xc0:0xffffffff}
        words.update({root.base+4*i:w for i,w in enumerate(root.words)})
        m=Module('main',synthetic_module(words,symbols=[symbol('blocked_root',value=0x10,size=len(root.data)),
            symbol('blocked_target',value=0xc0,size=8)]))
        linker=Linker([m]);self.assertTrue(linker.apply()['link_complete'])
        report=survey_modules(linker.modules,memory=True)
        frontier=report['memory_clusters']['remaining_callee_frontier']
        self.assertEqual((frontier['dependency_blocked_roots'],frontier['unique_missing_targets'],frontier['unique_caller_target_edges']),(1,1,1))
        failure=frontier['samples'][0]['discovery_failure']
        self.assertEqual((failure['entry_offset'],failure['window_bytes']),(0xc0,8))
        self.assertIn('symbol_size',failure['limiting_evidence']);self.assertIn('function_symbol',failure['metadata_sources'])


@unittest.skipUnless(os.name=='nt' and importlib.util.find_spec('unicorn'),'native Windows and pinned reference required')
class NativeCheckedMemoryTests(unittest.TestCase):
    def test_effect_windows_mixed_graph_depth_matrix_negative_contracts_and_ownership(self):
        r,path=run_validation(os.environ.get('OOT_LIFTER_COMPILER','cmake'))
        self.assertEqual((r['matrix_programs'],r['bad_callback_modes'],r['max_depth']),(62,12,16))
        self.assertEqual((r['whole_call_cases'],r['prefix_checks']),(887,11551));self.assertTrue(path.is_file())

    def test_actual_schema_nine_factories_both_keys_and_return_styles(self):
        sources,fixtures=[],[]
        for explicit in (False,True):
            linker,config,programs=bundle_fixture(explicit);blob,source,m=build_bundle(linker,config)
            sources.append(source.replace('oot_create_bound_registry','oot_create_memory1') if explicit else source)
            fixtures.append((blob,m,programs,bytes(linker.modules[0].image[0x2000:0x2200])))
        mode=os.environ.get('OOT_LIFTER_COMPILER','cmake');lib,build=compile_library([],mode,'\n'.join(sources));bindings(lib)
        keys=lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));self.assertTrue(keys)
        whole=prefixes=0;rng=random.Random(0x8FAC70)
        try:
            for index,(blob,m,programs,data) in enumerate(fixtures):
                path=Path(build['directory'])/f'memory-bundle{index}.ootmem';path.write_bytes(blob)
                message,error,report=create_string_buffer(192),c_uint32(),Report()
                image=lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
                memory=lib.oot_runtime_memory(image)
                rows=m['image']['regions'];stack=memory.contents.regions[next(i for i,r in enumerate(rows) if r['kind']=='stack')].data
                region=memory.contents.regions[next(i for i,r in enumerate(rows) if r['owner']=='main' and r['kind']=='data')]
                factory=lib.oot_create_memory1 if index else lib.oot_create_bound_registry
                factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
                d=factory(image,keys,byref(error));self.assertTrue(d,error.value);lib.oot_runtime_close(image)
                ref=PltReference(programs,{m['plts'][0]['slot']:m['leaves'][0]['entry']})
                try:
                    for flags in range(16):
                        for value in (0,1,(1<<64)-1,1<<63,rng.getrandbits(64)):
                            memset(stack,0,STACK_SIZE);memmove(region.data,data,len(data));ref.u.mem_write(region.base,data);ref.u.mem_write(next(r['base'] for r in rows if r['kind']=='stack'),bytes(STACK_SIZE))
                            s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)]
                            s.pc,s.sp,s.x[30],s.nzcv=m['root']['entry'],m['image']['initial_sp'],EXIT,flags<<28
                            s.x[0],s.x[1]=value,m['write_ranges'][0]['base'];initial=State.from_buffer_copy(s)
                            self.assertEqual(lib.oot_stack_begin(d,byref(s),EXIT,byref(report)),0)
                            while initial.pc!=EXIT:
                                self.assertEqual(lib.oot_stack_run(d,byref(s),0,byref(report)),1)
                                initial=ref.step(initial,ref.words[initial.pc])
                                status=lib.oot_stack_run(d,byref(s),1,byref(report));self.assertEqual(status,2 if initial.pc==EXIT else 1,report.error)
                                self.assertEqual(s.values(),initial.values());prefixes+=1
                                self.assertEqual(bytes(stack[:STACK_SIZE]),bytes(ref.u.mem_read(next(r['base'] for r in rows if r['kind']=='stack'),STACK_SIZE)))
                                self.assertEqual(bytes(region.data[:len(data)]),bytes(ref.u.mem_read(region.base,len(data))))
                            self.assertEqual(s.x[0],(value+12)&((1<<64)-1))
                            self.assertEqual(bytes(region.data[0x100:0x110]),value.to_bytes(8,'little')+((value+5)&((1<<64)-1)).to_bytes(8,'little'));whole+=1
                finally:lib.oot_stack_destroy(d)
        finally:lib.oot_pauth_destroy(keys)
        self.assertEqual(whole,160)
        (ROOT/f'build/lifter-validation/{mode}-checked-memory-factory-dispatch-report.json').write_text(json.dumps(dict(synthetic_only=True,game_code_executed=False,whole_call_cases=whole,prefix_checks=prefixes,native_build=build),indent=2)+'\n')


if __name__=='__main__':unittest.main()
