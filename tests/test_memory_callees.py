"""Separate memory-leaf proofs, schema-10 direct/PLT factories and static callee closures."""
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
from dispatcher_validation import EXIT,STACK_SIZE,Report
from input_formats import InputError
from leaf_verifier import verify_leaf
from lifter_validation import compile_library
from lifter_validation_types import Program,State
from memory_callee_validation import bindings,run_validation,graph_programs,matrix_programs
from memory_leaf_verifier import verify_memory_leaf
from memory_validation import transfer
from module_linker import Module,Linker
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from plt_validation import PltReference
from plt_verifier import verify_plt_stub,verify_memory_plt_stub
from prepare_registry import build_bundle
from profile_survey import survey_modules
from run_milestone import compare_memory_callees
from stack_cfg_validation import add_immediate
from stack_layout_verifier import verify_memory_callee_stack_functions,verify_memory_stack_functions
from test_arm64_analysis import synthetic_module,branch,RET
from test_module_linker import symbol


def bundle_fixture(explicit=False):
    r=LrAssembler('callee_bundle'+str(int(explicit)),0x10,64,19,key=int(explicit),explicit_auth=explicit)
    r.bl(0xa0);r.bl(0x50);r.emit(add_immediate(0,0,7));root=r.finish()
    c=PauthAssembler('callee_helper'+str(int(explicit)),0x50,64,48,key=1-int(explicit),explicit_auth=not explicit)
    c.bl(0xc0);c.emit(add_immediate(0,0,3));child=c.finish()
    writer=Program('bundle_writer'+str(int(explicit)),[transfer(3,0,0,1),RET],[],base=0xa0)
    reader=Program('bundle_reader'+str(int(explicit)),[transfer(3,1,0,1),add_immediate(0,0,5),transfer(3,0,0,1,immediate=1),RET],[],base=0x40)
    assert root.base+len(root.data)<=0x50 and child.base+len(child.data)<=0x80
    words={0:branch(0,0x10),0xc0:0xd0000010,0xc4:0xf9400211,0xc8:0x91000210,0xcc:0xd61f0220}
    for p in (root,child,writer):words.update({p.base+4*i:w for i,w in enumerate(p.words)})
    raw=synthetic_module(words,symbols=[symbol('memory_helper',section=0,value=0,size=0)]+[symbol(p.name,value=p.base,size=len(p.data)) for p in (root,child,writer)],plt=((0x2000,1026,1,0),))
    sdk=synthetic_module({0:branch(0,reader.base),**{reader.base+4*i:w for i,w in enumerate(reader.words)}},symbols=[symbol('memory_helper',value=reader.base,size=len(reader.data))])
    linker=Linker([Module('main',raw),Module('sdk',sdk)]);assert linker.apply()['link_complete']
    config=dict(schema_version=10,pauth_model=MODEL,root=root.name,return_sites=[EXIT],stack_size=STACK_SIZE,
        frames=[dict(name=p.name,module='main',offset=p.base,size=len(p.data)) for p in (root,child)],leaves=[],
        memory_leaves=[dict(name=p.name,module=m,offset=p.base,size=len(p.data)) for p,m in ((writer,'main'),(reader,'sdk'))],
        plts=[dict(name='bundle_bridge'+str(int(explicit)),module='main',offset=0xc0,leaf=reader.name)],
        read_ranges=[dict(module='main',offset=0x2100,size=32)],write_ranges=[dict(module='main',offset=0x2100,size=32)])
    programs=[Program(p.name,p.words,[],base=linker.modules[n].base+p.base) for p,n in ((root,0),(child,0),(writer,0),(reader,1))]
    programs.append(Program(config['plts'][0]['name'],[words[k] for k in (0xc0,0xc4,0xc8,0xcc)],[],base=linker.modules[0].base+0xc0))
    return linker,config,programs


class MemoryCalleePolicyTests(unittest.TestCase):
    def test_all_supported_load_store_fixtures_have_original_byte_closed_proofs(self):
        rows=matrix_programs();self.assertEqual(len(rows),109)
        for p,*_ in rows:
            before=p.data;proof=verify_memory_leaf(p.data,p.base)
            self.assertTrue(proof['acyclic']);self.assertTrue(proof['all_declared_words_reachable'])
            self.assertEqual(proof['checked_read_count']+proof['checked_write_count'],1);self.assertEqual(p.data,before)
            with self.assertRaises(InputError):verify_leaf(p.data,p.base)

    def test_stack_protected_writeback_call_cycle_and_nonmemory_rejections(self):
        for words in ([RET],[transfer(3,1,18,1),RET],[transfer(3,1,29,1),RET],[transfer(3,0,0,31),RET],
                [transfer(3,0,0,29),RET],[transfer(3,0,0,1,'pre',8),RET],[transfer(3,1,0,1),0x94000000,RET],
                [transfer(3,1,0,1),0x17ffffff,RET],[transfer(3,1,0,1),RET,RET],[0xf8200020,RET],[0x3d800020,RET]):
            p=Program('denied',words,[],base=0x1000)
            with self.subTest(words=words),self.assertRaises(InputError):verify_memory_leaf(p.data,p.base)

    def test_explicit_callee_and_plt_contracts_preserve_old_leaf_domain(self):
        fs,mems,ordinary,(stub,record)=graph_programs();f={p.base:p.data for p in fs};m={p.base:p.data for p in mems};o={p.base:p.data for p in ordinary}
        p=verify_memory_callee_stack_functions(f,o,fs[0].base,{stub.base:record},m)
        self.assertEqual(p[fs[0].base]['policy'],'memory-callee-stack-dag-v9');self.assertEqual(p[fs[0].base]['max_depth'],2)
        with self.assertRaises(InputError):verify_memory_stack_functions(f,o|m,fs[0].base,{stub.base:record})
        with self.assertRaises(InputError):verify_plt_stub(stub.data,stub.base,record['slot'],record['target'],m,record['symbol'])
        bridge=verify_memory_plt_stub(stub.data,stub.base,record['slot'],record['target'],m,record['symbol'],m)
        self.assertEqual(bridge['max_retired_instructions'],4+verify_memory_leaf(m[record['target']],record['target'])['max_retired_instructions'])
        with self.assertRaises(InputError):verify_memory_plt_stub(stub.data,stub.base,record['slot'],record['target'],{},record['symbol'],m)

    def test_schema_ten_selection_hashes_permissions_and_input_preservation(self):
        linker,config,_=bundle_fixture();before=[bytes(m.image) for m in linker.modules]
        _,source,m=build_bundle(linker,config)
        self.assertEqual((m['schema_version'],m['profile']),(10,'memory-callee-stack-dag'))
        self.assertEqual(len(m['memory_leaves']),2);self.assertIn('oot_stack_create_memory_callees',source)
        self.assertFalse(m['keys_embedded']);self.assertEqual([bytes(x.image) for x in linker.modules],before)
        for change in (dict(schema_version=9),dict(memory_leaves=[]),dict(memory_leaves=None),dict(plts=[]),
                dict(write_ranges=[dict(module='main',offset=0x1000,size=8)]),dict(write_ranges=[dict(module='main',offset=0x2000,size=0x120)]),dict(memory_leaves=config['memory_leaves']*2)):
            c=deepcopy(config);c.update(change)
            with self.subTest(change=change),self.assertRaises(InputError):build_bundle(linker,c)

    def test_survey_proves_real_upgraded_multiframe_and_memory_leaf_edges(self):
        linker,_,_=bundle_fixture();before=[bytes(x.image) for x in linker.modules]
        r=survey_modules(linker.modules,memory_callees=True);c=r['memory_callee_cohort']
        self.assertEqual((r['totals']['profiles']['checked_memory']['accepted_regions'],r['totals']['profiles']['memory_callees']['accepted_regions']),(0,2))
        self.assertEqual((c['candidate_memory_leaves'],c['newly_accepted_roots'],c['unique_used_memory_leaves']),(2,2,2))
        self.assertEqual((c['unique_frames_in_upgraded_closures'],c['unique_call_edges'],c['eligible_memory_target_bridges']),(2,4,1))
        self.assertFalse(c['runtime_capabilities_granted']);self.assertFalse(r['translation_performed']);self.assertEqual([bytes(x.image) for x in linker.modules],before)

    def test_evidence_rejects_changed_source_shared_policy_and_runtime_grants(self):
        linker,_,_=bundle_fixture();old=survey_modules(linker.modules,memory=True);new=survey_modules(linker.modules,memory_callees=True)
        self.assertTrue(compare_memory_callees(old,new)['shared_policy_outcomes_match'])
        bad=deepcopy(new);bad['runtime_write_ranges_supplied']=True
        with self.assertRaises(InputError):compare_memory_callees(old,bad)
        bad=deepcopy(new);bad['modules'][0]['source_sha256']='changed'
        with self.assertRaises(InputError):compare_memory_callees(old,bad)
        bad=deepcopy(new);bad['modules'][0]['profiles']['checked_memory']['accepted_regions']+=1
        with self.assertRaises(InputError):compare_memory_callees(old,bad)


@unittest.skipUnless(os.name=='nt' and importlib.util.find_spec('unicorn'),'native Windows and pinned reference required')
class NativeMemoryCalleeTests(unittest.TestCase):
    def test_native_effect_windows_direct_plt_depth_denials_and_retained_ownership(self):
        r,path=run_validation(os.environ.get('OOT_LIFTER_COMPILER','cmake'))
        self.assertEqual((r['whole_call_cases'],r['prefix_checks']),(589,6828));self.assertTrue(path.is_file())

    def test_actual_schema_ten_factories_both_keys_and_return_styles(self):
        sources,fixtures=[],[]
        for explicit in (False,True):
            linker,c,programs=bundle_fixture(explicit);blob,source,m=build_bundle(linker,c)
            sources.append(source.replace('oot_create_bound_registry','oot_create_callee1') if explicit else source)
            fixtures.append((blob,m,programs,bytes(linker.modules[0].image[0x2000:0x2200])))
        mode=os.environ.get('OOT_LIFTER_COMPILER','cmake');lib,build=compile_library([],mode,'\n'.join(sources));bindings(lib)
        keys=lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));self.assertTrue(keys)
        rng=random.Random(0x10FAC70);whole=prefixes=0
        try:
            for index,(blob,m,programs,data) in enumerate(fixtures):
                path=Path(build['directory'])/f'callee-bundle{index}.ootmem';path.write_bytes(blob)
                message,error,report=create_string_buffer(192),c_uint32(),Report()
                image=lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
                memory=lib.oot_runtime_memory(image);rows=m['image']['regions'];stack_row=next(i for i,r in enumerate(rows) if r['kind']=='stack')
                stack=memory.contents.regions[stack_row].data;region=memory.contents.regions[next(i for i,r in enumerate(rows) if r['owner']=='main' and r['kind']=='data')]
                f=lib.oot_create_callee1 if index else lib.oot_create_bound_registry;f.argtypes,f.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
                d=f(image,keys,byref(error));self.assertTrue(d,error.value);lib.oot_runtime_close(image)
                ref=PltReference(programs,{m['plts'][0]['slot']:m['memory_leaves'][1]['entry']})
                try:
                    for flags in range(16):
                        for value in (0,1,(1<<64)-1,1<<63,rng.getrandbits(64)):
                            memset(stack,0,STACK_SIZE);memmove(region.data,data,len(data));ref.u.mem_write(region.base,data);ref.u.mem_write(rows[stack_row]['base'],bytes(STACK_SIZE))
                            s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)]
                            s.pc,s.sp,s.x[30],s.nzcv=m['root']['entry'],m['image']['initial_sp'],EXIT,flags<<28;s.x[0],s.x[1]=value,m['write_ranges'][0]['base'];expected=State.from_buffer_copy(s)
                            self.assertEqual(lib.oot_stack_begin(d,byref(s),EXIT,byref(report)),0)
                            while expected.pc!=EXIT:
                                self.assertEqual(lib.oot_stack_run(d,byref(s),0,byref(report)),1)
                                expected=ref.step(expected,ref.words[expected.pc]);status=lib.oot_stack_run(d,byref(s),1,byref(report))
                                self.assertEqual(status,2 if expected.pc==EXIT else 1,report.error);self.assertEqual(s.values(),expected.values());prefixes+=1
                                self.assertEqual(bytes(stack[:STACK_SIZE]),bytes(ref.u.mem_read(rows[stack_row]['base'],STACK_SIZE)))
                                self.assertEqual(bytes(region.data[:len(data)]),bytes(ref.u.mem_read(region.base,len(data))))
                            self.assertEqual(s.x[0],(value+15)&((1<<64)-1));whole+=1
                finally:lib.oot_stack_destroy(d)
        finally:lib.oot_pauth_destroy(keys)
        self.assertEqual(whole,160)
        (ROOT/f'build/lifter-validation/{mode}-memory-callee-factory-dispatch-report.json').write_text(json.dumps(dict(synthetic_only=True,game_code_executed=False,whole_call_cases=whole,prefix_checks=prefixes,native_build=build),indent=2)+'\n')


if __name__=='__main__':unittest.main()
