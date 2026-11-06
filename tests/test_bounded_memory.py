"""Bounded loop/writeback policy and actual schema-11 native factory evidence."""
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
from bounded_memory_validation import bindings,make_loop,writeback_matrix,loop_matrix,graph_programs,run_validation,CAP
from bounded_memory_verifier import verify_bounded_memory_leaf
from call_validation import LrAssembler
from dispatcher_validation import EXIT,STACK_SIZE,Report
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import Program,State
from memory_leaf_verifier import verify_memory_leaf
from memory_validation import transfer
from module_linker import Module,Linker
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from plt_validation import PltReference
from prepare_registry import build_bundle
from profile_survey import survey_modules
from run_milestone import compare_bounded_memory
from stack_cfg_validation import mov,add_immediate
from stack_layout_verifier import verify_bounded_callee_stack_functions,verify_memory_callee_stack_functions
from test_arm64_analysis import synthetic_module,branch,RET
from test_module_linker import symbol,change_memory


def bundle_fixture(explicit=False):
    root=LrAssembler('bounded_bundle'+str(int(explicit)),0x10,64,19,key=int(explicit),explicit_auth=explicit)
    root.emit(mov(19,3));root.bl(0xa0);root.emit(mov(3,19));root.bl(0x50);root.emit(add_immediate(0,0,7));r=root.finish()
    child=PauthAssembler('bounded_helper'+str(int(explicit)),0x50,64,48,key=1-int(explicit),explicit_auth=not explicit)
    child.bl(0xc0);c=child.finish()
    fill=make_loop('bundle_bounded_fill'+str(int(explicit)),0xa0,64,'cbnz',True)
    copy=make_loop('bundle_bounded_copy'+str(int(explicit)),0x40,32,'bne',True,True)
    assert r.base+len(r.data)<=0x50 and c.base+len(c.data)<=0x80 and fill.base+len(fill.data)<=0xc0
    words={0:branch(0,0x10),0xc0:0xd0000010,0xc4:0xf9400211,0xc8:0x91000210,0xcc:0xd61f0220}
    for p in (r,c,fill):words.update({p.base+4*i:w for i,w in enumerate(p.words)})
    raw=synthetic_module(words,symbols=[symbol('bounded_helper',section=0,value=0,size=0)]+[symbol(p.name,value=p.base,size=len(p.data)) for p in (r,c,fill)],plt=((0x2000,1026,1,0),))
    raw=change_memory(raw,0x2140,bytes(range(64)))
    sdk=synthetic_module({0:branch(0,copy.base),**{copy.base+4*i:w for i,w in enumerate(copy.words)}},symbols=[symbol('bounded_helper',value=copy.base,size=len(copy.data))])
    linker=Linker([Module('main',raw),Module('sdk',sdk)]);assert linker.apply()['link_complete']
    config=dict(schema_version=11,pauth_model=MODEL,root=r.name,return_sites=[EXIT],stack_size=STACK_SIZE,
        frames=[dict(name=p.name,module='main',offset=p.base,size=len(p.data)) for p in (r,c)],leaves=[],memory_leaves=[],
        bounded_leaves=[dict(name=p.name,module=m,offset=p.base,size=len(p.data)) for p,m in ((fill,'main'),(copy,'sdk'))],
        plts=[dict(name='bounded_bundle_bridge'+str(int(explicit)),module='main',offset=0xc0,leaf=copy.name)],
        read_ranges=[dict(module='main',offset=0x2140,size=64)],write_ranges=[dict(module='main',offset=0x2100,size=64)])
    programs=[Program(p.name,p.words,[],base=linker.modules[n].base+p.base) for p,n in ((r,0),(c,0),(fill,0),(copy,1))]
    programs.append(Program(config['plts'][0]['name'],[words[k] for k in (0xc0,0xc4,0xc8,0xcc)],[],base=linker.modules[0].base+0xc0))
    return linker,config,programs


class BoundedMemoryPolicyTests(unittest.TestCase):
    def test_original_byte_survey_and_evidence_preserve_old_policy_and_frontier(self):
        linker,_,_=bundle_fixture();before=[bytes(m.image) for m in linker.modules]
        baseline=survey_modules(linker.modules,memory_callees=True)
        report=survey_modules(linker.modules,bounded_memory=True)
        comparison=compare_bounded_memory(baseline,report)
        self.assertTrue(comparison['shared_policy_outcomes_match'])
        self.assertEqual(report['totals']['profiles']['bounded_callees']['accepted_regions'],2)
        self.assertEqual(report['bounded_memory_cohort']['unique_used_loop_leaves'],2)
        self.assertEqual(report['bounded_memory_cohort']['roots_using_loop_helpers'],2)
        self.assertEqual([bytes(m.image) for m in linker.modules],before)
        for mutate in ('runtime','hash','previously_accepted_lost','previous_memory_candidates_lost','frontier'):
            bad=deepcopy(report)
            if mutate=='runtime':bad['runtime_write_ranges_supplied']=True
            elif mutate=='hash':bad['modules'][0]['source_sha256']='changed'
            elif mutate=='frontier':bad['bounded_memory_cohort']['prior_missing_frontier']['unique_missing_targets']+=1
            else:bad['bounded_memory_cohort'][mutate]=1
            with self.subTest(mutate=mutate),self.assertRaises(InputError):compare_bounded_memory(baseline,bad)

    def test_writeback_matrix_preserves_old_policy_and_exact_bytes(self):
        rows=writeback_matrix();self.assertEqual(len(rows),72)
        for p,*_ in rows:
            before=p.data;proof=verify_bounded_memory_leaf(p.data,p.base)
            self.assertEqual(proof['writeback_count'],1);self.assertEqual(proof['loop_count'],0);self.assertEqual(p.data,before)
            with self.assertRaises(InputError):verify_memory_leaf(p.data,p.base)

    def test_counter_loop_original_words_cut_ranks_and_static_worst_bound(self):
        for p in loop_matrix():
            proof=verify_bounded_memory_leaf(p.data,p.base);info=p.test_loop;loop=proof['loop']
            self.assertEqual((loop['header'],loop['decrement'],loop['latch'],loop['width'],loop['max_iterations']),
                (info['header'],info['decrement'],info['latch'],info['width'],CAP))
            self.assertEqual(proof['words'],p.words)
            self.assertEqual(proof['max_retired_instructions'],len(p.words)+(CAP-1)*(info['latch']-info['header']+1))
            self.assertLessEqual(max(f['max_steps'] for f in proof['control_flow']),len(p.words))
            self.assertEqual(proof['loop_count'],1)
            with self.assertRaises(InputError):verify_memory_leaf(p.data,p.base)

    def test_second_counter_writer_internal_branch_flag_clobber_and_protected_wb_rejected(self):
        p=make_loop('counter_bad',0x1000,64,'cbnz',True)
        words=p.words.copy();words[p.test_loop['header']]=add_immediate(3,3,1)
        with self.assertRaises(InputError):verify_bounded_memory_leaf(Program('bad',words,[],base=p.base).data,p.base)
        words=p.words.copy();words[p.test_loop['header']]=0x14000002
        with self.assertRaises(InputError):verify_bounded_memory_leaf(Program('bad',words,[],base=p.base).data,p.base)
        p=make_loop('flags_bad',0x1000,64,'bne',True,after_dec=True);words=p.words.copy()
        words[p.test_loop['decrement']+1]=0xb10004c6 # adds x6,x6,#1 after counter SUBS
        with self.assertRaises(InputError):verify_bounded_memory_leaf(Program('bad',words,[],base=p.base).data,p.base)
        for word in (transfer(3,0,0,18,'post',8),transfer(3,0,0,31,'post',8),transfer(3,1,1,1,'post',8)):
            with self.subTest(word=word),self.assertRaises(InputError):verify_bounded_memory_leaf(Program('bad',[word,RET],[],base=0x1000).data,0x1000)

    def test_direct_plt_closure_and_old_stack_policy_boundary(self):
        fs,loops,ordinary,(stub,record)=graph_programs();f={p.base:p.data for p in fs};b={p.base:p.data for p in loops};o={p.base:p.data for p in ordinary}
        proof=verify_bounded_callee_stack_functions(f,o,fs[0].base,{stub.base:record},{},b)
        self.assertEqual(proof[fs[0].base]['max_depth'],2)
        self.assertGreater(proof[fs[0].base]['max_retired_instructions'],CAP)
        with self.assertRaises(InputError):verify_memory_callee_stack_functions(f,o,fs[0].base,{stub.base:record},b)

    def test_schema_eleven_source_permissions_and_original_input_preservation(self):
        linker,c,_=bundle_fixture();before=[bytes(x.image) for x in linker.modules]
        _,source,m=build_bundle(linker,c)
        self.assertEqual(m['schema_version'],11);self.assertIn('bounded',m['profile']);self.assertEqual(len(m['bounded_leaves']),2)
        self.assertIn('oot_stack_create_bounded_callees',source);self.assertFalse(m['keys_embedded']);self.assertEqual([bytes(x.image) for x in linker.modules],before)
        for change in (dict(schema_version=10),dict(bounded_leaves=[]),dict(bounded_leaves=None),dict(plts=[]),
                dict(write_ranges=[dict(module='main',offset=0x2000,size=0x100)]),dict(bounded_leaves=c['bounded_leaves']*2)):
            bad=deepcopy(c);bad.update(change)
            with self.subTest(change=change),self.assertRaises(InputError):build_bundle(linker,bad)


@unittest.skipUnless(os.name=='nt' and importlib.util.find_spec('unicorn'),'native Windows and pinned reference required')
class NativeBoundedMemoryTests(unittest.TestCase):
    def test_native_counter_admission_writeback_prefixes_and_contract_denials(self):
        r,path=run_validation(os.environ.get('OOT_LIFTER_COMPILER','cmake'))
        self.assertEqual((r['writeback_programs'],r['loop_programs'],r['max_depth']),(72,20,16))
        self.assertGreater(r['whole_call_cases'],600);self.assertGreater(r['prefix_checks'],r['whole_call_cases']);self.assertTrue(path.is_file())
        self.assertEqual(path.name,os.environ.get('OOT_LIFTER_COMPILER','cmake')+'-bounded-memory-dispatch-report.json')

    def test_actual_schema_eleven_factories_both_keys_and_return_styles(self):
        sources,fixtures=[],[]
        for explicit in (False,True):
            linker,c,programs=bundle_fixture(explicit);blob,source,m=build_bundle(linker,c)
            sources.append(source.replace('oot_create_bound_registry','oot_create_bounded1') if explicit else source)
            fixtures.append((blob,m,programs,bytes(linker.modules[0].image[0x2000:0x2200])))
        mode=os.environ.get('OOT_LIFTER_COMPILER','cmake');lib,build=compile_library([],mode,'\n'.join(sources));bindings(lib)
        keys=lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));self.assertTrue(keys)
        whole=prefixes=0;rng=random.Random(0xb011fac)
        try:
            for index,(blob,m,programs,data) in enumerate(fixtures):
                path=Path(build['directory'])/f'bounded-bundle{index}.ootmem';path.write_bytes(blob)
                message,error,report=create_string_buffer(192),c_uint32(),Report()
                image=lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
                memory=lib.oot_runtime_memory(image);rows=m['image']['regions'];stack_row=next(i for i,r in enumerate(rows) if r['kind']=='stack')
                stack=memory.contents.regions[stack_row].data;region=memory.contents.regions[next(i for i,r in enumerate(rows) if r['owner']=='main' and r['kind']=='data')]
                factory=lib.oot_create_bounded1 if index else lib.oot_create_bound_registry
                factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
                d=factory(image,keys,byref(error));self.assertTrue(d,error.value);lib.oot_runtime_close(image)
                ref=PltReference(programs,{m['plts'][0]['slot']:m['bounded_leaves'][1]['entry']})
                try:
                    for flags in range(16):
                        for n in (0,1,3,7):
                            memset(stack,0,STACK_SIZE);memmove(region.data,data,len(data));ref.u.mem_write(region.base,data);ref.u.mem_write(rows[stack_row]['base'],bytes(STACK_SIZE))
                            s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)]
                            s.pc,s.sp,s.x[30],s.nzcv=m['root']['entry'],m['image']['initial_sp'],EXIT,flags<<28
                            value=rng.getrandbits(64);s.x[0],s.x[1],s.x[2],s.x[3]=value,region.base+0x100,region.base+0x140,n;expected=State.from_buffer_copy(s)
                            self.assertEqual(lib.oot_stack_begin(d,byref(s),EXIT,byref(report)),0)
                            while expected.pc!=EXIT:
                                self.assertEqual(lib.oot_stack_run(d,byref(s),0,byref(report)),1)
                                expected=ref.step(expected,ref.words[expected.pc]);status=lib.oot_stack_run(d,byref(s),1,byref(report))
                                self.assertEqual(status,2 if expected.pc==EXIT else 1,report.error);self.assertEqual(s.values(),expected.values());prefixes+=1
                                self.assertEqual(bytes(stack[:STACK_SIZE]),bytes(ref.u.mem_read(rows[stack_row]['base'],STACK_SIZE)))
                                self.assertEqual(bytes(region.data[:len(data)]),bytes(ref.u.mem_read(region.base,len(data))))
                            self.assertEqual(s.x[0],(value+7)&((1<<64)-1))
                            self.assertEqual(bytes(region.data[0x100:0x100+2*n]),bytes([value&255])*n+bytes(range(n)));whole+=1
                finally:lib.oot_stack_destroy(d)
        finally:lib.oot_pauth_destroy(keys)
        self.assertEqual(whole,128)
        (ROOT/f'build/lifter-validation/{mode}-bounded-memory-factory-dispatch-report.json').write_text(json.dumps(dict(synthetic_only=True,game_code_executed=False,whole_call_cases=whole,prefix_checks=prefixes,native_build=build),indent=2)+'\n')


if __name__=='__main__':unittest.main()
