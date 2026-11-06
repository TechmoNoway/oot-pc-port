"""Exact relocation-backed PLT-to-leaf policy, schema 8 and native fault isolation."""

from copy import deepcopy
from ctypes import byref,c_uint32,c_uint64,create_string_buffer
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from call_validation import LrAssembler
from dispatcher_validation import EXIT,Report
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import State
from module_linker import Module,Linker
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from plt_validation import stub,synthetic_programs,bindings,run_validation
from plt_verifier import verify_plt_stub,eligible_plts
from prepare_exefs import prepare
from prepare_registry import build_bundle
from profile_survey import survey_modules
from stack_cfg_validation import mov,add_immediate
from stack_layout_validation import add
from stack_layout_verifier import verify_plt_stack_functions,verify_call_stack_functions
from test_arm64_analysis import synthetic_module,branch,RET
from test_module_linker import symbol,change_memory


def bundle_fixture(explicit=False,symbol_name='ordinary_helper'):
    root=LrAssembler('plt_bundle'+str(int(explicit)),0x10,64,19,not explicit,key=int(explicit),explicit_auth=explicit)
    root.emit(mov(19,0));root.bl(0x40);root.emit(add(0,0,19));root.bl(0xc0);r=root.finish()
    helper=PauthAssembler('plt_helper'+str(int(explicit)),0x40,64,48,key=1-int(explicit),explicit_auth=not explicit)
    helper.bl(0xc0);h=helper.finish()
    words={0:branch(0,0x10),0xc0:0xd0000010,0xc4:0xf9400211,0xc8:0x91000210,0xcc:0xd61f0220}
    for p in (r,h):words.update({p.base+i:int.from_bytes(p.data[i:i+4],'little') for i in range(0,len(p.data),4)})
    raw=synthetic_module(words,symbols=[symbol(symbol_name,section=0,value=0,size=0),
        symbol(r.name,value=r.base,size=len(r.data)),symbol(h.name,value=h.base,size=len(h.data))],plt=((0x2000,1026,1,0),))
    sdk=synthetic_module({0:branch(0,0x40),0x40:add_immediate(0,0,7),0x44:RET},symbols=[symbol(symbol_name,value=0x40,size=8)])
    linker=Linker([Module('main',raw),Module('sdk',sdk)]);assert linker.apply()['link_complete']
    suffix=str(int(explicit))
    config={'schema_version':8,'pauth_model':MODEL,'root':r.name,'return_sites':[EXIT],'stack_size':4096,
        'frames':[{'name':p.name,'module':'main','offset':p.base,'size':len(p.data)} for p in (r,h)],
        'leaves':[{'name':'selected_leaf'+suffix,'module':'sdk','offset':0x40,'size':8}],
        'plts':[{'name':'selected_plt'+suffix,'module':'main','offset':0xc0,'leaf':'selected_leaf'+suffix}],
        'read_ranges':[{'module':'main','offset':0x2100,'size':8}]}
    return raw,sdk,linker,config


class PltPolicyTests(unittest.TestCase):
    def test_original_stub_words_real_leaf_and_weighted_mixed_call_proof(self):
        frames,leaves,bridges=synthetic_programs();codes={p.base:p.data for p in frames};leaf={p.base:p.data for p in leaves}
        before=deepcopy(codes);p={b.base:r for b,r in bridges}
        proof=verify_plt_stack_functions(codes,leaf,frames[0].base,p)
        self.assertEqual(codes,before);self.assertEqual(proof[frames[0].base]['policy'],'plt-leaf-stack-dag-v7')
        self.assertEqual(proof[frames[0].base]['max_depth'],2)
        with self.assertRaises(InputError):verify_call_stack_functions(codes,leaf,frames[0].base)
        self.assertEqual(proof[frames[1].base]['max_retired_instructions'],len(frames[1].words)+4+len(leaves[1].words))

    def test_exact_registers_offsets_branch_and_nonlocal_rejections(self):
        frames,leaves,bridges=synthetic_programs();b,r=bridges[0];leaf={p.base:p.data for p in leaves}
        p=verify_plt_stub(b.data,b.base,r['slot'],r['target'],leaf,r['symbol'])
        self.assertEqual(p['words'],b.words);self.assertEqual(p['max_retired_instructions'],4+len(leaves[0].words))
        for i in range(4):
            words=b.words.copy();words[i]^=1
            with self.subTest(index=i),self.assertRaises(InputError):
                verify_plt_stub(struct.pack('<4I',*words),b.base,r['slot'],r['target'],leaf,r['symbol'])
        for symbol_name in ('setjmp','_setjmp','longjmp','siglongjmp'):
            with self.assertRaises(InputError):verify_plt_stub(b.data,b.base,r['slot'],r['target'],leaf,symbol_name)
        with self.assertRaises(InputError):verify_plt_stub(b.data,b.base,r['slot']+8,r['target'],leaf,r['symbol'])
        with self.assertRaises(InputError):verify_plt_stub(b.data,b.base,r['slot'],frames[1].base,leaf,r['symbol'])
        with self.assertRaises(InputError):verify_plt_stub(b.data[:-4],b.base,r['slot'],r['target'],leaf,r['symbol'])

    def test_negative_adrp_and_stub_crossing_page_boundary(self):
        leaf={0x5000:RET.to_bytes(4,'little')}
        for entry,slot in ((0x1ffc,0x800),(0x1000,0x3ff8),(0x3000,0x1000)):
            p,r=stub('test_stub',entry,slot,0x5000)
            proof=verify_plt_stub(p.data,p.base,slot,0x5000,leaf,'ordinary')
            self.assertEqual(proof['got_slot'],slot)

    def test_frame_leaf_or_stub_overlap_and_unverified_leaf_are_rejected(self):
        frames,leaves,bridges=synthetic_programs();b,r=bridges[0];codes={p.base:p.data for p in frames};leaf={p.base:p.data for p in leaves}
        with self.assertRaises(InputError):verify_plt_stack_functions(codes,{r['target']:b.data},frames[0].base,{b.base:r})
        bad=deepcopy(r);bad['target']=b.base
        with self.assertRaises(InputError):verify_plt_stack_functions(codes,{**leaf,b.base:RET.to_bytes(4,'little')},frames[0].base,{b.base:bad})


class PltBundleSurveyTests(unittest.TestCase):
    def test_actual_relocation_backed_bundle_preserves_source_and_prior_profiles(self):
        _,_,linker,config=bundle_fixture();before=[bytes(m.image) for m in linker.modules]
        _,source,m=build_bundle(linker,config)
        self.assertEqual((m['schema_version'],m['profile']),(8,'plt-leaf-stack-dag'))
        self.assertIn('oot_stack_create_plt',source);self.assertTrue(m['runtime_got_targets_checked'])
        self.assertEqual(m['plts'][0]['slot'],linker.modules[0].base+0x2000)
        self.assertEqual([bytes(m.image) for m in linker.modules],before);self.assertFalse(m['guest_code_executed'])
        for change in ({'schema_version':7},{'plts':[]},{'plts':[dict(config['plts'][0],offset=0xc4)]},
                       {'leaves':[dict(config['leaves'][0],offset=0x44,size=4)]},{'read_ranges':[]},{'pauth_model':None}):
            bad=deepcopy(config);bad.update(change)
            with self.subTest(change=change),self.assertRaises(InputError):build_bundle(linker,bad)
        for name in ('setjmp','longjmp'):
            _,_,linker,bad=bundle_fixture(symbol_name=name)
            with self.assertRaises(InputError):build_bundle(linker,bad)

    def test_static_survey_keeps_old_acceptance_and_only_adds_real_bridges(self):
        _,_,linker,_=bundle_fixture();before=[bytes(m.image) for m in linker.modules]
        report=survey_modules(linker.modules,plt=True);totals=report['totals']['profiles']
        self.assertEqual(totals['lr_calls']['accepted_regions'],0);self.assertEqual(totals['plt_leaf']['accepted_regions'],2)
        self.assertEqual(report['eligible_plt_leaf_bridges'],1);self.assertFalse(report['runtime_got_targets_checked'])
        self.assertFalse(report['runtime_read_ranges_supplied']);self.assertFalse(report['translation_performed']);self.assertFalse(report['native_callbacks_registered'])
        self.assertEqual([bytes(m.image) for m in linker.modules],before)
        # A matching code shape with no symbol relocation is not an eligible PLT.
        m=linker.modules[0];m.rela=[]
        leaf={linker.modules[1].base+0x40:bytes(linker.modules[1].image[0x40:0x48])}
        self.assertEqual(eligible_plts(linker.modules,leaf),{})

    def test_unapproved_or_nonlocal_snapshot_is_not_silently_admitted(self):
        for name in ('setjmp','longjmp'):
            _,_,linker,_=bundle_fixture(symbol_name=name);r=survey_modules(linker.modules,plt=True)
            self.assertEqual(r['eligible_plt_leaf_bridges'],0);self.assertEqual(r['totals']['profiles']['plt_leaf']['accepted_regions'],0)

    def test_cli_bundle_survey_integrity_and_fresh_output(self):
        main,sdk,_,config=bundle_fixture(True)
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            folder=Path(temporary);inputs=folder/'inputs';inputs.mkdir();(inputs/'main').write_bytes(main);(inputs/'sdk').write_bytes(sdk)
            prepared=folder/'prepared';prepare(inputs,prepared);before={p.name:p.read_bytes() for p in prepared.iterdir()}
            selection=folder/'selection.json';selection.write_text(json.dumps(config));bundle=folder/'bundle';report=folder/'survey.json'
            args=[sys.executable,'-B',str(ROOT/'tools/prepare_registry.py'),str(prepared),'--config',str(selection),'--output',str(bundle)]
            result=subprocess.run(args,capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads((bundle/'manifest.json').read_text())['schema_version'],8)
            result=subprocess.run([sys.executable,'-B',str(ROOT/'tools/survey_function_profiles.py'),str(prepared),'--plt','--report',str(report)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);self.assertFalse(json.loads(report.read_text())['guest_code_executed'])
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)
            self.assertEqual({p.name:p.read_bytes() for p in prepared.iterdir()},before)


@unittest.skipUnless(os.name=='nt' and importlib.util.find_spec('unicorn'),'native Windows and pinned reference required')
class NativePltTests(unittest.TestCase):
    def test_native_bridges_prefixes_faults_and_retained_ownership(self):
        r,path=run_validation(os.environ.get('OOT_LIFTER_COMPILER','cmake'))
        self.assertEqual((r['whole_call_cases'],r['prefix_checks'],r['matrix_layouts'],r['bad_callback_modes']),(114,2145,16,16))
        self.assertEqual(r['got_pause_points'],7);self.assertFalse(r['game_code_executed']);self.assertTrue(path.is_file())

    def test_actual_schema_eight_factories_mixed_frames_and_return_styles(self):
        sources,blobs=[],[]
        for explicit in (False,True):
            _,_,linker,config=bundle_fixture(explicit);blob,source,m=build_bundle(linker,config)
            sources.append(source.replace('oot_create_bound_registry','oot_create_plt1') if explicit else source);blobs.append((blob,m))
        lib,_=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),'\n'.join(sources));bindings(lib)
        context=lib.oot_pauth_create(1,(c_uint64*4)(*KEYS))
        try:
            with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
                for i,(blob,m) in enumerate(blobs):
                    path=Path(temporary)/f'image{i}.ootmem';path.write_bytes(blob)
                    message,error,report=create_string_buffer(192),c_uint32(),Report()
                    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
                    factory=lib.oot_create_plt1 if i else lib.oot_create_bound_registry
                    factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
                    d=factory(image,context,byref(error));self.assertTrue(d,error.value);lib.oot_runtime_close(image)
                    try:
                        s=State();s.pc,s.sp,s.x[0],s.x[19],s.x[29],s.x[30]=m['root']['entry'],m['image']['initial_sp'],9,0xA5,0x12345678,EXIT
                        self.assertEqual(lib.oot_stack_begin(d,byref(s),EXIT,byref(report)),0)
                        self.assertEqual(lib.oot_stack_run(d,byref(s),1000,byref(report)),2)
                        self.assertEqual((s.x[0],s.x[19],s.x[29]),(32,0xA5,0x12345678))
                    finally:lib.oot_stack_destroy(d)
        finally:lib.oot_pauth_destroy(context)


if __name__=='__main__':unittest.main()
