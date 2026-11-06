"""Separate LR-pair policy, real mixed closures, schema 7, and native contracts."""

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
from call_validation import LrAssembler,bindings,run_validation,synthetic_programs,matrix_programs,boundary_programs
from dispatcher_validation import EXIT,Report
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import State
from module_linker import Linker,Module
from ordered_programs import rcpc
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from prepare_exefs import prepare
from prepare_registry import build_bundle
from profile_survey import survey_modules
from stack_cfg_validation import mov,add_immediate
from stack_layout_validation import add,memory_word
from stack_layout_verifier import verify_call_stack_functions,verify_read_stack_functions,OPEN_LR,CLOSE_LR
from test_module_linker import fixture,change_memory,symbol
from test_profile_survey import programs_module


def bundle_fixture(explicit=False):
    base=Linker([Module('main',fixture())]).modules[0].base
    a=LrAssembler('call_bundle'+str(int(explicit)),base+0x10,64,19,not explicit,key=int(explicit),explicit_auth=explicit)
    a.emit(mov(19,0),rcpc(0));a.bl(base+0xa0);a.emit(add(0,0,19));root=a.finish()
    a=PauthAssembler('call_helper'+str(int(explicit)),base+0xa0,32,16,key=1-int(explicit),explicit_auth=not explicit)
    a.emit(add_immediate(0,0,5));child=a.finish()
    raw=fixture(symbols=[symbol(p.name,value=p.base-base,size=len(p.data)) for p in (root,child)])
    raw=change_memory(raw,0x94,struct.pack('<i',0x1100-0x80))
    for p in (root,child):raw=change_memory(raw,p.base-base,p.data)
    raw=change_memory(raw,0x2100,b'\x80')
    linker=Linker([Module('main',raw)]);assert linker.apply()['link_complete']
    config={'schema_version':7,'pauth_model':MODEL,'root':root.name,'stack_size':4096,'return_sites':[EXIT],
        'frames':[{'name':p.name,'module':'main','offset':p.base-base,'size':len(p.data)} for p in (root,child)],'leaves':[],
        'read_ranges':[{'module':'main','offset':0x2100,'size':1}]}
    return raw,linker,config


class LrCallPolicyTests(unittest.TestCase):
    def test_mixed_real_closures_preserve_original_words_and_prior_policy(self):
        frames,leaves=synthetic_programs();codes={p.base:p.data for p in frames};before=deepcopy(codes)
        proof=verify_call_stack_functions(codes,{p.base:p.data for p in leaves},frames[0].base)
        self.assertEqual(codes,before);self.assertEqual(proof[frames[0].base]['max_depth'],3)
        self.assertEqual([proof[p.base]['layout'] for p in frames],['lr-pair','split','lr-pair'])
        self.assertTrue(all(s['fp']==0 for s in proof[frames[0].base]['states']))
        with self.assertRaises(InputError):verify_read_stack_functions(codes,{p.base:p.data for p in leaves},frames[0].base)
        with self.assertRaises(InputError):verify_call_stack_functions({frames[0].base:frames[0].data},{},frames[0].base)

    def test_all_partners_orders_keys_and_returns_have_real_proofs(self):
        for p in matrix_programs():
            proof=verify_call_stack_functions({p.base:p.data},{},p.base)[p.base]
            partner=(p.words[1]&31) if p.words[1]&31!=30 else (p.words[1]>>10)&31
            self.assertEqual(proof['saved_mask'],1<<partner);self.assertEqual(proof['reserved_ranges'],[(0,16)])
            self.assertEqual(proof['steps'][1]['kind'],OPEN_LR)
            self.assertEqual(sum(s['kind']==CLOSE_LR for s in proof['steps']),1)
            self.assertEqual(proof['open_word'],p.words[1]);self.assertFalse(proof['guest_code_executed'])

    def test_empty_frame_and_all_ten_saved_registers(self):
        for p in boundary_programs():
            proof=verify_call_stack_functions({p.base:p.data},{},p.base)[p.base]
            self.assertEqual(proof['instruction_count'],len(p.words))
        self.assertEqual(proof['saved_registers'],list(range(19,29)))
        self.assertEqual(proof['control_flow'][-3]['writable_mask'],0)

    def test_invalid_pair_restore_fp_effects_reserved_slots_and_calls(self):
        a=LrAssembler('bad_lr',0x1000,64);a.emit(mov(19,0),memory_word(8,False,0,31,16));p=a.finish()
        variants=[(1,p.words[1]^(1<<23)),(1,p.words[1]^1),(-2,p.words[-2]^1),(-2,p.words[-2]^(1<<15)),
                  (2,0x910003fd),(2,mov(18,0)),(2,mov(29,0)),(2,mov(30,0)),
                  (2,memory_word(8,True,0,31,0)),(2,memory_word(8,True,0,29,16)),
                  (2,memory_word(8,False,0,1,16)),(2,0x94000100),(2,0x17ffffff),(2,0x14000000)]
        for index,word in variants:
            words=p.words.copy();words[index]=word
            with self.subTest(index=index,word=hex(word)),self.assertRaises(InputError):
                verify_call_stack_functions({p.base:struct.pack(f'<{len(words)}I',*words)},{},p.base)

    def test_existing_fp_layout_is_explicitly_accepted_without_pair_metadata(self):
        a=PauthAssembler('old_fp',0x1000,32);a.emit(mov(0,1));p=a.finish()
        old=verify_read_stack_functions({p.base:p.data},{},p.base)[p.base]
        new=verify_call_stack_functions({p.base:p.data},{},p.base)[p.base]
        self.assertEqual((new['open_word'],new['close_word']),(0,0))
        self.assertEqual((new['steps'],new['states'],new['source_sha256']),(old['steps'],old['states'],old['source_sha256']))


class LrCallBundleSurveyTests(unittest.TestCase):
    def test_schema_seven_preserves_inputs_and_requires_explicit_model_and_ranges(self):
        _,linker,config=bundle_fixture();before=bytes(linker.modules[0].image)
        _,source,m=build_bundle(linker,config)
        self.assertEqual(m['profile'],'lr-pair-read-stack-dag');self.assertIn('oot_stack_create_calls',source)
        self.assertEqual(bytes(linker.modules[0].image),before);self.assertFalse(m['keys_embedded'])
        for change in ({'schema_version':6},{'pauth_model':None},{'read_ranges':[]},{'frames':config['frames'][:1]}):
            bad=deepcopy(config);bad.update(change)
            with self.subTest(change=change),self.assertRaises(InputError):build_bundle(linker,bad)

    def test_static_mixed_closure_and_missing_target_use_actual_proofs(self):
        root=LrAssembler('root',0x10,32);root.bl(0xa0)
        child=PauthAssembler('child',0xa0,32,16);child.emit(mov(0,1))
        root_code,child_code=root.finish().data,child.finish().data
        m=programs_module([('root',0x10,root_code),('child',0xa0,child_code)])
        before=bytes(m.image);r=survey_modules([m],lr_calls=True)
        p=r['modules'][0]['profiles'];self.assertEqual(p['lr_calls']['accepted_regions'],2)
        self.assertEqual(p['checked_reads']['accepted_regions'],1)
        sample=next(s for s in p['lr_calls']['accepted_samples'] if s['offset']==0x10)
        self.assertEqual(sample['closure_frames'],2);self.assertEqual(bytes(m.image),before)
        self.assertFalse(r['runtime_read_ranges_supplied']);self.assertFalse(r['translation_performed']);self.assertFalse(r['native_callbacks_registered'])
        missing=programs_module([('root',0x10,root_code)])
        self.assertEqual(survey_modules([missing],lr_calls=True)['totals']['profiles']['lr_calls']['accepted_regions'],0)

    def test_cli_bundle_and_survey_preserve_prepared_inputs_and_fresh_outputs(self):
        raw,_,config=bundle_fixture(True)
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            folder=Path(temporary);src,prepared,selection,out,report=[folder/n for n in ('main','prepared','config.json','bundle','report.json')]
            src.write_bytes(raw);prepare(src,prepared);selection.write_text(json.dumps(config))
            before={p.name:p.read_bytes() for p in prepared.iterdir()}
            args=[sys.executable,'-B',str(ROOT/'tools/prepare_registry.py'),str(prepared),'--config',str(selection),'--output',str(out)]
            result=subprocess.run(args,capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads((out/'manifest.json').read_text())['schema_version'],7)
            survey=[sys.executable,'-B',str(ROOT/'tools/survey_function_profiles.py'),str(prepared),'--lr-calls','--report',str(report)]
            result=subprocess.run(survey,capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse(json.loads(report.read_text())['guest_code_executed'])
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)
            self.assertNotEqual(subprocess.run(survey,capture_output=True).returncode,0)
            self.assertEqual({p.name:p.read_bytes() for p in prepared.iterdir()},before)


@unittest.skipUnless(os.name=='nt' and importlib.util.find_spec('unicorn'),'native Windows and pinned reference required')
class NativeLrCallTests(unittest.TestCase):
    def test_native_mixed_dags_prefixes_boundaries_and_negative_contracts(self):
        r,path=run_validation(os.environ.get('OOT_LIFTER_COMPILER','cmake'))
        self.assertEqual((r['whole_call_cases'],r['prefix_checks'],r['matrix_programs'],r['bad_callback_modes']),(437,3957,80,10))
        self.assertFalse(r['game_code_executed']);self.assertTrue(path.is_file())

    def test_actual_schema_seven_mixed_factories_for_both_return_styles(self):
        sources,blobs=[],[]
        for explicit in (False,True):
            _,linker,config=bundle_fixture(explicit);blob,source,m=build_bundle(linker,config)
            sources.append(source.replace('oot_create_bound_registry','oot_create_lr1') if explicit else source);blobs.append((blob,m))
        lib,_=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),'\n'.join(sources));bindings(lib)
        keys=(c_uint64*4)(*KEYS);context=lib.oot_pauth_create(1,keys)
        try:
            with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
                for i,(blob,m) in enumerate(blobs):
                    path=Path(temporary)/f'image{i}.ootmem';path.write_bytes(blob)
                    message,error,report=create_string_buffer(192),c_uint32(),Report()
                    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
                    factory=lib.oot_create_lr1 if i else lib.oot_create_bound_registry
                    factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
                    d=factory(image,context,byref(error));self.assertTrue(d,error.value);lib.oot_runtime_close(image)
                    try:
                        s=State();s.pc,s.sp,s.x[0],s.x[1],s.x[19],s.x[29],s.x[30]=m['root']['entry'],m['image']['initial_sp'],9,m['read_ranges'][0]['base'],0xA5,0x12345678,EXIT
                        self.assertEqual(lib.oot_stack_begin(d,byref(s),EXIT,byref(report)),0)
                        self.assertEqual(lib.oot_stack_run(d,byref(s),1000,byref(report)),2)
                        self.assertEqual((s.x[0],s.x[19],s.x[29]),(142,0xA5,0x12345678))
                    finally:lib.oot_stack_destroy(d)
        finally:lib.oot_pauth_destroy(context)


if __name__=='__main__':unittest.main()
