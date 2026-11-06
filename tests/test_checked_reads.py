"""Policy-5/schema-6 capability reads, unchanged prior policies, native snapshots."""

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
from dispatcher_validation import EXIT,Report
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import State
from module_linker import Module,Linker
from ordered_programs import rcpc
from pauth_lifter import MODEL
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from prepare_exefs import prepare
from prepare_registry import build_bundle
from profile_survey import survey_modules
from read_validation import bindings,run_validation,synthetic_programs,matrix_programs
from stack_layout_verifier import READ,verify_read_stack_functions,verify_pauth_stack_functions
from test_module_linker import fixture,change_memory,symbol
from test_profile_survey import programs_module


def bundle_fixture(rcpc_load=False):
    base=Linker([Module('main',fixture())]).modules[0].base
    a=PauthAssembler('cap_bundle'+str(int(rcpc_load)),base+0x10,64,48,((32,(19,)),),key=int(rcpc_load),explicit_auth=rcpc_load)
    a.emit(rcpc(0) if rcpc_load else 0xF9400020)
    p=a.finish();raw=fixture(symbols=[symbol(p.name,value=0x10,size=len(p.data))])
    raw=change_memory(raw,0x94,struct.pack('<i',0x1100-0x80));raw=change_memory(raw,0x10,p.data)
    raw=change_memory(raw,0x2100,bytes.fromhex('8070605040302010'))
    linker=Linker([Module('main',raw)]);assert linker.apply()['link_complete']
    config={'schema_version':6,'pauth_model':MODEL,'root':p.name,'stack_size':4096,'return_sites':[EXIT],
        'frames':[{'name':p.name,'module':'main','offset':0x10,'size':len(p.data)}],'leaves':[],
        'read_ranges':[{'module':'main','offset':0x2100,'size':8}]}
    return raw,linker,config


class CheckedReadPolicyTests(unittest.TestCase):
    def test_original_bytes_dynamic_read_obligations_and_old_policy_rejection(self):
        frames,leaves=synthetic_programs();code={p.base:p.data for p in frames};leaf={p.base:p.data for p in leaves}
        before=deepcopy(code);proof=verify_read_stack_functions(code,leaf,frames[0].base)
        root=proof[frames[0].base]
        self.assertEqual(root['policy'],'checked-read-pauth-stack-dag-v5');self.assertEqual(root['checked_read_count'],3)
        self.assertTrue(all((s['kind']==READ)==bool(w) for s,w in zip(root['steps'],root['read_words'])))
        self.assertIn('runtime',root['runtime_read_preconditions']);self.assertEqual(code,before)
        with self.assertRaises(InputError):verify_pauth_stack_functions(code,leaf,frames[0].base)

    def test_load_writeback_external_stores_and_protected_destinations_rejected(self):
        for word in (0xF8408420,0xF9000020,0xF9400032,0xF940003D,0xF940003E,0xF8BFC032):
            a=PauthAssembler('bad_read',0x1000,32);a.emit(word);p=a.finish()
            with self.subTest(word=hex(word)),self.assertRaises(InputError):verify_read_stack_functions({p.base:p.data},{},p.base)

    def test_static_frame_offsets_still_exclude_records_and_saved_slots(self):
        for word in (0xF94003E0,rcpc(0,0,31),0xF94003A0):
            a=PauthAssembler('bad_frame',0x1000,32,split=False);a.emit(word);p=a.finish()
            with self.subTest(word=hex(word)),self.assertRaises(InputError):verify_read_stack_functions({p.base:p.data},{},p.base)
        a=PauthAssembler('local_acquire',0x1000,64,48);a.emit(rcpc(0,0,31));p=a.finish()
        self.assertEqual(verify_read_stack_functions({p.base:p.data},{},p.base)[p.base]['checked_read_count'],1)

    def test_every_supported_read_addressing_class_has_a_real_profile_proof(self):
        for p,_,_,_ in matrix_programs():
            proof=verify_read_stack_functions({p.base:p.data},{},p.base)[p.base]
            self.assertEqual(proof['checked_read_count'],1)


class CheckedReadBundleSurveyTests(unittest.TestCase):
    def test_explicit_retained_region_ranges_and_schema_boundary(self):
        _,linker,config=bundle_fixture();before=bytes(linker.modules[0].image)
        blob,source,m=build_bundle(linker,config)
        self.assertEqual((m['schema_version'],m['profile']),(6,'checked-read-pauth-stack-dag'))
        self.assertIn('oot_stack_create_reads',source);self.assertEqual(m['read_ranges'][0]['offset'],0x2100)
        self.assertTrue(m['read_addresses_checked_at_runtime']);self.assertFalse(m['guest_code_executed'])
        self.assertEqual(bytes(linker.modules[0].image),before)
        for change in ({'schema_version':5},{'read_ranges':[]},{'read_ranges':[{'module':'main','offset':0x21ff,'size':2}]},
                       {'read_ranges':[{'module':'main','offset':0x2100,'size':8}]*2},{'read_ranges':[{'module':'stack','offset':0,'size':8}]},
                       {'read_ranges':[{'module':'main','offset':True,'size':8}]}):
            bad=deepcopy(config);bad.update(change)
            with self.subTest(change=change),self.assertRaises(InputError):build_bundle(linker,bad)

    def test_static_survey_reports_conditional_reads_without_granting_capabilities(self):
        a=PauthAssembler('root',0x10,32);a.emit(rcpc(0));p=a.finish()
        m=programs_module([('root',0x10,p.data)]);before=bytes(m.image)
        r=survey_modules([m],reads=True)
        self.assertEqual(r['totals']['profiles']['pauth_stack']['accepted_regions'],0)
        self.assertEqual(r['totals']['profiles']['checked_reads']['accepted_regions'],1)
        self.assertFalse(r['runtime_read_ranges_supplied']);self.assertIn('dynamic',r['read_survey_scope'])
        self.assertFalse(r['translation_performed']);self.assertFalse(r['native_callbacks_registered']);self.assertEqual(bytes(m.image),before)

    def test_cli_registry_and_read_survey_preserve_inputs_and_fresh_outputs(self):
        raw,_,config=bundle_fixture(True)
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            folder=Path(temporary);src,prepared,selection,out,report=[folder/n for n in ('main','prepared','selection.json','bundle','survey.json')]
            src.write_bytes(raw);prepare(src,prepared);selection.write_text(json.dumps(config))
            before={p.name:p.read_bytes() for p in prepared.iterdir()}
            args=[sys.executable,'-B',str(ROOT/'tools/prepare_registry.py'),str(prepared),'--config',str(selection),'--output',str(out)]
            result=subprocess.run(args,capture_output=True,text=True);self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads((out/'manifest.json').read_text())['schema_version'],6)
            result=subprocess.run([sys.executable,'-B',str(ROOT/'tools/survey_function_profiles.py'),str(prepared),'--reads','--report',str(report)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);self.assertFalse(json.loads(report.read_text())['runtime_read_ranges_supplied'])
            self.assertEqual({p.name:p.read_bytes() for p in prepared.iterdir()},before)
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)


@unittest.skipUnless(os.name=='nt' and importlib.util.find_spec('unicorn'),'native Windows and pinned reference required')
class NativeCheckedReadTests(unittest.TestCase):
    def test_native_snapshots_dag_matrix_denials_and_retained_ownership(self):
        r,path=run_validation(os.environ.get('OOT_LIFTER_COMPILER','cmake'))
        self.assertEqual((r['whole_call_cases'],r['matrix_programs'],r['bad_callback_modes']),(205,49,11))
        self.assertGreater(r['prefix_checks'],2500);self.assertFalse(r['game_code_executed']);self.assertTrue(path.is_file())

    def test_actual_schema_six_factory_both_ordinary_and_rcpc_loads(self):
        sources,blobs=[],[]
        for rcpc_load in (False,True):
            _,linker,config=bundle_fixture(rcpc_load);blob,source,m=build_bundle(linker,config)
            sources.append(source.replace('oot_create_bound_registry','oot_create_cap1') if rcpc_load else source);blobs.append((blob,m))
        lib,_=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),'\n'.join(sources));bindings(lib)
        keys=(c_uint64*4)(*KEYS);context=lib.oot_pauth_create(1,keys)
        try:
            with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
                for i,(blob,m) in enumerate(blobs):
                    path=Path(temporary)/f'image{i}.ootmem';path.write_bytes(blob)
                    message,error,report=create_string_buffer(192),c_uint32(),Report()
                    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
                    factory=lib.oot_create_cap1 if i else lib.oot_create_bound_registry
                    factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
                    d=factory(image,context,byref(error));self.assertTrue(d,error.value);lib.oot_runtime_close(image)
                    try:
                        s=State();s.pc,s.sp,s.x[30],s.x[1]=m['root']['entry'],m['image']['initial_sp'],EXIT,m['read_ranges'][0]['base']
                        self.assertEqual(lib.oot_stack_begin(d,byref(s),EXIT,byref(report)),0)
                        self.assertEqual(lib.oot_stack_run(d,byref(s),1000,byref(report)),2)
                        self.assertEqual(s.x[0],128 if i else 0x1020304050607080)
                    finally:lib.oot_stack_destroy(d)
        finally:lib.oot_pauth_destroy(context)


if __name__=='__main__':unittest.main()
