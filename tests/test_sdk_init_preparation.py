"""Synthetic generation isolates large init guards from older startup modes."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from build_startup import run
from input_formats import InputError
from module_linker import Linker,Module
from prepare_startup import CONTEXT,emit_startup,prepare_bundle,selection
from test_arm64_analysis import RET,branch,synthetic_module


class SdkInitPreparationTests(unittest.TestCase):
    def fixture(self):
        words={0:branch(0,0x40),0x40:RET,0xc0:RET}
        raw=Linker([Module('main',synthetic_module(words)),Module('sdk',synthetic_module(words))])
        return raw,raw.modules[0].base

    def test_large_consumer_boundary_set_requires_separate_sdk_init_opt_in(self):
        raw,base=self.fixture();entries=tuple(base+n*4 for n in range(64))+(raw.modules[1].base,)
        before=bytes(raw.modules[0].image)
        with self.assertRaises(InputError):selection(raw,sdk=True,native_entries=entries)
        with self.assertRaises(InputError):selection(raw,sdk_init=True,native_entries=entries)
        audit,nodes=selection(raw,sdk=True,sdk_init=True,native_entries=entries,extra_entries=(base+0x40,))
        boundary=next(node for node in nodes if node['address']==base+0x40)
        self.assertTrue(boundary['native_boundary'])
        self.assertFalse(boundary['semantic_supported'])
        self.assertEqual(boundary['word'],RET)
        self.assertFalse(audit['entry_graph']['runtime_path_proven'])
        self.assertEqual(bytes(raw.modules[0].image),before)

    def test_emitted_profile_flags_are_separate_and_keep_private_entropy_out_of_source(self):
        raw,base=self.fixture()
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='sdk-init-preparation-') as temporary:
            bundle=prepare_bundle(raw,Path(temporary)/'raw')
            _,nodes=selection(raw,sdk=True,native_entries=(base+0xc0,))
            config=dict(CONTEXT,heap_capacity=0x80000000)
            sdk=dict(core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,
                alias_base=0x5000000000,alias_size=0x80000000,program_id=0x1000,is_application=1,
                total_memory=bundle['package']['backing_bytes']+config['tls_size']+0x100000000,
                main_thread_id=7,main_thread_priority=44,main_thread_core=0)
            functions=[dict(handler_id=208,entry=base+0xc0,size=4,
                body_sha256=hashlib.sha256(raw.modules[0].read(0xc0,4)).hexdigest())]
            legacy,_=emit_startup(raw,nodes,bundle['package'],config,sdk_config=sdk,native_functions=functions)
            native,_=emit_startup(raw,nodes,bundle['package'],config,sdk_config=sdk,native_functions=functions,sdk_init=True)
            self.assertNotIn('OOT_STARTUP_INIT_RUNTIME',legacy)
            self.assertNotIn('OOT_SDK_INITIALIZATION',legacy)
            self.assertIn('OOT_STARTUP_RAW_IMAGE | OOT_STARTUP_SDK_RUNTIME | OOT_STARTUP_NATIVE_RUNTIME | OOT_STARTUP_INIT_RUNTIME',native)
            self.assertIn('OOT_SDK_NATIVE_FUNCTIONS | OOT_SDK_INITIALIZATION, {0,0,0,0}',native)
            self.assertIn('OOT_NATIVE_FUNCTION_VERSION, 208',native)
            again,_=emit_startup(raw,nodes,bundle['package'],config,sdk_config=sdk,native_functions=functions)
            self.assertEqual(legacy,again)

    def test_missing_sdk_or_native_dependencies_reject_before_preparation_side_effects(self):
        raw,base=self.fixture()
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='sdk-init-invalid-') as temporary:
            output=Path(temporary)/'invalid'
            for kwargs in (dict(sdk_init=True),dict(native_sdk=True,sdk_init=True)):
                with self.assertRaises(InputError):prepare_bundle(raw,output,**kwargs)
                self.assertFalse(output.exists())
            for kwargs in (dict(sdk_init=True),dict(sdk=True,sdk_init=True),
                    dict(native_sdk=True,sdk_init=True),dict(sdk=True,native_sdk=True,sdk_init=1)):
                with self.assertRaises(InputError):run(Path(temporary)/'absent-input',output,**kwargs)
                self.assertFalse(output.exists())
            _,nodes=selection(raw)
            with self.assertRaises(InputError):emit_startup(raw,nodes,{},sdk_init=True)


if __name__=='__main__':unittest.main()
