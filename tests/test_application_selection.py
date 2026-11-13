"""Post-entry discovery adds code without redistributing initialization roots."""
from copy import deepcopy
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from module_linker import Linker,Module
from test_arm64_analysis import synthetic_module,branch,RET
from prepare_startup import selection,extend_application_selection,application_sites
from startup_audit import StartupDecodeCache
from input_formats import InputError
from prepare_startup import sdk_init_vtable_entries
from test_sdk_init_vtables import fixture as pointer_fixture

class ApplicationSelectionTests(unittest.TestCase):
    def test_legacy_bundle_does_not_gain_application_site_records(self):
        import tempfile
        from prepare_startup import prepare_bundle
        raw=Linker([Module('main',synthetic_module({0x40:RET}))])
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
            report=prepare_bundle(raw,Path(tmp)/'legacy')
            self.assertNotIn('application_simd_sites',report)
            self.assertNotIn('application_svc_sites',report)

    def test_site_records_require_original_words_and_exclude_native_and_scaffolding(self):
        import hashlib,struct
        raw=Linker([Module('main',synthetic_module({0x40:0x7e21d808,0x44:0xd4024681,0x48:0x4ea21c20,0x4c:RET}))])
        m=raw.modules[0];base=m.base+0x40
        nodes=[dict(address=base+i*4,word=w) for i,w in enumerate((0x7e21d808,0xd4024681,0x4ea21c20,RET))]
        nodes[2]['native_boundary']=True
        simd,services=application_sites(raw.modules,nodes)
        self.assertEqual(len(simd),1);self.assertEqual(len(services),1)
        self.assertEqual(simd[0]['source_sha256'],m.source_sha256)
        self.assertEqual(simd[0]['word_sha256'],hashlib.sha256(struct.pack('<I',0x7e21d808)).hexdigest())
        self.assertEqual(services[0]['service'],0x1234)
        m.name='hostboot'
        self.assertEqual(application_sites(raw.modules,nodes),([],[]))
        m.name='main';nodes[0]['word']^=1
        with self.assertRaises(InputError):application_sites(raw.modules,nodes)

    def test_main_neighborhoods_need_an_observed_original_relocated_pointer(self):
        raw,linked=pointer_fixture()
        raw.modules[0].name=linked.modules[0].name='main'
        options=dict(module_name='main',object_prefix=None)
        entries,report=sdk_init_vtable_entries(raw,linked,(),**options)
        self.assertEqual(entries,[]);self.assertEqual(report['objects'],[])
        entries,report=sdk_init_vtable_entries(raw,linked,[raw.modules[0].base+0x100],**options)
        self.assertEqual(entries,[raw.modules[0].base+0x100,raw.modules[0].base+0x120])
        self.assertFalse(report['runtime_authority_granted']);self.assertEqual(report['objects'],[])
        linked.modules[0].image[0x7018]^=1
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked,[raw.modules[0].base+0x100],**options)
        with self.assertRaises(InputError):sdk_init_vtable_entries(raw,linked,module_name='main')

    def fixture(self):
        raw=Linker([Module('main',synthetic_module({0:branch(0,0x40),0x40:RET,
            0x50:0xd63f0020,0x54:RET,0xc0:0x91000400,0xc4:RET}))])
        _,nodes=selection(raw,sdk=True,sdk_init=True)
        return raw,{n['address']:n for n in nodes},raw.modules[0].base

    def test_old_rows_are_retained_and_diagnostic_callees_add_only_original_code(self):
        raw,old,base=self.fixture();original=deepcopy(old);image=bytes(raw.modules[0].image)
        for cache in (None,StartupDecodeCache()):
            merged,report=extend_application_selection(raw,old,base+0x50,(),(),{base+0x50:base+0xc0},cache)
            self.assertEqual({p:merged[p] for p in old},original)
            self.assertEqual(merged[base+0xc0]['word'],0x91000400)
            self.assertFalse(report['runtime_targets_authorized']);self.assertTrue(report['original_bytes_only'])
            self.assertEqual(report['roots'],[base+0x50])
        self.assertEqual(old,original);self.assertEqual(bytes(raw.modules[0].image),image)

    def test_native_guards_and_invalid_observed_roots_remain_boundaries(self):
        raw,old,base=self.fixture()
        merged,_=extend_application_selection(raw,old,base+0x50,[base+0xc0],(base+0xc0,),{},None)
        self.assertTrue(merged[base+0xc0]['native_boundary'])
        self.assertFalse(merged[base+0xc0]['semantic_supported'])
        for entries in ([base+1],[base+0x20000],[True],[base+0xc0]*1025):
            with self.assertRaises(InputError):extend_application_selection(raw,old,base+0x50,entries,(),{},None)
