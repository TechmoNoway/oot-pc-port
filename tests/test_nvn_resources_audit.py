"""Artificial source roles and rejection of a different SDK identity."""
import hashlib,struct,unittest
from types import SimpleNamespace
from input_formats import InputError
from nvn_resources_audit import prove_body,prove_sampler_float_getter,prove_sampler_method,extend_nvn_resources_audit,BUFFER_BUILDERS
from test_nvn_layout_audit import LayoutModule
class NvnResourceAuditTests(unittest.TestCase):
    def test_complete_buffer_storage_setter_and_rehashed_wrong_field_reject(self):
        m=LayoutModule();words=(0xa9010801,0xf9001003,0xd65f03c0)
        raw=struct.pack('<3I',*words);m.image[:12]=raw
        p=dict(entry=m.base,size=12,body_sha256=hashlib.sha256(raw).hexdigest())
        roles=dict(enumerate(BUFFER_BUILDERS['nvnBufferBuilderSetStorage']))
        self.assertEqual(len(prove_body(m,p,12,roles)),3)
        for changes in ('hash','size','field'):
            bad=dict(p)
            if changes=='hash':bad['body_sha256']='ff'*32
            if changes=='size':bad['size']=8
            if changes=='field':
                struct.pack_into('<I',m.image,0,0xa9000801);bad['body_sha256']=hashlib.sha256(m.read(0,12)).hexdigest()
            with self.subTest(change=changes),self.assertRaises(InputError):prove_body(m,bad,12,roles)
    def test_cross_build_and_missing_preceding_profile_reject(self):
        l=SimpleNamespace(modules=[SimpleNamespace(name='sdk',source_sha256='ff'*32)])
        for flags in (7,15):
            original=dict(nvn_layout_runtime=True,display_objects=dict(declaration=dict(flags=flags)),nvn=dict(consumer_closure=True))
            with self.subTest(flags=flags),self.assertRaises(InputError):extend_nvn_resources_audit(l,original)

    def test_sampler_cpu_record_bounds_reject_rehashed_driver_field_access(self):
        m=LayoutModule();raw=struct.pack('<2I',0xf9000001,0xd65f03c0);m.image[:8]=raw
        p=dict(name='nvnSamplerBuilderSetDevice',entry=m.base,size=8,body_sha256=hashlib.sha256(raw).hexdigest())
        self.assertTrue(prove_sampler_method(m,p)['complete_body_verified'])
        struct.pack_into('<I',m.image,0,0xf9010001);p['body_sha256']=hashlib.sha256(m.read(0,8)).hexdigest()
        with self.assertRaises(InputError):prove_sampler_method(m,p)

    def test_float_field_role_rejects_rehashed_different_in_record_offset(self):
        m=LayoutModule();raw=struct.pack('<II',0xbd401400,0xd65f03c0);m.image[:8]=raw
        p=dict(entry=m.base,size=8,body_sha256=hashlib.sha256(raw).hexdigest())
        prove_sampler_float_getter(m,p,20)
        struct.pack_into('<I',m.image,0,0xbd401000);p['body_sha256']=hashlib.sha256(m.read(0,8)).hexdigest()
        with self.assertRaises(InputError):prove_sampler_float_getter(m,p,20)
