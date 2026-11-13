"""Post-entry evidence must include initialization, real execution and effects."""
from copy import deepcopy
from pathlib import Path
import hashlib,struct,sys,unittest
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from run_milestone import application_evidence,application_endpoint
from input_formats import InputError
from test_sdk_init_milestone import completed

def evidence():
    old=completed();old['host_linked']=True
    old['iterations'][-1]['execution'].update(host_linked=True,host_scaffold_retired=10,original_retired=90,constructors_completed=3)
    report=deepcopy(old);report.update(format='oot-startup-experiment',application_runtime=True)
    e=report['iterations'][-1]['execution']
    e.update(error=9,service=31,pc='0x2000',word=0xd503237f,native_handler_stop=True,application_entry_retired=True,
        retired=200,original_retired=190,post_entry_retired=100,native_calls=12,trace_steps=212,trace_rows=213,
        application_services=dict(policy_calls=1,graphics_notifications=1,language_calls=1,language_code=int.from_bytes(b'en-US\0\0\0','little')),
        application_thread=dict(priority=44,core=0,ideal_core=0xffffffff,affinity=1,priority_updates=1,affinity_updates=1))
    e['native_stats']['calls']=12
    bundle=dict(host_boot=dict(module_order=[{}, {}, {}],original_rtld_execution_allowed=False),
        package=dict(image_phase='host-offline-linked'),native_audit=dict(functions=[dict(names=['boundary'],
            entry=0x2000,entry_word=0xd503237f,handler_id=31)]))
    return report,bundle,old

class ApplicationMilestoneTests(unittest.TestCase):
    def test_endpoint_alternatives_are_exclusive_and_svc_zero_is_valid(self):
        for values in (('export',None,None),(None,0xffffffff,None),(None,None,0)):
            application_endpoint(*values)
        for values in ((None,None,None),('',None,None),('export',1,None),('export',None,1),
                       (None,1,1),(None,True,None),(None,None,True),(None,None,-1),(None,None,65536)):
            with self.subTest(values=values),self.assertRaises(InputError):application_endpoint(*values)

    def test_svc_endpoint_requires_exact_original_word_source_and_no_native_guard(self):
        report,bundle,old=evidence();e=report['iterations'][-1]['execution']
        word=0xd4000001 | 0x1234 << 5
        e.update(service=0x1234,word=word,native_handler_stop=False)
        row=dict(address=0x2000,word=word,service=0x1234,module='main',source_sha256='22'*32,
                 word_sha256=hashlib.sha256(struct.pack('<I',word)).hexdigest())
        bundle.update(application_svc_sites=[row],entry_audit=dict(modules=[dict(name='main',source_sha256='22'*32)]))
        application_evidence(report,bundle,old,7,100,None,expected_svc=0x1234)
        for key,value in (('address',0x2004),('word',0),('service',31),('module','sdk'),
                          ('source_sha256','33'*32),('word_sha256','44'*32)):
            bad=deepcopy(bundle);bad['application_svc_sites'][0][key]=value
            with self.subTest(key=key),self.assertRaises(InputError):
                application_evidence(report,bad,old,7,100,None,expected_svc=0x1234)
        for key,value in (('pc','0x2004'),('word',0xd503201f),('service',31),('native_handler_stop',True),('error',8)):
            bad=deepcopy(report);bad['iterations'][-1]['execution'][key]=value
            with self.subTest(key=key),self.assertRaises(InputError):
                application_evidence(bad,bundle,old,7,100,None,expected_svc=0x1234)
        for value in (True,-1,65536):
            with self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,None,expected_svc=value)
        with self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,'boundary',expected_svc=0x1234)
        with self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,None,expected_word=word,expected_svc=0x1234)
        bundle['application_svc_sites'].append(row)
        with self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,None,expected_svc=0x1234)

    def test_declared_instruction_frontier_requires_exact_original_source_and_word(self):
        report,bundle,old=evidence();e=report['iterations'][-1]['execution']
        e.update(error=8,service=0,native_handler_stop=False,word=0xffffffff)
        row=dict(address=0x2000,word=0xffffffff,module='main',source_sha256='22'*32,
            word_sha256=hashlib.sha256(struct.pack('<I',0xffffffff)).hexdigest(),semantic_error='unsupported synthetic encoding')
        bundle.update(application_word_boundaries=[row],entry_audit=dict(modules=[dict(name='main',source_sha256='22'*32)]))
        application_evidence(report,bundle,old,7,100,None,expected_word=0xffffffff)
        for field,value in (('address',0x2004),('word',0),('module','sdk'),('source_sha256','33'*32),
            ('word_sha256','44'*32),('semantic_error','')):
            bad=deepcopy(bundle);bad['application_word_boundaries'][0][field]=value
            with self.subTest(field=field),self.assertRaises(InputError):application_evidence(report,bad,old,7,100,None,expected_word=0xffffffff)
        for expected in (True,-1,0x100000000,0):
            with self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,None,expected_word=expected)
        with self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,'boundary',expected_word=0xffffffff)

    def test_real_content_evidence_requires_matching_seal_mount_and_file_reads(self):
        assets=dict(index_sha256='11'*32,files=100,directories=10,cached_bytes=4096)
        report,bundle,old=evidence();bundle['romfs_input']=assets.copy()
        fs=dict(files=100,directories=10,cache_bytes=4096,mounted=1,mount_calls=1,
            open_calls=4,read_calls=4,bytes_read=3427,verified_files=4)
        report['iterations'][-1]['execution']['romfs']=fs
        application_evidence(report,bundle,old,7,100,'boundary',assets)
        for field,value in (('files',99),('directories',9),('cache_bytes',0),('mounted',0),
            ('mount_calls',0),('open_calls',0),('read_calls',0),('bytes_read',0),('verified_files',0)):
            bad=deepcopy(report);bad['iterations'][-1]['execution']['romfs'][field]=value
            with self.subTest(field=field),self.assertRaises(InputError):application_evidence(bad,bundle,old,7,100,'boundary',assets)
        bundle['romfs_input']['index_sha256']='22'*32
        with self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,'boundary',assets)

    def test_verified_diagnostic_is_not_reported_as_completed_startup(self):
        report,bundle,old=evidence()
        result=application_evidence(report,bundle,old,7,100,'boundary')
        self.assertTrue(result['sdk_initialization_completed']);self.assertFalse(result['startup_completed'])
        self.assertEqual(result['post_entry_retired'],100)

    def test_entry_markers_contract_faults_wrong_endpoint_and_missing_effects_reject(self):
        for field,value in (('application_entry_retired',False),('sdk_initialization_completed',False),
            ('post_entry_retired',99),('constructors_completed',2),('host_scaffold_retired',11),('retired',201),
            ('status',4),('error',15),('service',32),('pc','0x2004'),('word',0),('native_calls',10),
            ('trace_rows',211),('relative_relocations_matching_offline_link',1)):
            report,bundle,old=evidence();report['iterations'][-1]['execution'][field]=value
            with self.subTest(field=field),self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,'boundary')
        for section,field,value in (('application_services','policy_calls',0),('application_services','graphics_notifications',0),
            ('application_services','language_calls',0),('application_services','language_code',0),
            ('application_thread','priority_updates',0),('application_thread','affinity_updates',0),
            ('application_thread','ideal_core',0),('application_thread','affinity',2),
            ('init_stats','heap_size',0),('init_stats','platform_initialized',0)):
            report,bundle,old=evidence();report['iterations'][-1]['execution'][section][field]=value
            with self.subTest(field=field),self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,'boundary')
        report,bundle,old=evidence()
        with self.assertRaises(InputError):application_evidence(report,bundle,old,7,100,'other_export')
