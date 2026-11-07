"""SDK evidence must distinguish a diagnostic from the original entry goal."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from build_startup import prepared_npdm
from input_formats import InputError
from run_milestone import startup_evidence


def experiment(complete=False):
    info=None if complete else dict(info_id=29,handle=0xffff8001,sub_id=0)
    execution=dict(status=2,error=15 if complete else 9,retired=100,pc='0x1000',word=1,service=0 if complete else 41,
        startup_completed=False,relative_relocation_probes=8,relative_relocations_matching_offline_link=8,
        trace_sha256='ab'*32,sdk_runtime=True,sdk_stages_completed=7 if complete else 3,
        sdk_initialization_completed=complete,game_entry_reached=complete)
    if info:execution['get_info_request']=info
    return dict(status='diagnostic-complete',game_code_executed=True,startup_completed=False,
        switch2_startup_abi_proven=False,sdk_runtime=True,sdk_initialization_completed=complete,
        iterations=[dict(compiler='synthetic',execution=execution)])


class SdkWorkflowTests(unittest.TestCase):
    def test_diagnostic_and_complete_endpoints_have_different_contracts(self):
        r=experiment();e=r['iterations'][0]['execution']
        self.assertFalse(startup_evidence(r,9,e['get_info_request'],3)['sdk_initialization_completed'])
        self.assertTrue(startup_evidence(experiment(True),15,None,7)['game_entry_reached'])
        with self.assertRaises(InputError):startup_evidence(r,15,None,7)
        for field,value in (('error',9),('sdk_stages_completed',6),('sdk_initialization_completed',False),('game_entry_reached',False),('relative_relocations_matching_offline_link',7)):
            r=experiment(True);r['iterations'][0]['execution'][field]=value
            with self.subTest(field=field),self.assertRaises(InputError):startup_evidence(r,15,None,7)
        r=experiment(True);r['sdk_initialization_completed']=False
        with self.assertRaises(InputError):startup_evidence(r,15,None,7)
        r=experiment();e=r['iterations'][0]['execution'];e.pop('get_info_request');e['service']=31;e['named_port']='sm:'
        self.assertEqual(startup_evidence(r,9,None,3,31,'sm:')['named_port'],'sm:')
        with self.assertRaises(InputError):startup_evidence(r,9,None,3,41,'sm:')
        with self.assertRaises(InputError):startup_evidence(r,9,None,3,31,'unrecognized')

    def test_npdm_only_uses_listed_size_and_hash_bound_bytes(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            folder=Path(temporary);raw=b'META'+bytes(128)
            (folder/'main.npdm').write_bytes(raw)
            manifest=dict(files=[])
            (folder/'manifest.json').write_text(json.dumps(manifest))
            self.assertIsNone(prepared_npdm(folder))
            record=dict(name='main.npdm',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            manifest['files']=[record];(folder/'manifest.json').write_text(json.dumps(manifest))
            self.assertEqual(prepared_npdm(folder),raw)
            for key,value in (('bytes',len(raw)-1),('bytes',32769),('sha256','00'*32)):
                bad=deepcopy(manifest);bad['files'][0][key]=value
                (folder/'manifest.json').write_text(json.dumps(bad))
                with self.subTest(key=key,value=value),self.assertRaises(InputError):prepared_npdm(folder)


if __name__=='__main__':unittest.main()
