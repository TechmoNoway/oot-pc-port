"""Artificial source materializations and guard reconciliation, no game fixtures."""
from copy import deepcopy
from types import SimpleNamespace as I
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from display_refresh_audit import PUBLIC,constructed_slots,bind_refresh_public,extend_refresh_audit
from input_formats import InputError

class RefreshAuditTests(unittest.TestCase):
    def test_original_adr_pairs_and_non_address_overwrites(self):
        rows=[I(mnemonic=a,op_str=b)for a,b in [('adr','x9, #0x1000'),('adr','x10, #0x2000'),
            ('stp','x9, x10, [x0, #0x198]'),('str','x8, [x0, #0x198]'),('str','x9, [x1, #0x198]')]]
        self.assertEqual(constructed_slots(rows,'x0'),{0x1a0:0x2000})
    def test_typed_entry_requires_complete_original_guard_and_void_abi(self):
        p=dict(module='sdk',symbol=PUBLIC,entry=0x1000,size=76,body_sha256='ab'*32,symbol_metadata={'index':7})
        old=[dict(p,names=[PUBLIC],handler_id=31,returns_value=False,return_register=None)]
        snapshot=deepcopy(old);new=bind_refresh_public(old,p)
        self.assertEqual(old,snapshot);self.assertEqual(new[0]['handler_id'],457)
        self.assertFalse(new[0]['returns_value']);self.assertIsNone(new[0]['return_register'])
        for key,value in (('handler_id',456),('body_sha256','cd'*32),('names',[PUBLIC,'alias']),('size',72)):
            mutated=deepcopy(old);mutated[0][key]=value
            with self.subTest(key=key),self.assertRaises(InputError):bind_refresh_public(mutated,p)
    def test_requires_preceding_event_profile(self):
        class Linker:
            def report(self):return {'link_complete':True}
        for before in ({},dict(events_runtime=True,display_objects={'declaration':{'flags':3}})):
            with self.assertRaises(InputError):extend_refresh_audit(Linker(),before,None)

if __name__=='__main__':unittest.main()
