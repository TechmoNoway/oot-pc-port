"""Independent synthetic procedure aliases and closed registry reconciliation."""
from copy import deepcopy
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from nvn_audit import merge_nvn_guards,extend_nvn_audit
from input_formats import InputError

def procedure(name,entry):return dict(name=name,entry=entry,size=8,body_sha256='ab'*32,extent={'entry':entry})
class NvnAuditTests(unittest.TestCase):
    def test_guards_private_entries_without_inventing_exports_or_replacing_retained(self):
        p=[procedure('nvnOriginalLeaf',0x1000),procedure('nvnUnsupported',0x1100),procedure('nvnAlias',0x1100)]
        before=deepcopy(p);r=merge_nvn_guards([],p,{'nvnOriginalLeaf'})
        self.assertEqual(p,before);self.assertEqual(len(r),1);self.assertEqual(r[0]['handler_id'],31)
        self.assertIsNone(r[0]['symbol']);self.assertEqual(r[0]['names'],[])
        self.assertEqual(set(r[0]['nvn_procedures']),{'nvnUnsupported','nvnAlias'})
    def test_crossed_alias_bodies_typed_entries_and_overlap_reject(self):
        p=[procedure('nvnOriginal',0x1000),procedure('nvnOther',0x1100)]
        with self.assertRaises(InputError):merge_nvn_guards([],p,{'absent'})
        with self.assertRaises(InputError):merge_nvn_guards([],[*p,procedure('alias',0x1000)],{'nvnOriginal'})
        for handler,size,digest in ((451,8,'ab'*32),(31,4,'ab'*32),(31,8,'cd'*32)):
            old=[dict(entry=0x1100,size=size,body_sha256=digest,handler_id=handler,names=[])]
            with self.subTest(handler=handler,size=size),self.assertRaises(InputError):merge_nvn_guards(old,p,{'nvnOriginal'})
        with self.assertRaises(InputError):merge_nvn_guards([],[*p,procedure('overlap',0x1104)],{'nvnOriginal'})
    def test_missing_preceding_profile_rejects(self):
        class Linker:
            def report(self):return {'link_complete':True}
        with self.assertRaises(InputError):extend_nvn_audit(Linker(),{},None)

if __name__=='__main__':unittest.main()
