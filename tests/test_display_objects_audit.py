"""Independent source identities and private-guard alias/extent boundaries."""
from copy import deepcopy
import hashlib,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from display_objects_audit import verify_sdk_identity,merge_private_guards,emit_object_declaration,extend_objects_audit

class Source:
    source_sha256='ab'*32
    ranges=((0,32),(64,96),(128,160))
    def __init__(self):
        self.image=bytearray(range(192))
        self.header={'segments':[dict(hash_verified=True,sha256=hashlib.sha256(self.read(a,b-a)).hexdigest())for a,b in self.ranges]}
    def read(self,at,size):return bytes(self.image[at:at+size])

def guard(entry=0x100,size=8,**changes):
    row=dict(entry=entry,size=size,body_sha256='12'*32,handler_id=31,returns_value=False,
        symbol='artificial_export',names=['artificial_export'],symbol_metadata={'index':1})
    row.update(changes);return row

def proof(*entries):
    return dict(module='sdk',targets=[dict(entry=e,size=8,body_sha256='12'*32,
        source_kind='canonical-unwind-private-entry',runtime_capability=False,slots=[])for e in entries])

class ObjectAuditTests(unittest.TestCase):
    def test_pristine_source_and_live_text_rodata_are_bound_independently(self):
        pristine=Source();linked=deepcopy(pristine)
        identity=dict(source_sha256=pristine.source_sha256,segments=tuple(s['sha256']for s in pristine.header['segments']))
        linked.image[128]^=1
        verify_sdk_identity(pristine,linked,identity)  # Linked DATA may be relocated.
        for change in ('source','text','rodata','original-data','verified','header'):
            a=Source();b=deepcopy(a)
            if change=='source':b.source_sha256='ef'*32
            if change=='text':b.image[0]^=1
            if change=='rodata':b.image[64]^=1
            if change=='original-data':a.image[128]^=1
            if change=='verified':a.header['segments'][1]['hash_verified']=False
            if change=='header':a.header['segments'][2]['sha256']='00'*32
            with self.subTest(change=change),self.assertRaises(InputError):verify_sdk_identity(a,b,identity)

    def test_private_targets_keep_provenance_without_inventing_exports(self):
        rows=[guard()];original=deepcopy(rows);p=proof(0x100,0x180)
        merged=merge_private_guards(rows,p)
        self.assertEqual(rows,original);self.assertEqual(len(merged),2)
        self.assertEqual(merged[0]['names'],['artificial_export'])
        self.assertEqual(len(merged[0]['private_vtable_proofs']),1)
        self.assertIsNone(merged[1]['symbol']);self.assertEqual(merged[1]['names'],[])
        self.assertNotIn('symbol_metadata',merged[1]);self.assertEqual(merged[1]['handler_id'],31)
        self.assertEqual(merged[1]['source_kind'],'canonical-unwind-private-entry')

    def test_conflicting_abi_bodies_and_overlapping_extents_reject(self):
        for changes in ({'handler_id':450},{'returns_value':True},{'size':4},{'body_sha256':'34'*32}):
            with self.subTest(changes=changes),self.assertRaises(InputError):merge_private_guards([guard(**changes)],proof(0x100))
        with self.assertRaises(InputError):merge_private_guards([guard()],proof(0x104))
        with self.assertRaises(InputError):merge_private_guards([guard(),guard()],proof(0x100))
        many=[guard(0x100+i*16)for i in range(4096)]
        with self.assertRaises(InputError):merge_private_guards(many,proof(0x20000))

    def test_compiled_declaration_rejects_malformed_shapes_and_integer_or_hash_injection(self):
        d=dict(version=1,flags=0,width=1920,height=1080,display=0x1000,display_size=64,
            layer=0x2000,layer_size=128,native_window=0x2018,anchor=0x3000,anchor_size=8,
            vptr_address=[0x1000,0x2000,0x2008,0x2018,0x2020],vptr_value=[0x4010]*5,
            anchor_sha256='ab'*32,tables=[dict(address=0x4000+i*32,size=24,sha256='cd'*32)for i in range(8)])
        text='\n'.join(emit_object_declaration(d,'ef'*32))
        self.assertIn('const OotObjectDeclaration *oot_startup_compiled_objects(void)',text)
        self.assertIn('.native_window=UINT64_C(8216)',text)
        for field,value in (('flags',2),('width',-1),('anchor',1<<64),('anchor_sha256','";bad'),('vptr_value',[]),('tables',[])):
            changed=deepcopy(d);changed[field]=value
            with self.subTest(field=field),self.assertRaises(InputError):emit_object_declaration(changed,'ef'*32)

    def test_incomplete_preceding_profile_cannot_authorize_an_object_audit(self):
        class Linker:
            def report(self):return dict(link_complete=True)
        for report in ({},{'display_runtime':True},{'display_initialization':{'skipped_provider_closure':True}}):
            with self.subTest(report=report),self.assertRaises(InputError):extend_objects_audit(Linker(),report,None)

if __name__=='__main__':unittest.main()
