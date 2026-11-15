"""Artificial canonical frame records; no captured instructions or game data."""
import hashlib,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from input_formats import InputError
from unwind_provenance import prove_extents

class SyntheticModule:
    base=0x53000000;name='synthetic';source_sha256='ab'*32
    ranges=((0x100,0x400),(0x600,0xc00))
    mod0={'exception_start':0x620,'exception_end':0x63c}
    def __init__(self,b_key=False):
        self.image=bytearray(0xc00)
        augmentation=b'zRB\0'if b_key else b'zR\0'
        payload=bytes(4)+b'\1'+augmentation+b'\1\x7c\x1e\1\x1b\x0c\x1f\0'
        payload+=bytes((-len(payload))%4)
        self.cie=0x800;self.first=self.cie+4+len(payload);self.second=self.first+20
        self.put(self.cie,struct.pack('<I',len(payload))+payload)
        self.put(0x620,b'\1\x1b\3\x3b'+struct.pack('<iI4i',self.cie-0x624,2,
            0x180-0x620,self.first-0x620,0x240-0x620,self.second-0x620))
        for fde,pc in ((self.first,0x180),(self.second,0x240)):
            self.put(fde,struct.pack('<IIiI',16,fde+4-self.cie,pc-fde-8,8)+bytes(4))
            self.put(pc,struct.pack('<II',0xd503201f,0xd65f03c0))
        self.seal()
    def put(self,offset,data):self.image[offset:offset+len(data)]=data
    def read(self,offset,size):return bytes(self.image[offset:offset+size])
    def is_code(self,pc):return pc%4==0 and self.ranges[0][0]<=pc<self.ranges[0][1]
    def seal(self):
        self.header={'segments':[dict(hash_verified=True,sha256=hashlib.sha256(self.read(a,b-a)).hexdigest())for a,b in self.ranges]}

class UnwindProvenanceTests(unittest.TestCase):
    def test_both_supported_cies_bind_full_records_source_and_body_without_capabilities(self):
        for b_key in (False,True):
            module=SyntheticModule(b_key)
            records=prove_extents(module,{module.base+0x180,module.base+0x240})
            self.assertEqual([r['size']for r in records],[8,8])
            for record in records:
                self.assertEqual(record['source_kind'],'canonical-unwind-private-entry')
                self.assertEqual(record['source_sha256'],module.source_sha256)
                self.assertEqual(record['b_key_marker'],b_key)
                self.assertFalse(record['runtime_capability'])
                self.assertEqual(record['body_sha256'],hashlib.sha256(module.read(record['entry']-module.base,8)).hexdigest())
                self.assertEqual(len(record['fde_sha256']),64)
                self.assertEqual(len(record['cie_sha256']),64)
                self.assertEqual(len(record['table_sha256']),64)
            self.assertEqual(prove_extents(module,set()),[])

    def test_header_selection_and_record_boundaries_reject(self):
        changes=((0x620,b'\2'),(0x621,b'\0'),(0x622,b'\4'),(0x623,b'\0'),
            (0x624,struct.pack('<i',0xc00-0x624)),(0x628,struct.pack('<I',0)),
            (0x628,struct.pack('<I',0xffffffff)),(0x62c,struct.pack('<i',0x181-0x620)),
            (0x634,struct.pack('<i',0x180-0x620)),(0x630,struct.pack('<i',0x818-0x620)),
            (0x800,struct.pack('<I',0)),(0x800,struct.pack('<I',0xffffffff)),
            (0x800,struct.pack('<I',15)),(0x800,struct.pack('<I',0x800)))
        for at,data in changes:
            with self.subTest(at=at,data=data):
                module=SyntheticModule();module.put(at,data);module.seal()
                with self.assertRaises(InputError):prove_extents(module,{module.base+0x180})
        for delta in (0x184,0x17c,0x400):
            module=SyntheticModule()
            with self.subTest(interior_or_absent=delta),self.assertRaises(InputError):
                prove_extents(module,{module.base+delta})
        module=SyntheticModule()
        with self.assertRaises(InputError):prove_extents(module,{True})

    def test_cie_identity_factors_encoding_and_initial_state_are_narrow(self):
        for at,data in ((0x804,b'\1'),(0x808,b'\3'),(0x80a,b'Q'),(0x80b,b'X'),
                (0x80c,b'\2'),(0x80d,b'\x78'),(0x80e,b'\x1d'),(0x80f,b'\2'),
                (0x810,b'\x18'),(0x811,b'\0'),(0x812,b'\x1e'),(0x813,b'\x7f')):
            module=SyntheticModule();module.put(at,data);module.seal()
            with self.subTest(at=at),self.assertRaises(InputError):prove_extents(module,{module.base+0x180})

    def test_fde_reference_start_range_augmentation_and_overlap_reject(self):
        for field,data in ((4,bytes(4)),(4,struct.pack('<I',0xffffffff)),(4,struct.pack('<I',16)),
                (8,struct.pack('<i',0)),(12,struct.pack('<I',0)),(12,struct.pack('<I',7)),
                (12,struct.pack('<I',0xc4)),(12,struct.pack('<I',0xfffffffc)),(16,b'\1')):
            module=SyntheticModule();module.put(module.first+field,data);module.seal()
            with self.subTest(field=field,data=data),self.assertRaises(InputError):prove_extents(module,{module.base+0x180})
        module=SyntheticModule();module.put(module.second,struct.pack('<I',0xfffffff0));module.seal()
        with self.assertRaises(InputError):prove_extents(module,{module.base+0x240})

    def test_text_rodata_and_verified_source_identity_cannot_change_silently(self):
        for offset in (0x180,0x620,0x800):
            module=SyntheticModule();module.image[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(InputError):prove_extents(module,{module.base+0x180})
        for segment in (0,1):
            module=SyntheticModule();module.header['segments'][segment]['hash_verified']=False
            with self.subTest(segment=segment),self.assertRaises(InputError):prove_extents(module,{module.base+0x180})
        module=SyntheticModule();module.source_sha256='unbound'
        with self.assertRaises(InputError):prove_extents(module,{module.base+0x180})

if __name__=='__main__':unittest.main()
