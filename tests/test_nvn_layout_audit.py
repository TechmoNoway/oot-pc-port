"""Artificial instruction/case-table proof; no captured original code."""
import hashlib,struct,unittest
from input_formats import InputError
from nvn_layout_audit import prove_constant_cases,prove_memory_pool_builder,LAYOUT_QUERIES
from test_arm64_analysis import NOP,RET,branch
from test_native_sdk_audit import adr

class LayoutModule:
    base=0x100000
    ranges=((0,512),(4096,8192),(8192,12288))
    def __init__(self):
        self.image=bytearray(12288);words=[NOP]*91
        words[:12]=[0x2a0003e8,0x51000909,0x2a1f03e0,0x7102c13f,NOP,
            0xb000000a,0x9100014a,0x528001c8,adr(self.base+32,self.base+48,11),
            0x3869694c,0x8b0c096b,0xd61f0160]
        for index,value in((12,32),(14,256),(16,4),(18,8)):
            words[index]=0x52800008|(value<<5)
            words[index+1]=branch(self.base+(index+1)*4,self.base+88*4)
        words[88:]=[0x52800020,0xb9000028,RET]
        struct.pack_into('<91I',self.image,0,*words)
        for q,index in((15,12),(16,12),(17,14),(18,14),(19,16),(20,18)):
            self.image[4096+q-2]=index-12
    def read(self,at,size):return bytes(self.image[at:at+size])
    def unpack(self,fmt,at):return struct.unpack_from(fmt,self.image,at)

class NvnLayoutAuditTests(unittest.TestCase):
    def test_retained_storage_setter_preserves_device_and_unwritten_fields(self):
        m=LayoutModule();words=(0xa9010801,0xb900201f,RET)
        raw=struct.pack('<3I',*words);m.image[:12]=raw
        p=dict(name='nvnMemoryPoolBuilderSetStorage',entry=m.base,size=12,body_sha256=hashlib.sha256(raw).hexdigest())
        self.assertEqual(prove_memory_pool_builder(m,p),p)
        # Changing to a broader store at +0 would clobber the device/preserved
        # prefix. Rehashing alone cannot make that altered source acceptable.
        struct.pack_into('<I',m.image,0,0xa9000801)
        p['body_sha256']=hashlib.sha256(m.read(0,12)).hexdigest()
        with self.assertRaises(InputError):prove_memory_pool_builder(m,p)
    def test_constant_paths_require_exact_output_and_return_geometry(self):
        result=prove_constant_cases(LayoutModule(),dict(entry=LayoutModule.base,size=364))
        self.assertEqual({int(k):v['value']for k,v in result['queries'].items()},LAYOUT_QUERIES)
    def test_wrong_constant_case_branch_output_and_bounds_are_rejected(self):
        for at,word in((12*4,NOP),(13*4,RET),(89*4,0xb9000029),(90*4,NOP),(32,NOP)):
            m=LayoutModule();struct.pack_into('<I',m.image,at,word)
            with self.subTest(at=at),self.assertRaises(InputError):
                prove_constant_cases(m,dict(entry=m.base,size=364))
        for value in(1,255):
            m=LayoutModule();m.image[4096+15-2]=value
            with self.subTest(case=value),self.assertRaises(InputError):
                prove_constant_cases(m,dict(entry=m.base,size=364))

if __name__=='__main__':unittest.main()
