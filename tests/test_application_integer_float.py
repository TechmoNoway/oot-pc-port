"""Application-only SCVTF/UCVTF against exact rationals and pinned ARM state."""
from ctypes import POINTER,byref,c_int,c_uint32
from fractions import Fraction
from pathlib import Path
import struct,sys,unittest
import math
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import test_sdk_init_vectors as fixtures
from lifter_validation_types import Memory,State
from sdk_init_instructions import decode_sdk_init_instruction,sdk_init_vector_kind
from input_formats import InputError

def word(width,source,unsigned,rn,rd):
    return 0x1e220000|((source==64)<<31)|((width==64)<<22)|(unsigned<<16)|(rn<<5)|rd

def oracle(value,width):
    # Native Python gives a close starting point; exact rational distances to
    # adjacent representable values resolve both ties and double-rounding cases.
    fmt,bits=('f','I') if width==32 else ('d','Q')
    initial=struct.unpack('<'+bits,struct.pack('<'+fmt,float(value)))[0]
    candidates=range(max(0,initial-2),initial+3) if value else (0,)
    exact=Fraction(value)
    ranked=[]
    for candidate in candidates:
        number=struct.unpack('<'+fmt,struct.pack('<'+bits,candidate))[0]
        ranked.append((abs(Fraction(number)-exact),candidate&1,candidate))
    error,_,result=min(ranked)
    return result,16 if error else 0

class ApplicationIntegerFloatTests(unittest.TestCase):
    fixture=fixtures.SdkInitVectorTests.fixture
    reference_start=fixtures.SdkInitVectorTests.reference_start
    reference_vectors=fixtures.SdkInitVectorTests.reference_vectors
    @classmethod
    def setUpClass(cls):
        fixtures.SdkInitVectorTests.setUpClass.__func__(cls)
        cls.prepare_fn=cls.lib.oot_startup_application_vector_prepare
        cls.prepare_fn.argtypes=cls.lib.oot_startup_vector_prepare.argtypes;cls.prepare_fn.restype=c_int
        cls.kind=cls.lib.oot_startup_application_vector_kind;cls.kind.argtypes=[c_uint32];cls.kind.restype=c_int
    def test_all_register_fields_widths_signedness_ties_and_full_state_match_reference(self):
        vectors,state,memory,backing,keep=self.fixture()
        values=(0,1,0xffffffff,0xffffffffffffffff,0x80000000,0x8000000000000000,
            (1<<24)+1,(1<<24)+3,(1<<53)+1,(1<<53)+3,(1<<63)+(1<<39)+1)
        for width in (32,64):
            for source in (32,64):
                for unsigned in (0,1):
                    for rn in range(32):
                        for rd in range(32):
                            instruction=word(width,source,unsigned,rn,rd)
                            registers=State.from_buffer_copy(state)
                            if rn!=31:registers.x[rn]=values[(rn+rd)%len(values)]
                            v=fixtures.VectorState.from_buffer_copy(vectors);v.fpcr=(rn&1)<<24;v.fpsr=0x8000001
                            self.reference_start(v,registers,backing,[instruction])
                            expected=self.reference.step(registers,instruction);expected_vectors=self.reference_vectors()
                            out=fixtures.VectorState();result=State();write=fixtures.VectorWrite()
                            self.assertEqual(self.prepare_fn(byref(v),instruction,byref(registers),byref(memory),byref(out),byref(result),byref(write)),0)
                            self.assertEqual(result.values(),expected.values());self.assertEqual(bytes(out),expected_vectors)
                            self.assertEqual(write.size,0)
                            value=0 if rn==31 else registers.x[rn]&((1<<source)-1)
                            if not unsigned and value>>(source-1):value-=1<<source
                            bits,flags=oracle(value,width)
                            self.assertEqual(bytes(out.q[rd]),bits.to_bytes(width//8,'little')+bytes(16-width//8))
                            self.assertEqual(out.fpsr,v.fpsr|flags)
    def test_legacy_and_reserved_domains_and_fault_outputs_remain_unchanged(self):
        vectors,state,memory,backing,keep=self.fixture();instruction=word(32,32,1,8,8)
        self.assertIsNone(sdk_init_vector_kind(instruction));self.assertEqual(self.lib.oot_startup_vector_kind(instruction),0)
        with self.assertRaises(InputError):decode_sdk_init_instruction(instruction,fixtures.BASE)
        self.assertEqual(decode_sdk_init_instruction(instruction,fixtures.BASE,application=True).operation,23)
        for bit in (10,11,12,13,14,15,17,18,19,20,21,23,24,25,26,27,28,29,30):
            other=instruction^(1<<bit);self.assertFalse(self.kind(other))
        for mutation in ('old','sp','pc','nzcv','fpcr','fpsr','alias'):
            v=fixtures.VectorState.from_buffer_copy(vectors);r=State.from_buffer_copy(state)
            if mutation=='sp':r.sp+=8
            if mutation=='pc':r.pc+=1
            if mutation=='nzcv':r.nzcv|=1
            if mutation=='fpcr':v.fpcr=1
            if mutation=='fpsr':v.fpsr=1<<28
            out=fixtures.VectorState.from_buffer_copy(bytes([0xa5])*520);result=State();write=fixtures.VectorWrite()
            before=(bytes(v),bytes(r),bytes(out),bytes(result),bytes(write),bytes(backing))
            fn=self.lib.oot_startup_vector_prepare if mutation=='old' else self.prepare_fn
            self.assertEqual(fn(byref(v),instruction,byref(r),byref(memory),byref(v if mutation=='alias' else out),byref(result),byref(write)),1 if mutation=='old' else 2)
            self.assertEqual((bytes(v),bytes(r),bytes(out),bytes(result),bytes(write),bytes(backing)),before)

    def test_float_to_integer_all_fields_nan_infinity_bounds_and_fractional_values(self):
        vectors,state,memory,backing,keep=self.fixture()
        numbers=(0.0,-0.0,1.0,-1.0,1.5,-0.5,-1.5,float('inf'),-float('inf'),float('nan'),
            float(1<<31),-float(1<<31),float(1<<32),float(1<<63),-float(1<<63),float(1<<64),
            2.0**-126,2.0**-149,2.0**-1022,2.0**-1074,2147483647.75,-2147483648.75)
        for width in (32,64):
            for destination in (32,64):
                for unsigned in (0,1):
                    for rn in range(32):
                        for rd in range(32):
                            instruction=word(width,destination,unsigned,rn,rd)^0x001a0000
                            v=fixtures.VectorState.from_buffer_copy(vectors);v.fpcr=(rn&1)<<24;v.fpsr=0x8000000|((rn&2)<<3)
                            fmt='f' if width==32 else 'd';encoded=struct.pack('<'+fmt,numbers[(rn+rd)%len(numbers)])
                            if (rn+rd)%31==0:encoded=(0x7f800001 if width==32 else 0x7ff0000000000001).to_bytes(width//8,'little')
                            v.q[rn][:len(encoded)]=encoded
                            self.reference_start(v,state,backing,[instruction])
                            expected=self.reference.step(state,instruction);expected_vectors=self.reference_vectors()
                            out=fixtures.VectorState();result=State();write=fixtures.VectorWrite()
                            self.assertEqual(self.prepare_fn(byref(v),instruction,byref(state),byref(memory),byref(out),byref(result),byref(write)),0)
                            self.assertEqual(result.values(),expected.values(),hex(instruction));self.assertEqual(bytes(out),expected_vectors,(hex(instruction),encoded.hex()))
                            self.assertEqual(write.size,0);self.assertEqual(self.lib.oot_startup_vector_kind(instruction),0)
                            self.assertEqual(self.kind(instruction),2)
                            self.assertEqual(decode_sdk_init_instruction(instruction,fixtures.BASE,application=True).operation,24)
                            number=struct.unpack('<'+fmt,encoded)[0];flags=0;minimum=0 if unsigned else -(1<<(destination-1));maximum=(1<<(destination-(not unsigned)))-1
                            if math.isnan(number):value=0;flags=1
                            elif math.isinf(number):value=minimum if number<0 else maximum;flags=1
                            elif v.fpcr and number and abs(number)<(2.0**(-126 if width==32 else -1022)):value=0;flags=128
                            else:
                                rational=Fraction(number);value=abs(rational.numerator)//rational.denominator
                                if number<0:value=-value
                                if value<minimum or value>maximum:value=min(max(value,minimum),maximum);flags=1
                                elif Fraction(value)!=rational:flags=16
                            if rd!=31:self.assertEqual(result.x[rd],value&((1<<destination)-1))
                            self.assertEqual(out.fpsr,v.fpsr|flags)

if __name__=='__main__':unittest.main()
