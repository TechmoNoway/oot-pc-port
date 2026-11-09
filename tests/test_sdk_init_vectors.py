"""Pinned ARM64 reference comparisons for initialization-only SIMD transfers."""

from ctypes import (POINTER,Structure,byref,c_int,c_size_t,c_uint8,c_uint32,c_uint64,c_void_p,sizeof,cast)
from importlib.metadata import version
import hashlib
import os
from pathlib import Path
import random
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from input_formats import InputError
from lifter_validation import compile_library
from lifter_validation_types import BASE,Memory,Region,State
from pauth_validation import Reference,STACK
from sdk_instructions import decode_sdk_instruction
from sdk_init_instructions import decode_sdk_init_instruction,sdk_init_vector_kind,sdk_init_atomic_kind
from test_sdk_init_dispatch import InitSession,SOURCE


class VectorState(Structure):
    _fields_=[('q',(c_uint8*16)*32),('fpcr',c_uint32),('fpsr',c_uint32)]


class VectorWrite(Structure):
    _fields_=[('address',c_uint64),('size',c_uint32),('bytes',c_uint8*64)]


def pair(size,load,rt,rt2,rn,mode,immediate):
    return (size<<30)|0x2c000000|(mode<<23)|(int(load)<<22)|((immediate&127)<<15)|(rt2<<10)|(rn<<5)|rt


def single(element,load,rt,rn,mode,immediate):
    size={4:2,8:3,16:0}[element]
    opc=int(load)|(2 if element==16 else 0)
    if mode=='unsigned':return size<<30|0x3d000000|opc<<22|immediate<<10|rn<<5|rt
    return size<<30|0x3c000000|opc<<22|(immediate&511)<<12|mode<<10|rn<<5|rt


def movi(q,op,cmode,immediate,rd):
    return 0x0f000400|q<<30|op<<29|(immediate>>5)<<16|cmode<<12|(immediate&31)<<5|rd


class SdkInitVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if version('unicorn')!='2.1.4':raise AssertionError('vector reference requires pinned Unicorn2.1.4')
        cls.reference=Reference()
        cls.reference.u.cpr_write(3,0,1,0,2,3<<20)
        if cls.reference.u.cpr_read(3,0,1,0,2)&(3<<20)!=3<<20:
            raise AssertionError('reference FP/ASIMD access is disabled')
        cls.qregs=[getattr(cls.reference.r,f'UC_ARM64_REG_Q{n}') for n in range(32)]
        cls.lib,cls.build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),startup=True,
            extra_source=SOURCE+'#include "startup_vector.h"\n'
                'OOT_LIFT_EXPORT size_t oot_test_vector_size(unsigned n) {\n'
                'return n?sizeof(OotStartupVectorWrite):sizeof(OotStartupVectorState);}\n')
        signatures={
            'oot_startup_vector_init':([POINTER(VectorState)],None),
            'oot_startup_vector_kind':([c_uint32],c_int),
            'oot_startup_vector_prepare':([POINTER(VectorState),c_uint32,POINTER(State),POINTER(Memory),
                POINTER(VectorState),POINTER(State),POINTER(VectorWrite)],c_int),
            'oot_memory_init':([POINTER(Memory),POINTER(Region),c_size_t],c_int),
            'oot_memory_store_record':([POINTER(Memory),c_uint64,POINTER(c_uint8),c_uint32],c_int),
            'oot_startup_context_vector_step':([c_void_p,c_uint32,POINTER(State)],c_int),
            'oot_startup_context_vectors':([c_void_p],POINTER(VectorState)),
            'oot_test_vector_size':([c_uint32],c_size_t)}
        for name,(args,result) in signatures.items():
            function=getattr(cls.lib,name);function.argtypes,function.restype=args,result
        if (cls.lib.oot_test_vector_size(0),cls.lib.oot_test_vector_size(1))!=(sizeof(VectorState),sizeof(VectorWrite)):
            raise AssertionError('vector native layout differs')

    def fixture(self,seed=1,permissions=3):
        rng=random.Random(seed)
        vectors=VectorState.from_buffer_copy(rng.randbytes(512)+bytes(8))
        registers=State()
        for n in range(31):registers.x[n]=rng.getrandbits(64)
        registers.x[6]=STACK+0x800;registers.pc=BASE;registers.sp=STACK+0x800;registers.nzcv=0xd0000000
        backing=(c_uint8*4096).from_buffer_copy(rng.randbytes(4096))
        table=(Region*1)(Region(STACK,4096,backing,permissions))
        memory=Memory();self.assertTrue(self.lib.oot_memory_init(byref(memory),table,1))
        return vectors,registers,memory,backing,table

    def prepare(self,vectors,word,registers,memory,status=0):
        next_state=VectorState.from_buffer_copy(bytes([0xa5])*sizeof(VectorState))
        result=State.from_buffer_copy(bytes([0xb6])*sizeof(State))
        write=VectorWrite.from_buffer_copy(bytes([0xc7])*sizeof(VectorWrite))
        before=(bytes(vectors),bytes(registers));outputs=(bytes(next_state),bytes(result),bytes(write))
        self.assertEqual(self.lib.oot_startup_vector_prepare(byref(vectors),word,byref(registers),byref(memory),
            byref(next_state),byref(result),byref(write)),status)
        self.assertEqual((bytes(vectors),bytes(registers)),before)
        if status:self.assertEqual((bytes(next_state),bytes(result),bytes(write)),outputs)
        return next_state,result,write

    def reference_start(self,vectors,registers,backing,words):
        reference=self.reference
        reference.code(struct.pack('<'+'I'*len(words),*words))
        reference.u.mem_write(STACK,bytes(backing))
        for register,value in zip(self.qregs,vectors.q):reference.u.reg_write(register,int.from_bytes(bytes(value),'little'))
        reference.u.reg_write(reference.r.UC_ARM64_REG_FPCR,vectors.fpcr)
        reference.u.reg_write(reference.r.UC_ARM64_REG_FPSR,vectors.fpsr)

    def reference_vectors(self):
        return b''.join(self.reference.u.reg_read(register).to_bytes(16,'little') for register in self.qregs)+struct.pack('<II',
            self.reference.u.reg_read(self.reference.r.UC_ARM64_REG_FPCR),self.reference.u.reg_read(self.reference.r.UC_ARM64_REG_FPSR))

    def compare_step(self,vectors,registers,memory,backing,word):
        self.assertIsNotNone(sdk_init_vector_kind(word))
        self.assertIsNone(sdk_init_atomic_kind(word))
        self.assertEqual(decode_sdk_init_instruction(word,BASE).form,'sdk_init_vector')
        expected=self.reference.step(registers,word)
        expected_vectors=self.reference_vectors()
        expected_memory=bytes(self.reference.u.mem_read(STACK,4096))
        before=bytes(backing)
        next_state,result,write=self.prepare(vectors,word,registers,memory)
        self.assertEqual(bytes(backing),before)
        if write.size:
            self.assertIn(write.size,(1,2,4,8,16,32))
            self.assertTrue(self.lib.oot_memory_store_record(byref(memory),write.address,write.bytes,write.size))
        self.assertEqual(result.values(),expected.values())
        self.assertEqual(bytes(next_state),expected_vectors,getattr(self,'fp_case',None))
        self.assertEqual(bytes(backing),expected_memory)
        return next_state,result

    def test_decoder_domain_and_old_decoders_remain_separate(self):
        for size in range(3):
            for load in (False,True):
                for mode in (1,2,3):
                    for immediate in (-64,-1,0,1,63):
                        word=pair(size,load,31,0,6,mode,immediate)
                        ins=decode_sdk_init_instruction(word,BASE)
                        self.assertEqual((ins.form,ins.width,ins.rd,ins.rt2,ins.rn,ins.immediate,
                            ins.operation,ins.load),('sdk_init_vector',32<<size,31,0,6,immediate*(4<<size),mode,load))
                        self.assertEqual(self.lib.oot_startup_vector_kind(word),1)
                        with self.assertRaises(InputError):decode_sdk_instruction(word,BASE)
        for word in (pair(3,False,0,1,6,2,0),pair(2,False,0,1,6,0,0),pair(2,True,7,7,6,2,0),
            0xd503201f,0xadbf1fe6^(1<<26),0xffffffff):
            self.assertIsNone(sdk_init_vector_kind(word));self.assertFalse(self.lib.oot_startup_vector_kind(word))

    def test_single_lane_and_general_fmov_match_pinned_reference(self):
        # Arm DUI 0802B 9.203; no post-index, register-offset or multi-register forms.
        for element in (1,2,4,8):
            for index in range(16//element):
                for load in (False,True):
                    if element==1:q,s,size=index>>3,index>>2&1,index&3;opcode=0
                    elif element==2:q,s,size=index>>2,index>>1&1,(index&1)<<1;opcode=2
                    elif element==4:q,s,size=index>>1,index&1,0;opcode=4
                    else:q,s,size=index,0,1;opcode=4
                    for rt,rn in ((0,6),(6,6),(31,31)):
                        word=0x0d000000|(q<<30)|(int(load)<<22)|(opcode<<13)|(s<<12)|(size<<10)|(rn<<5)|rt
                        ins=decode_sdk_init_instruction(word,BASE)
                        self.assertEqual((ins.access_size,ins.immediate,ins.load),(element,index,load))
                        with self.assertRaises(InputError):decode_sdk_instruction(word,BASE)
                        vectors,registers,memory,backing,keep=self.fixture(word)
                        self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)
        for base in (0x1e260000,0x1e270000,0x9e660000,0x9e670000):
            for rn in (0,6,31):
                for rt in (0,6,31):
                    word=base|(rn<<5)|rt
                    vectors,registers,memory,backing,keep=self.fixture(word)
                    self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)
                    with self.assertRaises(InputError):decode_sdk_instruction(word,BASE)
        for word in (0x0d002000,0x0d004400,0x0d008800,0x0d009400,0x0d010000,0x0d200000,0x0d800000,0x9eae0000):
            self.assertIsNone(sdk_init_vector_kind(word));self.assertFalse(self.lib.oot_startup_vector_kind(word))

    def test_lane_transfer_faults_preserve_complete_register_bank_and_staged_outputs(self):
        for load in (False,True):
            word=0x4d008100|(int(load)<<22) # S lane 2, [X8].
            vectors,registers,memory,backing,keep=self.fixture(321,permissions=2 if load else 1)
            registers.x[8]=STACK+128
            before=bytes(backing);self.prepare(vectors,word,registers,memory,status=2);self.assertEqual(bytes(backing),before)
            vectors,registers,memory,backing,keep=self.fixture(322)
            registers.x[8]=STACK+4094
            before=bytes(backing);self.prepare(vectors,word,registers,memory,status=2);self.assertEqual(bytes(backing),before)

    def test_scalar_fp_compare_select_move_and_exception_state_match_reference(self):
        for width in (32,64):
            sign=1<<(width-1);exp=0x7f800000 if width==32 else 0x7ff0000000000000
            one=0x3f800000 if width==32 else 0x3ff0000000000000
            quiet=1<<(22 if width==32 else 51)
            values=[0,sign,1,sign|1,one,sign|one,exp,sign|exp,exp|1,exp|quiet|7]
            dtype=0x400000 if width==64 else 0
            for a in values:
                for b in values:
                    for signal in (0,16):
                        word=0x1e222020|dtype|signal # FCMP(E) S/D1, S/D2.
                        vectors,registers,memory,backing,keep=self.fixture(word)
                        vectors.q[1][:width//8]=a.to_bytes(width//8,'little');vectors.q[2][:width//8]=b.to_bytes(width//8,'little')
                        vectors.fpsr=0x08000002
                        self.fp_case=(width,'compare',hex(a),hex(b))
                        self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)
            for condition in range(16):
                for nzcv in range(16):
                    word=0x1e220c20|dtype|(condition<<12)
                    vectors,registers,memory,backing,keep=self.fixture(word);registers.nzcv=nzcv<<28
                    self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)
            for word in (0x1e204021|dtype,0x1e202028|dtype,0x1e202038|dtype):
                vectors,registers,memory,backing,keep=self.fixture(word)
                self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)

    def test_fccmp_all_conditions_fallback_flags_and_lazy_fp_exceptions_match_reference(self):
        for width in (32,64):
            snan=0x7f800001 if width==32 else 0x7ff0000000000001
            for fpcr in (0,1<<24):
                for condition in range(16):
                    for nzcv in range(16):
                        for fallback in (0,5,10,15):
                            for signal in (0,16):
                                word=0x1e220420|(0x400000 if width==64 else 0)|(condition<<12)|fallback|signal
                                vectors,registers,memory,backing,keep=self.fixture(word);vectors.fpcr=fpcr;registers.nzcv=nzcv<<28
                                vectors.q[1][:width//8]=snan.to_bytes(width//8,'little');vectors.q[2][:width//8]=(1).to_bytes(width//8,'little')
                                self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)

    def test_finite_scalar_arithmetic_matches_reference_bits_and_cumulative_exceptions(self):
        for width in (32,64):
            sign=1<<(width-1);exp=0x7f800000 if width==32 else 0x7ff0000000000000
            one=0x3f800000 if width==32 else 0x3ff0000000000000
            tiny=0x800000 if width==32 else 0x10000000000000
            values=[0,sign,1,sign|1,tiny-1,tiny,one,one+1,one-(tiny>>1),sign|one,exp-1,sign|(exp-1)]
            for operation in range(4):
                for a in values:
                    for b in values:
                        word=0x1e220820|(0x400000 if width==64 else 0)|(operation<<12)
                        self.fp_case=(width,operation,hex(a),hex(b))
                        vectors,registers,memory,backing,keep=self.fixture(word)
                        vectors.q[1][:width//8]=a.to_bytes(width//8,'little');vectors.q[2][:width//8]=b.to_bytes(width//8,'little')
                        vectors.fpsr=0x08000002
                        self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)

    def test_fp_control_and_unsupported_arithmetic_operands_preserve_candidates(self):
        word=0x1e222820
        vectors,registers,memory,backing,keep=self.fixture(322)
        vectors.q[1][:4]=(0x7f800001).to_bytes(4,'little')
        self.prepare(vectors,word,registers,memory,status=1)
        vectors.fpcr=1
        self.prepare(vectors,word,registers,memory,status=2)
        vectors.fpcr=0;vectors.fpsr=0x40000000
        self.prepare(vectors,word,registers,memory,status=2)

    def test_default_fp_sign_operations_preserve_payloads_and_exception_state(self):
        words=[0x1e20c000,0x1e214000,0x1e60c000,0x1e614000,
            0x0ea0f800,0x2ea0f800,0x4ea0f800,0x6ea0f800,0x4ee0f800,0x6ee0f800]
        for base in words:
            for rn,rd in ((0,0),(1,0),(31,31)):
                word=base|(rn<<5)|rd
                for seed in (1,2,3):
                    vectors,registers,memory,backing,keep=self.fixture(seed)
                    vectors.fpsr=0x08000002
                    if seed==1:vectors.q[rn][:]=bytes.fromhex('0100807f010080ff0100807f010080ff')
                    if seed==2:vectors.q[rn][:]=bytes.fromhex('010000000000f07f010000000000f0ff')
                    self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)

    def test_fmadd_fused_results_tininess_cancellation_and_sqrt_match_reference(self):
        for width in (32,64):
            sign=1<<(width-1);tiny=1<<(23 if width==32 else 52)
            one=0x3f800000 if width==32 else 0x3ff0000000000000
            exp=0x7f800000 if width==32 else 0x7ff0000000000000
            values=[0,sign,1,sign|1,tiny-1,tiny,one,one+1,one-(tiny>>1),sign|one,exp-1]
            for fpcr in (0,1<<24):
                for a in values:
                    for b in values:
                        for c in values:
                            word=0x1f020c20|(0x400000 if width==64 else 0)
                            vectors,registers,memory,backing,keep=self.fixture(word);vectors.fpcr=fpcr
                            for register,value in ((1,a),(2,b),(3,c)):vectors.q[register][:width//8]=value.to_bytes(width//8,'little')
                            self.fp_case=(fpcr,width,'fmadd',hex(a),hex(b),hex(c))
                            self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)
                for a in values+[exp,sign|exp,exp|1,exp|(1<<(22 if width==32 else 51))]:
                    word=0x1e21c020|(0x400000 if width==64 else 0)
                    vectors,registers,memory,backing,keep=self.fixture(word);vectors.fpcr=fpcr
                    vectors.q[1][:width//8]=a.to_bytes(width//8,'little');self.fp_case=(fpcr,width,'sqrt',hex(a))
                    self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)

    def test_fused_cancellation_detects_tininess_before_rounding(self):
        from fractions import Fraction
        def exact_bits(significand,power,fraction,bias):
            length=significand.bit_length();shift=fraction+1-length
            self.assertGreaterEqual(shift,0)
            normalized=significand<<shift;exponent=power+length-1+bias
            self.assertGreater(exponent,0)
            return exponent<<fraction | (normalized&((1<<fraction)-1))
        for width,p,bias,u in ((32,23,127,3),(64,52,1023,6361)):
            v=((1<<(p+1))-1)//u
            self.assertEqual(u*v,(1<<(p+1))-1)
            sa,sb=(1<<p)+u,(1<<p)+v
            product=sa*sb;low=p+1;rounded=(product>>low)
            minimum=1-bias;power=minimum-low;ea=power//2;eb=power-ea
            a=exact_bits(sa,ea,p,bias);b=exact_bits(sb,eb,p,bias)
            c=exact_bits(rounded,minimum,p,bias)|(1<<(width-1))
            exact=Fraction(product-(rounded<<low))*Fraction(2)**power
            self.assertEqual(exact,Fraction(2)**minimum-Fraction(2)**(minimum-p-1))
            for fpcr in (0,1<<24):
                vectors,registers,memory,backing,keep=self.fixture(width);vectors.fpcr=fpcr
                for reg,value in ((1,a),(2,b),(3,c)):vectors.q[reg][:width//8]=value.to_bytes(width//8,'little')
                word=0x1f020c20|(int(width==64)<<22)
                self.reference_start(vectors,registers,backing,[word])
                result,_=self.compare_step(vectors,registers,memory,backing,word)
                self.assertEqual(int.from_bytes(bytes(result.q[0]),'little'),0 if fpcr else 1<<p)
                self.assertEqual(result.fpsr,8 if fpcr else 24)

    def test_fused_sign_variants_aliases_and_exact_arithmetic(self):
        rng=random.Random(0x1013)
        for width in (32,64):
            exponent=0x7f800000 if width==32 else 0x7ff0000000000000
            one=0x3f800000 if width==32 else 0x3ff0000000000000
            sign=1<<(width-1)
            values=[0,sign,1,sign|1,one,one+1,sign|one,exponent-1]
            for fpcr in (0,1<<24):
                for variant in (0,0x8000,0x200000,0x208000):
                    for case in range(150):
                        fields=(0,1,2,3) if case%2 else (31,31,31,31)
                        rd,rn,rm,ra=fields
                        word=0x1f000000|(int(width==64)<<22)|variant|rm<<16|ra<<10|rn<<5|rd
                        vectors,registers,memory,backing,keep=self.fixture(case);vectors.fpcr=fpcr
                        for reg in set((rn,rm,ra)):
                            value=values[case%len(values)] if case<40 else rng.getrandbits(width)
                            if value&exponent==exponent:value^=1<<(width-2)
                            vectors.q[reg][:width//8]=value.to_bytes(width//8,'little')
                        self.fp_case=(width,fpcr,variant,case)
                        self.reference_start(vectors,registers,backing,[word])
                        self.compare_step(vectors,registers,memory,backing,word)

    def test_scalar_conversion_flush_mode_and_control_registers_match_reference(self):
        values32=[0,0x80000000,1,0x7fffff,0x800000,0x3f800001,0x7f7fffff,0x7f800000,0x7f800001,0x7fc00007]
        values64=[0,0x8000000000000000,1,0x3810000000000000-1,0x3810000000000000,0x3ff0000000000001,
            0x7fefffffffffffff,0x7ff0000000000000,0x7ff0000000000001,0x7ff8000000000007]
        for fpcr in (0,1<<24):
            for target,word,values in ((64,0x1e22c020,values32),(32,0x1e624020,values64)):
                for value in values:
                    vectors,registers,memory,backing,keep=self.fixture(word);vectors.fpcr=fpcr
                    vectors.q[1][:(96-target)//8]=value.to_bytes((96-target)//8,'little')
                    self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)
            for width,values in ((32,values32),(64,values64)):
                for operation in range(4):
                    for a in values[:7]:
                        for b in values[:7]:
                            word=0x1e220820|(0x400000 if width==64 else 0)|(operation<<12)
                            vectors,registers,memory,backing,keep=self.fixture(word);vectors.fpcr=fpcr
                            vectors.q[1][:width//8]=a.to_bytes(width//8,'little');vectors.q[2][:width//8]=b.to_bytes(width//8,'little')
                            self.fp_case=(fpcr,width,operation,hex(a),hex(b))
                            self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)
                for a in values:
                    word=0x1e222020|(0x400000 if width==64 else 0)
                    vectors,registers,memory,backing,keep=self.fixture(word);vectors.fpcr=fpcr
                    vectors.q[1][:width//8]=a.to_bytes(width//8,'little');vectors.q[2][:width//8]=(1).to_bytes(width//8,'little')
                    self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)
            for word,value in ((0xd53b4400,0),(0xd53b4420,0),(0xd51b4400,fpcr),(0xd51b4420,0x0800009f),(0xd51b441f,0)):
                vectors,registers,memory,backing,keep=self.fixture(word);vectors.fpcr=fpcr;vectors.fpsr=0x0800001f;registers.x[0]=value
                self.reference_start(vectors,registers,backing,[word]);self.compare_step(vectors,registers,memory,backing,word)
        for word,value in ((0xd51b4400,1<<22),(0xd51b4420,1<<31)):
            vectors,registers,memory,backing,keep=self.fixture(word);registers.x[0]=value
            self.prepare(vectors,word,registers,memory,status=1)

    def test_all_sizes_modes_offsets_and_register_banks_match_pinned_reference(self):
        count=0
        for size in range(3):
            for load in (False,True):
                for mode in (1,2,3):
                    for immediate in (-64,-1,0,1,63):
                        for rt,rt2,rn in ((0,1,6),(6,7,6),(31,30,6),(0,31,31)):
                            if rn==31 and mode!=2 and immediate*(4<<size)%16:continue
                            word=pair(size,load,rt,rt2,rn,mode,immediate)
                            vectors,registers,memory,backing,keep=self.fixture(count+23)
                            self.reference_start(vectors,registers,backing,[word])
                            self.compare_step(vectors,registers,memory,backing,word);count+=1
        self.assertGreaterEqual(count,300)

    def test_resolver_shaped_save_restore_every_prefix_matches_full_bank_and_bytes(self):
        words=[pair(2,False,n,n+1,31,3,-2) for n in range(0,32,2)]
        words += [pair(2,True,n,n+1,31,1,2) for n in range(30,-1,-2)]
        for prefix in range(len(words)+1):
            vectors,registers,memory,backing,keep=self.fixture(0x451)
            initial_vectors,initial_registers=bytes(vectors),State.from_buffer_copy(registers)
            self.reference_start(vectors,registers,backing,words)
            for word in words[:prefix]:vectors,registers=self.compare_step(vectors,registers,memory,backing,word)
            if prefix==len(words):
                self.assertEqual(bytes(vectors),initial_vectors)
                self.assertEqual(registers.sp,initial_registers.sp)
                self.assertEqual(tuple(registers.x),tuple(initial_registers.x))
                self.assertEqual(registers.nzcv,initial_registers.nzcv)

    def test_s_and_d_loads_clear_all_upper_destination_bits(self):
        for size in (0,1):
            vectors,registers,memory,backing,keep=self.fixture()
            word=pair(size,True,31,6,6,2,0)
            next_state,result,write=self.prepare(vectors,word,registers,memory)
            element=4<<size
            self.assertEqual(bytes(next_state.q[31][element:]),bytes(16-element))
            self.assertEqual(bytes(next_state.q[6][element:]),bytes(16-element))
            self.assertEqual((write.size,result.x[6]),(0,registers.x[6]))

    def test_single_s_d_q_immediate_transfers_match_full_reference_state(self):
        cases=0
        for element in (4,8,16):
            for load in (False,True):
                for mode in ('unsigned',0,1,3):
                    for immediate in ((0,1,63) if mode=='unsigned' else (-256,-32,-1,0,1,32,255)):
                        for rt,rn in ((0,6),(6,6),(31,31)):
                            if rn==31 and mode in (1,3) and immediate%16:continue
                            word=single(element,load,rt,rn,mode,immediate)
                            vectors,registers,memory,backing,keep=self.fixture(1000+cases)
                            ins=decode_sdk_init_instruction(word,BASE)
                            self.assertEqual((ins.form,ins.access_size,ins.load,ins.rd,ins.rn),
                                ('sdk_init_vector',element,load,rt,rn))
                            with self.assertRaises(InputError):decode_sdk_instruction(word,BASE)
                            self.reference_start(vectors,registers,backing,[word])
                            self.compare_step(vectors,registers,memory,backing,word);cases+=1
        self.assertGreater(cases,300)

    def test_integer_movi_patterns_match_reference_including_zero_upper_half(self):
        cases=0
        for q in (0,1):
            for op,cmode in [(0,n) for n in (0,2,4,6,8,10,12,13,14)]+[(1,14)]:
                for immediate in (0,1,0x43,0xa5,0xff):
                    word=movi(q,op,cmode,immediate,31 if cases%2 else 0)
                    vectors,registers,memory,backing,keep=self.fixture(2000+cases)
                    self.reference_start(vectors,registers,backing,[word])
                    next_state,result=self.compare_step(vectors,registers,memory,backing,word)
                    if not q:self.assertEqual(bytes(next_state.q[word&31][8:]),bytes(8))
                    self.assertEqual(decode_sdk_init_instruction(word,BASE).operation,8)
                    with self.assertRaises(InputError):decode_sdk_instruction(word,BASE)
                    cases+=1
        self.assertEqual(cases,100)

    def test_scalar_fmov_all_immediates_is_exact_bit_transfer_without_fp_flags(self):
        for width in (32,64):
            for immediate in range(256):
                word=0x1e201000|(int(width==64)<<22)|(immediate<<13)|(31 if immediate&1 else 0)
                vectors,registers,memory,backing,keep=self.fixture(3000+immediate)
                self.reference_start(vectors,registers,backing,[word])
                before=self.reference.u.reg_read(self.reference.r.UC_ARM64_REG_FPSR)
                next_state,result=self.compare_step(vectors,registers,memory,backing,word)
                self.assertEqual(self.reference.u.reg_read(self.reference.r.UC_ARM64_REG_FPSR),before)
                self.assertEqual(bytes(next_state.q[word&31][width//8:]),bytes(16-width//8))
                self.assertEqual(decode_sdk_init_instruction(word,BASE).operation,9)

    def test_dup_general_all_lane_sizes_ignored_encoding_bits_and_zero_register(self):
        cases=0
        for q in (0,1):
            for imm5 in range(32):
                low=imm5&15
                if not low or (low==8 and not q):continue
                for rn in (0,6,31):
                    word=0x0e000c00|q<<30|imm5<<16|rn<<5|31
                    vectors,registers,memory,backing,keep=self.fixture(4000+cases)
                    self.reference_start(vectors,registers,backing,[word])
                    next_state,result=self.compare_step(vectors,registers,memory,backing,word)
                    self.assertEqual(decode_sdk_init_instruction(word,BASE).operation,10)
                    if not q:self.assertEqual(bytes(next_state.q[31][8:]),bytes(8))
                    if rn==31:self.assertEqual(bytes(next_state.q[31]),bytes(16))
                    cases+=1
        self.assertGreater(cases,100)

    def test_new_transfer_domain_keeps_other_simd_and_fp_operations_closed(self):
        vectors,registers,memory,backing,keep=self.fixture()
        words=[single(4,True,0,6,2,0),single(4,False,0,6,'unsigned',0)^(1<<31),
            0x1ee04000,0x1e204800,0x4e208400,0x9eae0000,
            0x0e000c00,0x0e080c00,0x1ee01000]
        words += [movi(1,0,cmode,0x55,0) for cmode in (1,3,5,7,9,11,15)]
        words += [movi(1,1,cmode,0x55,0) for cmode in (0,2,4,6,8,10,12,13,15)]
        for word in words:
            self.assertIsNone(sdk_init_vector_kind(word),hex(word))
            self.assertFalse(self.lib.oot_startup_vector_kind(word),hex(word))
            self.prepare(vectors,word,registers,memory,1)
        for element in (4,8,16):
            for load in (False,True):
                backing=(c_uint8*4096)();table=(Region*1)(Region(STACK,0x808,backing,3))
                self.assertTrue(self.lib.oot_memory_init(byref(memory),table,1))
                registers.x[6]=STACK+0x808-element+1
                word=single(element,load,0,6,1,16)
                before=bytes(backing);self.prepare(vectors,word,registers,memory,2)
                self.assertEqual(bytes(backing),before)
                self.assertEqual(memory.fault.size,element)

    def test_pair_faults_preserve_candidates_entire_memory_and_writeback(self):
        for load in (False,True):
            for reason in ('permission','unmapped'):
                vectors,registers,memory,backing,keep=self.fixture()
                first=Region(STACK,0x810,backing,3)
                second=Region(STACK+0x810,4096-0x810,cast(byref(backing,0x810),POINTER(c_uint8)),2 if load else 1)
                table=(Region*2)(first,second)
                self.assertTrue(self.lib.oot_memory_init(byref(memory),table,2 if reason=='permission' else 1))
                word=pair(2,load,0,1,6,1,2)
                before=bytes(backing);self.prepare(vectors,word,registers,memory,2)
                self.assertEqual(bytes(backing),before)
                self.assertEqual((memory.fault.address,memory.fault.failing_address,memory.fault.size,
                    memory.fault.access,memory.fault.reason),(STACK+0x800,STACK+0x810,32,1 if load else 2,
                    2 if reason=='permission' else 1))
        # A repeated store source is valid; the banks are distinct from Xn.
        vectors,registers,memory,backing,keep=self.fixture(permissions=2)
        next_state,result,write=self.prepare(vectors,pair(2,False,6,6,6,2,0),registers,memory)
        self.assertEqual(bytes(write.bytes[:32]),bytes(vectors.q[6])*2)

    def test_bad_protocol_addresses_alignment_and_aliases_preserve_outputs(self):
        vectors,original,memory,backing,keep=self.fixture()
        for field,value in (('pc',BASE+1),('pc',1<<39),('nzcv',1),('sp',original.sp+8)):
            registers=State.from_buffer_copy(original);setattr(registers,field,value)
            self.prepare(vectors,pair(2,False,0,1,6,2,0),registers,memory,2)
        for base,immediate in ((0,-1),(1<<39,0),((1<<39)-16,0),((1<<39)-16,1)):
            registers=State.from_buffer_copy(original);registers.x[6]=base
            self.prepare(vectors,pair(2,False,0,1,6,2,immediate),registers,memory,2)
        self.prepare(vectors,pair(0,False,0,1,31,3,-1),original,memory,2)
        self.assertEqual(memory.fault.reason,5)
        for word in (pair(3,False,0,1,6,2,0),pair(2,False,0,1,6,0,0),pair(2,True,7,7,6,2,0)):
            self.prepare(vectors,word,original,memory,1)
        result=State();write=VectorWrite();before=(bytes(vectors),bytes(original),bytes(backing))
        self.assertEqual(self.lib.oot_startup_vector_prepare(byref(vectors),pair(2,False,0,1,6,2,0),
            byref(original),byref(memory),byref(vectors),byref(result),byref(write)),2)
        self.assertEqual((bytes(vectors),bytes(original),bytes(backing)),before)
        next_state=VectorState()
        self.assertEqual(self.lib.oot_startup_vector_prepare(byref(vectors),pair(2,False,0,1,6,2,0),
            byref(original),byref(memory),byref(next_state),byref(original),byref(write)),2)
        self.assertEqual((bytes(vectors),bytes(original),bytes(backing)),before)

    def test_explicit_initial_zero_bank_and_context_profile_guard(self):
        state=VectorState.from_buffer_copy(bytes([0xf7])*sizeof(VectorState))
        self.lib.oot_startup_vector_init(byref(state));self.assertEqual(bytes(state),bytes(sizeof(VectorState)))
        lib=self.lib
        from startup_validation import bindings
        from test_sdk_instructions import SdkConfig
        from startup_validation import Config
        bindings(lib)
        lib.oot_startup_context_create_sdk.argtypes=[c_void_p,POINTER(Config),POINTER(SdkConfig),POINTER(c_uint32)]
        lib.oot_startup_context_create_sdk.restype=c_void_p
        lib.oot_startup_context_vectors.argtypes=[c_void_p];lib.oot_startup_context_vectors.restype=POINTER(VectorState)
        lib.oot_startup_context_vector_step.argtypes=[c_void_p,c_uint32,POINTER(State)]
        lib.oot_startup_context_vector_step.restype=c_int
        holder=type('Fixture',(),{'lib':lib,'build':self.build})()
        for enabled in (False,True):
            session=InitSession(holder,enabled=enabled)
            try:
                registers=session.initial();original=registers.values()
                bank=lib.oot_startup_context_vectors(session.context)
                if not enabled:
                    self.assertFalse(bank)
                    self.assertEqual(lib.oot_startup_context_vector_step(session.context,pair(2,False,0,1,31,3,-2),byref(registers)),1)
                    self.assertEqual(registers.values(),original)
                else:
                    self.assertEqual(bytes(bank.contents),bytes(sizeof(VectorState)))
                    self.assertEqual(lib.oot_startup_context_vector_step(session.context,pair(2,False,0,1,31,3,-2),byref(registers)),0)
                    self.assertEqual((registers.pc,registers.sp),(original[2]+4,original[1]-32))
                    self.assertEqual(bytes(bank.contents),bytes(sizeof(VectorState)))
            finally:session.close()

    def test_dispatcher_vector6_prefixes_preserve_full_integer_and_vector_state(self):
        from startup_validation import Config,Program,Report,bindings
        from test_sdk_instructions import SdkConfig,make_fixture
        from test_native_sdk_dispatch import NativeFunction
        from pauth_validation import KEYS
        from prepare_startup import CONTEXT
        lib=self.lib;bindings(lib)
        signatures={
            'oot_startup_context_create_sdk':([c_void_p,POINTER(Config),POINTER(SdkConfig),POINTER(c_uint32)],c_void_p),
            'oot_runtime_backing_bytes':([c_void_p],c_uint64),
            'oot_startup_dispatch_create_init':([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_create_native':([c_void_p,c_void_p,c_void_p,POINTER(Program),c_uint64,POINTER(c_uint32)],c_void_p),
            'oot_startup_dispatch_set_native_functions':([c_void_p,POINTER(NativeFunction),c_size_t,POINTER(c_uint32)],c_int),
            'oot_startup_dispatch_native_calls':([c_void_p],c_uint64)}
        for name,(args,result) in signatures.items():
            fn=getattr(lib,name);fn.argtypes,fn.restype=args,result
        words=[pair(2,True,0,1,31,2,-2),pair(2,False,0,1,31,3,-4),pair(2,True,2,3,31,1,4)]
        blob,program,rows,spans=make_fixture(words)
        for row in rows[:-1]:row.kind=6
        path=Path(self.build['directory'])/'vector-dispatch.ootmem';path.write_bytes(blob)
        from ctypes import create_string_buffer
        image=context=keys=dispatcher=None
        error=c_uint32();message=create_string_buffer(192)
        try:
            image=lib.oot_runtime_open(os.fsencode(path),message,len(message));self.assertTrue(image,message.value)
            config=Config(**dict(CONTEXT,heap_capacity=0x200000))
            sdk=SdkConfig(version=1,flags=1|2|8|128|256,entropy=(c_uint64*4)(1,2,3,4),
                core_mask=1,priority_mask=(1<<64)-1,aslr_base=0,aslr_size=1<<39,
                alias_base=0x5000000000,alias_size=0x200000,program_id=0x1000,is_application=1,
                total_memory=lib.oot_runtime_backing_bytes(image)+config.tls_size+config.heap_capacity,
                main_thread_id=1,main_thread_priority=44,main_thread_core=0)
            context=lib.oot_startup_context_create_sdk(image,byref(config),byref(sdk),byref(error));self.assertTrue(context,error.value)
            keys=lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));self.assertTrue(keys)
            program.flags=15
            dispatcher=lib.oot_startup_dispatch_create_init(image,context,keys,byref(program),100,byref(error))
            self.assertTrue(dispatcher,error.value)
            stop=BASE+len(words)*4
            function=NativeFunction(1,31,stop,4,(c_uint8*32).from_buffer_copy(hashlib.sha256(struct.pack('<I',0xd4200000)).digest()))
            self.assertTrue(lib.oot_startup_dispatch_set_native_functions(dispatcher,byref(function),1,byref(error)))
            registers=State();self.assertTrue(lib.oot_startup_context_initial_state(context,BASE,byref(registers)))
            for n in range(31):registers.x[n]=0xcafe000000000000+n
            registers.x[30]=BASE
            registers.nzcv=0xb0000000
            initial=State.from_buffer_copy(registers);seed=(c_uint8*32)(*range(32))
            memory=lib.oot_startup_context_memory(context)
            report=Report();self.assertEqual(lib.oot_startup_dispatch_begin(dispatcher,byref(registers),byref(report)),0)
            self.assertTrue(lib.oot_memory_store_record(memory,initial.sp-32,seed,32))
            expected_bank=bytearray(sizeof(VectorState))
            for n in range(3):
                self.assertEqual(lib.oot_startup_dispatch_run(dispatcher,byref(registers),1,None,None,byref(report)),1)
                expected=State.from_buffer_copy(initial);expected.pc=BASE+(n+1)*4
                if n==1:expected.sp-=64
                expected_bank[:32]=bytes(seed)
                if n==2:expected_bank[32:64]=bytes(seed)
                self.assertEqual(registers.values(),expected.values())
                self.assertEqual(bytes(lib.oot_startup_context_vectors(context).contents),bytes(expected_bank))
                self.assertEqual(report.retired,n+1)
                if n==0:
                    # The bank is architectural state even though the integer
                    # ABI stores it separately. A public context operation may
                    # not silently change it beneath a yielded dispatcher.
                    side=State.from_buffer_copy(initial)
                    self.assertEqual(lib.oot_startup_context_vector_step(context,pair(2,True,4,5,31,2,-2),byref(side)),0)
                    before=registers.values()
                    self.assertEqual(lib.oot_startup_dispatch_run(dispatcher,byref(registers),1,None,None,byref(report)),3)
                    self.assertEqual((report.error,report.retired,registers.values()),(5,1,before))
                    side=State.from_buffer_copy(initial)
                    self.assertEqual(lib.oot_startup_context_vector_step(context,pair(2,True,4,5,31,2,-8),byref(side)),0)
                    self.assertEqual(bytes(lib.oot_startup_context_vectors(context).contents),bytes(expected_bank))
            self.assertEqual(lib.oot_startup_dispatch_run(dispatcher,byref(registers),1,None,None,byref(report)),2)
            self.assertEqual((report.error,report.retired,lib.oot_startup_dispatch_native_calls(dispatcher)),(9,3,0))
            lib.oot_startup_dispatch_destroy(dispatcher);dispatcher=None
            lib.oot_startup_context_destroy(context);context=None
            sdk.flags&=~256
            context=lib.oot_startup_context_create_sdk(image,byref(config),byref(sdk),byref(error));self.assertTrue(context)
            program.flags=7
            self.assertFalse(lib.oot_startup_dispatch_create_native(image,context,keys,byref(program),100,byref(error)))
            self.assertEqual(error.value,2)
        finally:
            if dispatcher:lib.oot_startup_dispatch_destroy(dispatcher)
            if keys:lib.oot_pauth_destroy(keys)
            if context:lib.oot_startup_context_destroy(context)
            if image:lib.oot_runtime_close(image)


if __name__=='__main__':unittest.main()
