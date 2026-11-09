"""Exact XPACLRI against pinned, enabled QARMA5/VA39/TBI0 reference.

Primary encoding/operation references (no source copied):
https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64InstrInfo.td
https://github.com/unicorn-engine/unicorn/blob/2.1.4/qemu/target/arm/pauth_helper.c
All pointers, keys, code and memory in this suite are synthetic.
"""
from ctypes import POINTER,byref,c_int,c_uint32,c_void_p
from importlib.metadata import version
from pathlib import Path
import random
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from arm64_lifter import U64,decode_instruction
from input_formats import InputError
from lifter_validation_types import State
from pauth_lifter import decode_pauth_instruction
from pauth_validation import Reference,KEYS,BASE,SIGN,AUTH
from sdk_instructions import decode_sdk_instruction
from startup_validation import snapshot
import test_sdk_init_context as context_fixture

XPACLRI=0xd50320ff


class SdkInitPointerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if version('unicorn')!='2.1.4':raise AssertionError('pinned Unicorn 2.1.4 is required')
        context_fixture.SdkInitContextTests.setUpClass()
        cls.lib=context_fixture.SdkInitContextTests.lib
        cls.lib.oot_startup_context_system.argtypes=[c_void_p,c_uint32,POINTER(State)]
        cls.lib.oot_startup_context_system.restype=c_int
        cls.reference=Reference()  # Asserts enabled IA/IB, basic QARMA5, VA39/TBI0 and EL0t.
        cls.reference.keys(KEYS)
        cls.reference.code(struct.pack('<5I',XPACLRI,*SIGN,*AUTH))

    def context(self,flags=context_fixture.INIT_FLAGS):
        helper=context_fixture.SdkInitContextTests()
        self.addCleanup(helper.doCleanups)
        context,config,sdk=helper.create(flags=flags,capacity=context_fixture.ALIGN)
        return helper,context

    def initial(self,lr,flags=0,sp=0x7000001000):
        rng=random.Random(lr)
        state=State()
        for n in range(31):state.x[n]=rng.getrandbits(64)
        state.x[30]=lr;state.sp=sp;state.pc=BASE;state.nzcv=flags<<28
        return state

    def compare(self,context,state):
        expected=self.reference.step(state,XPACLRI)
        actual=State.from_buffer_copy(state)
        self.assertEqual(self.lib.oot_startup_context_system(context,XPACLRI,byref(actual)),0)
        self.assertEqual(actual.values(),expected.values())
        return actual

    def test_exact_init_decoder_and_earlier_profiles_remain_closed(self):
        from sdk_init_instructions import decode_sdk_init_instruction,sdk_init_pointer_kind
        instruction=decode_sdk_init_instruction(XPACLRI,BASE)
        self.assertEqual((instruction.form,instruction.width,instruction.rd),('sdk_pointer',64,30))
        self.assertEqual(sdk_init_pointer_kind(XPACLRI),'xpaclri')
        for legacy in (decode_instruction,decode_pauth_instruction,decode_sdk_instruction):
            with self.assertRaises(InputError):legacy(XPACLRI,BASE)
        for bit in range(32):self.assertIsNone(sdk_init_pointer_kind(XPACLRI^(1<<bit)))
        for word in (True,-1,1<<32,None,'xpaclri'):self.assertIsNone(sdk_init_pointer_kind(word))
        for pc in (True,-4,BASE+1,1<<64):
            with self.assertRaises(InputError):decode_sdk_init_instruction(XPACLRI,pc)

    def test_canonical_pac_boundaries_and_bit55_selector_preserve_full_state(self):
        helper,context=self.context();before=helper.providers(context);memory=snapshot(self.lib,context)
        low=(1<<39)-1;upper=U64^low
        values=[0,1,3,4,(1<<38)-1,1<<38,low,upper,upper|1,U64,
            1<<39,1<<54,1<<55,1<<56,1<<63,(1<<55)|1,(1<<63)|1]
        values += [1<<bit for bit in range(64)]
        rng=random.Random(0x58504143);values += [rng.getrandbits(64) for _ in range(128)]
        for lr in values:
            for flags in range(16):self.compare(context,self.initial(lr,flags))
        # The retained selector is bit55, including when it disagrees with bit63.
        self.assertEqual(self.compare(context,self.initial(0x0080000000000001)).x[30],0xffffff8000000001)
        self.assertEqual(self.compare(context,self.initial(0x8000000000000001)).x[30],1)
        for sp in (0,1,U64,0x7000001000):self.compare(context,self.initial(0xfedcba9876543210,9,sp))
        self.assertEqual(helper.providers(context),before)
        self.assertEqual(snapshot(self.lib,context),memory)

    def test_signed_and_authentication_poisoned_link_registers_strip_without_authentication(self):
        helper,context=self.context();poisoned=0;signed_count=0
        low=(1<<39)-1
        for key in range(2):
            for pointer in (BASE+0x800,0,low,(U64^low)|0x1234):
                state=self.initial(pointer,11);state.pc=BASE+4+key*4
                signed=self.reference.step(state,SIGN[key])
                if signed.x[30]!=pointer:signed_count+=1
                trial=State.from_buffer_copy(signed);trial.pc=BASE
                self.compare(context,trial)
                for bit in range(39,64):
                    trial=State.from_buffer_copy(signed);trial.pc=BASE+12+key*4
                    trial.x[30]^=1<<bit
                    authenticated=self.reference.step(trial,AUTH[key])
                    if authenticated.x[30]!=pointer:poisoned+=1
                    authenticated.pc=BASE
                    self.compare(context,authenticated)
        self.assertGreater(signed_count,0,'PAuth reference cannot act as a NOP')
        self.assertGreater(poisoned,0,'authentication failures must be exercised')

    def test_old_raw_sdk_and_native_contexts_reject_without_retirement_or_effects(self):
        for flags in (1,1|2|8,1|2|8|128):
            helper,context=self.context(flags)
            state=self.initial(0xff123456789abcde,13);before=state.values();memory=snapshot(self.lib,context)
            self.assertEqual(self.lib.oot_startup_context_system(context,XPACLRI,byref(state)),1)
            self.assertEqual(state.values(),before)
            self.assertEqual(snapshot(self.lib,context),memory)
        helper,context=self.context()
        for field,value in (('pc',BASE+1),('pc',1<<39),('nzcv',1)):
            state=self.initial(0xffff123456789abc);setattr(state,field,value);before=state.values()
            self.assertEqual(self.lib.oot_startup_context_system(context,XPACLRI,byref(state)),2)
            self.assertEqual(state.values(),before)

    def test_raw_context_and_similar_encodings_do_not_gain_pointer_support(self):
        helper=context_fixture.SdkInitContextTests();self.addCleanup(helper.doCleanups)
        config,_=helper.config(capacity=context_fixture.ALIGN);error=c_uint32()
        raw=self.lib.oot_startup_context_create(helper.image(),byref(config),byref(error))
        self.assertTrue(raw,error.value);self.addCleanup(self.lib.oot_startup_context_destroy,raw)
        state=self.initial(0xff123456789abcde,10);before=state.values()
        self.assertEqual(self.lib.oot_startup_context_system(raw,XPACLRI,byref(state)),1)
        self.assertEqual(state.values(),before)
        helper,context=self.context()
        for bit in range(32):
            state=self.initial(0xff123456789abcde,10);before=state.values()
            self.assertEqual(self.lib.oot_startup_context_system(context,XPACLRI^(1<<bit),byref(state)),1)
            self.assertEqual(state.values(),before)


if __name__=='__main__':unittest.main()
