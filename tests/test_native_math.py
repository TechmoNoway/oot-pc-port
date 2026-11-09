"""Independent Decimal oracle, domain rejection and host FP environment ownership."""
from ctypes import POINTER,byref,c_int,c_uint32,c_uint64,c_void_p
from decimal import Decimal,localcontext
import math,os,random,struct,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from lifter_validation import compile_library
import test_sdk_init_context as context_fixture
from test_sdk_init_context import ALIGN
from test_sdk_init_vectors import VectorState
from test_native_sdk_runtime import NativeReport
from startup_validation import State

SOURCE=r'''
#include "native_math.h"
#include "arm64_lift.h"
#include <errno.h>
#include <fenv.h>
OOT_LIFT_EXPORT int oot_test_math_environment(void){
 fenv_t saved;int old_errno=errno;uint64_t result=0;
 if(feholdexcept(&saved))return 0;
 if(fesetround(FE_DOWNWARD) || feraiseexcept(FE_INEXACT)){(void)fesetenv(&saved);return 0;}
 int flags=fetestexcept(FE_ALL_EXCEPT);errno=123;
 int status=oot_native_math_prepare(256,UINT64_C(0x4000000000000000),&result);
 int valid=status==0 && errno==123 && fegetround()==FE_DOWNWARD && fetestexcept(FE_ALL_EXCEPT)==flags;
 (void)fesetenv(&saved);errno=old_errno;return valid;
}
'''
def bits(value):return struct.unpack('<Q',struct.pack('<d',value))[0]
def number(value):return struct.unpack('<d',struct.pack('<Q',value))[0]

class NativeMathTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.lib,cls.build=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),SOURCE,startup=True)
  cls.lib.oot_native_math_prepare.argtypes=[c_uint32,c_uint64,POINTER(c_uint64)];cls.lib.oot_native_math_prepare.restype=c_int
  cls.lib.oot_test_math_environment.restype=c_int
 def test_binary64_log_matches_independent_decimal_over_full_exponent_range(self):
  rng=random.Random(3841);inputs=[1,2,(1<<52)-1,1<<52,bits(1.),bits(2.),bits(0.5),bits(1.0000000000000002),0x7fefffffffffffff]
  inputs += [rng.randrange(1,0x7ff0000000000000) for _ in range(1024)]
  with localcontext() as context:
   context.prec=200
   for value in inputs:
    result=c_uint64();self.assertEqual(self.lib.oot_native_math_prepare(256,value,byref(result)),0)
    expected=float(Decimal.from_float(number(value)).ln());actual=number(result.value)
    self.assertLessEqual(abs(actual-expected),math.ulp(expected)*2,(value,actual,expected))
 def test_invalid_domains_do_not_publish_results_and_host_environment_is_restored(self):
  for value in (0,1<<63,bits(-1.),0x7ff0000000000000,0xfff0000000000000,0x7ff0000000000001,0x7ff8000000000012):
   output=c_uint64(0xdeadbeef)
   self.assertEqual(self.lib.oot_native_math_prepare(256,value,byref(output)),1);self.assertEqual(output.value,0xdeadbeef)
  self.assertEqual(self.lib.oot_native_math_prepare(255,bits(2.),None),1)
  self.assertEqual(self.lib.oot_test_math_environment(),1)

class NativeMathContextTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):context_fixture.SdkInitContextTests.setUpClass();cls.lib=context_fixture.SdkInitContextTests.lib
 def test_only_d0_result_changes_and_failed_calls_preserve_context(self):
  helper=context_fixture.SdkInitContextTests();self.addCleanup(helper.doCleanups);context,_,_=helper.create(capacity=ALIGN)
  self.lib.oot_startup_context_vectors.argtypes=[c_void_p];self.lib.oot_startup_context_vectors.restype=POINTER(VectorState)
  vectors=self.lib.oot_startup_context_vectors(context).contents
  for n in range(32):vectors.q[n][:]=bytes([n+1])*16
  vectors.q[0][:8]=struct.pack('<d',2.0);before=bytes(vectors)
  state=helper.state();original=State.from_buffer_copy(state);report=NativeReport()
  self.assertEqual(self.lib.oot_startup_context_native_call(context,256,byref(state),byref(report)),0)
  original.pc=original.x[30];self.assertEqual(state.values(),original.values())
  self.assertEqual(bytes(vectors)[8:],before[8:]);self.assertAlmostEqual(struct.unpack('<d',bytes(vectors.q[0][:8]))[0],math.log(2.),places=15)
  vectors.q[0][:8]=struct.pack('<Q',0x7ff8000000000012);before=bytes(vectors)
  self.assertEqual(self.lib.oot_startup_context_native_call(context,256,byref(state),byref(report)),1)
  self.assertEqual(bytes(vectors),before);self.assertEqual(self.lib.oot_startup_context_native(context).contents.calls,1)

if __name__=='__main__':unittest.main()
