#include "native_math.h"
#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <string.h>
_Static_assert(sizeof(double)==8 && FLT_RADIX==2 && DBL_MANT_DIG==53,"binary64 required");
int oot_native_math_prepare(uint32_t id,uint64_t input,uint64_t *output)
{
    double x,value;fenv_t environment;int saved_errno=errno,status=1;
    uint64_t bits=0;
    if(id!=OOT_NATIVE_MATH_LOG || !output || (input>>63) || !(input&UINT64_C(0x7fffffffffffffff)) ||
       ((input>>52)&2047)==2047)return 1;
    if(feholdexcept(&environment)){errno=saved_errno;return 2;}
    if(!fesetenv(FE_DFL_ENV) && !fesetround(FE_TONEAREST)){
        double (*volatile calculate)(double)=log;
        memcpy(&x,&input,8);value=calculate(x);memcpy(&bits,&value,8);
        if(isfinite(value))status=0;
    }
    if(fesetenv(&environment))status=2;
    errno=saved_errno;
    if(!status)*output=bits;
    return status;
}
