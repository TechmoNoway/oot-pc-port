#include "startup_float.h"
#include "arm64_lift.h"
#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <math.h>
#include <string.h>
_Static_assert(sizeof(float)==4 && sizeof(double)==8 && FLT_RADIX==2 && FLT_EVAL_METHOD==0,"IEEE scalar evaluation required");
static int bit_length(uint64_t value){int n=0;while(value){++n;value>>=1;}return n;}
typedef struct FloatWide { uint64_t w[4]; } FloatWide;
static int wide_compare(const FloatWide *a,const FloatWide *b){
    for(int n=3;n>=0;--n)if(a->w[n]!=b->w[n])return a->w[n]<b->w[n] ? -1:1;
    return 0;
}
static FloatWide wide_sum(const FloatWide *a,const FloatWide *b,int subtract){
    FloatWide out={{0}};uint64_t carry=0;
    for(unsigned n=0;n<4;++n){uint64_t x=a->w[n],y=b->w[n],v;
        if(subtract){v=x-y;out.w[n]=v-carry;carry=(x<y)||(v<carry);}
        else{v=x+y;out.w[n]=v+carry;carry=(v<x)||(out.w[n]<v);}
    }return out;
}
static int wide_scaled(uint64_t low,uint64_t high,int shift,FloatWide *out,int *sticky){
    *out=(FloatWide){{0}};*sticky=0;
    if(shift<0){unsigned n=(unsigned)-shift;
        if(n>=128){*sticky=!!(low|high);return 1;}
        if(n>=64){unsigned k=n-64;*sticky=!!low || (k && !!(high&((UINT64_C(1)<<k)-1)));low=high>>k;high=0;}
        else{*sticky=!!(low&((UINT64_C(1)<<n)-1));low=(low>>n)|(high<<(64-n));high>>=n;}
        out->w[0]=low;out->w[1]=high;return 1;
    }
    {unsigned index=(unsigned)shift/64,bits=(unsigned)shift%64;uint64_t words[2]={low,high};
     for(unsigned n=0;n<2;++n){uint64_t upper=bits ? words[n]>>(64-bits):0;
        if(index+n>=4){if(words[n])return 0;}else out->w[index+n]|=words[n]<<bits;
        if(upper){if(index+n+1>=4)return 0;out->w[index+n+1]|=upper;}
     }}return 1;
}
static void parts(uint64_t value,unsigned fraction,unsigned bias,uint64_t *significand,int *power){
    unsigned exponent=(unsigned)((value>>fraction)&(fraction==23 ? 255u:2047u));
    *significand=value&((UINT64_C(1)<<fraction)-1);
    if(exponent)*significand|=UINT64_C(1)<<fraction;
    *power=(int)(exponent ? exponent:1)-(int)bias-(int)fraction;
}
/* Called only at the rounded minimum-normal boundary. Nonzero cancellation
 * that small cannot involve magnitudes beyond 106 significand bits above it.
 * Four limbs therefore retain every relevant integer bit; a discarded product
 * tail is kept as a signed sticky fraction for exact threshold comparison. */
static int fma_tiny(unsigned width,uint64_t left,uint64_t right,uint64_t addend){
    unsigned fraction=width==32 ? 23:52,bias=width==32 ? 127:1023;
    uint64_t a,b,c,low,high;int ea,eb,ec,sp,sc,comparison;FloatWide p,q,magnitude,target={{0,0,1,0}};
    parts(left,fraction,bias,&a,&ea);parts(right,fraction,bias,&b,&eb);parts(addend,fraction,bias,&c,&ec);
    low=a*b;high=oot_arm64_mul_high(a,b,0);
    if(!wide_scaled(low,high,ea+eb-(1-(int)bias)+128,&p,&sp) ||
       !wide_scaled(c,0,ec-(1-(int)bias)+128,&q,&sc) || sc)return 0;
    if(((left^right^addend)>>(width-1))&1){
        comparison=wide_compare(&p,&q);
        magnitude=comparison>=0 ? wide_sum(&p,&q,1):wide_sum(&q,&p,1);
        int at=wide_compare(&magnitude,&target);
        return at<0 || (at==0 && comparison<0 && sp);
    }
    magnitude=wide_sum(&p,&q,0);return wide_compare(&magnitude,&target)<0;
}
/* ARM detects tininess before rounding. SSE can round the largest subnormal
 * product/quotient up to minimum normal without FE_UNDERFLOW. Resolve that
 * boundary from exact integer significands rather than trusting host flags. */
static int exact_tiny(unsigned operation,unsigned width,uint64_t left,uint64_t right)
{
    unsigned fraction=width==32 ? 23:52,bias=width==32 ? 127:1023;
    uint64_t mask=(UINT64_C(1)<<fraction)-1,sa=left&mask,sb=right&mask;
    unsigned xa=(unsigned)((left>>fraction)&(width==32 ? 255u:2047u)),xb=(unsigned)((right>>fraction)&(width==32 ? 255u:2047u));
    int ea=(int)(xa ? xa:1)-(int)bias-(int)fraction,eb=(int)(xb ? xb:1)-(int)bias-(int)fraction,minimum=1-(int)bias;
    if(xa)sa|=UINT64_C(1)<<fraction;
    if(xb)sb|=UINT64_C(1)<<fraction;
    if(!sa || !sb)return 0;
    if(!operation){uint64_t high=oot_arm64_mul_high(sa,sb,0),low=sa*sb;
        return (high ? 64+bit_length(high):bit_length(low))-1+ea+eb<minimum;
    }
    if(operation==1){int shift=minimum-ea+eb,a=bit_length(sa),b=bit_length(sb)+shift;
        if(a!=b)return a<b;
        return shift>=0 ? sa<(sb<<(unsigned)shift):(sa<<(unsigned)-shift)<sb;
    }
    return 0;
}
static int float_compute(unsigned operation,unsigned width,unsigned fpcr,uint64_t left,uint64_t right,uint64_t addend,uint64_t *result,uint32_t *exceptions)
{
    fenv_t environment;uint64_t bits=0,exponent,mantissa;uint32_t flags=0;
    int saved_errno=errno,status=2,raised;
    if(!result || !exceptions || operation>6 || (width!=32 && width!=64) || (fpcr&~(1u<<24)))return 1;
    {uintptr_t a=(uintptr_t)result,b=(uintptr_t)exceptions;
     if(a<=b ? b-a<sizeof(*result):a-b<sizeof(*exceptions))return 1;}
    exponent=width==32 ? UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000);
    mantissa=width==32 ? UINT64_C(0x7fffff):UINT64_C(0xfffffffffffff);
    if(operation==4){
        uint64_t exp_in=width==32 ? UINT64_C(0x7ff0000000000000):UINT64_C(0x7f800000);
        uint64_t frac_in=width==32 ? UINT64_C(0xfffffffffffff):UINT64_C(0x7fffff);
        unsigned input_sign=width==32 ? 63:31;
        if((left&exp_in)==exp_in){
            bits=((left>>input_sign)&1)<<(width-1);bits|=exponent;
            if(left&frac_in){uint64_t payload=left&frac_in;
                if(!(payload&((frac_in+1)>>1)))flags|=1;
                bits|=(width==32 ? payload>>29:payload<<29)|((mantissa+1)>>1);
            }
            *result=bits;*exceptions=flags;return 0;
        }
        if(fpcr && !(left&exp_in) && (left&frac_in)){left&=UINT64_C(1)<<input_sign;flags|=128;}
    }else if(operation==5){
        uint64_t sign=UINT64_C(1)<<(width-1);
        if((left&exponent)==exponent && (left&mantissa)){
            *result=left|((mantissa+1)>>1);*exceptions=(left&((mantissa+1)>>1)) ? 0:1;return 0;
        }
        if(fpcr && !(left&exponent) && (left&mantissa)){left&=sign;flags|=128;}
        if((left&sign) && (left&~sign)){*result=exponent|((mantissa+1)>>1);*exceptions=flags|1;return 0;}
        if(!(left&~sign) || (left&exponent)==exponent){*result=left;*exceptions=flags;return 0;}
    }else{
        if((left&exponent)==exponent || (right&exponent)==exponent || (operation==6 && (addend&exponent)==exponent))return 1;
        if(fpcr){
            if(!(left&exponent) && (left&mantissa)){left&=UINT64_C(1)<<(width-1);flags|=128;}
            if(!(right&exponent) && (right&mantissa)){right&=UINT64_C(1)<<(width-1);flags|=128;}
            if(operation==6 && !(addend&exponent) && (addend&mantissa)){addend&=UINT64_C(1)<<(width-1);flags|=128;}
        }
    }
    if(feholdexcept(&environment)){errno=saved_errno;return 2;}
    if(!fesetenv(FE_DFL_ENV) && !fesetround(FE_TONEAREST) && !feclearexcept(FE_ALL_EXCEPT)){
        if(operation>=5 && width==32){
            uint32_t a=(uint32_t)left,b=(uint32_t)right,c=(uint32_t)addend,out;float x,y,z,value;
            memcpy(&x,&a,4);memcpy(&y,&b,4);memcpy(&z,&c,4);
            volatile float vx=x,vy=y,vz=z,v;
            if(operation==5){float (*volatile square)(float)=sqrtf;v=square(vx);}
            else{float (*volatile fused)(float,float,float)=fmaf;v=fused(vx,vy,vz);}
            value=v;memcpy(&out,&value,4);bits=out;
        }else if(operation>=5){
            double x,y,z,value;memcpy(&x,&left,8);memcpy(&y,&right,8);memcpy(&z,&addend,8);
            volatile double vx=x,vy=y,vz=z,v;
            if(operation==5){double (*volatile square)(double)=sqrt;v=square(vx);}
            else{double (*volatile fused)(double,double,double)=fma;v=fused(vx,vy,vz);}
            value=v;memcpy(&bits,&value,8);
        }else if(operation==4 && width==32){
            double x;float value;uint32_t out;memcpy(&x,&left,8);
            volatile double vx=x;volatile float v=(float)vx;value=v;memcpy(&out,&value,4);bits=out;
        }else if(operation==4){
            uint32_t input=(uint32_t)left;float x;double value;memcpy(&x,&input,4);
            volatile float vx=x;volatile double v=(double)vx;value=v;memcpy(&bits,&value,8);
        }else if(width==32){
            uint32_t a=(uint32_t)left,b=(uint32_t)right,out;float x,y,value;
            memcpy(&x,&a,4);memcpy(&y,&b,4);
            volatile float vx=x,vy=y,v;
            if(!operation)v=vx*vy;else if(operation==1)v=vx/vy;else if(operation==2)v=vx+vy;else v=vx-vy;
            value=v;memcpy(&out,&value,4);bits=out;
        }else{
            double x,y,value;memcpy(&x,&left,8);memcpy(&y,&right,8);
            volatile double vx=x,vy=y,v;
            if(!operation)v=vx*vy;else if(operation==1)v=vx/vy;else if(operation==2)v=vx+vy;else v=vx-vy;
            value=v;memcpy(&bits,&value,8);
        }
        raised=fetestexcept(FE_ALL_EXCEPT);
        if(raised&FE_INVALID)flags|=1;
        if(raised&FE_DIVBYZERO)flags|=2;
        if(raised&FE_OVERFLOW)flags|=4;
        if(raised&FE_UNDERFLOW)flags|=8;
        if(raised&FE_INEXACT)flags|=16;
        if((flags&16u) && (bits&~(UINT64_C(1)<<(width-1)))==(UINT64_C(1)<<(width==32 ? 23:52)) &&
           exact_tiny(operation,width,left,right))flags|=8;
        if(operation==4 && width==32 && (flags&16u) && (bits&UINT64_C(0x7fffffff))==UINT64_C(0x800000) &&
           (left&UINT64_C(0x7fffffffffffffff))<UINT64_C(0x3810000000000000))flags|=8;
        if(operation==6 && (flags&16u) && (bits&~(UINT64_C(1)<<(width-1)))==(UINT64_C(1)<<(width==32 ? 23:52)) &&
           fma_tiny(width,left,right,addend))flags|=8;
        if(fpcr){
            int tiny;
            if(operation==4)tiny=width==32 && (left&UINT64_C(0x7fffffffffffffff)) &&
                (left&UINT64_C(0x7fffffffffffffff))<UINT64_C(0x3810000000000000);
            else if(operation<2)tiny=exact_tiny(operation,width,left,right);
            else if(operation==6)tiny=!!(flags&8u) || (!(bits&exponent) && !!(bits&mantissa));
            else tiny=!(bits&exponent) && !!(bits&mantissa);
            if(tiny){bits&=UINT64_C(1)<<(width-1);flags=(flags&~16u)|8u;}
        }
        if((bits&exponent)==exponent && (bits&mantissa))bits=exponent|(width==32 ? UINT64_C(0x400000):UINT64_C(0x8000000000000));
        status=0;
    }
    if(fesetenv(&environment))status=2;
    errno=saved_errno;
    if(!status){*result=bits;*exceptions=flags;}
    return status;
}
int oot_startup_float_binary(unsigned operation,unsigned width,unsigned fpcr,uint64_t left,uint64_t right,uint64_t *result,uint32_t *exceptions)
{return operation>5 ? 1:float_compute(operation,width,fpcr,left,right,0,result,exceptions);}
int oot_startup_float_fmadd(unsigned width,unsigned fpcr,uint64_t left,uint64_t right,uint64_t addend,uint64_t *result,uint32_t *exceptions)
{return float_compute(6,width,fpcr,left,right,addend,result,exceptions);}
