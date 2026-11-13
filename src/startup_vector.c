#include "startup_vector.h"
#include "startup_float.h"

#include <string.h>

#define VECTOR_ADDRESS_LIMIT (UINT64_C(1)<<39)

void oot_startup_vector_init(OotStartupVectorState *state)
{
    if (state) *state=(OotStartupVectorState){0};
}

static unsigned vector_family(uint32_t word)
{
    unsigned size=word>>30,mode=(word>>23)&3u,opc=(word>>22)&3u;
    unsigned cmode=(word>>12)&15u,op=(word>>29)&1u;
    uint32_t move=word&UINT32_C(0xfffffc00);
    if((word&UINT32_C(0xffa00c00))==UINT32_C(0x1e200400))return 19;
    if((word&UINT32_C(0xff800000))==UINT32_C(0x1f000000))return 17;
    if((word&UINT32_C(0xffbffc00))==UINT32_C(0x1e21c000))return 18;
    if(move==UINT32_C(0x1e22c000) || move==UINT32_C(0x1e624000))return 15;
    if((word&UINT32_C(0xffffffe0))==UINT32_C(0xd53b4400) || (word&UINT32_C(0xffffffe0))==UINT32_C(0xd53b4420) ||
       (word&UINT32_C(0xffffffe0))==UINT32_C(0xd51b4400) || (word&UINT32_C(0xffffffe0))==UINT32_C(0xd51b4420))return 16;
    if((word&UINT32_C(0xffbffc00))==UINT32_C(0x1e20c000) || (word&UINT32_C(0xffbffc00))==UINT32_C(0x1e214000) ||
       ((word&UINT32_C(0x9fbffc00))==UINT32_C(0x0ea0f800) && (!(word&UINT32_C(0x400000)) || (word&UINT32_C(0x40000000)))))return 14;
    if((word&UINT32_C(0xffa0fc07))==UINT32_C(0x1e202000) && (!(word&8u) || !((word>>16)&31u)))return 10;
    if((word&UINT32_C(0xffa00c00))==UINT32_C(0x1e200c00))return 11;
    if((word&UINT32_C(0xffbffc00))==UINT32_C(0x1e204000))return 12;
    if((word&UINT32_C(0xffa00c00))==UINT32_C(0x1e200800) && ((word>>12)&15u)<4)return 13;
    if(move==UINT32_C(0x1e260000) || move==UINT32_C(0x1e270000) || move==UINT32_C(0x9e660000) || move==UINT32_C(0x9e670000))return 9;
    if((word&UINT32_C(0xbfbf0000))==UINT32_C(0x0d000000)){
        unsigned opcode=(word>>13)&7u,lane_size=(word>>10)&3u,s=(word>>12)&1u;
        if(!opcode || (opcode==2 && !(lane_size&1u)) || (opcode==4 && (!lane_size || (lane_size==1 && !s))))return 8;
    }
    if ((word & UINT32_C(0x3e000000))==UINT32_C(0x2c000000) && size<3 && mode &&
        (!(word & UINT32_C(0x00400000)) || (word&31u)!=((word>>10)&31u))) return 1;
    if ((opc<2 && size>=2) || (opc>=2 && !size)) {
        if ((word & UINT32_C(0x3f000000))==UINT32_C(0x3d000000)) return 2;
        if ((word & UINT32_C(0x3f200000))==UINT32_C(0x3c000000) &&
            ((word>>10)&3u)!=2) return 3;
    }
    if ((word & UINT32_C(0x9ff80c00))==UINT32_C(0x0f000400) &&
        ((!op && ((cmode<=10 && !(cmode&1u)) || (cmode>=12 && cmode<=14))) ||
            (op && cmode==14))) return 4;
    if ((word & UINT32_C(0xff201fe0))==UINT32_C(0x1e201000) && ((word>>22)&3u)<2) return 5;
    if ((word & UINT32_C(0xbfe0fc00))==UINT32_C(0x0e000c00)) {
        unsigned imm5=(word>>16)&15u;
        if (imm5 && (imm5!=8 || (word & UINT32_C(0x40000000)))) return 6;
    }
    return 0;
}

int oot_startup_vector_kind(uint32_t word) { return vector_family(word)!=0; }
int oot_startup_application_vector_kind(uint32_t word)
{ uint32_t fixed=word&UINT32_C(0x7fbefc00);
  if((word&UINT32_C(0xdfbffc00))==UINT32_C(0x5e21d800))return 3;
  if((word&UINT32_C(0xbfe0fc00))==UINT32_C(0x0ea01c00))return 4;
  if((word&UINT32_C(0xbfe0fc00))==UINT32_C(0x2ee01c00))return 8;
  if((word&UINT32_C(0xbf20fc00))==UINT32_C(0x2e208c00) &&
      (((word>>22)&3u)!=3 || (word&UINT32_C(0x40000000))))return 7;
  if(((word>>16)&31u) && ((word>>16)&31u)!=16){
      if((word&UINT32_C(0xffe0fc00))==UINT32_C(0x5e000400))return 5;
      if((word&UINT32_C(0xffe08400))==UINT32_C(0x6e000400))return 6;
  }
  return fixed==UINT32_C(0x1e220000) ? 1:fixed==UINT32_C(0x1e380000) ? 2:0; }

static uint64_t vector_movi(uint32_t word)
{
    unsigned cmode=(word>>12)&15u,imm=((word>>16)&7u)<<5 | ((word>>5)&31u);
    uint64_t value=0,lane;
    if (cmode==14) {
        for (unsigned n=0;n<8;++n)
            value|=(uint64_t)((word & UINT32_C(0x20000000)) ?
                ((imm & (1u<<n)) ? 255u:0u) : imm)<<(8*n);
    } else if (cmode>=12) {
        unsigned shift=cmode==12 ? 8:16;
        lane=(uint64_t)imm<<shift | ((UINT64_C(1)<<shift)-1);
        value=lane | lane<<32;
    } else if (cmode>=8) {
        lane=(uint64_t)imm<<((cmode-8)*4);
        for (unsigned n=0;n<4;++n) value|=lane<<(16*n);
    } else {
        lane=(uint64_t)imm<<(cmode*4);
        value=lane | lane<<32;
    }
    return value;
}

static uint64_t vector_fmov(uint32_t word)
{
    unsigned width=(word & UINT32_C(0x00400000)) ? 64:32;
    unsigned exponent_bits=width==64 ? 11:8,fraction_bits=width-exponent_bits-1;
    unsigned imm=(word>>13)&255u,b=(imm>>6)&1u;
    uint64_t exponent=b ? ((UINT64_C(1)<<(exponent_bits-1))-4) : UINT64_C(1)<<(exponent_bits-1);
    exponent|=(imm>>4)&3u;
    return (uint64_t)(imm>>7)<<(width-1) | exponent<<fraction_bits |
        (uint64_t)(imm&15u)<<(fraction_bits-4);
}

static int vector_separate(const void *a, size_t a_size, const void *b, size_t b_size)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y ? y-x>=a_size : x-y>=b_size;
}

static int vector_ownership(const void *const *pointers, const size_t *sizes,
    size_t count, OotGuestMemory *memory)
{
    if (!memory || memory->valid!=1 || (memory->count && !memory->regions) ||
        memory->count>SIZE_MAX/sizeof(OotGuestRegion)) return 0;
    for (size_t n=0;n<count;++n) {
        if (!pointers[n] || !vector_separate(pointers[n],sizes[n],memory,sizeof(*memory))) return 0;
        for (size_t k=n+1;k<count;++k)
            if (!vector_separate(pointers[n],sizes[n],pointers[k],sizes[k])) return 0;
        if (memory->count && !vector_separate(pointers[n],sizes[n],memory->regions,
                memory->count*sizeof(OotGuestRegion))) return 0;
        for (size_t k=0;k<memory->count;++k) {
            const OotGuestRegion *r=memory->regions+k;
            if (r->size>SIZE_MAX || !vector_separate(pointers[n],sizes[n],r->data,(size_t)r->size)) return 0;
        }
    }
    return 1;
}

static int vector_fault(OotGuestMemory *memory, uint64_t address, unsigned size,
    unsigned access, unsigned reason)
{
    memory->fault=(OotMemoryFault){address,address,size,access,reason};
    return OOT_STARTUP_VECTOR_FAULT;
}

static int vector_prepare(const OotStartupVectorState *state, uint32_t word,
    const OotArm64State *registers, OotGuestMemory *memory,
    OotStartupVectorState *next, OotArm64State *result, OotStartupVectorWrite *write,int application)
{
    const void *pointers[]={state,registers,next,result,write};
    const size_t sizes[]={sizeof(*state),sizeof(*registers),sizeof(*next),sizeof(*result),sizeof(*write)};
    OotStartupVectorState candidate;
    OotArm64State output;
    OotStartupVectorWrite planned={0};
    uint8_t captured[32];
    uint64_t base,address,updated;
    unsigned family,element,mode,rt,rt2,rn,load,total,access;
    int offset;
    if (!vector_ownership(pointers,sizes,sizeof(sizes)/sizeof(sizes[0]),memory))
        return OOT_STARTUP_VECTOR_FAULT;
    family=vector_family(word);
    if(application && oot_startup_application_vector_kind(word))family=19u+(unsigned)oot_startup_application_vector_kind(word);
    if (!family) return OOT_STARTUP_VECTOR_UNSUPPORTED;
    if (registers->pc%4 || registers->pc>=VECTOR_ADDRESS_LIMIT-4 ||
        registers->sp%16 || (registers->nzcv & UINT32_C(0x0fffffff)) || (state->fpcr&~UINT32_C(0x1000000)) ||
        (state->fpsr&~UINT32_C(0x0800009f))) return OOT_STARTUP_VECTOR_FAULT;
    rn=(word>>5)&31u;rt=word&31u;rt2=(word>>10)&31u;
    candidate=*state;output=*registers;output.pc+=4;
    if(family>=23 && family<=27){
        unsigned rm=(word>>16)&31u;
        total=(word&UINT32_C(0x40000000)) ? 16:8;
        if(family==24 || family==25){
            unsigned imm5=(word>>16)&31u,destination,source;
            element=imm5&(~imm5+1u);
            destination=imm5/(2*element);
            source=family==24 ? destination:((word>>11)&15u)/element;
            if(family==24){memset(candidate.q[rt],0,16);destination=0;}
            /* Original source is required even when Rn and Rd alias. Low INS
             * source-index bits are architecturally ignored, not reserved. */
            memcpy(candidate.q[rt]+destination*element,state->q[rn]+source*element,element);
        }else{
            memset(candidate.q[rt],0,16);
            if(family==26){
                element=1u<<((word>>22)&3u);
                for(unsigned n=0;n<total;n+=element)
                    memset(candidate.q[rt]+n,memcmp(state->q[rn]+n,state->q[rm]+n,element) ? 0:255,element);
            }else for(unsigned n=0;n<total;++n)
                candidate.q[rt][n]=family==23 ? (uint8_t)(state->q[rn][n]|state->q[rm][n]):
                    (uint8_t)((state->q[rt][n]&state->q[rm][n])|(state->q[rn][n]&(uint8_t)~state->q[rm][n]));
        }
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if(family==20 || family==22){
        uint64_t value=0,input=0;uint32_t flags=0;
        unsigned width=(word&UINT32_C(0x400000)) ? 64:32;
        unsigned source_width=family==22 ? width:((word>>31) ? 64:32);
        unsigned is_unsigned=family==22 ? (word>>29)&1u:(word>>16)&1u;
        if(family==22){
            /* Snapshot the original SIMD lane: Q31 is a register, not XZR. */
            for(unsigned n=0;n<width/8;++n)input|=(uint64_t)state->q[rn][n]<<(8*n);
        }else input=oot_arm64_read(registers,rn,source_width,0);
        int status=oot_startup_float_from_integer(width,source_width,is_unsigned,input,&value,&flags);
        if(status)return status;
        candidate.fpsr|=flags;memset(candidate.q[rt],0,16);
        for(unsigned n=0;n<width/8;++n)candidate.q[rt][n]=(uint8_t)(value>>(8*n));
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if(family==21){
        uint64_t input=0,value=0;uint32_t flags=0;
        unsigned width=(word&UINT32_C(0x400000)) ? 64:32,destination_width=(word>>31) ? 64:32;
        for(unsigned n=0;n<width/8;++n)input|=(uint64_t)state->q[rn][n]<<(8*n);
        int status=oot_startup_float_to_integer(width,destination_width,(word>>16)&1u,state->fpcr,input,&value,&flags);
        if(status)return status;
        candidate.fpsr|=flags;oot_arm64_write(&output,rt,destination_width,0,value);
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if(family==16){
        unsigned status=!!(word&32u),read=!!(word&UINT32_C(0x200000));
        uint64_t mask=status ? UINT64_C(0x0800009f):UINT64_C(0x1000000),value;
        if(read)oot_arm64_write(&output,rt,64,0,status ? state->fpsr:state->fpcr);
        else{value=oot_arm64_read(registers,rt,64,0);if(value&~mask)return OOT_STARTUP_VECTOR_UNSUPPORTED;
            if(status)candidate.fpsr=(uint32_t)value;else candidate.fpcr=(uint32_t)value;}
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if(family==15){
        uint64_t input=0,value=0;uint32_t flags=0;
        unsigned width=(word&UINT32_C(0xfffffc00))==UINT32_C(0x1e22c000) ? 64:32;
        for(unsigned n=0;n<(96-width)/8;++n)input|=(uint64_t)state->q[rn][n]<<(8*n);
        int status=oot_startup_float_binary(4,width,state->fpcr,input,0,&value,&flags);
        if(status)return status;
        candidate.fpsr|=flags;memset(candidate.q[rt],0,16);
        for(unsigned n=0;n<width/8;++n)candidate.q[rt][n]=(uint8_t)(value>>(8*n));
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if(family==17 || family==18){
        uint64_t a=0,b=0,c=0,value=0;uint32_t flags=0;
        unsigned width=(word&UINT32_C(0x400000)) ? 64:32,rm=(word>>16)&31u,ra=(word>>10)&31u;
        for(unsigned n=0;n<width/8;++n){a|=(uint64_t)state->q[rn][n]<<(8*n);b|=(uint64_t)state->q[rm][n]<<(8*n);c|=(uint64_t)state->q[ra][n]<<(8*n);}
        if(family==17){
            /* ARM negates operands before the single rounding operation. */
            unsigned negate_add=(word>>21)&1u,negate_product=negate_add^((word>>15)&1u);
            if(negate_product)a^=UINT64_C(1)<<(width-1);
            if(negate_add)c^=UINT64_C(1)<<(width-1);
        }
        int status=family==17 ? oot_startup_float_fmadd(width,state->fpcr,a,b,c,&value,&flags):
            oot_startup_float_binary(5,width,state->fpcr,a,0,&value,&flags);
        if(status)return status;
        candidate.fpsr|=flags;memset(candidate.q[rt],0,16);
        for(unsigned n=0;n<width/8;++n)candidate.q[rt][n]=(uint8_t)(value>>(8*n));
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if(family==14){
        unsigned scalar=!!(word&UINT32_C(0x10000000));
        element=(word&UINT32_C(0x400000)) ? 8:4;
        total=scalar ? element:((word&UINT32_C(0x40000000)) ? 16:8);
        unsigned negate=scalar ? !!(word&UINT32_C(0x10000)):!!(word&UINT32_C(0x20000000));
        memset(candidate.q[rt],0,16);memcpy(candidate.q[rt],state->q[rn],total);
        for(unsigned n=element-1;n<total;n+=element){if(negate)candidate.q[rt][n]^=128u;else candidate.q[rt][n]&=127u;}
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if(family>=10){
        unsigned width=(word&UINT32_C(0x400000)) ? 64:32,bytes_count=width/8,rm=(word>>16)&31u;
        uint64_t a=0,b=0,value=0;
        for(unsigned n=0;n<bytes_count;++n){a|=(uint64_t)state->q[rn][n]<<(8*n);b|=(uint64_t)state->q[rm][n]<<(8*n);}
        if(family==10 || family==19){
            uint64_t exponent=width==32 ? UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000);
            uint64_t mantissa=width==32 ? UINT64_C(0x7fffff):UINT64_C(0xfffffffffffff),sign=UINT64_C(1)<<(width-1),quiet=(mantissa+1)>>1;
            int an,bn,less;
            if(family==19 && !oot_arm64_condition(registers->nzcv,(word>>12)&15u)){
                output.nzcv=(word&15u)<<28;
                *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
            }
            if(family==10 && (word&8u))b=0;
            if(state->fpcr){
                if(!(a&exponent) && (a&mantissa)){a&=sign;candidate.fpsr|=128;}
                if(!(b&exponent) && (b&mantissa)){b&=sign;candidate.fpsr|=128;}
            }
            an=(a&exponent)==exponent && !!(a&mantissa);bn=(b&exponent)==exponent && !!(b&mantissa);
            if(an || bn){
                output.nzcv=UINT32_C(0x30000000);
                if((word&16u) || (an && !(a&quiet)) || (bn && !(b&quiet)))candidate.fpsr|=1;
            }else if(a==b || (!(a&~sign) && !(b&~sign)))output.nzcv=UINT32_C(0x60000000);
            else{less=(a&sign)!=(b&sign) ? !!(a&sign):((a&sign) ? a>b:a<b);
                output.nzcv=less ? UINT32_C(0x80000000):UINT32_C(0x20000000);}
        }else{
            if(family==11)value=oot_arm64_condition(registers->nzcv,(word>>12)&15u) ? a:b;
            else if(family==12)value=a;
            else{uint32_t flags=0;int status=oot_startup_float_binary((word>>12)&15u,width,state->fpcr,a,b,&value,&flags);
                if(status)return status;
                candidate.fpsr|=flags;}
            memset(candidate.q[rt],0,16);
            for(unsigned n=0;n<bytes_count;++n)candidate.q[rt][n]=(uint8_t)(value>>(8*n));
        }
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if(family==9){
        uint64_t value=0;unsigned width=(word>>31) ? 8:4;
        if(word&UINT32_C(0x10000)){
            value=oot_arm64_read(registers,rn,width*8,0);memset(candidate.q[rt],0,16);
            for(unsigned n=0;n<width;++n)candidate.q[rt][n]=(uint8_t)(value>>(8*n));
        }else{
            for(unsigned n=0;n<width;++n)value|=(uint64_t)state->q[rn][n]<<(8*n);
            oot_arm64_write(&output,rt,width*8,0,value);
        }
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if(family==8){
        unsigned opcode=(word>>13)&7u,size=(word>>10)&3u,s=(word>>12)&1u,q=(word>>30)&1u,index;
        if(!opcode){element=1;index=q*8+s*4+size;}
        else if(opcode==2){element=2;index=q*4+s*2+(size>>1);}
        else if(!size){element=4;index=q*2+s;}else{element=8;index=q;}
        base=rn==31 ? registers->sp:registers->x[rn];load=(word>>22)&1u;
        if(base>=VECTOR_ADDRESS_LIMIT || element>VECTOR_ADDRESS_LIMIT-base)
            return vector_fault(memory,base,element,load ? OOT_MEMORY_READ:OOT_MEMORY_WRITE,OOT_MEMORY_ADDRESS_WRAP);
        if(load){
            if(!oot_memory_load_record(memory,base,captured,element))return OOT_STARTUP_VECTOR_FAULT;
            memcpy(candidate.q[rt]+index*element,captured,element);
        }else{
            if(!oot_memory_probe(memory,base,element,OOT_MEMORY_WRITE))return OOT_STARTUP_VECTOR_FAULT;
            planned.address=base;planned.size=element;memcpy(planned.bytes,state->q[rt]+index*element,element);
        }
        *next=candidate;*result=output;*write=planned;return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    if (family>=4) {
        uint64_t value;
        unsigned width;
        memset(candidate.q[rt],0,16);
        if (family==4) {
            value=vector_movi(word);width=(word & UINT32_C(0x40000000)) ? 16:8;
            for (unsigned n=0;n<width;++n) candidate.q[rt][n]=(uint8_t)(value>>(8*(n%8)));
        } else if (family==5) {
            value=vector_fmov(word);width=(word & UINT32_C(0x00400000)) ? 8:4;
            for (unsigned n=0;n<width;++n) candidate.q[rt][n]=(uint8_t)(value>>(8*n));
        } else {
            unsigned imm=(word>>16)&15u;
            element=1;
            while (!(imm&1u)) { element*=2;imm>>=1; }
            value=rn==31 ? 0:registers->x[rn];
            width=(word & UINT32_C(0x40000000)) ? 16:8;
            for (unsigned n=0;n<width;++n) candidate.q[rt][n]=(uint8_t)(value>>(8*(n%element)));
        }
        *next=candidate;*result=output;*write=planned;
        return OOT_STARTUP_VECTOR_IMPLEMENTED;
    }
    load=(word>>22)&1u;
    if (family==1) {
        element=4u<<(word>>30);mode=(word>>23)&3u;
        offset=(int)((word>>15)&127u);
        if (offset>=64) offset-=128;
        offset*=(int)element;
    } else {
        element=(word & UINT32_C(0x00800000)) ? 16 : 1u<<(word>>30);
        if (family==2) { mode=2;offset=(int)((word>>10)&4095u)*(int)element; }
        else {
            mode=(word>>10)&3u;
            if (!mode) mode=2;
            offset=(int)((word>>12)&511u);
            if (offset>=256) offset-=512;
        }
    }
    total=element*(family==1 ? 2u:1u);access=load ? OOT_MEMORY_READ : OOT_MEMORY_WRITE;
    base=rn==31 ? registers->sp : registers->x[rn];
    if (base>=VECTOR_ADDRESS_LIMIT || (offset<0 && base<(uint64_t)-offset) ||
        (offset>=0 && (uint64_t)offset>=VECTOR_ADDRESS_LIMIT-base))
        return vector_fault(memory,base,total,access,OOT_MEMORY_ADDRESS_WRAP);
    updated=offset<0 ? base-(uint64_t)-offset : base+(uint64_t)offset;
    address=mode==1 ? base : updated;
    if (total>VECTOR_ADDRESS_LIMIT-address)
        return vector_fault(memory,address,total,access,OOT_MEMORY_ADDRESS_WRAP);
    if (rn==31 && mode!=2 && updated%16)
        return vector_fault(memory,address,total,access,OOT_MEMORY_ALIGNMENT);
    if (load) {
        if (!oot_memory_load_record(memory,address,captured,total)) return OOT_STARTUP_VECTOR_FAULT;
        memset(candidate.q[rt],0,16);
        memcpy(candidate.q[rt],captured,element);
        if (family==1) {
            memset(candidate.q[rt2],0,16);
            memcpy(candidate.q[rt2],captured+element,element);
        }
    } else {
        /* Existing scalar preflight stays <=16 bytes. The enclosing commit is
         * one serialized complete record, not two partial stores/reservations. */
        for (unsigned n=0;n<total;n+=16) {
            unsigned chunk=total-n<16 ? total-n : 16;
            if (!oot_memory_probe(memory,address+n,chunk,OOT_MEMORY_WRITE)) {
                memory->fault.address=address;memory->fault.size=total;
                return OOT_STARTUP_VECTOR_FAULT;
            }
        }
        planned.address=address;planned.size=total;
        memcpy(planned.bytes,state->q[rt],element);
        if (family==1) memcpy(planned.bytes+element,state->q[rt2],element);
    }
    if (mode!=2) {
        if (rn==31) output.sp=updated;
        else output.x[rn]=updated;
    }
    *next=candidate;*result=output;*write=planned;
    return OOT_STARTUP_VECTOR_IMPLEMENTED;
}

int oot_startup_vector_prepare(const OotStartupVectorState *state,uint32_t word,
    const OotArm64State *registers,OotGuestMemory *memory,OotStartupVectorState *next,
    OotArm64State *result,OotStartupVectorWrite *write)
{ return vector_prepare(state,word,registers,memory,next,result,write,0); }
int oot_startup_application_vector_prepare(const OotStartupVectorState *state,uint32_t word,
    const OotArm64State *registers,OotGuestMemory *memory,OotStartupVectorState *next,
    OotArm64State *result,OotStartupVectorWrite *write)
{ return vector_prepare(state,word,registers,memory,next,result,write,1); }
