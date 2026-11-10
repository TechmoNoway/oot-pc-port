#include "startup_init_atomic.h"

#define INIT_ATOMIC_ADDRESS_LIMIT (UINT64_C(1)<<39)

int oot_startup_init_atomic_kind(uint32_t word)
{
    uint32_t add=word & UINT32_C(0xbfe0fc00);
    if (add==UINT32_C(0xb8200000)) return OOT_STARTUP_INIT_LDADD;
    if (add==UINT32_C(0xb8e00000)) return OOT_STARTUP_INIT_LDADDAL;
    if ((word & UINT32_C(0xbf20fc00))==UINT32_C(0xb8203000)) return OOT_STARTUP_INIT_LDSET;
    if ((word & UINT32_C(0xbf20fc00))==UINT32_C(0xb8201000)) return OOT_STARTUP_INIT_LDCLR;
    if ((word & UINT32_C(0x3ffffc00))==UINT32_C(0x089ffc00)) return OOT_STARTUP_INIT_STLR;
    return OOT_STARTUP_INIT_ATOMIC_NONE;
}

int oot_startup_application_atomic_kind(uint32_t word)
{
    uint32_t add=word&UINT32_C(0xbfe0fc00);
    return add==UINT32_C(0xb8a00000) ? OOT_STARTUP_APP_LDADDA:
        add==UINT32_C(0xb8600000) ? OOT_STARTUP_APP_LDADDL:0;
}

static int atomic_step(uint32_t word, OotArm64State *registers,
    OotGuestMemory *memory,int kind)
{
    OotArm64State output;
    uint64_t address,source,old;
    unsigned rn=(word>>5)&31u,rt=word&31u,rs=(word>>16)&31u,size;
    if (!kind) return 1;
    if (!registers || !memory || memory->valid!=1 || registers->pc%4 ||
        registers->pc>=INIT_ATOMIC_ADDRESS_LIMIT-4 || registers->sp%16 ||
        (registers->nzcv & UINT32_C(0x0fffffff))) return 2;
    size=kind==OOT_STARTUP_INIT_STLR ? 1u<<(word>>30) : (word & UINT32_C(0x40000000)) ? 8u:4u;
    address=rn==31 ? registers->sp:registers->x[rn];
    if (address>=INIT_ATOMIC_ADDRESS_LIMIT || size>INIT_ATOMIC_ADDRESS_LIMIT-address) {
        memory->fault=(OotMemoryFault){address,address,size,
            kind==OOT_STARTUP_INIT_STLR ? OOT_MEMORY_WRITE:OOT_MEMORY_READ | OOT_MEMORY_WRITE,
            OOT_MEMORY_ADDRESS_WRAP};
        return 2;
    }
    output=*registers;output.pc+=4;
    if (kind==OOT_STARTUP_INIT_STLR) {
        source=rt==31 ? 0:registers->x[rt];
        if (!oot_memory_store_release(memory,address,size,rn==31,source)) return 2;
    } else {
        source=rs==31 ? 0:registers->x[rs];
        if (!(kind==OOT_STARTUP_INIT_LDSET ? oot_memory_fetch_or(memory,address,size,rn==31,source,&old):
                kind==OOT_STARTUP_INIT_LDCLR ? oot_memory_fetch_clear(memory,address,size,rn==31,source,&old):
                oot_memory_fetch_add(memory,address,size,rn==31,source,&old))) return 2;
        if (rt!=31) output.x[rt]=old;
    }
    *registers=output;
    return 0;
}
int oot_startup_init_atomic_step(uint32_t word,OotArm64State *registers,OotGuestMemory *memory)
{ return atomic_step(word,registers,memory,oot_startup_init_atomic_kind(word)); }
int oot_startup_application_atomic_step(uint32_t word,OotArm64State *registers,OotGuestMemory *memory)
{ return atomic_step(word,registers,memory,oot_startup_application_atomic_kind(word)); }
