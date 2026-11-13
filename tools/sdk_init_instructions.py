"""Profile-gated SIMD transfers, bounded scalar FP and pointer stripping.

The enclosing profile owns a separate vector bank. Earlier SDK/PAC/integer
decoders remain unchanged. Scalar FP permits default/FZ FPCR and owned FPSR;
this is a finite subset, not a complete floating-point emulator. Application
conversions and register bit operations require the separate application gate.
Architectural reference: Arm Instruction Set Reference Guide D4.49/D4.57,
https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab
and Arm A64 ISA encoding reference,
https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85
No-offset single-lane transfers: Arm DUI 0802B, sections 9.94/9.203,
https://documentation-service.arm.com/static/5f3fa899428f7a6b3328fd44
"""

from arm64_lifter import Instruction, U64
from input_formats import require
from sdk_instructions import decode_sdk_instruction

XPACLRI=0xd50320ff


def sdk_init_atomic_kind(word,application=False):
    if type(word) is not int or not 0<=word<=0xffffffff:return None
    if word&0xbfe0fc00==0xb8200000:return 'ldadd'
    if word&0xbfe0fc00==0xb8e00000:return 'ldaddal'
    if application and word&0xbfe0fc00==0xb8a00000:return 'ldadda'
    if application and word&0xbfe0fc00==0xb8600000:return 'ldaddl'
    if word&0xbf20fc00==0xb8203000:return 'ldset'
    if word&0xbf20fc00==0xb8201000:return 'ldclr'
    if word&0x3ffffc00==0x089ffc00:return 'stlr'
    return None


def sdk_init_pointer_kind(word):
    return 'xpaclri' if type(word) is int and word==XPACLRI else None


def sdk_init_vector_kind(word,application=False):
    if type(word) is not int or not 0<=word<=0xffffffff:return None
    if application and word&0x7fbefc00==0x1e220000:return 'integer_fp'
    if application and word&0x7fbefc00==0x1e380000:return 'fp_integer'
    if application and word&0xdfbffc00==0x5e21d800:return 'simd_integer_fp'
    if application:
        if word&0xbfe0fc00==0x0ea01c00:return 'simd_orr'
        if word&0xbfe0fc00==0x2ee01c00:return 'simd_bif'
        if word&0xbf20fc00==0x2e208c00 and (word>>22&3!=3 or word>>30&1):return 'simd_cmeq'
        if (word>>16&31) not in (0,16):
            if word&0xffe0fc00==0x5e000400:return 'simd_dup_element'
            if word&0xffe08400==0x6e000400:return 'simd_ins_element'
    if word&0xffa00c00==0x1e200400:return 'fp_cond_compare'
    if word&0xff800000==0x1f000000:return 'fp_fmadd'
    if word&0xffbffc00==0x1e21c000:return 'fp_sqrt'
    if word&0xfffffc00 in (0x1e22c000,0x1e624000):return 'fp_convert'
    if word&0xffffffe0 in (0xd53b4400,0xd53b4420,0xd51b4400,0xd51b4420):return 'fp_control'
    if word&0xffbffc00 in (0x1e20c000,0x1e214000):return 'fp_sign'
    if word&0x9fbffc00==0x0ea0f800 and (not(word>>22&1) or word>>30&1):return 'fp_sign'
    if word&0xffa0fc07==0x1e202000 and (not(word&8) or not(word>>16&31)):return 'fp_compare'
    if word&0xffa00c00==0x1e200c00:return 'fp_select'
    if word&0xffbffc00==0x1e204000:return 'fp_move'
    if word&0xffa00c00==0x1e200800 and (word>>12&15)<4:return 'fp_binary'
    if word&0xfffffc00 in (0x1e260000,0x1e270000,0x9e660000,0x9e670000):return 'fmov_general'
    if word&0xbfbf0000==0x0d000000:
        opcode,size,s=word>>13&7,word>>10&3,word>>12&1
        if opcode==0 or (opcode==2 and not(size&1)) or (opcode==4 and (size==0 or (size==1 and not s))):return 'simd_lane'
    if word&0x3e000000==0x2c000000 and word>>30<3 and word>>23&3:
        if not(word>>22&1) or word&31!=word>>10&31:return 'simd_pair'
    size,opc=word>>30,word>>22&3
    if (opc<2 and size>=2) or (opc>=2 and size==0):
        if word&0x3f000000==0x3d000000:return 'simd_single_unsigned'
        if word&0x3f200000==0x3c000000 and word>>10&3!=2:return 'simd_single_signed'
    cmode,op=word>>12&15,word>>29&1
    if word&0x9ff80c00==0x0f000400 and (
        (not op and ((cmode<=10 and not(cmode&1)) or 12<=cmode<=14)) or (op and cmode==14)):
        return 'movi'
    if word&0xff201fe0==0x1e201000 and word>>22&3<2:return 'fmov_immediate'
    imm=word>>16&15
    if word&0xbfe0fc00==0x0e000c00 and imm and (imm!=8 or word>>30&1):return 'dup_general'
    return None


def decode_sdk_init_instruction(word,pc,application=False):
    require(type(word) is int and 0<=word<=0xffffffff,'initialization instruction must be uint32')
    require(type(pc) is int and 0<=pc<=U64 and pc%4==0,'initialization PC must be aligned uint64')
    require(type(application) is bool,'application instruction mode must be explicit')
    atomic=sdk_init_atomic_kind(word,application)
    if atomic:
        width=(8<<(word>>30)) if atomic=='stlr' else (64 if word>>30==3 else 32)
        return Instruction(pc,word,'sdk_init_atomic',width=width,access_size=width//8,
            rd=word&31,rn=word>>5&31,rm=word>>16&31,
            operation=('ldadd','ldaddal','stlr','ldset','ldclr','ldadda','ldaddl').index(atomic))
    if sdk_init_pointer_kind(word):return Instruction(pc,word,'sdk_pointer',width=64,rd=30)
    vector=sdk_init_vector_kind(word,application)
    if vector=='fp_integer':
        return Instruction(pc,word,'sdk_init_vector',width=64 if word>>31 else 32,
            rd=word&31,rn=word>>5&31,immediate=64 if word>>22&1 else 32,condition=word>>16&1,operation=24)
    if vector=='integer_fp':
        return Instruction(pc,word,'sdk_init_vector',width=64 if word>>22&1 else 32,
            rd=word&31,rn=word>>5&31,immediate=64 if word>>31 else 32,condition=word>>16&1,operation=23)
    if vector=='simd_integer_fp':
        width=64 if word>>22&1 else 32
        return Instruction(pc,word,'sdk_init_vector',width=width,
            rd=word&31,rn=word>>5&31,immediate=width,condition=word>>29&1,operation=25)
    if vector in ('simd_orr','simd_bif','simd_cmeq'):
        return Instruction(pc,word,'sdk_init_vector',width=128 if word>>30&1 else 64,
            rd=word&31,rn=word>>5&31,rm=word>>16&31,
            access_size=1<<(word>>22&3) if vector=='simd_cmeq' else 0,
            operation={'simd_orr':26,'simd_cmeq':29,'simd_bif':30}[vector])
    if vector in ('simd_dup_element','simd_ins_element'):
        imm5=word>>16&31
        element=imm5&-imm5
        return Instruction(pc,word,'sdk_init_vector',width=element*8 if vector=='simd_dup_element' else 128,
            rd=word&31,rn=word>>5&31,access_size=element,immediate=imm5//(2*element),
            condition=(word>>11&15)//element if vector=='simd_ins_element' else 0,
            operation=27 if vector=='simd_dup_element' else 28)
    if vector=='fp_cond_compare':
        return Instruction(pc,word,'sdk_init_vector',width=64 if word>>22&1 else 32,
            rn=word>>5&31,rm=word>>16&31,condition=word>>12&15,nzcv=word&15,operation=22)
    if vector in ('fp_fmadd','fp_sqrt'):
        return Instruction(pc,word,'sdk_init_vector',width=64 if word>>22&1 else 32,
            rd=word&31,rn=word>>5&31,rm=word>>16&31,ra=word>>10&31,operation=20 if vector=='fp_fmadd' else 21)
    if vector=='fp_convert':
        return Instruction(pc,word,'sdk_init_vector',width=64 if word&0xfffffc00==0x1e22c000 else 32,rd=word&31,rn=word>>5&31,operation=18)
    if vector=='fp_control':
        return Instruction(pc,word,'sdk_init_vector',width=64,rd=word&31,load=bool(word>>21&1),operation=19)
    if vector=='fp_sign':
        return Instruction(pc,word,'sdk_init_vector',width=64 if word>>22&1 else 32,rd=word&31,rn=word>>5&31,operation=17)
    if vector in ('fp_compare','fp_select','fp_move','fp_binary'):
        return Instruction(pc,word,'sdk_init_vector',width=64 if word>>22&1 else 32,
            rd=word&31,rn=word>>5&31,rm=word>>16&31,
            operation=13+('fp_compare','fp_select','fp_move','fp_binary').index(vector),condition=word>>12&15)
    if vector=='fmov_general':
        return Instruction(pc,word,'sdk_init_vector',width=64 if word>>31 else 32,rd=word&31,rn=word>>5&31,load=not bool(word>>16&1),operation=12)
    if vector=='simd_lane':
        opcode,size,s,q=word>>13&7,word>>10&3,word>>12&1,word>>30&1
        element,index=(1,q*8+s*4+size) if opcode==0 else ((2,q*4+s*2+(size>>1)) if opcode==2 else ((4,q*2+s) if size==0 else (8,q)))
        return Instruction(pc,word,'sdk_init_vector',width=element*8,access_size=element,rd=word&31,rn=word>>5&31,immediate=index,load=bool(word>>22&1),operation=11)
    if vector=='simd_pair':
        element=4<<(word>>30)
        immediate=word>>15&127
        if immediate>=64:immediate-=128
        mode=word>>23&3
        return Instruction(pc,word,'sdk_init_vector',width=element*8,access_size=element,
            rd=word&31,rn=word>>5&31,rm=word>>10&31,rt2=word>>10&31,
            immediate=immediate*element,operation=mode,load=bool(word>>22&1),
            writeback=mode!=2,post_index=mode==1)
    if vector in ('simd_single_unsigned','simd_single_signed'):
        element=16 if word>>23&1 else 1<<(word>>30)
        mode=2
        if vector=='simd_single_unsigned':immediate=(word>>10&4095)*element
        else:
            immediate=word>>12&511
            if immediate>=256:immediate-=512
            mode=word>>10&3
            if not mode:mode=2
        return Instruction(pc,word,'sdk_init_vector',width=element*8,access_size=element,
            rd=word&31,rn=word>>5&31,immediate=immediate,operation=4 if vector=='simd_single_unsigned' else 5,
            load=bool(word>>22&1),writeback=mode!=2,post_index=mode==1)
    if vector=='movi':
        return Instruction(pc,word,'sdk_init_vector',width=64<<(word>>30&1),rd=word&31,
            immediate=(word>>16&7)<<5 | (word>>5&31),amount=word>>12&15,
            flags=bool(word>>29&1),operation=8)
    if vector=='fmov_immediate':
        return Instruction(pc,word,'sdk_init_vector',width=32<<(word>>22&1),rd=word&31,
            immediate=word>>13&255,operation=9)
    if vector=='dup_general':
        imm=word>>16&15
        element=(imm&-imm)
        return Instruction(pc,word,'sdk_init_vector',width=64<<(word>>30&1),access_size=element,
            rd=word&31,rn=word>>5&31,operation=10)
    return decode_sdk_instruction(word,pc)
