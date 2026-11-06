"""Exact four-instruction PLT bridges to real verified register-only leaves."""

import hashlib
import re
import struct

from arm64_analysis import NONLOCAL, plt_stubs
from arm64_lifter import U64
from input_formats import require
from leaf_verifier import verify_leaf

POLICY='plt-leaf-stack-dag-v7'


def verify_plt_stub(data,entry,slot,target,leaves,symbol):
    require(len(data)==16 and type(entry) is int and entry % 4==0 and 0 <= entry < (1<<39)-15,
            'invalid PLT text span')
    require(type(slot) is int and slot % 8==0 and 0 <= slot < (1<<39)-7,'invalid PLT GOT slot')
    require(type(target) is int and 0 <= target < (1<<39) and target % 4==0,'invalid PLT leaf target')
    require(isinstance(symbol,str) and symbol and symbol not in NONLOCAL,'PLT nonlocal/service continuation is outside this policy')
    require(target in leaves,'PLT target must be an actual verified register-only leaf')
    leaf=verify_leaf(leaves[target],target)
    adrp,load,add,branch=struct.unpack('<4I',data)
    require(adrp & 0x9f00001f==0x90000010 and load & 0xffc003ff==0xf9400211 and
            add & 0xffc003ff==0x91000210 and branch==0xd61f0220,'unsupported PLT instruction pattern')
    low=((load>>10)&4095)*8
    require((add>>10)&4095==low,'PLT ADD and load offsets differ')
    delta=((adrp>>29)&3)|(((adrp>>5)&0x7ffff)<<2)
    if delta & (1<<20):delta-=1<<21
    page=((entry & ~4095)+delta*4096)&U64
    require((page+low)&U64==slot,'PLT instructions do not address the declared GOT slot')
    require(not (entry < target+len(leaves[target]) and target < entry+16),'PLT and leaf code overlap')
    return {'policy':'exact-plt-register-leaf-v1','base':entry,'byte_count':16,'instruction_count':4,
        'got_slot':slot,'target':target,'symbol':symbol,'page':page,'words':list(struct.unpack('<4I',data)),
        'source_sha256':hashlib.sha256(data).hexdigest(),'target_source_sha256':leaf['source_sha256'],
        'max_retired_instructions':4+leaf['max_retired_instructions'],'guest_code_executed':False,
        'runtime_preconditions':'exact current stub/leaf hashes and GOT target; retained readable image slot; no nonlocal returns'}


def eligible_plts(modules,leaves):
    result={}
    for m in modules:
        for offset,stub in plt_stubs(m).items():
            target=int(stub['resolved_address'],16)
            if target not in leaves or stub['symbol'] in NONLOCAL:continue
            entry=m.base+offset;slot=m.base+stub['got_offset'];data=bytes(m.image[offset:offset+16])
            proof=verify_plt_stub(data,entry,slot,target,leaves,stub['symbol'])
            result[entry]={'data':data,'slot':slot,'target':target,'symbol':stub['symbol'],'proof':proof}
    return result


def emit_plt_descriptor(proof,name):
    require(re.fullmatch(r'oot_lift_[a-z][a-z0-9_]{0,63}',name) is not None,'invalid PLT callback name')
    suffix=name[len('oot_lift_'):]
    return '\n'.join(['#include "stack_dispatch.h"','#if OOT_STACK_PLT_POLICY_VERSION != 7 || OOT_LIFT_ABI_VERSION != 2',
        '#error Regenerate PLT descriptor','#endif',f'static const OotPltFunction oot_plt_info_{suffix} = {{',
        f"    UINT64_C(0x{proof['base']:x}), UINT64_C(0x{proof['got_slot']:x}), UINT64_C(0x{proof['target']:x}), {name},",
        '    {'+', '.join(f'UINT32_C(0x{w:08x})' for w in proof['words'])+'},',
        '    {{'+', '.join(f'0x{b:02x}' for b in bytes.fromhex(proof['source_sha256']))+'}}',
        '};',f'OOT_LIFT_EXPORT const OotPltFunction *oot_plt_descriptor_{suffix}(void)',
        '{',f'    return &oot_plt_info_{suffix};','}',''])
