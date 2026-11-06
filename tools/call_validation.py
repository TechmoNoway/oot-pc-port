"""Synthetic LR/callee-save pair frames, mixed PAC calls, and fault isolation."""

import argparse
from ctypes import POINTER, Structure, byref, c_uint8, c_uint32, c_uint64, c_void_p, cast, create_string_buffer, memset, string_at
from dataclasses import replace
from importlib.metadata import version
import json
import os
from pathlib import Path
import random

from arm64_lifter import U64
from dispatcher_validation import CALLER, EXIT, STACK_LOW, STACK_HIGH, STACK_SIZE, Report, LeafFunction, CodeHash
from input_formats import require
from leaf_validation import leaf_programs, remainder
from lifter_validation import compile_library
from lifter_validation_types import Program, State
from ordered_programs import rcpc
from pair_validation import pair
from pauth_lifter import emit_pauth_c
from pauth_stack_validation import PauthAssembler, PauthReference
from pauth_validation import KEYS, SIGN, AUTH, RETURN
from prepare_registry import emit_stack_factory
from read_validation import ReadFunction, ReadRange, CAPS, RO, RW, BSS, LITERAL, package, patterns, bindings as read_bindings
from stack_cfg_validation import Assembler, add_immediate, mov, immediate
from stack_layout_validation import memory_word, add, LayoutStep
from stack_layout_verifier import verify_call_stack_functions, emit_call_stack_descriptor, OPEN_LR, CLOSE_LR, READ


class CallFunction(Structure):
    _fields_ = [('reads', ReadFunction), ('open_word', c_uint32), ('close_word', c_uint32)]


def bindings(lib):
    read_bindings(lib)
    args = lib.oot_stack_create_reads.argtypes.copy(); args[1] = POINTER(CallFunction)
    lib.oot_stack_create_calls.argtypes, lib.oot_stack_create_calls.restype = args, c_void_p


class LrAssembler(Assembler):
    def __init__(self, name, base, size=64, partner=19, lr_first=True, saves=(), key=1, explicit_auth=False):
        self.name, self.base, self.size = name, base, size
        self.partner, self.saves, self.key, self.explicit_auth = partner, list(saves), key, explicit_auth
        self.regs = (30, partner) if lr_first else (partner, 30)
        self.labels, self.fixups, self.words = {}, [], []
        self.emit(SIGN[key], pair(2, False, *self.regs, 31, 3, -size // 8))
        for offset, regs in self.saves:
            self.emit(pair(2, False, *regs, 31, 2, offset // 8) if len(regs) == 2 else memory_word(8, False, regs[0], 31, offset))

    def finish(self):
        self.label('epilogue')
        for offset, regs in reversed(self.saves):
            self.emit(pair(2, True, *regs, 31, 2, offset // 8) if len(regs) == 2 else memory_word(8, True, regs[0], 31, offset))
        self.emit(pair(2, True, *self.regs, 31, 1, self.size // 8))
        self.emit(AUTH[self.key], 0xD65F03C0) if self.explicit_auth else self.emit(RETURN[self.key])
        for index, name, opcode, bits in self.fixups:
            delta = (self.labels[name] - index) & ((1 << bits) - 1)
            self.words[index] = opcode | (delta if bits == 26 else delta << 5)
        return Program(self.name, self.words, [], base=self.base)


def synthetic_programs():
    leaf = replace(next(p for p in leaf_programs() if p.name == 'leaf_remainder'), name='call_rem', base=CALLER+0x3000, trials=[])
    root = LrAssembler('call_root', CALLER, 96, 19, saves=((32,(20,21)),))
    root.branch('zero', 0xB4000006)
    root.emit(mov(19,0),mov(21,2),rcpc(0,20),mov(0,20),memory_word(8,False,19,31,64))
    root.bl(CALLER+0x1000)
    root.emit(memory_word(8,True,4,31,64),add(0,0,4),mov(1,21));root.bl(leaf.base)
    root.branch('epilogue',0x14000000,26);root.label('zero');root.emit(immediate(0,42))
    child=PauthAssembler('call_fp',CALLER+0x1000,64,48,((32,(19,)),),key=0,explicit_auth=True)
    child.emit(add_immediate(0,0,5));child.bl(CALLER+0x2000);child.emit(add_immediate(0,0,3))
    inner=LrAssembler('call_inner',CALLER+0x2000,48,28,False,key=0,explicit_auth=True)
    inner.emit(add_immediate(28,0,7),memory_word(8,False,28,31,16),memory_word(8,True,0,31,16))
    return [root.finish(),child.finish(),inner.finish()],[leaf]


def matrix_programs():
    result=[]
    for partner in range(19,29):
        for lr_first in (False,True):
            for key in (0,1):
                for explicit in (False,True):
                    n=len(result)
                    a=LrAssembler('call_matrix'+str(n),CALLER+0x10000+n*4096,64,partner,lr_first,key=key,explicit_auth=explicit)
                    a.emit(add_immediate(partner,0,partner),memory_word(8,False,partner,31,16),memory_word(8,True,0,31,16))
                    result.append(a.finish())
    return result


def depth_programs():
    result=[]
    for i in range(16):
        base=CALLER+0x100000+i*4096
        a=(LrAssembler('call_depth'+str(i),base,256,19+i%10,bool(i%3),key=i%2,explicit_auth=i%3==0) if i%2==0 else
           PauthAssembler('call_depth'+str(i),base,256,240,key=i%2,explicit_auth=i%3==0))
        if i<15:a.bl(base+4096)
        result.append(a.finish())
    return result


def boundary_programs():
    empty=LrAssembler('call_empty',CALLER+0x70000,16,key=0).finish()
    a=LrAssembler('call_all_saved',CALLER+0x71000,128,19,False,
        saves=tuple((16+16*i,(20+2*i,21+2*i)) for i in range(4))+((96,(28,)),),key=0,explicit_auth=True)
    for r in range(19,29):a.emit(add_immediate(r,0,r))
    a.emit(mov(0,19))
    for r in range(20,29):a.emit(add(0,0,r))
    a.emit(memory_word(8,False,0,31,112),memory_word(8,True,0,31,112))
    return [empty,a.finish()]


def run_validation(mode='cmake'):
    require(version('unicorn')=='2.1.4','pinned PAuth reference required')
    frames,leaves=synthetic_programs();matrix,chain,edges=matrix_programs(),depth_programs(),boundary_programs()
    proofs=verify_call_stack_functions({p.base:p.data for p in frames},{p.base:p.data for p in leaves},CALLER)
    singles={p.base:verify_call_stack_functions({p.base:p.data},{},p.base)[p.base] for p in matrix+edges}
    depths=verify_call_stack_functions({p.base:p.data for p in chain},{},chain[0].base)
    programs=frames+leaves+matrix+edges+chain;blob,digest=package(programs);source=''
    for p in frames+matrix+edges+chain:
        proof=(proofs if p in frames else singles if p.base in singles else depths)[p.base]
        source+=emit_pauth_c(p.data,p.base,'oot_pauth_lift_'+p.name)[0]+emit_call_stack_descriptor(proof,'oot_pauth_lift_'+p.name)
    source+=emit_stack_factory([p.name for p in frames],[p.name for p in leaves],CALLER,digest.hex(),[EXIT],lr_calls=True,read_ranges=CAPS)
    for p in matrix+edges+chain[:1]:
        selected=chain if p in chain else [p]
        source+=emit_stack_factory([q.name for q in selected],[],p.base,digest.hex(),[EXIT],lr_calls=True,read_ranges=CAPS).replace('oot_create_bound_registry','oot_create_'+p.name)
    close=next(i for i,s in enumerate(proofs[CALLER]['steps']) if s['kind']==CLOSE_LR)
    read=next(i for i,s in enumerate(proofs[CALLER]['steps']) if s['kind']==READ)
    modes=[(1,'s->x[29]^=1;',12),(1,'m->regions[0].data[0]^=1;',49),
        (close,'s->x[19]^=1;',12),(close,'s->x[30]^=1;',12),(close,'s->sp-=16;',12),
        (1,'*n=0;',10),(0,'s->x[30]=old_lr;',12),(read,'s->x[5]^=1;',53),
        (close,'s->x[29]=s->sp;',12),(close,'status=OOT_LIFT_DISPATCH;',13)]
    source+='''
static unsigned call_bad_mode, call_bad_calls;
OOT_LIFT_EXPORT void oot_call_bad_set(unsigned m) { call_bad_mode=m; }
OOT_LIFT_EXPORT unsigned oot_call_bad_count(void) { return call_bad_calls; }
OOT_LIFT_EXPORT int oot_call_bad(OotArm64State *s,OotGuestMemory *m,const OotPauth *p,uint64_t b,uint64_t *n)
{
    uint64_t pc=s->pc,old_lr=s->x[30];
    int status;
    ++call_bad_calls;
    status=oot_pauth_lift_call_root(s,m,p,b,n);
    switch(call_bad_mode) {
'''+''.join(f'    case {i}: if(pc==UINT64_C(0x{CALLER+index*4:x})) {{ {action} }} break;\n' for i,(index,action,_) in enumerate(modes,1))+'''    }
    return status;
}
'''
    lib,build=compile_library(leaves,mode,source);bindings(lib)
    lib.oot_call_bad_set.argtypes=[c_uint32];lib.oot_call_bad_count.restype=c_uint32
    path=Path(build['directory'])/'synthetic.ootmem';path.write_bytes(blob)
    message,error,report=create_string_buffer(192),c_uint32(),Report()
    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));require(image,f'LR image rejected: {message.value}')
    memory=lib.oot_runtime_memory(image);stack=memory.contents.regions[4].data
    key_data=(c_uint64*4)(*KEYS);keys=lib.oot_pauth_create(1,key_data);require(keys,'LR keys rejected')
    ref=PauthReference(programs)
    require((ref.isar1>>20)&15>=1,'LR reference lacks FEAT_LRCPC')
    for base,data in ((RO,patterns()[0]),(RW,patterns()[1]),(BSS,patterns()[2]),(LITERAL,patterns()[3])):
        ref.u.mem_map(base&~4095,4096);ref.u.mem_write(base,data)
    rng=random.Random(0x1A9A6);whole=prefixes=0
    def initial(base=CALLER,value=0,divisor=3,flag=1):
        s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)]
        s.pc,s.sp,s.x[0],s.x[1],s.x[2],s.x[6],s.x[30],s.nzcv=base,STACK_HIGH,value,RO+64,divisor,flag,EXIT,rng.randrange(16)<<28
        return s
    def reset():memset(stack,0,STACK_SIZE)
    def check(d,s,expected,budget=1):
        nonlocal whole,prefixes
        reset();states,memories=ref.trace(s)
        require(lib.oot_stack_begin(d,byref(s),EXIT,byref(report))==0,'LR begin rejected')
        before=s.values();require(lib.oot_stack_run(d,byref(s),0,byref(report))==1 and s.values()==before,'LR zero budget changed state')
        for _ in range(1000):
            status=lib.oot_stack_run(d,byref(s),budget,byref(report));n=report.total_retired
            require(status in (1,2) and not report.error,f'LR step rejected {status}/{report.error} pc={s.pc:x}')
            require(s.values()==states[n].values() and bytes(stack[:STACK_SIZE])==memories[n],'LR prefix differs from reference')
            prefixes+=1
            if status==2:break
        else:raise ValueError('LR DAG did not terminate')
        require(s.x[0]==expected and n==len(states)-1,'LR independent result/count differs');whole+=1
    context=lib.oot_create_bound_registry(image,keys,byref(error));require(context,f'LR registry rejected {error.value}')
    try:
        for flag in (0,1):
            for value in (0,1,U64,1<<63):
                for divisor in (0,3,U64):
                    check(context,initial(value=value,divisor=divisor,flag=flag),remainder((143+value)&U64,divisor) if flag else 42)
        check(context,initial(value=7),remainder(150,3),1000)
    finally:lib.oot_stack_destroy(context)
    for p in matrix+edges+chain[:1]:
        factory=getattr(lib,'oot_create_'+p.name);factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
        context=factory(image,keys,byref(error));require(context,f'LR matrix registry rejected {error.value}/{p.name}')
        try:
            for value in ((0,1,U64,1<<63,rng.getrandbits(64)) if p in matrix+edges else (0xABCD,)):
                partner=(p.words[1]&31) if p.words[1]&31!=30 else (p.words[1]>>10)&31
                expected=(value+partner)&U64 if p in matrix else (value*10+235)&U64 if p==edges[1] else value
                check(context,initial(p.base,value=value),expected)
        finally:lib.oot_stack_destroy(context)
    table=(CallFunction*len(frames))()
    for i,p in enumerate(frames):
        getter=getattr(lib,'oot_stack_call_descriptor_'+p.name);getter.restype=POINTER(CallFunction);table[i]=getter().contents
    leaf_table,hashes=(LeafFunction*len(leaves))(),(CodeHash*len(leaves))()
    for i,p in enumerate(leaves):
        getter=getattr(lib,'oot_leaf_descriptor_'+p.name);getter.restype=POINTER(LeafFunction);leaf_table[i]=getter().contents
        getter=getattr(lib,'oot_leaf_code_hash_'+p.name);getter.restype=POINTER(CodeHash);hashes[i]=getter().contents
    body,returns=(c_uint8*32).from_buffer_copy(digest),(c_uint64*1)(EXIT)
    ranges=(ReadRange*len(CAPS))(*[ReadRange(*r) for r in CAPS])
    def create():return lib.oot_stack_create_calls(image,table,len(frames),CALLER,leaf_table,len(leaves),hashes,body,returns,1,keys,ranges,len(ranges),byref(error))
    # A structurally valid reversal of both pair orders must still match text.
    opening,closing=table[0].open_word,table[0].close_word
    def swapped(word):return (word&~0x7c1f)|((word>>10)&31)|((word&31)<<10)
    table[0].open_word,table[0].close_word=swapped(opening),swapped(closing)
    require(create() is None,'valid LR metadata with a different bound opcode accepted')
    table[0].open_word,table[0].close_word=opening,closing
    for field,word in (('open_word',table[0].open_word^1),('close_word',table[0].close_word^1),
                       ('open_word',table[0].open_word^(1<<23)),('open_word',0)):
        old=getattr(table[0],field);setattr(table[0],field,word)
        require(create() is None,'invalid LR pair metadata accepted');setattr(table[0],field,old)
    old=table[0].reads.pauth.layout.cfg.saved_mask;table[0].reads.pauth.layout.cfg.saved_mask^=1<<19
    require(create() is None,'missing implicit saved partner accepted');table[0].reads.pauth.layout.cfg.saved_mask=old
    layout=table[0].reads.pauth.layout;n=layout.cfg.info.instruction_count
    states=(LayoutStep*n).from_buffer_copy(string_at(layout.states,n*4))
    original_states=cast(c_void_p(cast(layout.states,c_void_p).value),POINTER(LayoutStep))
    table[0].reads.pauth.layout.states=states;states[read].fp=1
    require(create() is None,'LR frame with changed FP phase accepted')
    table[0].reads.pauth.layout.states=original_states
    old_table=(ReadFunction*len(frames))(*[f.reads for f in table])
    require(lib.oot_stack_create_reads(image,old_table,len(frames),CALLER,leaf_table,len(leaves),hashes,body,returns,1,keys,ranges,len(ranges),byref(error)) is None,
            'policy-5 constructor accepted policy-6 descriptors')
    table[0].reads.pauth.run=cast(lib.oot_call_bad,c_void_p).value
    for mode_index,(index,_,expected_error) in enumerate(modes,1):
        context=create();require(context,'LR negative fixture rejected');lib.oot_call_bad_set(mode_index)
        try:
            s=initial(value=7);reset();require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'LR negative begin rejected')
            while s.pc!=CALLER+index*4:require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'LR negative setup rejected')
            before,backing=s.values(),bytes(stack[:STACK_SIZE])
            require(lib.oot_stack_run(context,byref(s),1,byref(report))==4 and report.error==expected_error and
                    s.values()==before and bytes(stack[:STACK_SIZE])==backing,f'LR bad callback committed {mode_index}/{report.error}')
            calls=lib.oot_call_bad_count();require(lib.oot_stack_run(context,byref(s),100,byref(report))==4 and lib.oot_call_bad_count()==calls,'LR contract fault not latched')
        finally:lib.oot_stack_destroy(context)
    lib.oot_call_bad_set(0)
    # Failed opening stores do not allocate a frame or sign LR a second time.
    context=create();require(context,'LR store-fault fixture rejected')
    try:
        s=initial(value=7);reset();require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'LR fault begin failed')
        require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'LR sign setup failed')
        before=s.values();memory.contents.regions[4].permissions=1
        require(lib.oot_stack_run(context,byref(s),1,byref(report))==3 and report.error==50 and s.values()==before and not any(stack[:STACK_SIZE]),'LR failed open changed state/stack')
        memory.contents.regions[4].permissions=3
        require(lib.oot_stack_run(context,byref(s),1000,byref(report))==2 and s.x[0]==0,'LR opening retry re-signed or corrupted state')
    finally:
        memory.contents.regions[4].permissions=3;lib.oot_stack_destroy(context)
    # Detect an edited ancestor LR record while a child is suspended.
    context=create();require(context,'LR owner fixture rejected')
    try:
        s=initial();reset();require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'LR owner begin failed')
        while s.pc!=frames[1].base:require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'LR owner setup failed')
        stack[STACK_SIZE-96]^=1;before=s.values()
        require(lib.oot_stack_run(context,byref(s),1,byref(report))==3 and report.error==49 and s.values()==before,'LR ancestor edit escaped checkpoint')
    finally:lib.oot_stack_destroy(context)
    # Copied pair metadata and independently retained context/image survive release.
    table[0].reads.pauth.run=cast(lib.oot_pauth_lift_call_root,c_void_p).value
    context=create();require(context,'LR retained fixture rejected');table[0].open_word=0;table[0].close_word=0
    lib.oot_pauth_destroy(keys);lib.oot_runtime_close(image)
    try:check(context,initial(value=9),remainder(152,3))
    finally:lib.oot_stack_destroy(context)
    result={'schema_version':1,'result':'passed','game_code_executed':False,'whole_call_cases':whole,
        'prefix_checks':prefixes,'matrix_programs':len(matrix),'boundary_layouts':len(edges),'bad_callback_modes':len(modes),'max_depth':16,
        'reference':{'unicorn':version('unicorn')},'native_build':build}
    destination=Path(build['directory'])/'call-report.json';destination.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result,destination


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--compiler',choices=('cmake','gcc'),default='cmake')
    r,path=run_validation(parser.parse_args().compiler);print(json.dumps({k:v for k,v in r.items() if k!='native_build'},indent=2));print(path)
