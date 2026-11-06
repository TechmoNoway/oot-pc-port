"""Synthetic exact PLT bridges, per-instruction retirement and retained targets."""

import argparse
from ctypes import POINTER,Structure,byref,c_size_t,c_uint8,c_uint32,c_uint64,c_void_p,cast,create_string_buffer,memset
from dataclasses import replace
from importlib.metadata import version
import hashlib
import json
import os
from pathlib import Path
import random

from arm64_lifter import U64,emit_c
from call_validation import LrAssembler,CallFunction,bindings as call_bindings
from dispatcher_validation import CALLER,EXIT,STACK_LOW,STACK_HIGH,STACK_SIZE,Report,LeafFunction,CodeHash
from input_formats import require
from leaf_validation import leaf_programs,remainder
from lifter_validation import compile_library
from lifter_validation_types import Program,State
from pauth_lifter import emit_pauth_c
from pauth_stack_validation import PauthAssembler,PauthReference
from pauth_validation import Reference,KEYS
from plt_verifier import verify_plt_stub,emit_plt_descriptor
from prepare_registry import emit_stack_factory
from prepare_runtime import HEADER,REGION
from read_validation import CAPS,RO,RW,package as read_package
from stack_cfg_validation import add_immediate,mov,immediate
from stack_layout_validation import add,memory_word
from stack_layout_verifier import verify_plt_stack_functions,emit_plt_stack_descriptor,CALL

LOW=CALLER+0x9000


class PltFunction(Structure):
    _fields_=[('entry',c_uint64),('slot',c_uint64),('target',c_uint64),('run',c_void_p),('words',c_uint32*4),('hash',CodeHash)]


def bindings(lib):
    call_bindings(lib)
    args=lib.oot_stack_create_calls.argtypes.copy()
    lib.oot_stack_create_plt.argtypes,lib.oot_stack_create_plt.restype=args[:-1]+[POINTER(PltFunction),c_size_t,args[-1]],c_void_p


def stub(name,entry,slot,target):
    delta=((slot&~4095)-(entry&~4095))//4096
    require(-(1<<20)<=delta<(1<<20) and slot%8==0,'synthetic PLT range invalid')
    encoded=delta&0x1fffff;low=slot&4095
    words=[0x90000010|((encoded&3)<<29)|((encoded>>2)<<5),0xf9400211|((low//8)<<10),0x91000210|(low<<10),0xd61f0220]
    p=Program(name,words,[],base=entry)
    return p,{'data':p.data,'slot':slot,'target':target,'symbol':'synthetic_'+name}


def synthetic_programs():
    rem=replace(next(p for p in leaf_programs() if p.name=='leaf_remainder'),name='plt_rem',base=CALLER+0x3000,trials=[])
    plus=Program('plt_plus',[add_immediate(0,0,7),0xd65f03c0],[],base=CALLER+0x4000,leaf=True)
    a,pa=stub('bridge_rem',CALLER+0x80000,RW+512,rem.base)
    b,pb=stub('bridge_plus',CALLER+0x81000,RO+4088,plus.base)
    root=LrAssembler('plt_root',CALLER,96,19,saves=((32,(20,21)),))
    root.branch('zero',0xb4000006);root.emit(mov(19,0),mov(21,1));root.bl(a.base)
    root.emit(memory_word(8,False,0,31,64));root.bl(CALLER+0x1000)
    root.emit(memory_word(8,True,4,31,64),add(0,0,4),add(0,0,19));root.bl(plus.base);root.bl(b.base)
    root.branch('epilogue',0x14000000,26);root.label('zero');root.emit(immediate(0,42))
    child=PauthAssembler('plt_child',CALLER+0x1000,64,48,key=0,explicit_auth=True)
    child.bl(b.base);child.emit(add_immediate(0,0,3))
    return [root.finish(),child.finish()],[rem,plus],[(a,pa),(b,pb)]


def matrix_programs(leaf):
    result=[];slots=[LOW,LOW+4088,RO,RO+8,RO+2040,RO+4088,RW+8,RW+4088]
    for i in range(16):
        p,record=stub('bridge_matrix'+str(i),CALLER+0x50000+i*0x2000+(4092 if i%2 else 0),slots[i%8],leaf)
        a=(LrAssembler('plt_matrix'+str(i),CALLER+0x10000+i*4096,64,19,bool(i%2),key=i%2,explicit_auth=bool(i&2)) if i&4 else
           PauthAssembler('plt_matrix'+str(i),CALLER+0x10000+i*4096,64,48,key=i%2,explicit_auth=bool(i&2)))
        a.bl(p.base);a.emit(add_immediate(0,0,i));result.append((a.finish(),p,record))
    return result


def depth_programs(bridge):
    result=[]
    for i in range(16):
        base=CALLER+0x100000+i*4096
        a=LrAssembler('plt_depth'+str(i),base,256,19+i%10,bool(i%3),key=i%2,explicit_auth=i%3==0) if i%2==0 else PauthAssembler('plt_depth'+str(i),base,256,240,key=i%2)
        a.bl(base+4096 if i<15 else bridge);result.append(a.finish())
    return result


def package(programs,slots):
    raw=bytearray(read_package(programs)[0])
    for slot,target in slots.items():
        for i in range(5):
            row=REGION.unpack_from(raw,HEADER.size+i*REGION.size)
            base,size,offset,payload=row[:4]
            if base<=slot and slot+8<=base+size and payload:
                raw[offset+slot-base:offset+slot-base+8]=target.to_bytes(8,'little');break
        else:raise ValueError('synthetic GOT slot has no payload')
    header=list(HEADER.unpack_from(raw));digest=hashlib.sha256(raw[HEADER.size:]).digest();header[-1]=digest
    raw[:HEADER.size]=HEADER.pack(*header)
    return bytes(raw),digest


class PltReference(PauthReference):
    def __init__(self,programs,slots):
        Reference.__init__(self);self.keys(KEYS);self.words={};pages={EXIT&~4095}
        for p in programs:
            pages.update(range(p.base&~4095,(p.base+len(p.data)+4095)&~4095,4096))
            self.words.update({p.base+4*i:w for i,w in enumerate(p.words)})
        pages.update(slot&~4095 for slot in slots)
        for page in sorted(pages):self.u.mem_map(page,4096)
        for p in programs:self.u.mem_write(p.base,p.data)
        for slot,target in slots.items():self.u.mem_write(slot,target.to_bytes(8,'little'))


def run_validation(mode='cmake'):
    require(version('unicorn')=='2.1.4','pinned PLT reference required')
    frames,leaves,bridges=synthetic_programs();matrix=matrix_programs(leaves[1].base);chain=depth_programs(bridges[1][0].base)
    leaf_codes={p.base:p.data for p in leaves};table_records={p.base:r for p,r in bridges}
    proofs=verify_plt_stack_functions({p.base:p.data for p in frames},leaf_codes,CALLER,table_records)
    singles={p.base:verify_plt_stack_functions({p.base:p.data},leaf_codes,p.base,{b.base:r})[p.base] for p,b,r in matrix}
    depths=verify_plt_stack_functions({p.base:p.data for p in chain},leaf_codes,chain[0].base,{bridges[1][0].base:bridges[1][1]})
    all_bridges=bridges+[(b,r) for _,b,r in matrix]
    programs=frames+leaves+[p for p,_,_ in matrix]+chain+[p for p,_ in all_bridges]
    slots={r['slot']:r['target'] for _,r in all_bridges};blob,digest=package(programs,slots);source=''
    for p in frames+[p for p,_,_ in matrix]+chain:
        proof=(proofs if p in frames else singles if p.base in singles else depths)[p.base]
        source+=emit_pauth_c(p.data,p.base,'oot_pauth_lift_'+p.name)[0]+emit_plt_stack_descriptor(proof,'oot_pauth_lift_'+p.name)
    for p,r in all_bridges:
        proof=verify_plt_stub(p.data,p.base,r['slot'],r['target'],leaf_codes,r['symbol'])
        source+=emit_c(p.data,p.base,'oot_lift_'+p.name)[0]+emit_plt_descriptor(proof,'oot_lift_'+p.name)
    def factory(selected,bs,name):
        return emit_stack_factory([p.name for p in selected],[p.name for p in leaves],selected[0].base,digest.hex(),[EXIT],
            plt_names=[p.name for p in bs],read_ranges=CAPS).replace('oot_create_bound_registry',name)
    source+=factory(frames,[p for p,_ in bridges],'oot_create_bound_registry')
    for p,b,_ in matrix:source+=factory([p],[b],'oot_create_'+p.name)
    source+=factory(chain,[bridges[1][0]],'oot_create_depth')
    modes=[(0,'s->x[16]^=1;',55),(1,'s->x[17]^=1;',55),(2,'s->x[16]^=8;',55),(3,'s->x[0]^=1;',55),
        (0,'s->x[30]^=1;',55),(0,'s->sp-=16;',55),(0,'s->nzcv^=UINT32_C(0x10000000);',55),
        (1,'m->regions[0].data[0]^=1;',55),(1,'(void)oot_memory_store(m,m->regions[0].base,1,0);',50),
        (1,'m->valid=2;',55),(0,'*n=0;',10),(3,'s->pc+=4;',11),(0,'status=OOT_LIFT_DISPATCH;',13),
        (0,'(void)oot_memory_load(m,s->sp,1,&scratch);',50),
        (1,'((OotGuestRegion *)m->regions)[0].permissions=3;',55),(0,'m->count=1;',55)]
    source+='''
static unsigned plt_bad_mode,plt_bad_calls;
OOT_LIFT_EXPORT void oot_plt_bad_set(unsigned m) { plt_bad_mode=m; }
OOT_LIFT_EXPORT unsigned oot_plt_bad_count(void) { return plt_bad_calls; }
OOT_LIFT_EXPORT int oot_plt_bad(OotArm64State *s,OotGuestMemory *m,uint64_t b,uint64_t *n) {
    uint64_t pc=s->pc,scratch=0;
    int status;
    ++plt_bad_calls;
    status=oot_lift_bridge_rem(s,m,b,n);
    switch(plt_bad_mode) {
'''+''.join(f'    case {i}: if(pc==UINT64_C(0x{bridges[0][0].base+4*index:x})) {{ {action} }} break;\n' for i,(index,action,_) in enumerate(modes,1))+'''    }
    return status;
}
'''
    lib,build=compile_library(leaves,mode,source);bindings(lib)
    lib.oot_plt_bad_set.argtypes=[c_uint32];lib.oot_plt_bad_count.restype=c_uint32
    path=Path(build['directory'])/'synthetic.ootmem';path.write_bytes(blob)
    message,error,report=create_string_buffer(192),c_uint32(),Report()
    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));require(image,f'PLT image rejected {message.value}')
    memory=lib.oot_runtime_memory(image);stack=memory.contents.regions[4].data;text=memory.contents.regions[0].data
    keys=lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));require(keys,'PLT keys rejected')
    ref=PltReference(programs,slots);rng=random.Random(0x9177);whole=prefixes=0
    def initial(base=CALLER,value=0,divisor=3,flag=1):
        s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)]
        s.pc,s.sp,s.x[0],s.x[1],s.x[6],s.x[30],s.nzcv=base,STACK_HIGH,value,divisor,flag,EXIT,rng.randrange(16)<<28
        return s
    def reset():memset(stack,0,STACK_SIZE)
    def check(d,s,expected,budget=1):
        nonlocal whole,prefixes
        reset();states,memories=ref.trace(s)
        require(lib.oot_stack_begin(d,byref(s),EXIT,byref(report))==0,'PLT begin rejected')
        require(lib.oot_stack_run(d,byref(s),0,byref(report))==1 and report.total_retired==0,'PLT zero budget changed retirement')
        for _ in range(1000):
            status=lib.oot_stack_run(d,byref(s),budget,byref(report));n=report.total_retired
            require(status in (1,2) and not report.error,f'PLT step rejected {status}/{report.error} pc={s.pc:x}')
            require(s.values()==states[n].values() and bytes(stack[:STACK_SIZE])==memories[n],'PLT prefix differs from ARM64 reference')
            prefixes+=1
            if status==2:break
        else:raise ValueError('PLT DAG did not finish')
        require(s.x[0]==expected and n==len(states)-1,'PLT independent result/count differs');whole+=1
    context=lib.oot_create_bound_registry(image,keys,byref(error));require(context,f'PLT registry rejected {error.value}')
    try:
        for flag in (0,1):
            for value in (0,1,U64,1<<63,rng.getrandbits(64)):
                for divisor in (0,3,U64):check(context,initial(value=value,divisor=divisor,flag=flag),(value+2*remainder(value,divisor)+24)&U64 if flag else 42)
        check(context,initial(value=7),33,7);check(context,initial(value=7),33,1000)
    finally:lib.oot_stack_destroy(context)
    for p,_,_ in matrix:
        factory=getattr(lib,'oot_create_'+p.name);factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
        context=factory(image,keys,byref(error));require(context,f'PLT matrix rejected {error.value}')
        try:
            for value in (0,1,U64,1<<63,rng.getrandbits(64)):
                index=next(i for i,row in enumerate(matrix) if row[0] is p)
                check(context,initial(p.base,value=value),(value+7+index)&U64)
        finally:lib.oot_stack_destroy(context)
    factory=lib.oot_create_depth;factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
    context=factory(image,keys,byref(error));require(context,'PLT depth rejected')
    try:check(context,initial(chain[0].base,value=9),16)
    finally:lib.oot_stack_destroy(context)
    frame_table=(CallFunction*len(frames))()
    for i,p in enumerate(frames):
        getter=getattr(lib,'oot_stack_plt_descriptor_'+p.name);getter.restype=POINTER(CallFunction);frame_table[i]=getter().contents
    plt_table=(PltFunction*len(bridges))()
    for i,(p,_) in enumerate(bridges):
        getter=getattr(lib,'oot_plt_descriptor_'+p.name);getter.restype=POINTER(PltFunction);plt_table[i]=getter().contents
    leaf_table,hashes=(LeafFunction*len(leaves))(),(CodeHash*len(leaves))()
    for i,p in enumerate(leaves):
        getter=getattr(lib,'oot_leaf_descriptor_'+p.name);getter.restype=POINTER(LeafFunction);leaf_table[i]=getter().contents
        getter=getattr(lib,'oot_leaf_code_hash_'+p.name);getter.restype=POINTER(CodeHash);hashes[i]=getter().contents
    body,returns=(c_uint8*32).from_buffer_copy(digest),(c_uint64*1)(EXIT)
    from read_validation import ReadRange
    ranges=(ReadRange*len(CAPS))(*[ReadRange(*r) for r in CAPS])
    def create():return lib.oot_stack_create_plt(image,frame_table,len(frames),CALLER,leaf_table,len(leaves),hashes,body,returns,1,keys,ranges,len(ranges),plt_table,len(bridges),byref(error))
    def pause(d,pc):
        s=initial(value=7);reset();require(lib.oot_stack_begin(d,byref(s),EXIT,byref(report))==0,'PLT pause begin rejected')
        for _ in range(1000):
            if s.pc==pc:return s
            require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'PLT pause failed')
        raise ValueError('PLT pause not reached')
    for field,value in (('slot',STACK_LOW),('slot',RW+513),('target',frames[1].base),('entry',CALLER),('run',0)):
        saved=getattr(plt_table[0],field);setattr(plt_table[0],field,value)
        require(create() is None,'invalid PLT metadata accepted');setattr(plt_table[0],field,saved)
    for i in range(4):
        old=plt_table[0].words[i];plt_table[0].words[i]^=1
        require(create() is None,'incorrect PLT instruction metadata accepted');plt_table[0].words[i]=old
    # A self-consistent alternate readable slot still cannot rewrite bound text.
    require(lib.oot_memory_store(memory,RW+520,8,leaves[0].base)==1,'alternate slot fixture failed')
    slot,load,add_word=plt_table[0].slot,plt_table[0].words[1],plt_table[0].words[2]
    plt_table[0].slot+=8;plt_table[0].words[1]+=1<<10;plt_table[0].words[2]+=8<<10
    require(create() is None,'valid alternate PLT words differing from bound text accepted')
    plt_table[0].slot,plt_table[0].words[1],plt_table[0].words[2]=slot,load,add_word
    returns[0]=bridges[0][0].base+4;require(create() is None,'return site inside PLT accepted');returns[0]=EXIT
    require(lib.oot_stack_create_calls(image,frame_table,len(frames),CALLER,leaf_table,len(leaves),hashes,body,returns,1,keys,ranges,len(ranges),byref(error)) is None,
        'old constructor accepted policy-7 frames')
    plt_table[0].run=cast(lib.oot_plt_bad,c_void_p).value
    for mode_index,(index,_,expected_error) in enumerate(modes,1):
        context=create();require(context,'PLT bad callback fixture rejected');lib.oot_plt_bad_set(mode_index)
        try:
            s=pause(context,bridges[0][0].base+index*4);before,backing=s.values(),bytes(stack[:STACK_SIZE])
            require(lib.oot_stack_run(context,byref(s),1,byref(report))==4 and report.error==expected_error and
                s.values()==before and bytes(stack[:STACK_SIZE])==backing,f'bad PLT callback committed {mode_index}/{report.error}')
            calls=lib.oot_plt_bad_count();require(lib.oot_stack_run(context,byref(s),100,byref(report))==4 and lib.oot_plt_bad_count()==calls,'PLT contract fault not latched')
        finally:lib.oot_stack_destroy(context)
    lib.oot_plt_bad_set(0)
    call=CALLER+4*next(i for i,x in enumerate(proofs[CALLER]['steps']) if x['kind']==CALL)
    stops=[call]+[bridges[0][0].base+4*i for i in range(4)]+[leaves[0].base,leaves[0].base+4]
    for pc in stops:
        context=create();require(context,'PLT GOT fault fixture rejected')
        try:
            s=pause(context,pc);before,backing=s.values(),bytes(stack[:STACK_SIZE]);calls=lib.oot_plt_bad_count()
            require(lib.oot_memory_store(memory,RW+512,8,leaves[1].base)==1,'GOT edit failed')
            require(lib.oot_stack_run(context,byref(s),1,byref(report))==3 and report.error==54 and s.values()==before and
                bytes(stack[:STACK_SIZE])==backing and lib.oot_plt_bad_count()==calls,'changed GOT retired a transfer')
            require(lib.oot_memory_store(memory,RW+512,8,leaves[0].base)==1,'GOT repair failed')
            require(lib.oot_stack_run(context,byref(s),1000,byref(report))==2 and s.x[0]==33,'GOT repair failed to resume')
        finally:lib.oot_stack_destroy(context)
    for offset in (bridges[0][0].base-CALLER,leaves[0].base-CALLER):
        context=create();require(context,'PLT code fault fixture rejected')
        try:
            s=pause(context,bridges[0][0].base+4);before=s.values();text[offset]^=1
            require(lib.oot_stack_run(context,byref(s),1,byref(report))==3 and report.error==17 and s.values()==before,'changed PLT/leaf code accepted')
        finally:text[offset]^=1;lib.oot_stack_destroy(context)
    context=create();require(context,'PLT permission fixture rejected')
    try:
        s=pause(context,bridges[0][0].base+4);before,backing=s.values(),bytes(stack[:STACK_SIZE])
        memory.contents.regions[2].permissions=0
        require(lib.oot_stack_run(context,byref(s),1,byref(report))==3 and report.error==50 and s.values()==before and bytes(stack[:STACK_SIZE])==backing,
            'GOT permission failure committed state')
        memory.contents.regions[2].permissions=3
        require(lib.oot_stack_run(context,byref(s),1000,byref(report))==2 and s.x[0]==33,'GOT permission repair failed')
    finally:memory.contents.regions[2].permissions=3;lib.oot_stack_destroy(context)
    context=create();require(context,'PLT ancestor fixture rejected')
    try:
        s=pause(context,bridges[0][0].base);before=s.values();stack[STACK_SIZE-96]^=1
        require(lib.oot_stack_run(context,byref(s),1,byref(report))==3 and report.error==49 and s.values()==before,'PLT ignored ancestor record edit')
    finally:lib.oot_stack_destroy(context)
    plt_table[0].run=cast(lib.oot_lift_bridge_rem,c_void_p).value
    context=create();require(context,'PLT retained fixture rejected');plt_table[0].words[0]=0;plt_table[0].slot=0
    lib.oot_pauth_destroy(keys);lib.oot_runtime_close(image)
    try:check(context,initial(value=7),33)
    finally:lib.oot_stack_destroy(context)
    result={'schema_version':1,'result':'passed','game_code_executed':False,'whole_call_cases':whole,'prefix_checks':prefixes,
        'matrix_layouts':len(matrix),'bad_callback_modes':len(modes),'got_pause_points':len(stops),'max_depth':16,
        'reference':{'unicorn':version('unicorn')},'native_build':build}
    destination=Path(build['directory'])/'plt-report.json';destination.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result,destination


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--compiler',choices=('cmake','gcc'),default='cmake')
    r,path=run_validation(parser.parse_args().compiler);print(json.dumps({k:v for k,v in r.items() if k!='native_build'},indent=2));print(path)
