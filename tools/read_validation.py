"""Synthetic policy-5 checked reads with retained-image capabilities and PAC."""

import argparse
from ctypes import (POINTER, Structure, byref, c_size_t, c_uint8, c_uint32, c_uint64,
                    c_void_p, cast, create_string_buffer, memset, memmove, sizeof, string_at)
from dataclasses import replace
from importlib.metadata import version
import hashlib
import json
import os
from pathlib import Path
import random

from arm64_lifter import U64, decode_instruction
from dispatcher_validation import CALLER, EXIT, STACK_LOW, STACK_HIGH, STACK_SIZE, Report, LeafFunction, CodeHash
from input_formats import require
from leaf_validation import leaf_programs, remainder
from lifter_validation import compile_library
from lifter_validation_types import State
from memory_validation import transfer
from ordered_programs import rcpc
from pair_validation import pair
from pauth_lifter import emit_pauth_c
from pauth_stack_validation import PauthAssembler, PauthFunction, PauthReference, bindings as pac_bindings, depth_programs
from pauth_validation import KEYS
from prepare_registry import emit_stack_factory
from prepare_runtime import HEADER,REGION,MAGIC
from stack_cfg_validation import add_immediate,mov,immediate
from stack_layout_validation import memory_word,add
from stack_layout_verifier import verify_read_stack_functions,emit_read_stack_descriptor,READ

ROOT=Path(__file__).resolve().parent.parent
RO,RW,BSS,LITERAL=CALLER+0x200000,CALLER+0x210000,CALLER+0x220000,CALLER+0xE0000
CAPS=((LITERAL,16),(RO+32,256),(RW+64,256),(BSS,128))


class ReadRange(Structure):
    _fields_=[('base',c_uint64),('size',c_uint64)]


class ReadFunction(Structure):
    _fields_=[('pauth',PauthFunction),('read_words',POINTER(c_uint32))]


def bindings(lib):
    pac_bindings(lib)
    args=lib.oot_stack_create_pauth.argtypes.copy();args[1]=POINTER(ReadFunction)
    lib.oot_stack_create_reads.argtypes,lib.oot_stack_create_reads.restype=args[:-1]+[POINTER(ReadRange),c_size_t,args[-1]],c_void_p
    lib.oot_memory_store.argtypes=[c_void_p,c_uint64,c_uint32,c_uint64]
    lib.oot_memory_store.restype=c_uint32


def patterns():
    ro=bytearray(bytes(range(256))*16);ro[64]=128;ro[78:80]=(-7).to_bytes(2,'little',signed=True)
    rw=bytearray(4096);rw[72:80]=(RO+80).to_bytes(8,'little');rw[80:84]=(-11).to_bytes(4,'little',signed=True)
    return bytes(ro),bytes(rw),bytes(4096),bytes.fromhex('67452381fedcba9801efcdab89674523')


def synthetic_programs():
    leaf=replace(next(p for p in leaf_programs() if p.name=='leaf_remainder'),name='read_rem',base=CALLER+0x3000,trials=[])
    root=PauthAssembler('read_root',CALLER,96,80,((48,(19,20)),(72,(21,))),fp_first=False)
    root.branch('zero',0xB4000006);root.emit(mov(19,0),mov(21,2),transfer(3,1,20,1,immediate=1),rcpc(0,0,0),memory_word(8,False,0,31,0))
    root.bl(CALLER+0x1000);root.emit(memory_word(8,True,4,29,-80),add(0,0,4),mov(1,21));root.bl(leaf.base)
    root.branch('epilogue',0x14000000,26);root.label('zero');root.emit(immediate(0,42))
    child=PauthAssembler('read_child',CALLER+0x1000,64,0,key=0,explicit_auth=True,split=False)
    child.emit(transfer(1,2,2,20,'unscaled',-2),add(0,0,2));child.bl(CALLER+0x2000)
    inner=PauthAssembler('read_inner',CALLER+0x2000,48,32,key=1)
    inner.emit(transfer(2,2,3,1,immediate=4),add(0,0,3))
    return [root.finish(),child.finish(),inner.finish()],[leaf]


def matrix_programs():
    result=[]
    def build(word,setup,formula,label):
        n=len(result);a=PauthAssembler('read_matrix'+str(n),CALLER+0x10000+n*4096,64,48,((32,(19,)),),key=n%2,explicit_auth=n%3==0)
        if callable(word):word=word(a.base+len(a.words)*4)
        i=decode_instruction(word,a.base+len(a.words)*4);a.emit(word)
        if i.form=='loadstore_pair':a.emit(add(0,i.rd,i.rt2))
        elif i.rd!=31:a.emit(mov(0,i.rd))
        result.append((a.finish(),setup,formula,label))
    def value(data,offset,size,opc):
        v=int.from_bytes(data[offset:offset+(1<<size)],'little',signed=opc>=2)
        return v & (U64 if size==3 or opc==2 else 0xffffffff)
    for size in range(4):
        for opc in range(1,4):
            if size==3 and opc>=2 or size==2 and opc==3:continue
            build(transfer(size,opc,0,1,immediate=1),lambda ea,s=size:{1:ea-(1<<s)},lambda d,o,s=size,p=opc:value(d,o,s,p),'unsigned')
            build(transfer(size,opc,1,1,'unscaled',-8),lambda ea:{1:ea+8},lambda d,o,s=size,p=opc:value(d,o,s,p),'unscaled-alias')
            build(transfer(size,opc,19,1,'register',rm=2,extend=6,scaled=1),
                  lambda ea,s=size:{1:ea+2*(1<<s),2:0x12345678fffffffe},lambda d,o,s=size,p=opc:value(d,o,s,p),'register-sxtw')
    for extend in (2,3,6,7):
        for scaled in (0,1):
            def setup(ea,e=extend,s=scaled):
                amount=8 if s else 1
                r=0x1234567800000002 if e==2 else 2 if e==3 else 0x12345678fffffffe if e==6 else U64
                offset=2*amount if e in (2,3) else -2*amount if e==6 else -amount
                return {1:(ea-offset)&U64,2:r}
            build(transfer(3,1,19,1,'register',rm=2,extend=extend,scaled=scaled),setup,lambda d,o:int.from_bytes(d[o:o+8],'little'),'register-extend')
    for size in range(4):
        for rt in (0,31):
            build(rcpc(size,rt),lambda ea:{1:ea},lambda d,o,s=size,r=rt:int.from_bytes(d[o:o+(1<<s)],'little') if r!=31 else 0xABCD,'rcpc')
    for opc in range(3):
        size=3 if opc==2 else 2
        build(pair(opc,True,0,19,1,2,0),lambda ea:{1:ea},
            lambda d,o,s=size,p=opc:(value(d,o,s,2 if p==1 else 1)+value(d,o+(1<<s),s,2 if p==1 else 1))&U64,'pair')
    for opc in range(3):
        build(lambda pc,p=opc:(p<<30)|0x18000000|((((LITERAL-pc)//4)&0x7ffff)<<5),lambda ea:{},
            lambda d,o,p=opc:value(patterns()[3],0,3 if p==1 else 2,2 if p==2 else 1),'literal')
    return result


def package(programs):
    text=bytearray(0x120000)
    for p in programs:text[p.base-CALLER:p.base-CALLER+len(p.data)]=p.data
    ro,rw,bss,literal=patterns();text[LITERAL-CALLER:LITERAL-CALLER+16]=literal
    rows=[];payloads=[];cursor=HEADER.size+5*REGION.size
    for base,data,permission,kind in ((CALLER,bytes(text),1,1),(RO,ro,1,2),(RW,rw,3,3),(BSS,bss,3,4),(STACK_LOW,bytes(STACK_SIZE),3,5)):
        payload=b'' if kind in (4,5) else data
        rows.append(REGION.pack(base,len(data),cursor,len(payload),permission,kind,b'stack' if kind==5 else b'synthetic',0));payloads.append(payload);cursor+=len(payload)
    body=b''.join(rows+payloads);digest=hashlib.sha256(body).digest()
    return HEADER.pack(MAGIC,1,5,STACK_HIGH,len(text)+3*4096+STACK_SIZE,HEADER.size,HEADER.size+5*REGION.size,cursor,0,digest)+body,digest


def run_validation(mode='cmake'):
    require(version('unicorn')=='2.1.4','checked reads require the pinned reference')
    frames,leaves=synthetic_programs();matrix=matrix_programs()
    chain=[replace(p,base=CALLER+0x100000+i*4096,name='read_depth'+str(i)) for i,p in enumerate(depth_programs())]
    # Assemble the synthetic depth chain again at the selected addresses.
    for i,p in enumerate(chain):
        a=PauthAssembler(p.name,p.base,256,240 if i%2==0 else 0,key=i%2,explicit_auth=i%3==0,split=i%2==0)
        if i!=15:a.bl(p.base+4096)
        chain[i]=a.finish()
    proofs=verify_read_stack_functions({p.base:p.data for p in frames},{p.base:p.data for p in leaves},CALLER)
    singles={p.base:verify_read_stack_functions({p.base:p.data},{},p.base)[p.base] for p,_,_,_ in matrix}
    depths=verify_read_stack_functions({p.base:p.data for p in chain},{},chain[0].base)
    programs=frames+leaves+[p for p,_,_,_ in matrix]+chain
    blob,digest=package(programs);source=''
    for p in frames+[p for p,_,_,_ in matrix]+chain:
        proof=(proofs if p in frames else singles if p.base in singles else depths)[p.base]
        source+=emit_pauth_c(p.data,p.base,'oot_pauth_lift_'+p.name)[0]+emit_read_stack_descriptor(proof,'oot_pauth_lift_'+p.name)
    source+=emit_stack_factory([p.name for p in frames],[p.name for p in leaves],CALLER,digest.hex(),[EXIT],reads=True,read_ranges=CAPS)
    for p,_,_,_ in matrix:
        source+=emit_stack_factory([p.name],[],p.base,digest.hex(),[EXIT],reads=True,read_ranges=CAPS).replace('oot_create_bound_registry','oot_create_'+p.name)
    source+=emit_stack_factory([p.name for p in chain],[],chain[0].base,digest.hex(),[EXIT],reads=True,read_ranges=CAPS).replace('oot_create_bound_registry','oot_create_read_depth')
    read_index=next(i for i,s in enumerate(proofs[CALLER]['steps']) if s['kind']==READ)
    source+='''
static unsigned read_bad_mode, read_bad_calls;
OOT_LIFT_EXPORT void oot_read_bad_set(unsigned m) { read_bad_mode=m; }
OOT_LIFT_EXPORT unsigned oot_read_bad_count(void) { return read_bad_calls; }
OOT_LIFT_EXPORT int oot_read_bad(OotArm64State *s,OotGuestMemory *m,const OotPauth *p,uint64_t b,uint64_t *n)
{
    uint64_t pc=s->pc;
    int result;
    ++read_bad_calls;
    result=oot_pauth_lift_read_root(s,m,p,b,n);
'''
    source+=f'    if (pc==UINT64_C(0x{CALLER+read_index*4:x})) {{\n'
    actions=['s->x[20]^=1;','s->x[5]^=1;','s->nzcv^=UINT32_C(0x10000000);',
             '(void)oot_memory_store(m,m->regions[0].base,1,0);','m->regions[0].data[0]^=1;',
             '*n=0;','s->pc+=4;','result=OOT_LIFT_DISPATCH;','m->valid=2;',
             '((OotGuestRegion *)m->regions)[0].size+=1;', '((OotGuestRegion *)m->regions)[0].permissions=3;']
    source+='    switch (read_bad_mode) {\n'+''.join(f'    case {i}: {a} break;\n' for i,a in enumerate(actions,1))+'    }\n    }\n    return result;\n}\n'
    lib,build=compile_library(leaves,mode,source);bindings(lib)
    lib.oot_read_bad_set.argtypes=[c_uint32];lib.oot_read_bad_count.restype=c_uint32
    path=Path(build['directory'])/'synthetic.ootmem';path.write_bytes(blob)
    message,error,report=create_string_buffer(192),c_uint32(),Report()
    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));require(image,f'read image rejected: {message.value}')
    memory=lib.oot_runtime_memory(image);stack=memory.contents.regions[4].data;rw=memory.contents.regions[2].data
    key_data=(c_uint64*4)(*KEYS);keys=lib.oot_pauth_create(1,key_data);require(keys,'read keys rejected')
    ref=PauthReference(programs)
    require((ref.isar1 >> 20) & 15 >= 1,'checked read reference lacks FEAT_LRCPC')
    for base,data in ((RO,patterns()[0]),(RW,patterns()[1]),(BSS,patterns()[2]),(LITERAL,patterns()[3])):
        ref.u.mem_map(base&~4095,4096);ref.u.mem_write(base,data)
    rng=random.Random(0xCA9A8);whole=prefixes=0
    def initial(base=CALLER,flag=1,divisor=3):
        s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)]
        s.pc,s.sp,s.x[0],s.x[1],s.x[2],s.x[6],s.x[30],s.nzcv=base,STACK_HIGH,RO+64,RW+64,divisor,flag,EXIT,rng.randrange(16)<<28
        return s
    def reset():
        memset(stack,0,STACK_SIZE);memmove(rw,patterns()[1],4096);ref.u.mem_write(RW,patterns()[1])
    def check(context,s,formula,budget=1):
        nonlocal whole,prefixes
        entry=s.pc
        reset();states,memories=ref.trace(s)
        require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'read begin rejected')
        require(lib.oot_stack_run(context,byref(s),0,byref(report))==1 and report.total_retired==0,'read zero budget changed state')
        for _ in range(1000):
            status=lib.oot_stack_run(context,byref(s),budget,byref(report));n=report.total_retired
            require(status in (1,2) and not report.error,f'read run rejected {status}/{report.error} pc={s.pc:x}')
            require(s.values()==states[n].values() and bytes(stack[:STACK_SIZE])==memories[n],'checked read differs from reference prefix')
            prefixes+=1
            if status==2:break
        else:raise ValueError('checked read did not terminate')
        require(s.x[0]==formula and n==len(states)-1,f'checked read independent result/count mismatch at {entry:x}: {s.x[0]:x} != {formula:x}')
        whole+=1
    context=lib.oot_create_bound_registry(image,keys,byref(error));require(context,f'read registry rejected {error.value}')
    try:
        for flag in (0,1):
            for divisor in (0,1,3,U64,1<<63):
                check(context,initial(flag=flag,divisor=divisor),42 if not flag else remainder(238,divisor))
        # Writable external bytes may evolve between yields; no stale snapshot is reused.
        s=initial();reset();target=CALLER+read_index*4
        require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'read pause begin failed')
        while s.pc!=target:require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'read pause failed')
        require(lib.oot_memory_store(memory,RW+72,8,RO+96)==1,'host data update failed')
        require(lib.oot_stack_run(context,byref(s),1,byref(report))==1 and s.x[20]==RO+96,'read resumed with stale external bytes')
        lib.oot_stack_abort(context,byref(report))
    finally:lib.oot_stack_destroy(context)
    for p,setup,formula,label in matrix:
        factory=getattr(lib,'oot_create_'+p.name);factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
        context=factory(image,keys,byref(error));require(context,f'matrix read registry rejected {label}/{error.value}')
        try:
            for offset in ((64,80,128) if label in ('rcpc','literal') else (64,65,80,128)):
                s=initial(p.base);s.x[0]=0xABCD
                for r,v in setup(RO+offset).items():s.x[r]=v
                check(context,s,formula(patterns()[0],offset))
            if label=='rcpc':
                s=initial(p.base);s.x[0]=0xABCD;s.x[1]=BSS
                check(context,s,0xABCD if decode_instruction(p.words[5],p.base+20).rd==31 else 0)
        finally:lib.oot_stack_destroy(context)
    factory=lib.oot_create_read_depth;factory.argtypes,factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
    context=factory(image,keys,byref(error));require(context,'read depth registry rejected')
    try:
        s=initial(chain[0].base);check(context,s,s.x[0])
    finally:lib.oot_stack_destroy(context)

    # Constructor metadata and runtime fault isolation use the actual generated descriptors.
    table=(ReadFunction*len(frames))()
    for i,p in enumerate(frames):
        getter=getattr(lib,'oot_stack_read_descriptor_'+p.name);getter.restype=POINTER(ReadFunction);table[i]=getter().contents
    leaf_table,hashes=(LeafFunction*len(leaves))(),(CodeHash*len(leaves))()
    for i,p in enumerate(leaves):
        getter=getattr(lib,'oot_leaf_descriptor_'+p.name);getter.restype=POINTER(LeafFunction);leaf_table[i]=getter().contents
        getter=getattr(lib,'oot_leaf_code_hash_'+p.name);getter.restype=POINTER(CodeHash);hashes[i]=getter().contents
    body,returns=(c_uint8*32).from_buffer_copy(digest),(c_uint64*1)(EXIT)
    ranges=(ReadRange*len(CAPS))(*[ReadRange(*r) for r in CAPS])
    def create():return lib.oot_stack_create_reads(image,table,len(frames),CALLER,leaf_table,len(leaves),hashes,body,returns,1,keys,ranges,len(ranges),byref(error))
    for base,size in ((STACK_LOW,16),(RW-1,16),(RW,8192),(RO,0),(RO,U64)):
        old=ranges[0];saved=(old.base,old.size);ranges[0]=ReadRange(base,size)
        require(create() is None,'invalid retained read range accepted');ranges[0]=ReadRange(*saved)
    n=table[0].pauth.layout.cfg.info.instruction_count
    words=(c_uint32*n).from_buffer_copy(string_at(table[0].read_words,n*4));table[0].read_words=words
    old=words[read_index];words[read_index]=rcpc(3,20,1)
    require(create() is None,'read opcode differing from bound text accepted');words[read_index]=old
    words[0]=old;require(create() is None,'read opcode outside READ phase accepted');words[0]=0
    table[0].pauth.run=cast(lib.oot_read_bad,c_void_p).value
    for mode_index,expected_error in enumerate((53,53,53,50,53,10,11,13,53,53,53),1):
        context=create();require(context,'bad read callback fixture rejected');lib.oot_read_bad_set(mode_index)
        try:
            s=initial();reset();require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'bad read begin failed')
            while s.pc!=target:require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'bad read setup failed')
            before,backing,data=s.values(),bytes(stack[:STACK_SIZE]),bytes(rw[:4096])
            require(lib.oot_stack_run(context,byref(s),1,byref(report))==4 and report.error==expected_error and
                    s.values()==before and bytes(stack[:STACK_SIZE])==backing and bytes(rw[:4096])==data,
                    f'bad read callback committed {mode_index}/{report.error}')
            calls=lib.oot_read_bad_count();require(lib.oot_stack_run(context,byref(s),100,byref(report))==4 and lib.oot_read_bad_count()==calls,'read fault not latched')
        finally:lib.oot_stack_destroy(context)
    lib.oot_read_bad_set(0)
    for pointer in (RW+55,RW+312,STACK_LOW,STACK_HIGH-8,U64-11,0):
        context=create();require(context,'read rejection fixture failed')
        try:
            s=initial();s.x[1]=pointer;reset();require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'read range begin failed')
            while s.pc!=target:require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'read range pause failed')
            before,backing=s.values(),bytes(stack[:STACK_SIZE])
            calls=lib.oot_read_bad_count()
            status=lib.oot_stack_run(context,byref(s),1,byref(report))
            require(status==3 and report.error==52 and report.retired_this_call==0 and s.values()==before and bytes(stack[:STACK_SIZE])==backing,
                    f'out-of-range read changed state {pointer:x}/{report.error}')
            require(lib.oot_read_bad_count()==calls,'out-of-range read invoked callback')
        finally:lib.oot_stack_destroy(context)
    # Current-frame local aliases are readable, but saved slots and ancestor locals are not.
    for offset,allowed in ((0,True),(48,False),(80,False),(92,False)):
        context=create();require(context,'local alias fixture rejected')
        try:
            s=initial();s.x[1]=STACK_HIGH-96+offset-8;reset()
            require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'local alias begin failed')
            while s.pc!=target:require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'local alias setup failed')
            before,backing=s.values(),bytes(stack[:STACK_SIZE]);status=lib.oot_stack_run(context,byref(s),1,byref(report))
            require((status==1 and s.x[20]==0) if allowed else (status==3 and report.error==52 and s.values()==before and bytes(stack[:STACK_SIZE])==backing),
                    'local alias escaped reserved-slot ownership')
        finally:lib.oot_stack_destroy(context)
    context=create();require(context,'ancestor read fixture rejected')
    try:
        s=initial();reset();require(lib.oot_memory_store(memory,RW+72,8,STACK_HIGH-96+2)==1,'ancestor pointer setup failed')
        require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'ancestor begin failed')
        child_read=frames[1].base+4*next(i for i,step in enumerate(proofs[frames[1].base]['steps']) if step['kind']==READ)
        while s.pc!=child_read:require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'ancestor setup failed')
        before,backing=s.values(),bytes(stack[:STACK_SIZE])
        require(lib.oot_stack_run(context,byref(s),1,byref(report))==3 and report.error==52 and s.values()==before and bytes(stack[:STACK_SIZE])==backing,
                'child read ancestor locals')
    finally:lib.oot_stack_destroy(context)
    saved_ranges=[(r.base,r.size) for r in ranges]
    ranges[2],ranges[3]=ReadRange(RW+64,8),ReadRange(RW+72,8)
    context=create();require(context,'adjacent capability fixture rejected')
    try:
        s=initial();s.x[1]=RW+60;reset();require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'cap boundary begin failed')
        while s.pc!=target:require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'cap boundary setup failed')
        before=s.values()
        require(lib.oot_stack_run(context,byref(s),1,byref(report))==3 and report.error==52 and s.values()==before,'read joined adjacent capabilities')
    finally:
        lib.oot_stack_destroy(context)
        for i,r in enumerate(saved_ranges):ranges[i]=ReadRange(*r)
    # An in-range but misaligned RCpc read rejects before its callback.
    p,_,_,_=next(row for row in matrix if row[3]=='rcpc' and decode_instruction(row[0].words[5],row[0].base+20).access_size==8)
    factory=getattr(lib,'oot_create_'+p.name);context=factory(image,keys,byref(error));require(context,'alignment fixture rejected')
    try:
        s=initial(p.base);s.x[1]=RO+65;reset();read_pc=p.base+20
        require(lib.oot_stack_begin(context,byref(s),EXIT,byref(report))==0,'alignment begin failed')
        while s.pc!=read_pc:require(lib.oot_stack_run(context,byref(s),1,byref(report))==1,'alignment setup failed')
        before=s.values()
        require(lib.oot_stack_run(context,byref(s),1,byref(report))==3 and report.error==50 and memory.contents.fault.reason==5 and s.values()==before,'misaligned checked acquire committed')
    finally:lib.oot_stack_destroy(context)
    table[0].pauth.run=cast(lib.oot_pauth_lift_read_root,c_void_p).value
    # The registry copies ranges/read metadata and retains keys/image independently.
    context=create();require(context,'read retained fixture rejected');ranges[0].size=0;words[read_index]=0
    lib.oot_pauth_destroy(keys);lib.oot_runtime_close(image)
    try:check(context,initial(),remainder(238,3))
    finally:lib.oot_stack_destroy(context)
    result={'schema_version':1,'result':'passed','game_code_executed':False,'whole_call_cases':whole,
            'prefix_checks':prefixes,'matrix_programs':len(matrix),'bad_callback_modes':len(actions),'max_depth':16,
            'runtime_read_ranges_required':True,'reference':{'unicorn':version('unicorn')},'native_build':build}
    destination=Path(build['directory'])/'read-report.json';destination.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result,destination


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--compiler',choices=('cmake','gcc'),default='cmake')
    r,path=run_validation(parser.parse_args().compiler);print(json.dumps({k:v for k,v in r.items() if k!='native_build'},indent=2));print(path)
