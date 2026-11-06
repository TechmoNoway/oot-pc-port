"""Synthetic memory-leaf direct/PLT calls, operand snapshots and retained ownership."""
from ctypes import POINTER,Structure,byref,c_size_t,c_uint8,c_uint32,c_uint64,c_void_p,cast,create_string_buffer,memset,memmove,string_at
from importlib.metadata import version
import json
import os
from pathlib import Path
import random
from arm64_lifter import U64,decode_instruction,emit_c
from call_validation import LrAssembler
from checked_memory_validation import bindings as stack_bindings, matrix_programs as store_matrix
from dispatcher_validation import CALLER,EXIT,STACK_LOW,STACK_HIGH,STACK_SIZE,Report,LeafFunction,CodeHash,bindings as leaf_bindings
from input_formats import require
from leaf_verifier import emit_leaf_descriptor
from lifter_validation import compile_library
from lifter_validation_types import Program,State
from memory_leaf_verifier import verify_memory_leaf,emit_memory_leaf_descriptor
from memory_validation import transfer
from pair_validation import pair
from pauth_lifter import emit_pauth_c
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from plt_validation import PltFunction,PltReference,stub,package
from plt_verifier import emit_plt_descriptor,verify_memory_plt_stub
from prepare_registry import emit_stack_factory
from read_validation import ReadRange,CAPS,RO,RW,BSS,LITERAL,patterns,matrix_programs as load_matrix
from stack_cfg_validation import add_immediate,mov,immediate
from stack_layout_validation import add
from stack_layout_verifier import verify_memory_callee_stack_functions,emit_memory_callee_stack_descriptor

ROOT=Path(__file__).resolve().parent.parent
WRITES=((RW+64,256),(BSS,128))


class MemoryLeafFunction(Structure):
    _fields_=[('info',LeafFunction),('effect_words',POINTER(c_uint32))]


def bindings(lib):
    stack_bindings(lib);leaf_bindings(lib)
    args=lib.oot_stack_create_memory.argtypes.copy();args[4]=POINTER(MemoryLeafFunction)
    lib.oot_stack_create_memory_callees.argtypes,lib.oot_stack_create_memory_callees.restype=args,c_void_p
    lib.oot_leaf_dispatcher_create_memory_bound.argtypes=[c_void_p,POINTER(MemoryLeafFunction),c_size_t,POINTER(CodeHash),POINTER(c_uint8),POINTER(c_uint64),c_size_t,POINTER(ReadRange),c_size_t,POINTER(ReadRange),c_size_t,POINTER(c_uint32)]
    lib.oot_leaf_dispatcher_create_memory_bound.restype=c_void_p


def graph_programs():
    writer=Program('callee_writer',[transfer(3,0,0,1),add_immediate(0,0,1),pair(2,False,0,0,1,2,1),0xd65f03c0],[],base=CALLER+0x3000)
    # Both original synthetic CFG paths compute the same sum with different loads.
    reader=Program('callee_reader',[0xb4000087,transfer(3,1,0,1),transfer(3,1,2,1,immediate=1),0x14000002,
        pair(2,True,0,2,1,2,0),add(0,0,2),transfer(3,0,0,1,immediate=3),0xd65f03c0],[],base=CALLER+0x4000)
    ordinary=Program('callee_ordinary',[add_immediate(0,0,7),0xd65f03c0],[],base=CALLER+0x5000,leaf=True)
    bridge,record=stub('callee_bridge',CALLER+0xd0000,RW+512,reader.base)
    r=LrAssembler('callee_root',CALLER,64,19);r.branch('zero',0xb4000006);r.bl(writer.base);r.bl(CALLER+0x1000);r.bl(ordinary.base)
    r.branch('epilogue',0x14000000,26);r.label('zero');r.emit(immediate(0,42))
    c=PauthAssembler('callee_child',CALLER+0x1000,64,48,key=0,explicit_auth=True);c.bl(bridge.base);c.emit(add_immediate(0,0,3))
    return [r.finish(),c.finish()],[writer,reader],[ordinary],(bridge,record)


def matrix_programs():
    result=[]
    for original,setup,z,regs,label in store_matrix():
        if label=='local':continue
        n=len(result);p=Program('memory_store'+str(n),[original.words[5],0xd65f03c0],[],base=CALLER+0x20000+n*4096)
        result.append((p,setup,'write',z,regs,label,None))
    for n,(original,setup,formula,label) in enumerate(load_matrix()):
        word=original.words[5];i=decode_instruction(word,original.base+20)
        if i.rd==19:word=(word&~31)|3
        if i.form=='loadstore_pair' and i.rt2==19:word=(word&~(31<<10))|(3<<10)
        base=CALLER+0x60000+n*4096
        if i.form=='load_literal':word=(word&~(0x7ffff<<5))|((((LITERAL-base)//4)&0x7ffff)<<5)
        d=decode_instruction(word,base)
        words=[word]
        if d.form=='loadstore_pair':words.append(add(0,d.rd,d.rt2))
        elif d.rd!=31:words.append(mov(0,d.rd))
        words.append(0xd65f03c0)
        p=Program('memory_load'+str(n),words,[],base=base)
        result.append((p,setup,'read',0,(),label,formula))
    return result


def depth_programs(writer,bridge):
    result=[]
    for n in range(16):
        a=(LrAssembler('callee_depth'+str(n),CALLER+0x100000+n*4096,256,28,key=n%2,explicit_auth=bool(n&2)) if n%3==0 else
           PauthAssembler('callee_depth'+str(n),CALLER+0x100000+n*4096,256,240 if n%2 else 0,key=n%2,explicit_auth=bool(n&2),split=bool(n%2)))
        a.bl(writer);a.bl(a.base+4096 if n!=15 else bridge);result.append(a.finish())
    return result


def run_validation(mode='cmake'):
    require(version('unicorn')=='2.1.4','pinned enabled QARMA5 reference required')
    frames,memories,ordinary,(bridge,record)=graph_programs();matrix=matrix_programs();chain=depth_programs(memories[0].base,bridge.base)
    terminal={p.base:p.data for p in ordinary};memory={p.base:p.data for p in memories};plts={bridge.base:record}
    proofs=verify_memory_callee_stack_functions({p.base:p.data for p in frames},terminal,CALLER,plts,memory)
    depth=verify_memory_callee_stack_functions({p.base:p.data for p in chain},{},chain[0].base,plts,memory)
    programs=frames+memories+ordinary+[bridge]+[p for p,*_ in matrix]+chain
    blob,digest=package(programs,{record['slot']:memories[1].base});source=''
    for p in frames+chain:source+=emit_pauth_c(p.data,p.base,'oot_pauth_lift_'+p.name)[0]+emit_memory_callee_stack_descriptor((proofs if p in frames else depth)[p.base],'oot_pauth_lift_'+p.name)
    for p in memories+[p for p,*_ in matrix]:source+=emit_c(p.data,p.base,'oot_lift_'+p.name)[0]+emit_memory_leaf_descriptor(p.data,p.base,'oot_lift_'+p.name)
    for p in ordinary:source+=emit_c(p.data,p.base,'oot_lift_'+p.name)[0]+emit_leaf_descriptor(p.data,p.base,'oot_lift_'+p.name)
    source+=emit_c(bridge.data,bridge.base,'oot_lift_'+bridge.name)[0]+emit_plt_descriptor(verify_memory_plt_stub(bridge.data,bridge.base,record['slot'],record['target'],terminal|memory,record['symbol'],memory),'oot_lift_'+bridge.name)
    def factory(fs,ordinaries,name,write_grants=WRITES):
        terms=sorted(ordinaries+memories,key=lambda p:p.base)
        return emit_stack_factory([p.name for p in fs],[p.name for p in terms],fs[0].base,digest.hex(),[EXIT],memory_callees=True,memory_leaf_names=[p.name for p in memories],read_ranges=CAPS,write_ranges=write_grants,plt_names=[bridge.name]).replace('oot_create_bound_registry',name)
    source+=factory(frames,ordinary,'oot_create_bound_registry')+factory(chain,[],'oot_create_callee_depth')
    source+=factory(frames,ordinary,'oot_create_bad_got_grant',((RW+64,456),))
    source+='''
static unsigned bad_mode, bad_calls;
OOT_LIFT_EXPORT void oot_callee_bad_set(unsigned m) { bad_mode=m; }
OOT_LIFT_EXPORT unsigned oot_callee_bad_count(void) { return bad_calls; }
OOT_LIFT_EXPORT int oot_callee_bad(OotArm64State *s,OotGuestMemory *m,uint64_t b,uint64_t *n)
{
    uint64_t pc=s->pc;
    int status;
    ++bad_calls;
'''+f'    if (pc==UINT64_C(0x{memories[0].base:x}) && bad_mode==12) {{ s->pc+=4;*n=1;return OOT_LIFT_BUDGET; }}\n'+'''
    status=oot_lift_callee_writer(s,m,b,n);
'''+f'    if (pc==UINT64_C(0x{memories[0].base:x})) {{ switch(bad_mode) {{\n'
    actions=['s->x[0]^=1;','s->x[18]^=1;','s->nzcv^=UINT32_C(0x10000000);','m->regions[0].data[0]^=1;',
             '*n=0;','s->pc+=4;','status=OOT_LIFT_DISPATCH;','m->valid=2;','((OotGuestRegion *)m->regions)[0].size+=1;',
             '((OotGuestRegion *)m->regions)[0].permissions=3;','{uint64_t v;(void)oot_memory_load(m,m->regions[0].base,1,&v);}']
    source+=''.join(f'case {n}: {a} break;\n' for n,a in enumerate(actions,1))+'} } return status;\n}\n'
    source+='''
OOT_LIFT_EXPORT int oot_callee_bad_read(OotArm64State *s,OotGuestMemory *m,uint64_t b,uint64_t *n)
{
    uint64_t pc=s->pc;
    int status;
    ++bad_calls;
'''+f'    if (pc==UINT64_C(0x{CALLER+0x60000:x}) && bad_mode==12) {{ s->pc+=4;*n=1;return OOT_LIFT_BUDGET; }}\n'+'''
    status=oot_lift_memory_load0(s,m,b,n);
'''+f'    if (pc==UINT64_C(0x{CALLER+0x60000:x})) {{ switch(bad_mode) {{\n'
    read_actions=['s->x[0]^=1;','m->regions[0].data[0]^=1;','(void)oot_memory_store(m,m->regions[0].base,1,0);',
        '((OotGuestRegion *)m->regions)[0].permissions=3;','s->x[17]^=1;','m->count=0;','s->x[18]^=1;',
        '*n=0;','s->pc+=4;','status=OOT_LIFT_DISPATCH;','m->regions=NULL;']
    source+=''.join(f'case {n}: {a} break;\n' for n,a in enumerate(read_actions,1))+'} } return status;\n}\n'
    lib,build=compile_library([],mode,source);bindings(lib)
    lib.oot_callee_bad_set.argtypes=[c_uint32];lib.oot_callee_bad_count.restype=c_uint32
    path=Path(build['directory'])/'memory-callees.ootmem';path.write_bytes(blob)
    message,error,report=create_string_buffer(192),c_uint32(),Report()
    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));require(image,message.value.decode())
    data=lib.oot_runtime_memory(image);regions=data.contents.regions;stack=regions[4].data;rw=regions[2].data;bss=regions[3].data
    keys=lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));require(keys,'memory callee keys rejected')
    ref=PltReference(programs,{record['slot']:memories[1].base})
    for base,content in ((RO,patterns()[0]),(RW,patterns()[1]),(BSS,patterns()[2]),(LITERAL,patterns()[3])):
        if base!=RW:ref.u.mem_map(base&~4095,4096)
        ref.u.mem_write(base,content)
    rng=random.Random(0x1EAFC411);whole=prefixes=0
    def initial(pc=CALLER):
        s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)]
        s.pc,s.sp,s.x[1],s.x[6],s.x[7],s.x[30],s.nzcv=pc,STACK_HIGH,RW+64,1,1,EXIT,rng.randrange(16)<<28
        return s
    def reset():
        memset(stack,0,STACK_SIZE);memset(bss,0,4096);memmove(rw,patterns()[1],4096)
        lib.oot_memory_store(data,record['slot'],8,memories[1].base)
        ref.u.mem_write(RW,bytes(rw[:4096]));ref.u.mem_write(BSS,bytes(4096));ref.u.mem_write(STACK_LOW,bytes(STACK_SIZE))
    def check(d,s,leaf=False,expected=None,budget=1):
        nonlocal whole,prefixes
        reset();first=State.from_buffer_copy(s);states=[first];bytes_by_step=[(bytes(stack[:STACK_SIZE]),bytes(rw[:4096]),bytes(bss[:4096]))]
        while states[-1].pc!=EXIT:
            t=states[-1];require(t.pc in ref.words and len(states)<1500,'memory callee reference escaped')
            states.append(ref.step(t,ref.words[t.pc]));bytes_by_step.append(tuple(bytes(ref.u.mem_read(a,z)) for a,z in ((STACK_LOW,STACK_SIZE),(RW,4096),(BSS,4096))))
        begin,run=(lib.oot_leaf_begin,lib.oot_leaf_run) if leaf else (lib.oot_stack_begin,lib.oot_stack_run)
        require((begin(d,byref(s),s.pc,EXIT,byref(report)) if leaf else begin(d,byref(s),EXIT,byref(report)))==0,'callee begin rejected')
        require(run(d,byref(s),0,byref(report))==1 and not report.total_retired,'callee zero budget retired')
        while True:
            status=run(d,byref(s),budget,byref(report));n=report.total_retired
            require(status in (1,2) and not report.error,f'callee run failed {status}/{report.error} pc={s.pc:x}')
            require(s.values()==states[n].values() and (bytes(stack[:STACK_SIZE]),bytes(rw[:4096]),bytes(bss[:4096]))==bytes_by_step[n],'callee state/memory prefix mismatch')
            prefixes+=1
            if status==2:break
        if expected:expected(first,s)
        if first.pc==CALLER:require(s.x[0]==((2*first.x[0]+11)&U64 if first.x[6] else 42),'independent mixed call formula mismatch')
        if first.pc==chain[0].base:require(s.x[0]==(2*first.x[0]+31)&U64,'independent full-depth formula mismatch')
        whole+=1
    def make(name):
        f=getattr(lib,name);f.argtypes,f.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
        d=f(image,keys,byref(error));require(d,f'callee factory rejected {name}/{error.value}');return d
    d=make('oot_create_bound_registry')
    bad_factory=lib.oot_create_bad_got_grant;bad_factory.argtypes,bad_factory.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
    require(bad_factory(image,keys,byref(error)) is None,'write grant overlapping a protected GOT slot accepted')
    try:
        for flags in range(16):
            for v in (0,1,U64,1<<63,rng.getrandbits(64)):
                for branch in (0,1):
                    s=initial();s.nzcv=flags<<28;s.x[0]=v;s.x[7]=branch;check(d,s)
        s=initial();s.x[6]=0;check(d,s,budget=7)
        check(d,initial(),budget=10000)
    finally:lib.oot_stack_destroy(d)
    d=make('oot_create_callee_depth')
    try:check(d,initial(chain[0].base))
    finally:lib.oot_stack_destroy(d)
    all_mem=sorted(memories+[p for p,*_ in matrix],key=lambda p:p.base)
    table=(MemoryLeafFunction*len(all_mem))();hashes=(CodeHash*len(all_mem))()
    for n,p in enumerate(all_mem):
        f=getattr(lib,'oot_memory_leaf_descriptor_'+p.name);f.restype=POINTER(MemoryLeafFunction);table[n]=f().contents
        f=getattr(lib,'oot_leaf_code_hash_'+p.name);f.restype=POINTER(CodeHash);hashes[n]=f().contents
    body=(c_uint8*32).from_buffer_copy(digest);returns=(c_uint64*1)(EXIT)
    reads=(ReadRange*len(CAPS))(*[ReadRange(*r) for r in CAPS]);writes=(ReadRange*len(WRITES))(*[ReadRange(*r) for r in WRITES])
    def create(rc=None,wc=None):return lib.oot_leaf_dispatcher_create_memory_bound(image,table,len(table),hashes,body,returns,1,reads,len(reads) if rc is None else rc,writes,len(writes) if wc is None else wc,byref(error))
    d=create();require(d,'standalone memory registry rejected')
    try:
        for p,setup,kind,z,regs,label,formula in matrix:
            for offset in ((64,80,128) if label in ('rcpc','literal') else (64,65,80,128)):
                s=initial(p.base);s.x[0]=0xABCD
                for r,v in setup((RW if kind=='write' else RO)+offset).items():s.x[r]=v
                def expected(first,last,k=kind,ea=RW+offset,rs=regs,size=z,fn=formula,o=offset):
                    if k=='write':require(bytes(ref.u.mem_read(ea,size*len(rs)))==b''.join(((first.x[r] if r!=31 else 0)&((1<<(8*size))-1)).to_bytes(size,'little') for r in rs),'independent write bytes mismatch')
                    else:require(last.x[0]==fn(patterns()[0],o),'independent load result mismatch')
                check(d,s,leaf=True,expected=expected)
    finally:lib.oot_leaf_dispatcher_destroy(d)
    original_run=table[0].info.run;table[0].info.run=cast(lib.oot_callee_bad,c_void_p).value
    n=table[0].info.instruction_count;words=(c_uint32*n).from_buffer_copy(string_at(table[0].effect_words,n*4));table[0].effect_words=words
    old=words[0];words[0]^=1;require(create() is None,'different effect opcode accepted');words[0]=old
    words[n-1]=old;require(create() is None,'effect at return accepted');words[n-1]=0
    ordinary_table=(LeafFunction*1)(table[0].info)
    require(lib.oot_leaf_dispatcher_create_bound(image,ordinary_table,1,hashes,body,returns,1,byref(error)) is None,'old leaf constructor admitted memory policy')
    require(lib.oot_leaf_dispatcher_create(ordinary_table,1,returns,1,STACK_LOW,STACK_HIGH,byref(error)) is None,'unbound leaf constructor admitted memory policy')
    saved_range=writes[0].base,writes[0].size
    for base,size in ((RO+64,8),(STACK_LOW,8),(RW,8192),(RW,0),(RW,U64),(BSS+1,8)):
        writes[0]=ReadRange(base,size);require(create() is None,'invalid external write capability accepted')
    writes[0]=ReadRange(*saved_range)
    hashes[0].bytes[0]^=1;require(create() is None,'wrong memory leaf hash accepted');hashes[0].bytes[0]^=1
    for mode_index,expected_error in enumerate((19,12,19,19,10,11,13,19,19,19,20,19),1):
        lib.oot_callee_bad_set(mode_index);d=create();require(d,'bad callback registry rejected')
        try:
            s=initial(memories[0].base);reset();require(lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))==0,'bad callee begin rejected')
            before=s.values(),bytes(rw[:4096]),bytes(stack[:STACK_SIZE])
            require(lib.oot_leaf_run(d,byref(s),1,byref(report))==4 and report.error==expected_error and
                (s.values(),bytes(rw[:4096]),bytes(stack[:STACK_SIZE]))==before,f'callee callback escaped transaction {mode_index}/{report.error}')
            calls=lib.oot_callee_bad_count();require(lib.oot_leaf_run(d,byref(s),100,byref(report))==4 and lib.oot_callee_bad_count()==calls,'callee fault did not latch')
        finally:lib.oot_leaf_dispatcher_destroy(d)
    lib.oot_callee_bad_set(0)
    read_index=next(n for n,p in enumerate(all_mem) if p.name=='memory_load0')
    read_run=table[read_index].info.run;table[read_index].info.run=cast(lib.oot_callee_bad_read,c_void_p).value
    for mode_index,expected_error in enumerate((19,19,20,19,19,19,12,10,11,13,19,19),1):
        lib.oot_callee_bad_set(mode_index);d=create();require(d,'bad read registry rejected')
        try:
            s=initial(all_mem[read_index].base);s.x[0]=0xABCD;s.x[1]=RO+63;reset()
            require(lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))==0,'bad read begin rejected')
            before=s.values(),bytes(rw[:4096]),bytes(stack[:STACK_SIZE]),bytes(regions[1].data[:4096]);calls=lib.oot_callee_bad_count()
            require(lib.oot_leaf_run(d,byref(s),1,byref(report))==4 and report.error==expected_error and
                (s.values(),bytes(rw[:4096]),bytes(stack[:STACK_SIZE]),bytes(regions[1].data[:4096]))==before,f'bad read callback changed state {mode_index}/{report.error}')
            require(lib.oot_leaf_run(d,byref(s),100,byref(report))==4 and lib.oot_callee_bad_count()==calls+1,'read callback fault did not latch')
        finally:lib.oot_leaf_dispatcher_destroy(d)
    table[read_index].info.run=read_run;lib.oot_callee_bad_set(0)
    ordered=next(p for p,_,kind,_,_,label,_ in matrix if kind=='read' and label=='rcpc' and decode_instruction(p.words[0],p.base).access_size==8)
    d=create();require(d,'ordered read registry rejected')
    try:
        s=initial(ordered.base);s.x[1]=RO+65;reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report));before=s.values()
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==20 and data.contents.fault.reason==5 and s.values()==before,'misaligned RCpc leaf retired')
    finally:lib.oot_leaf_dispatcher_destroy(d)
    d=create();require(d,'pair boundary registry rejected')
    try:
        s=initial(memories[0].base);s.x[1]=RW+304;reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))
        require(lib.oot_leaf_run(d,byref(s),2,byref(report))==1,'pair boundary prefix failed')
        before=s.values(),bytes(rw[:4096])
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==18 and report.total_retired==2 and
            (s.values(),bytes(rw[:4096]))==before,'memory leaf pair partially committed')
    finally:lib.oot_leaf_dispatcher_destroy(d)
    for pointer in (RO+64,RW+63,RW+313,STACK_LOW,STACK_HIGH-64+16,STACK_HIGH-16,0,U64-3):
        d=create();require(d,'range callee registry failed')
        try:
            reset();s=initial(memories[0].base);s.x[1]=pointer
            require(lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))==0,'range callee begin failed')
            before=s.values(),bytes(rw[:4096]),bytes(stack[:STACK_SIZE]);calls=lib.oot_callee_bad_count()
            require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==18 and
                (s.values(),bytes(rw[:4096]),bytes(stack[:STACK_SIZE]))==before and lib.oot_callee_bad_count()==calls,'callee range denial retired')
        finally:lib.oot_leaf_dispatcher_destroy(d)
    # Whole-operand capabilities cannot be assembled from adjacent grants.
    saved=[(r.base,r.size) for r in writes];writes[0],writes[1]=ReadRange(RW+64,4),ReadRange(RW+68,4)
    d=create();require(d,'adjacent grant registry rejected')
    try:
        s=initial(memories[0].base);reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==18,'callee joined adjacent grants')
    finally:
        lib.oot_leaf_dispatcher_destroy(d)
        for n,r in enumerate(saved):writes[n]=ReadRange(*r)
    d=create(wc=0);require(d,'empty write grants rejected')
    try:
        s=initial(memories[0].base);reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==18,'read grant implied a write grant')
    finally:lib.oot_leaf_dispatcher_destroy(d)
    # Write grants do not authorize loads; each read observes the current data.
    p=next(p for p,*_ in matrix if p.name=='memory_load0')
    d=create(rc=0);require(d,'empty read grants rejected')
    try:
        s=initial(p.base);s.x[1]=RW+63;reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==18,'write grant implied a read grant')
    finally:lib.oot_leaf_dispatcher_destroy(d)
    d=create();require(d,'evolving read registry rejected')
    try:
        s=initial(p.base);s.x[1]=RW+63;reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))
        require(lib.oot_leaf_run(d,byref(s),0,byref(report))==1,'read pause failed')
        lib.oot_memory_store(data,RW+64,1,128)
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==1 and s.x[0]==128,'callee used stale data snapshot')
    finally:lib.oot_leaf_dispatcher_destroy(d)
    d=make('oot_create_bound_registry')
    try:
        s=initial();s.x[1]=STACK_HIGH-64+16;reset();lib.oot_stack_begin(d,byref(s),EXIT,byref(report))
        while s.pc!=memories[0].base:require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'owned caller stack pause failed')
        before=s.values(),bytes(stack[:STACK_SIZE])
        require(lib.oot_stack_run(d,byref(s),1,byref(report))==3 and report.error==18 and (s.values(),bytes(stack[:STACK_SIZE]))==before,'memory leaf wrote owned caller locals')
    finally:lib.oot_stack_destroy(d)
    # Backend denial is retriable; commit needs no read permission on backing.
    d=create();require(d,'retry registry rejected')
    try:
        s=initial(memories[0].base);reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report));before=s.values(),bytes(rw[:4096]);calls=lib.oot_callee_bad_count()
        regions[2].permissions=1
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==20 and (s.values(),bytes(rw[:4096]))==before and lib.oot_callee_bad_count()==calls,'backend callee denial changed state')
        regions[2].permissions=2;require(lib.oot_leaf_run(d,byref(s),1,byref(report))==1,'write-only callee retry failed');regions[2].permissions=3
    finally:lib.oot_leaf_dispatcher_destroy(d)
    # The bridge checks its live binding while a memory leaf is suspended.
    d=make('oot_create_bound_registry')
    try:
        s=initial();reset();lib.oot_stack_begin(d,byref(s),EXIT,byref(report))
        while s.pc!=memories[1].base:require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'GOT pause failed')
        before=s.values(),bytes(rw[:4096]);lib.oot_memory_store(data,record['slot'],8,ordinary[0].base)
        require(lib.oot_stack_run(d,byref(s),1,byref(report))==3 and report.error==54 and s.values()==before[0],'memory leaf changed GOT accepted')
        lib.oot_memory_store(data,record['slot'],8,memories[1].base)
        require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'GOT restore did not resume memory leaf')
    finally:lib.oot_stack_destroy(d)
    # Caller storage and handles may be released after registry creation.
    table[0].info.run=original_run;d=create();require(d,'retained callee registry rejected')
    words[0]=0;reads[0].size=0;writes[0].size=0
    lib.oot_runtime_close(image);lib.oot_pauth_destroy(keys)
    try:check(d,initial(memories[0].base),leaf=True)
    finally:lib.oot_leaf_dispatcher_destroy(d)
    result=dict(schema_version=1,result='passed',synthetic_only=True,game_code_executed=False,whole_call_cases=whole,prefix_checks=prefixes,
        store_programs=60,load_programs=49,bad_callback_modes=24,max_depth=16,max_stack_bytes=4096,native_build=build,reference=dict(unicorn=version('unicorn')))
    destination=ROOT/f'build/lifter-validation/{mode}-memory-callees-dispatch-report.json';destination.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result,destination
