"""Synthetic bounded memory loops, writeback effects, direct/PLT calls and fault isolation."""
from ctypes import POINTER,Structure,byref,c_size_t,c_uint32,c_uint64,c_void_p,cast,create_string_buffer,memset,memmove,string_at
from pathlib import Path
from importlib.metadata import version
import json
import os
import random
from arm64_lifter import U64,emit_c
from bounded_memory_verifier import verify_bounded_memory_leaf,emit_bounded_memory_leaf_descriptor
from call_validation import LrAssembler
from dispatcher_validation import CALLER,EXIT,STACK_LOW,STACK_HIGH,STACK_SIZE,Report,LeafFunction,CodeHash
from input_formats import require
from leaf_verifier import emit_leaf_descriptor
from lifter_validation import compile_library
from lifter_validation_types import Program,State
from memory_callee_validation import MemoryLeafFunction,bindings as callee_bindings
from memory_validation import transfer
from pair_validation import pair
from pauth_lifter import emit_pauth_c
from pauth_stack_validation import PauthAssembler
from pauth_validation import KEYS
from plt_validation import PltReference,stub,package
from plt_verifier import emit_plt_descriptor
from prepare_registry import emit_stack_factory
from read_validation import ReadRange,RO,RW,BSS,patterns
from stack_cfg_validation import mov,add_immediate
from stack_layout_verifier import verify_bounded_callee_stack_functions,emit_bounded_callee_stack_descriptor

ROOT=Path(__file__).resolve().parent.parent
CAP=1024
READS=((RO+32,3072),(RW+32,3072),(BSS,3072))
WRITES=((RW+32,3072),(BSS,3072))


class LeafLoop(Structure):
    _fields_=[(n,c_uint32) for n in ('header','latch','decrement','guard','counter','width','max_iterations','reserved')]


class BoundedLeafFunction(Structure):
    _fields_=[('memory',MemoryLeafFunction),('words',POINTER(c_uint32)),('loop',LeafLoop)]


def bindings(lib):
    callee_bindings(lib)
    args=lib.oot_leaf_dispatcher_create_memory_bound.argtypes.copy();args[1]=POINTER(BoundedLeafFunction)
    lib.oot_leaf_dispatcher_create_bounded_bound.argtypes,lib.oot_leaf_dispatcher_create_bounded_bound.restype=args,c_void_p
    args=lib.oot_stack_create_memory_callees.argtypes.copy();args[4]=POINTER(BoundedLeafFunction)
    lib.oot_stack_create_bounded_callees.argtypes,lib.oot_stack_create_bounded_callees.restype=args,c_void_p


def make_loop(name,base,width=64,control='cbnz',guard=True,copy=False,step=1,prefix=False,sentinel=False,after_dec=False):
    words=[]
    if sentinel:words.append(transfer(0,0,0,1,'unscaled',-1))
    if prefix:words.append((0xaa0403e3 if width==64 else 0x2a0403e3)) # mov c3,c4
    gi=len(words) if guard else None
    if guard:words.append(0)
    header=len(words);words.append(add_immediate(5,5,1))
    if copy:words.append(transfer(0,1,4,2,'post',1))
    words.append(transfer(0,0,4 if copy else 0,1,'post',1))
    dec=len(words);shift=int(step==4096);imm=1 if shift else step
    require(0<imm<4096,'synthetic decrement immediate invalid')
    words.append((0xd1000000 if width==64 else 0x51000000)|((control=='bne')<<29)|(shift<<22)|(imm<<10)|(3<<5)|3)
    if after_dec:words.extend((add_immediate(6,6,0),transfer(0,0,4 if copy else 0,1,'unscaled',-1)))
    latch=len(words);delta=(header-latch)&0x7ffff
    words.append((0x54000001 if control=='bne' else 0xb5000003 if width==64 else 0x35000003)|(delta<<5))
    exit_index=len(words);words.append(0xd65f03c0)
    if guard:words[gi]=(0xb4000003 if width==64 else 0x34000003)|(((exit_index-gi)&0x7ffff)<<5)
    p=Program(name,words,[],base=base)
    p.test_loop=dict(header=header,latch=latch,decrement=dec,guard=gi,counter=3,width=width,copy=copy,step=step,prefix=prefix,sentinel=sentinel,after_dec=after_dec)
    return p


def writeback_matrix():
    result=[]
    def add(word,load,element,opc,regs,offset,mode,label):
        n=len(result);p=Program('wb_matrix'+str(n),[word,0xd65f03c0],[],base=CALLER+0x20000+n*4096)
        result.append((p,load,element,opc,regs,offset,mode,label))
    for size in range(4):
        for mode in ('pre','post'):
            for offset in (-8,8):
                add(transfer(size,0,0,1,mode,offset),False,1<<size,0,(0,),offset,mode,'scalar')
                for opc in (1,2,3):
                    if size==3 and opc>=2 or size==2 and opc==3:continue
                    add(transfer(size,opc,0,1,mode,offset),True,1<<size,opc,(0,),offset,mode,'scalar')
    for opc in (0,1,2):
        for load in (False,True):
            if opc==1 and not load:continue
            element=8 if opc==2 else 4
            for mode in (1,3):
                for offset in (-2,2):
                    add(pair(opc,load,0,2,1,mode,offset),load,element,2 if opc==1 else 1,(0,2),offset*element,'post' if mode==1 else 'pre','pair')
    return result


def loop_matrix():
    result=[]
    for width in (32,64):
        for control in ('cbnz','bne'):
            for guard in (False,True):
                for copy in (False,True):
                    n=len(result);result.append(make_loop('loop_matrix'+str(n),CALLER+0x80000+n*4096,width,control,guard,copy))
    result.append(make_loop('loop_prefix',CALLER+0x91000,32,'bne',True,True,4,prefix=True))
    result.append(make_loop('loop_shifted',CALLER+0x92000,64,'cbnz',True,False,4096))
    result.append(make_loop('loop_sentinel',CALLER+0x93000,64,'cbnz',False,False,4,prefix=True,sentinel=True))
    result.append(make_loop('loop_postdec',CALLER+0x94000,64,'bne',True,True,after_dec=True))
    return result


def graph_programs():
    fill=make_loop('bounded_fill',CALLER+0x3000,64,'cbnz',True)
    copy=make_loop('bounded_copy',CALLER+0x4000,32,'bne',True,True)
    ordinary=Program('bounded_ordinary',[add_immediate(0,0,7),0xd65f03c0],[],base=CALLER+0x5000,leaf=True)
    bridge,record=stub('bounded_bridge',CALLER+0xd0000,RO+4088,copy.base)
    r=LrAssembler('bounded_root',CALLER,64,19);r.emit(mov(19,3));r.bl(fill.base);r.emit(mov(3,19));r.bl(CALLER+0x1000);r.bl(ordinary.base)
    c=PauthAssembler('bounded_child',CALLER+0x1000,64,48,key=0,explicit_auth=True);c.bl(bridge.base)
    return [r.finish(),c.finish()],[fill,copy],[ordinary],(bridge,record)


def depth_programs(bridge):
    result=[]
    for n in range(16):
        a=(LrAssembler('bounded_depth'+str(n),CALLER+0x100000+n*4096,256,28,key=n%2,explicit_auth=bool(n&2)) if n%3==0 else
           PauthAssembler('bounded_depth'+str(n),CALLER+0x100000+n*4096,256,240 if n%2 else 0,key=n%2,explicit_auth=bool(n&2),split=bool(n%2)))
        a.bl(a.base+4096 if n!=15 else bridge);result.append(a.finish())
    return result


def run_validation(mode='cmake'):
    compiler_mode=mode
    require(version('unicorn')=='2.1.4','pinned enabled QARMA5 reference required')
    frames,loops,ordinary,(bridge,record)=graph_programs();matrix=writeback_matrix();singles=loop_matrix();chain=depth_programs(bridge.base)
    bounded={p.base:p.data for p in loops};legacy={p.base:p.data for p in ordinary};plts={bridge.base:record}
    proofs=verify_bounded_callee_stack_functions({p.base:p.data for p in frames},legacy,CALLER,plts,{},bounded)
    depth=verify_bounded_callee_stack_functions({p.base:p.data for p in chain},{},chain[0].base,plts,{},bounded)
    programs=frames+loops+ordinary+[bridge]+[p for p,*_ in matrix]+singles+chain
    blob,digest=package(programs,{record['slot']:loops[1].base});source=''
    for p in frames+chain:source+=emit_pauth_c(p.data,p.base,'oot_pauth_lift_'+p.name)[0]+emit_bounded_callee_stack_descriptor((proofs if p in frames else depth)[p.base],'oot_pauth_lift_'+p.name)
    for p in loops+[p for p,*_ in matrix]+singles:source+=emit_c(p.data,p.base,'oot_lift_'+p.name)[0]+emit_bounded_memory_leaf_descriptor(p.data,p.base,'oot_lift_'+p.name)
    for p in ordinary:source+=emit_c(p.data,p.base,'oot_lift_'+p.name)[0]+emit_leaf_descriptor(p.data,p.base,'oot_lift_'+p.name)
    # Root verifier already bound the exact bridge and its bounded target.
    bridge_proof=dict(base=bridge.base,got_slot=record['slot'],target=record['target'],words=bridge.words,source_sha256=__import__('hashlib').sha256(bridge.data).hexdigest())
    source+=emit_c(bridge.data,bridge.base,'oot_lift_'+bridge.name)[0]+emit_plt_descriptor(bridge_proof,'oot_lift_'+bridge.name)
    def factory(fs,ords,name,grants=WRITES):
        terms=sorted(ords+loops,key=lambda p:p.base)
        return emit_stack_factory([p.name for p in fs],[p.name for p in terms],fs[0].base,digest.hex(),[EXIT],bounded_callees=True,bounded_leaf_names=[p.name for p in loops],read_ranges=READS,write_ranges=grants,plt_names=[bridge.name]).replace('oot_create_bound_registry',name)
    source+=factory(frames,ordinary,'oot_create_bound_registry')+factory(chain,[],'oot_create_bounded_depth')
    source+='''
static unsigned bad_mode,bad_calls;
OOT_LIFT_EXPORT void oot_bounded_bad_set(unsigned m) { bad_mode=m; }
OOT_LIFT_EXPORT unsigned oot_bounded_bad_count(void) { return bad_calls; }
OOT_LIFT_EXPORT int oot_bounded_bad(OotArm64State *s,OotGuestMemory *m,uint64_t b,uint64_t *n)
{
    uint64_t pc=s->pc,base=s->x[1];
    int status=oot_lift_bounded_fill(s,m,b,n);
    ++bad_calls;
'''
    layout=loops[0].test_loop;addr=lambda i:f'UINT64_C(0x{loops[0].base+4*i:x})'
    source+=f'''    if (bad_mode==1 && pc=={addr(layout['header'])}) s->x[3]+=1;
    if (bad_mode==2 && pc=={addr(layout['decrement'])}) s->x[3]+=1;
    if (bad_mode==3 && pc=={addr(layout['decrement'])}) s->x[0]^=1;
    if (bad_mode==4 && pc=={addr(layout['latch'])}) s->pc={addr(layout['latch']+1)};
    if (bad_mode==5 && pc=={addr(layout['guard'])}) s->pc={addr(layout['header'])};
    if (pc=={addr(layout['header']+1)}) {{
        switch(bad_mode) {{
        case 6:s->x[1]=base;break;
        case 7:m->regions[0].data[0]^=1;break;
        case 8:((OotGuestRegion *)m->regions)[0].permissions=3;break;
        case 9:*n=0;break;
        case 10:status=OOT_LIFT_DISPATCH;break;
        }}
    }}
    return status;
}}
'''
    postdec=next(p for p in singles if p.name=='loop_postdec')
    flag_pc=postdec.base+4*(postdec.test_loop['decrement']+1)
    source+=f"""
OOT_LIFT_EXPORT int oot_bounded_bad_flags(OotArm64State *s,OotGuestMemory *m,uint64_t b,uint64_t *n)
{{
    uint64_t pc=s->pc;
    int status=oot_lift_loop_postdec(s,m,b,n);
    ++bad_calls;
    if (pc==UINT64_C(0x{flag_pc:x})) s->nzcv^=UINT32_C(0x40000000);
    return status;
}}
"""
    lib,build=compile_library([],compiler_mode,source);bindings(lib)
    lib.oot_bounded_bad_set.argtypes=[c_uint32];lib.oot_bounded_bad_count.restype=c_uint32
    path=Path(build['directory'])/'bounded-memory.ootmem';path.write_bytes(blob)
    message,error,report=create_string_buffer(192),c_uint32(),Report()
    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));require(image,message.value.decode())
    data=lib.oot_runtime_memory(image);regions=data.contents.regions;stack=regions[4].data;rw=regions[2].data;bss=regions[3].data;ro=regions[1].data
    keys=lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));require(keys,'bounded keys rejected')
    ref=PltReference(programs,{record['slot']:loops[1].base})
    for base,content in ((RO,patterns()[0]),(RW,patterns()[1]),(BSS,patterns()[2])):
        if base!=RO:ref.u.mem_map(base,4096)
        ref.u.mem_write(base,content)
    rng=random.Random(0xb0a0d3d);whole=prefixes=0
    def initial(pc=CALLER,n=3):
        s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)]
        s.pc,s.sp,s.x[0],s.x[1],s.x[2],s.x[3],s.x[4],s.x[30],s.nzcv=pc,STACK_HIGH,0x5a,RW+64,RO+64,n,n,EXIT,rng.randrange(16)<<28
        return s
    def reset():
        memset(stack,0,STACK_SIZE);memset(bss,0,4096);memmove(rw,patterns()[1],4096)
        lib.oot_memory_store(data,record['slot'],8,loops[1].base)
        for a,z in ((RO,ro),(RW,rw),(BSS,bss),(STACK_LOW,stack)):ref.u.mem_write(a,bytes(z[:4096]))
    def bytes_now():return tuple(bytes(z[:4096]) for z in (stack,rw,bss,ro))
    def ref_bytes():return tuple(bytes(ref.u.mem_read(a,4096)) for a in (STACK_LOW,RW,BSS,RO))
    def check(d,s,leaf=False,expected=None,budget=1):
        nonlocal whole,prefixes
        reset();first=State.from_buffer_copy(s);reference=State.from_buffer_copy(s)
        begin,run=(lib.oot_leaf_begin,lib.oot_leaf_run) if leaf else (lib.oot_stack_begin,lib.oot_stack_run)
        require((begin(d,byref(s),s.pc,EXIT,byref(report)) if leaf else begin(d,byref(s),EXIT,byref(report)))==0,'bounded begin rejected')
        require(run(d,byref(s),0,byref(report))==1 and not report.total_retired,'zero budget retired')
        for calls in range(100000):
            status=run(d,byref(s),budget,byref(report));retired=report.retired_this_call
            require(status in (1,2) and not report.error,f'bounded run failed {status}/{report.error} pc={s.pc:x}')
            for _ in range(retired):
                require(reference.pc in ref.words,'reference escaped bounded region');reference=ref.step(reference,ref.words[reference.pc])
            require(s.values()==reference.values() and bytes_now()==ref_bytes(),'bounded state/memory prefix differs from reference')
            prefixes+=1
            if status==2:break
        else:raise ValueError('bounded call did not terminate')
        require(reference.pc==EXIT,'bounded return mismatch')
        if expected:expected(first,s)
        whole+=1
    def make(name):
        f=getattr(lib,name);f.argtypes,f.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
        d=f(image,keys,byref(error));require(d,f'bounded factory rejected {name}/{error.value}');return d
    d=make('oot_create_bound_registry')
    try:
        for flags in range(16):
            for n in (0,1,3,7):
                s=initial(n=n);s.nzcv=flags<<28
                def expected(a,b):
                    require(bytes(rw[64:64+2*n])==bytes([a.x[0]&255])*n+patterns()[0][64:64+n],'independent fill/copy result mismatch')
                    require(b.x[0]==(a.x[0]+7)&U64 and b.x[1]==a.x[1]+2*n and b.x[2]==a.x[2]+n,'independent mixed pointer/result mismatch')
                check(d,s,expected=expected)
        check(d,initial(n=9),budget=7);check(d,initial(n=11),budget=100000)
    finally:lib.oot_stack_destroy(d)
    d=make('oot_create_bounded_depth')
    try:check(d,initial(chain[0].base,n=3))
    finally:lib.oot_stack_destroy(d)
    all_leaves=sorted(loops+[p for p,*_ in matrix]+singles,key=lambda p:p.base)
    table=(BoundedLeafFunction*len(all_leaves))();hashes=(CodeHash*len(all_leaves))()
    for n,p in enumerate(all_leaves):
        f=getattr(lib,'oot_bounded_leaf_descriptor_'+p.name);f.restype=POINTER(BoundedLeafFunction);table[n]=f().contents
        f=getattr(lib,'oot_leaf_code_hash_'+p.name);f.restype=POINTER(CodeHash);hashes[n]=f().contents
    from ctypes import c_uint8
    body=(c_uint8*32).from_buffer_copy(digest);returns=(c_uint64*1)(EXIT)
    reads=(ReadRange*len(READS))(*[ReadRange(*r) for r in READS]);writes=(ReadRange*len(WRITES))(*[ReadRange(*r) for r in WRITES])
    def create():return lib.oot_leaf_dispatcher_create_bounded_bound(image,table,len(table),hashes,body,returns,1,reads,len(reads),writes,len(writes),byref(error))
    d=create();require(d,'bounded leaf registry rejected')
    try:
        for p,load,z,opc,regs,offset,mode,label in matrix:
            for unaligned in (0,1):
                s=initial(p.base);ea=(RO if load else RW)+128+unaligned;s.x[1]=ea-offset if mode=='pre' else ea;s.x[0]=0x89abcdef12345680
                def expected(a,b,load=load,z=z,opc=opc,rs=regs,ea=ea,off=offset,mode=mode,label=label):
                    require(b.x[1]==(ea if mode=='pre' else ea+off),'independent writeback address mismatch')
                    if not load:
                        wanted=b''.join((a.x[r]&((1<<(8*z))-1)).to_bytes(z,'little') for r in rs)
                        require(bytes(ref.u.mem_read(ea,len(wanted)))==wanted,'independent writeback store bytes mismatch')
                    else:
                        signed=opc>=2;width=64 if z==8 or opc==2 else 32
                        for j,r in enumerate(rs):require(b.x[r]==int.from_bytes(bytes(ref.u.mem_read(ea+j*z,z)),'little',signed=signed)&((1<<width)-1),'independent writeback load value mismatch')
                check(d,s,leaf=True,expected=expected)
        for p in singles:
            info=p.test_loop;step=info['step'];width=info['width']
            for flags in range(16):
                for iterations in (1,3):
                    n=iterations*step;s=initial(p.base,n=n);s.nzcv=flags<<28
                    if info['prefix']:s.x[3]=U64;s.x[4]=n
                    if width==32:
                        if info['prefix']:s.x[4]|=0xa5a5a5a5<<32
                        else:s.x[3]|=0xa5a5a5a5<<32
                    def expected(a,b,it=iterations,info=info):
                        wanted=patterns()[0][64:64+it] if info['copy'] else bytes([a.x[0]&255])*it
                        require(bytes(rw[64:64+it])==wanted and b.x[1]==a.x[1]+it and b.x[3]==0,'independent bounded loop result mismatch')
                    check(d,s,leaf=True,expected=expected,budget=1 if flags<8 else 7)
            if info['guard'] is not None:
                s=initial(p.base,n=0)
                if info['prefix']:s.x[4]=0
                check(d,s,leaf=True)
        for p in (singles[0],singles[9]):check(d,initial(p.base,n=CAP),leaf=True)
    finally:lib.oot_leaf_dispatcher_destroy(d)
    # Admission happens at first header, after any legitimate prefix retires.
    for p in singles:
        info=p.test_loop;step=info['step']
        invalid=[(CAP+1)*step]+([step+1] if step>1 else [])+([0] if info['guard'] is None else [])
        for value in invalid:
            d=create();require(d,'admission fixture rejected')
            try:
                s=initial(p.base,n=value)
                if info['prefix']:s.x[4]=value
                reset();require(lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))==0,'bounded begin must allow prefix')
                target=p.base+4*info['header']
                while s.pc!=target:
                    status=lib.oot_leaf_run(d,byref(s),1,byref(report))
                    require(status==1,f'prefix before admission failed {p.name} value={value} status={status}/{report.error} pc={s.pc:x} target={target:x}')
                before=s.values(),bytes_now();total=report.total_retired
                require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==21 and report.total_retired==total and (s.values(),bytes_now())==before,'invalid loop input retired header')
                require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==21,'input rejection incorrectly latched')
            finally:lib.oot_leaf_dispatcher_destroy(d)
    # Full descriptors/words are copied, and semantic counter/branch violations never commit.
    original_run=table[0].memory.info.run;table[0].memory.info.run=cast(lib.oot_bounded_bad,c_void_p).value
    for mode_index,target_index in ((1,layout['header']),(2,layout['decrement']),(3,layout['decrement']),(4,layout['latch']),(5,layout['guard']),
                                  (6,layout['header']+1),(7,layout['header']+1),(8,layout['header']+1),(9,layout['header']+1),(10,layout['header']+1)):
        lib.oot_bounded_bad_set(mode_index);d=create();require(d,'bad loop callback fixture rejected')
        try:
            s=initial(loops[0].base,n=0 if mode_index==5 else 3);reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))
            target=loops[0].base+4*target_index
            while s.pc!=target:require(lib.oot_leaf_run(d,byref(s),1,byref(report))==1,'bad loop callback pause failed')
            before=s.values(),bytes_now();calls=lib.oot_bounded_bad_count()
            require(lib.oot_leaf_run(d,byref(s),1,byref(report))==4 and report.error in (10,13,19,22) and (s.values(),bytes_now())==before,f'bad loop callback escaped isolation {mode_index}/{report.error}')
            require(lib.oot_leaf_run(d,byref(s),100,byref(report))==4 and lib.oot_bounded_bad_count()==calls+1,'bad loop callback fault did not latch')
        finally:lib.oot_leaf_dispatcher_destroy(d)
    lib.oot_bounded_bad_set(0);table[0].memory.info.run=original_run
    pi=next(n for n,p in enumerate(all_leaves) if p.name=='loop_postdec');old_run=table[pi].memory.info.run
    table[pi].memory.info.run=cast(lib.oot_bounded_bad_flags,c_void_p).value;d=create();require(d,'post-decrement flag fixture rejected')
    try:
        s=initial(postdec.base,n=3);reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report))
        while s.pc!=flag_pc:require(lib.oot_leaf_run(d,byref(s),1,byref(report))==1,'post-decrement flag pause failed')
        before=s.values(),bytes_now()
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==4 and report.error==22 and (s.values(),bytes_now())==before,'post-decrement NZCV violation escaped')
    finally:lib.oot_leaf_dispatcher_destroy(d)
    table[pi].memory.info.run=old_run
    count=table[0].memory.info.instruction_count;words=(c_uint32*count).from_buffer_copy(string_at(table[0].words,count*4));table[0].words=words
    old=words[layout['decrement']];words[layout['decrement']]^=1;require(create() is None,'changed decrement word accepted');words[layout['decrement']]=old
    old=table[0].loop.max_iterations;table[0].loop.max_iterations=CAP+1;require(create() is None,'unsupported loop cap accepted');table[0].loop.max_iterations=old
    for field in ('header','latch','decrement','counter'):
        old=getattr(table[0].loop,field);setattr(table[0].loop,field,0xffffffff)
        require(create() is None,'unbounded loop metadata index accepted: '+field);setattr(table[0].loop,field,old)
    old=table[0].loop.guard;table[0].loop.guard=0xfffffffe;require(create() is None,'invalid guard index accepted');table[0].loop.guard=old
    old=table[0].memory.info.max_steps;table[0].memory.info.max_steps-=1;require(create() is None,'incorrect loop retirement bound accepted');table[0].memory.info.max_steps=old
    # Writeback faults retain both base and backing, including whole pairs.
    p=next(p for p,load,z,opc,rs,off,mode,label in matrix if not load and label=='pair' and z==8 and mode=='post')
    d=create();require(d,'writeback range registry rejected')
    try:
        s=initial(p.base);s.x[1]=RW+3096;reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report));before=s.values(),bytes_now()
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==18 and (s.values(),bytes_now())==before,'faulting pair performed writeback/partial store')
    finally:lib.oot_leaf_dispatcher_destroy(d)
    # Backend faults must preserve writeback as well as transferred registers/bytes.
    p=next(p for p,load,z,opc,rs,off,mode,label in matrix if not load and label=='scalar' and z==8 and mode=='pre' and off==8)
    d=create();require(d,'writeback retry registry rejected')
    try:
        s=initial(p.base);s.x[1]=RW+120;reset();lib.oot_leaf_begin(d,byref(s),s.pc,EXIT,byref(report));before=s.values(),bytes_now()
        regions[2].permissions=1
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==3 and report.error==20 and (s.values(),bytes_now())==before,'backend store fault performed writeback')
        regions[2].permissions=2
        require(lib.oot_leaf_run(d,byref(s),1,byref(report))==1 and s.x[1]==RW+128,'write-only backing retry lost writeback')
        regions[2].permissions=3
    finally:lib.oot_leaf_dispatcher_destroy(d)
    # Live binding checks remain active inside a bounded loop, including backedge yields.
    d=make('oot_create_bound_registry')
    try:
        s=initial(n=3);reset();lib.oot_stack_begin(d,byref(s),EXIT,byref(report))
        while s.pc!=loops[1].base+4*loops[1].test_loop['header']:require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'GOT loop pause failed')
        before=s.values(),bytes_now();permission=regions[1].permissions;regions[1].permissions=3
        require(lib.oot_memory_store(data,record['slot'],8,ordinary[0].base)==1,'host GOT mutation fixture failed');regions[1].permissions=permission
        require(lib.oot_stack_run(d,byref(s),1,byref(report))==3 and report.error==54 and s.values()==before[0],'bounded loop ignored changed GOT')
        regions[1].permissions=3;require(lib.oot_memory_store(data,record['slot'],8,loops[1].base)==1,'host GOT restore failed');regions[1].permissions=permission
        require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'restored GOT did not resume')
    finally:lib.oot_stack_destroy(d)
    # The retained standalone context survives caller descriptor/range/key/image releases.
    d=create();require(d,'retained bounded registry rejected');words[0]^=1;table[0].loop.header=0xffffffff;table[0].loop.max_iterations=0;reads[0].size=0;writes[0].size=0
    lib.oot_runtime_close(image);lib.oot_pauth_destroy(keys)
    try:check(d,initial(loops[0].base,n=3),leaf=True)
    finally:lib.oot_leaf_dispatcher_destroy(d)
    result=dict(schema_version=1,result='passed',synthetic_only=True,game_code_executed=False,whole_call_cases=whole,prefix_checks=prefixes,
        writeback_programs=len(matrix),loop_programs=len(singles),bad_callback_modes=11,max_depth=16,max_stack_bytes=4096,native_build=build,reference=dict(unicorn=version('unicorn')))
    destination=ROOT/f'build/lifter-validation/{compiler_mode}-bounded-memory-dispatch-report.json';destination.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result,destination
