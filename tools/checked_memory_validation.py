"""Independent synthetic checked-write matrices, mixed callee graphs and fault isolation."""
from ctypes import POINTER, byref, c_size_t, c_uint8, c_uint32, c_uint64, c_void_p, cast, create_string_buffer, memset, memmove, string_at
from importlib.metadata import version
import json
import os
from pathlib import Path
import random

from arm64_lifter import U64, emit_c
from call_validation import CallFunction, LrAssembler
from dispatcher_validation import CALLER, EXIT, STACK_LOW, STACK_HIGH, STACK_SIZE, Report, LeafFunction, CodeHash
from input_formats import require
from lifter_validation import compile_library
from lifter_validation_types import Program, State
from memory_validation import transfer
from pair_validation import pair
from pauth_lifter import emit_pauth_c
from pauth_stack_validation import PauthAssembler, PauthReference
from pauth_validation import KEYS
from plt_validation import PltFunction, stub, bindings as plt_bindings, package as plt_package
from plt_verifier import emit_plt_descriptor, verify_plt_stub
from prepare_registry import emit_stack_factory
from read_validation import CAPS, RW, RO, BSS, ReadRange, patterns
from stack_cfg_validation import add_immediate, mov, immediate
from stack_layout_verifier import verify_memory_stack_functions, emit_memory_stack_descriptor, WRITE

ROOT=Path(__file__).resolve().parent.parent
WRITES=((RW+64,256),(BSS,128))


def bindings(lib):
    plt_bindings(lib)
    args=lib.oot_stack_create_plt.argtypes.copy()
    lib.oot_stack_create_memory.argtypes=args[:-1]+[POINTER(ReadRange),c_size_t,args[-1]]
    lib.oot_stack_create_memory.restype=c_void_p
    lib.oot_memory_probe.argtypes=[c_void_p,c_uint64,c_uint32,c_uint32]
    lib.oot_memory_probe.restype=c_uint32


def matrix_programs():
    result=[]
    def add(word,setup,size,registers,label):
        n=len(result)
        a=PauthAssembler('write_matrix'+str(n),CALLER+0x10000+n*4096,64,48,((32,(19,)),),key=n%2,explicit_auth=bool(n&2))
        a.emit(word)
        result.append((a.finish(),setup,size,registers,label))
    for size in range(4):
        add(transfer(size,0,0,1,immediate=1),lambda ea,z=size:{1:ea-(1<<z)},1<<size,(0,),'unsigned')
        add(transfer(size,0,0,1,'unscaled',-8),lambda ea:{1:ea+8},1<<size,(0,),'unscaled')
        for extend in (2,3,6,7):
            for scaled in (0,1):
                def setup(ea,e=extend,z=size,t=scaled):
                    r={2:0x1234567800000002,3:2,6:0x12345678fffffffe,7:U64}[e]
                    offset={2:2,3:2,6:-2,7:-1}[e]*(1<<z if t else 1)
                    return {1:(ea-offset)&U64,2:r}
                add(transfer(size,0,0,1,'register',rm=2,extend=extend,scaled=scaled),setup,1<<size,(0,),'register')
        add(transfer(size,0,1,1),lambda ea:{1:ea},1<<size,(1,),'base-alias')
        add(transfer(size,0,2,1,'register',rm=2,extend=3),lambda ea:{1:ea-7,2:7},1<<size,(2,),'offset-alias')
        add(transfer(size,0,31,1),lambda ea:{1:ea},1<<size,(31,),'zero')
    for opc in (0,2):
        for regs in ((0,3),(0,0),(31,31),(1,0)):
            add(pair(opc,False,*regs,1,2,0),lambda ea:{1:ea},4 if opc==0 else 8,regs,'pair')
    for rn in (31,29):
        add(transfer(3,0,0,rn,immediate=2) if rn==31 else transfer(3,0,0,rn,'unscaled',-32),lambda ea:{},8,(0,),'local')
    return result


def graph_programs():
    leaf=Program('memory_plus',[add_immediate(0,0,7),0xd65f03c0],[],base=CALLER+0x3000,leaf=True)
    bridge,record=stub('memory_bridge',CALLER+0x80000,RW+512,leaf.base)
    root=LrAssembler('memory_root',CALLER,64,19)
    root.branch('zero',0xb4000006);root.emit(mov(19,0),transfer(3,0,0,1));root.bl(CALLER+0x1000);root.bl(bridge.base)
    root.branch('epilogue',0x14000000,26);root.label('zero');root.emit(immediate(0,42))
    child=PauthAssembler('memory_child',CALLER+0x1000,64,48,key=0,explicit_auth=True)
    child.emit(transfer(3,1,0,1),add_immediate(0,0,1),transfer(3,0,0,1,immediate=1));child.bl(CALLER+0x2000)
    inner=PauthAssembler('memory_inner',CALLER+0x2000,48,32)
    inner.emit(pair(2,False,0,0,1,2,2),transfer(3,1,0,1,immediate=1))
    return [root.finish(),child.finish(),inner.finish()],leaf,(bridge,record)


def depth_programs():
    programs=[]
    for n in range(16):
        a=(LrAssembler('write_depth'+str(n),CALLER+0x100000+n*4096,256,28,key=n%2,explicit_auth=bool(n&2)) if n%3==0 else
           PauthAssembler('write_depth'+str(n),CALLER+0x100000+n*4096,256,240 if n%2 else 0,key=n%2,explicit_auth=bool(n&2),split=bool(n%2)))
        a.emit(transfer(3,0,0,1,immediate=n))
        if n!=15:a.bl(a.base+4096)
        programs.append(a.finish())
    return programs


def run_validation(mode='cmake'):
    require(version('unicorn')=='2.1.4','pinned enabled PAC reference required')
    frames,leaf,(bridge,record)=graph_programs();matrix=matrix_programs();chain=depth_programs()
    proofs=verify_memory_stack_functions({p.base:p.data for p in frames},{leaf.base:leaf.data},CALLER,{bridge.base:record})
    singles={p.base:verify_memory_stack_functions({p.base:p.data},{},p.base)[p.base] for p,*_ in matrix}
    depths=verify_memory_stack_functions({p.base:p.data for p in chain},{},chain[0].base)
    programs=frames+[leaf,bridge]+[p for p,*_ in matrix]+chain
    blob,digest=plt_package(programs,{record['slot']:leaf.base});source=''
    for p in frames+[p for p,*_ in matrix]+chain:
        proof=(proofs if p in frames else singles if p.base in singles else depths)[p.base]
        source+=emit_pauth_c(p.data,p.base,'oot_pauth_lift_'+p.name)[0]+emit_memory_stack_descriptor(proof,'oot_pauth_lift_'+p.name)
    from leaf_verifier import emit_leaf_descriptor
    source+=emit_c(leaf.data,leaf.base,'oot_lift_'+leaf.name)[0]+emit_leaf_descriptor(leaf.data,leaf.base,'oot_lift_'+leaf.name)
    source+=emit_c(bridge.data,bridge.base,'oot_lift_'+bridge.name)[0]+emit_plt_descriptor(verify_plt_stub(bridge.data,bridge.base,record['slot'],leaf.base,{leaf.base:leaf.data},record['symbol']),'oot_lift_'+bridge.name)
    def factory(ps,root,name,leaves=(),plts=()):
        return emit_stack_factory([p.name for p in ps],list(leaves),root,digest.hex(),[EXIT],writes=True,read_ranges=CAPS if leaves else (),write_ranges=WRITES,plt_names=plts).replace('oot_create_bound_registry',name)
    source+=factory(frames,CALLER,'oot_create_bound_registry',[leaf.name],[bridge.name])
    for p,*_ in matrix:source+=factory([p],p.base,'oot_create_'+p.name)
    source+=factory(chain,chain[0].base,'oot_create_write_depth')
    write_index=next(i for i,s in enumerate(proofs[CALLER]['steps']) if s['kind']==WRITE)
    source+='''
static unsigned write_bad_mode, write_bad_calls;
OOT_LIFT_EXPORT void oot_write_bad_set(unsigned n) { write_bad_mode=n; }
OOT_LIFT_EXPORT unsigned oot_write_bad_count(void) { return write_bad_calls; }
OOT_LIFT_EXPORT int oot_write_bad(OotArm64State *s,OotGuestMemory *m,const OotPauth *p,uint64_t b,uint64_t *n)
{
    uint64_t pc=s->pc;
    int result;
    ++write_bad_calls;
    if (write_bad_mode==12 && pc=='''+f'UINT64_C(0x{CALLER+write_index*4:x})'+''') { s->pc+=4;*n=1;return OOT_LIFT_BUDGET; }
    result=oot_pauth_lift_memory_root(s,m,p,b,n);
'''
    actions=['s->x[0]^=1;','s->x[5]^=1;','s->nzcv^=UINT32_C(0x10000000);','m->regions[0].data[0]^=1;',
             '*n=0;','s->pc+=4;','result=OOT_LIFT_DISPATCH;','m->valid=2;',
             '((OotGuestRegion *)m->regions)[0].size+=1;','((OotGuestRegion *)m->regions)[0].permissions=3;',
             '{uint64_t v;(void)oot_memory_load(m,m->regions[0].base,1,&v);}']
    source+=f'    if (pc==UINT64_C(0x{CALLER+write_index*4:x})) {{ switch(write_bad_mode) {{\n'
    source+=''.join(f'    case {n}: {a} break;\n' for n,a in enumerate(actions,1))+'    } } return result;\n}\n'
    lib,build=compile_library([],mode,source);bindings(lib)
    lib.oot_write_bad_set.argtypes=[c_uint32];lib.oot_write_bad_count.restype=c_uint32
    path=Path(build['directory'])/'checked-memory.ootmem';path.write_bytes(blob)
    message,error,report=create_string_buffer(192),c_uint32(),Report()
    image=lib.oot_runtime_open(os.fsencode(path),message,len(message));require(image,message.value.decode())
    memory=lib.oot_runtime_memory(image);stack=memory.contents.regions[4].data;rw=memory.contents.regions[2].data;bss=memory.contents.regions[3].data
    keys=lib.oot_pauth_create(1,(c_uint64*4)(*KEYS));require(keys,'write keys rejected')
    ref=PauthReference(programs)
    for base,data in ((RO,patterns()[0]),(RW,patterns()[1]),(BSS,patterns()[2])):ref.u.mem_map(base,4096);ref.u.mem_write(base,data)
    rng=random.Random(0x8CA11EE);whole=prefixes=0
    def initial(base=CALLER):
        s=State();s.x[:]=[rng.getrandbits(64) for _ in range(31)]
        s.pc,s.sp,s.x[1],s.x[6],s.x[30],s.nzcv=base,STACK_HIGH,RW+64,1,EXIT,rng.randrange(16)<<28
        return s
    def reset():
        memset(stack,0,STACK_SIZE);memset(bss,0,4096);memmove(rw,patterns()[1],4096)
        lib.oot_memory_store(memory,record['slot'],8,leaf.base)
        ref.u.mem_write(RW,bytes(rw[:4096]));ref.u.mem_write(BSS,bytes(4096));ref.u.mem_write(STACK_LOW,bytes(STACK_SIZE))
    def trace(s):
        states=[State.from_buffer_copy(s)];memories=[(bytes(STACK_SIZE),bytes(rw[:4096]),bytes(bss[:4096]))]
        while states[-1].pc!=EXIT:
            t=states[-1];require(t.pc in ref.words and len(states)<1000,'memory reference escaped graph')
            states.append(ref.step(t,ref.words[t.pc]));memories.append(tuple(bytes(ref.u.mem_read(a,z)) for a,z in ((STACK_LOW,STACK_SIZE),(RW,4096),(BSS,4096))))
        return states,memories
    def check(d,s,expected=None,budget=1):
        nonlocal whole,prefixes
        reset();initial_s=State.from_buffer_copy(s);states,memories=trace(s)
        if expected:
            address,data=expected(initial_s)
            require(bytes(ref.u.mem_read(address,len(data)))==data,'independent little-endian store result disagrees')
        require(lib.oot_stack_begin(d,byref(s),EXIT,byref(report))==0,'memory begin rejected')
        require(lib.oot_stack_run(d,byref(s),0,byref(report))==1 and not report.total_retired,'zero budget retired')
        while True:
            status=lib.oot_stack_run(d,byref(s),budget,byref(report));n=report.total_retired
            require(status in (1,2) and not report.error,f'write run failed {status}/{report.error} pc={s.pc:x}')
            require(s.values()==states[n].values(),'write state/reference mismatch')
            require((bytes(stack[:STACK_SIZE]),bytes(rw[:4096]),bytes(bss[:4096]))==memories[n],'write memory/reference prefix mismatch')
            prefixes+=1
            if status==2:break
        require(n==len(states)-1,'write retirement mismatch')
        if s.pc==EXIT and initial_s.pc==CALLER:require(s.x[0]==((initial_s.x[0]+8)&U64 if initial_s.x[6] else 42),'independent mixed callee result mismatch')
        whole+=1
    def make(name):
        f=getattr(lib,name);f.argtypes,f.restype=lib.oot_create_bound_registry.argtypes,lib.oot_create_bound_registry.restype
        d=f(image,keys,byref(error));require(d,f'write registry rejected {name}/{error.value}');return d
    d=make('oot_create_bound_registry')
    try:
        for flags in range(16):
            for value in (0,1,U64,0x8000000000000000,0x123456789abcdef0):
                s=initial();s.nzcv=flags<<28;s.x[0]=value;check(d,s)
        s=initial();s.x[6]=0;check(d,s,budget=7)
    finally:lib.oot_stack_destroy(d)
    for p,setup,element,registers,label in matrix:
        d=make('oot_create_'+p.name)
        try:
            for offset in (64,65,80,304):
                for value in (0,U64,0x123456789abcdef0):
                    s=initial(p.base);s.x[0]=value
                    for r,v in setup(RW+offset).items():s.x[r]=v
                    target=STACK_HIGH-64+16 if label=='local' else RW+offset
                    def expected(t,ea=target,z=element,rs=registers):return ea,b''.join(((t.x[r] if r!=31 else 0)&((1<<(8*z))-1)).to_bytes(z,'little') for r in rs)
                    check(d,s,expected)
            if label!='local':
                s=initial(p.base)
                for r,v in setup(BSS+16).items():s.x[r]=v
                check(d,s)
        finally:lib.oot_stack_destroy(d)
    d=make('oot_create_write_depth')
    try:check(d,initial(chain[0].base))
    finally:lib.oot_stack_destroy(d)

    # Direct constructor uses copied real descriptors, not altered source bytes.
    table=(CallFunction*len(frames))()
    for n,p in enumerate(frames):
        f=getattr(lib,'oot_stack_memory_descriptor_'+p.name);f.restype=POINTER(CallFunction);table[n]=f().contents
    leaf_get=getattr(lib,'oot_leaf_descriptor_'+leaf.name);leaf_get.restype=POINTER(LeafFunction)
    hash_get=getattr(lib,'oot_leaf_code_hash_'+leaf.name);hash_get.restype=POINTER(CodeHash)
    plt_get=getattr(lib,'oot_plt_descriptor_'+bridge.name);plt_get.restype=POINTER(PltFunction)
    leaf_table=(LeafFunction*1)(leaf_get().contents);hashes=(CodeHash*1)(hash_get().contents);plts=(PltFunction*1)(plt_get().contents)
    body=(c_uint8*32).from_buffer_copy(digest);returns=(c_uint64*1)(EXIT)
    ranges=(ReadRange*len(CAPS))(*[ReadRange(*r) for r in CAPS]);writes=(ReadRange*len(WRITES))(*[ReadRange(*r) for r in WRITES])
    def create(count=2):return lib.oot_stack_create_memory(image,table,len(table),CALLER,leaf_table,1,hashes,body,returns,1,keys,ranges,len(ranges),plts,1,writes,count,byref(error))
    def pause(d,s):
        reset();require(lib.oot_stack_begin(d,byref(s),EXIT,byref(report))==0,'write pause begin failed')
        while s.pc!=CALLER+write_index*4:require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'write pause failed')
    n=table[0].reads.pauth.layout.cfg.info.instruction_count
    words=(c_uint32*n).from_buffer_copy(string_at(table[0].reads.read_words,n*4));table[0].reads.read_words=words
    old=words[write_index];words[write_index]^=1;require(create() is None,'changed write word accepted');words[write_index]=old
    words[write_index]=transfer(3,1,0,1);require(create() is None,'load word in WRITE phase accepted');words[write_index]=old
    words[0]=old;require(create() is None,'effect word outside phase accepted');words[0]=0
    original=writes[0].base,writes[0].size
    for base,size in ((RO,8),(STACK_LOW,16),(RW-1,8),(RW,8192),(RW,0),(RW,U64),(BSS+1,8)):
        writes[0]=ReadRange(base,size);require(create() is None,'invalid write capability accepted')
    writes[0]=ReadRange(*original)
    require(lib.oot_stack_create_calls(image,table,len(table),CALLER,leaf_table,1,hashes,body,returns,1,keys,ranges,len(ranges),byref(error)) is None,
            'old constructor admitted memory policy')
    table[0].reads.pauth.run=cast(lib.oot_write_bad,c_void_p).value
    for mode_index,expected_error in enumerate((57,57,57,57,10,11,13,57,57,57,50,57),1):
        d=create();require(d,'bad write fixture rejected');lib.oot_write_bad_set(mode_index)
        try:
            s=initial();pause(d,s);before=s.values(),bytes(stack[:STACK_SIZE]),bytes(rw[:4096])
            require(lib.oot_stack_run(d,byref(s),1,byref(report))==4 and report.error==expected_error and
                    (s.values(),bytes(stack[:STACK_SIZE]),bytes(rw[:4096]))==before,f'bad write escaped isolation {mode_index}/{report.error}')
            calls=lib.oot_write_bad_count();require(lib.oot_stack_run(d,byref(s),100,byref(report))==4 and lib.oot_write_bad_count()==calls,'write callback fault not latched')
        finally:lib.oot_stack_destroy(d)
    lib.oot_write_bad_set(0)
    for pointer,allowed in ((RW+64,True),(RW+312,True),(RW+63,False),(RW+313,False),(RO+64,False),(STACK_LOW,False),(STACK_HIGH-64+16,True),(STACK_HIGH-64,False),(STACK_HIGH-64+12,False),(STACK_HIGH-64+60,False),(U64-3,False),(0,False)):
        d=create();require(d,'write range fixture failed')
        try:
            s=initial();s.x[1]=pointer;pause(d,s);before=s.values(),bytes(stack[:STACK_SIZE]),bytes(rw[:4096]);calls=lib.oot_write_bad_count()
            status=lib.oot_stack_run(d,byref(s),1,byref(report))
            require(status==1 if allowed else status==3 and report.error==56 and (s.values(),bytes(stack[:STACK_SIZE]),bytes(rw[:4096]))==before and lib.oot_write_bad_count()==calls,'write capability/owned slot check failed')
        finally:lib.oot_stack_destroy(d)
    # No implicit write grant from readable data; no joining adjacent grants.
    for count in (0,2):
        if count:writes[0],writes[1]=ReadRange(RW+64,4),ReadRange(RW+68,4)
        d=create(count);require(d,'write grant denial fixture rejected')
        try:
            s=initial();pause(d,s);before=s.values(),bytes(rw[:4096])
            require(lib.oot_stack_run(d,byref(s),1,byref(report))==3 and report.error==56 and (s.values(),bytes(rw[:4096]))==before,'read grant/adjacent write ranges broadened')
        finally:lib.oot_stack_destroy(d)
    writes[0],writes[1]=[ReadRange(*r) for r in WRITES]
    p=next(p for p,_,z,rs,label in matrix if label=='pair' and z==8 and rs==(0,3))
    d=make('oot_create_'+p.name)
    try:
        s=initial(p.base);s.x[1]=RW+312;reset()
        require(lib.oot_stack_begin(d,byref(s),EXIT,byref(report))==0,'pair boundary begin failed')
        target=p.base+4*next(i for i,t in enumerate(singles[p.base]['steps']) if t['kind']==WRITE)
        while s.pc!=target:require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'pair boundary pause failed')
        before=s.values(),bytes(rw[:4096])
        require(lib.oot_stack_run(d,byref(s),1,byref(report))==3 and report.error==56 and (s.values(),bytes(rw[:4096]))==before,
                'pair partially committed across write capability boundary')
    finally:lib.oot_stack_destroy(d)
    # Capability succeeds but backend permission can fail; no callback, retry same checkpoint.
    d=create();require(d,'write backend denial fixture rejected')
    try:
        s=initial();pause(d,s);regions=memory.contents.regions;permissions=regions[2].permissions;regions[2].permissions=1
        before=s.values(),bytes(rw[:4096]);calls=lib.oot_write_bad_count()
        require(lib.oot_stack_run(d,byref(s),1,byref(report))==3 and report.error==50 and (s.values(),bytes(rw[:4096]))==before and calls==lib.oot_write_bad_count(),'backend denial invoked callback')
        regions[2].permissions=2
        require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'backend write failure was not retriable with write-only backing')
        regions[2].permissions=permissions
    finally:lib.oot_stack_destroy(d)
    # A child cannot overwrite its parent's unreserved local bytes.
    d=make('oot_create_write_depth')
    try:
        s=initial(chain[0].base);s.x[1]=STACK_HIGH-256+16;reset()
        require(lib.oot_stack_begin(d,byref(s),EXIT,byref(report))==0,'ancestor begin failed')
        child_store=chain[1].base+4*next(i for i,t in enumerate(depths[chain[1].base]['steps']) if t['kind']==WRITE)
        while s.pc!=child_store:require(lib.oot_stack_run(d,byref(s),1,byref(report))==1,'ancestor setup failed')
        before=s.values(),bytes(stack[:STACK_SIZE])
        require(lib.oot_stack_run(d,byref(s),1,byref(report))==3 and report.error==56 and (s.values(),bytes(stack[:STACK_SIZE]))==before,'child overwrote ancestor bytes')
    finally:lib.oot_stack_destroy(d)
    # Registry copies metadata/ranges and retains image/keys across caller releases.
    table[0].reads.pauth.run=cast(lib.oot_pauth_lift_memory_root,c_void_p).value
    d=create();require(d,'write retained ownership failed');writes[0].size=0;words[write_index]=0
    lib.oot_pauth_destroy(keys);lib.oot_runtime_close(image)
    try:check(d,initial())
    finally:lib.oot_stack_destroy(d)
    result=dict(schema_version=1,result='passed',synthetic_only=True,game_code_executed=False,whole_call_cases=whole,prefix_checks=prefixes,
                matrix_programs=len(matrix),bad_callback_modes=12,max_depth=16,max_stack_bytes=4096,native_build=build,reference=dict(unicorn=version('unicorn')))
    destination=ROOT/f'build/lifter-validation/{mode}-checked-memory-dispatch-report.json';destination.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result,destination
