"""Bounded image-memory leaves: original CFG, writeback and one proved counter loop."""
from collections import Counter
import hashlib
from arm64_lifter import decode_block
from input_formats import require,InputError
from leaf_verifier import leaf_edges,VALUE_FORMS,emit_verified_leaf_descriptor
from memory_leaf_verifier import MEMORY_FORMS
MAX_ITERATIONS=1024
POLICY='bounded-memory-leaf-v3'
NONE=0xffffffff


def written_registers(i):
    if i.form in MEMORY_FORMS:
        out=([i.rd,i.rt2] if i.form=='loadstore_pair' else [i.rd]) if i.load else []
        if i.writeback:out.append(i.rn)
        return {r for r in out if r!=31}
    return {i.rd} if i.form in VALUE_FORMS and not i.form.startswith('conditional_compare') and i.rd!=31 else set()


def writes_nzcv(i):
    return i.flags or i.form.startswith('conditional_compare') or i.form in ('logical_shifted','logical_immediate') and i.operation==3


def _lengths(edges):
    colors,lengths={},{}
    def visit(n):
        require(colors.get(n)!=1,'bounded leaf CFG contains an unproved cycle')
        if colors.get(n)==2:return lengths[n]
        colors[n]=1;lengths[n]=1+max((visit(t) for t in edges[n]),default=0);colors[n]=2;return lengths[n]
    visit(0);require(len(colors)==len(edges),'bounded leaf contains unreachable words')
    return lengths


def verify_bounded_memory_leaf(data,base):
    require(0<len(data)<=256*4,'bounded memory leaf range exceeds policy limit')
    ins=decode_block(data,base);end=base+len(data);edges={};effects=[];reads=writes=wb=0
    for n,i in enumerate(ins):
        if i.form in MEMORY_FORMS:
            require(i.form=='load_literal' or i.rn not in (29,31),'bounded memory leaf excludes SP/FP memory bases')
            require(not i.writeback or i.rn<18,'bounded writeback writes protected register')
            regs=[i.rd,i.rt2] if i.form=='loadstore_pair' else [i.rd]
            require(not i.load or all(r<18 or r==31 for r in regs),'bounded memory load writes protected register')
            targets=[i.pc+4];require(targets[0]<end,'bounded memory falls off declared range')
            reads+=int(i.load);writes+=int(not i.load);wb+=int(i.writeback);effects.append(i.word)
        else:targets=leaf_edges(i,base,end);effects.append(0)
        edges[n]=[(t-base)//4 for t in targets]
    require(reads+writes,'bounded memory leaf requires a memory effect')
    loop=dict(header=0,latch=0,decrement=0,guard=0,counter=0,width=0,max_iterations=0,reserved=0)
    try:lengths=_lengths(edges)
    except InputError as error:
        if 'unproved cycle' not in str(error):raise
        back=[(a,b) for a,targets in edges.items() for b in targets if b<=a]
        require(len(back)==1,'bounded loop requires exactly one backward edge')
        latch,header=back[0];require(header<latch<len(ins)-1,'invalid bounded loop interval')
        require(all(edges[n]==[n+1] for n in range(header,latch)),'bounded loop body must be linear')
        require(set(edges[latch])=={header,latch+1},'bounded loop latch must exit after the body')
        require(all(b>a for a,targets in edges.items() if a!=latch for b in targets),'bounded loop has another backward edge')
        require(all(not (header<b<=latch) for a,targets in edges.items() if not header<=a<=latch for b in targets),'bounded loop has a side entry')
        branch=ins[latch]
        if branch.form=='compare_branch' and branch.operation==1:
            counter,width=branch.rd,branch.width
            decs=[n for n in range(header,latch) if counter in written_registers(ins[n])]
            require(len(decs)==1,'bounded loop must have one counter writer');decrement=decs[0]
        else:
            require(branch.form=='branch_condition' and branch.operation==1,'bounded latch must be CBNZ or B.NE')
            decs=[n for n in range(header,latch) if writes_nzcv(ins[n])]
            require(decs,'bounded B.NE requires a flag-setting decrement');decrement=decs[-1]
            counter,width=ins[decrement].rd,ins[decrement].width
        d=ins[decrement]
        require(counter<18 and d.form=='addsub_immediate' and d.operation==1 and d.rd==d.rn==counter and d.width==width and d.immediate>0,
                'bounded loop requires a positive immediate counter decrement')
        require([n for n in range(header,latch) if counter in written_registers(ins[n])]==[decrement],'bounded loop counter has another writer')
        require(branch.form!='branch_condition' or d.flags,'bounded B.NE requires SUBS')
        require(any(effects[n] for n in range(header,latch)),'bounded counter loop requires a memory effect in its body')
        guard=NONE
        if header:
            g=ins[header-1]
            if g.form=='compare_branch' and not g.operation and g.rd==counter and g.width==width and g.target>ins[latch].pc:
                guard=header-1
        loop.update(header=header,latch=latch,decrement=decrement,guard=guard,counter=counter,width=width,max_iterations=MAX_ITERATIONS)
        cut={n:[t for t in ts if not(n==latch and t==header)] for n,ts in edges.items()};lengths=_lengths(cut)
    bound=len(ins)+(MAX_ITERATIONS-1)*(loop['latch']-loop['header']+1) if loop['max_iterations'] else lengths[0]
    require(any(not ts for ts in edges.values()),'bounded leaf has no standard return')
    return dict(schema_version=1,policy=POLICY,base=base,byte_count=len(data),instruction_count=len(ins),
        source_sha256=hashlib.sha256(data).hexdigest(),forms=dict(sorted(Counter(i.form for i in ins).items())),
        control_flow=[dict(next=edges[n],max_steps=lengths[n]) for n in range(len(ins))],effect_words=effects,words=[i.word for i in ins],loop=loop,
        max_retired_instructions=bound,checked_read_count=reads,checked_write_count=writes,writeback_count=wb,
        loop_count=int(bool(loop['max_iterations'])),acyclic=not loop['max_iterations'],all_declared_words_reachable=True,
        protected_registers='x18-x30,sp',memory_access=True,external_calls=False,guest_code_executed=False,
        runtime_preconditions='first header count positive, divisible by decrement and at most 1024 iterations; explicit image grants; entire stack excluded',
        proof_scope='original-byte bounded structural proof with runtime admission; not original function identity')


def emit_bounded_memory_leaf_descriptor(data,base,name):
    p=verify_bounded_memory_leaf(data,base);suffix=name[len('oot_lift_'):]
    source=emit_verified_leaf_descriptor(p,name,memory=True,bounded=True)
    literal=source.split(f'static const OotLeafFunction oot_leaf_info_{suffix} = ',1)[1].split(';\n',1)[0]
    lines=[f'static const uint32_t oot_bounded_effects_{suffix}[] = {{'+', '.join(f'UINT32_C(0x{w:08x})' for w in p['effect_words'])+'};',
        f'static const uint32_t oot_bounded_words_{suffix}[] = {{'+', '.join(f'UINT32_C(0x{w:08x})' for w in p['words'])+'};',
        f'static const OotBoundedLeafFunction oot_bounded_info_{suffix} = {{',f'    {{{literal}, oot_bounded_effects_{suffix}}},',f'    oot_bounded_words_{suffix},',
        '    {'+', '.join(str(p['loop'][k])+'u' for k in ('header','latch','decrement','guard','counter','width','max_iterations','reserved'))+'}',
        '};',f'OOT_LIFT_EXPORT const OotBoundedLeafFunction *oot_bounded_leaf_descriptor_{suffix}(void)',
        '{',f'    return &oot_bounded_info_{suffix};','}','']
    return source+'\n'.join(lines)
