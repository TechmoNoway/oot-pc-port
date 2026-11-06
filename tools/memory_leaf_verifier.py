"""Separate acyclic memory-leaf policy; unchanged source bytes and external image grants."""
from collections import Counter
import hashlib
from arm64_lifter import decode_block
from input_formats import require
from leaf_verifier import leaf_edges, emit_verified_leaf_descriptor

POLICY='acyclic-memory-leaf-v2'
MEMORY_FORMS=frozenset(('loadstore_unsigned','loadstore_immediate','loadstore_register','load_literal','loadstore_pair','load_acquire_rcpc'))


def verify_memory_leaf(data,base):
    require(0 < len(data) <= 256*4,'memory leaf range exceeds policy limit')
    ins=decode_block(data,base);end=base+len(data);edges={};words=[];reads=writes=0
    for i in ins:
        if i.form in MEMORY_FORMS:
            require(not i.writeback and not i.post_index,'memory leaf excludes writeback')
            require(i.form=='load_literal' or i.rn not in (29,31),'memory leaf excludes SP/FP memory bases')
            regs=[i.rd,i.rt2] if i.form=='loadstore_pair' else [i.rd]
            require(not i.load or all(r<18 or r==31 for r in regs),'memory leaf load writes protected register')
            targets=[i.pc+4]
            require(targets[0]<end,'memory leaf falls off declared range')
            reads+=int(i.load);writes+=int(not i.load);words.append(i.word)
        else:
            targets=leaf_edges(i,base,end);words.append(0)
        edges[i.pc]=targets
    require(reads+writes>0,'memory leaf requires at least one memory effect')
    colors,lengths={},{}
    def visit(pc):
        require(colors.get(pc)!=1,'memory leaf control flow contains a cycle')
        if colors.get(pc)==2:return lengths[pc]
        colors[pc]=1;bound=1+max((visit(t) for t in edges[pc]),default=0)
        colors[pc]=2;lengths[pc]=bound;return bound
    bound=visit(base)
    require(len(colors)==len(ins),'declared memory leaf includes unreachable words')
    require(any(not e for e in edges.values()),'memory leaf has no standard return')
    return dict(schema_version=1,policy=POLICY,base=base,byte_count=len(data),source_sha256=hashlib.sha256(data).hexdigest(),
        instruction_count=len(ins),forms=dict(sorted(Counter(i.form for i in ins).items())),
        control_flow=[dict(next=[(t-base)//4 for t in edges[i.pc]],max_steps=lengths[i.pc]) for i in ins],
        effect_words=words,checked_read_count=reads,checked_write_count=writes,max_retired_instructions=bound,
        return_count=sum(not e for e in edges.values()),acyclic=True,all_declared_words_reachable=True,
        protected_registers='x18-x30,sp',memory_access=True,external_calls=False,guest_code_executed=False,
        preconditions=['exact entry and approved external LR','canonical NZCV','explicit retained-image read/write grants; entire stack excluded'],
        proof_scope='structural memory-leaf policy with runtime address obligations; not original function identity')


def emit_memory_leaf_descriptor(data,base,name):
    p=verify_memory_leaf(data,base);suffix=name[len('oot_lift_'):]
    source=emit_verified_leaf_descriptor(p,name,memory=True)
    literal=source.split(f'static const OotLeafFunction oot_leaf_info_{suffix} = ',1)[1].split(';\n',1)[0]
    return source+'\n'.join([f'static const uint32_t oot_leaf_effects_{suffix}[] = {{'+', '.join(f'UINT32_C(0x{w:08x})' for w in p['effect_words'])+'};',
        f'static const OotMemoryLeafFunction oot_memory_leaf_info_{suffix} = {{',
        f'    {literal}, oot_leaf_effects_{suffix}', '};',
        f'OOT_LIFT_EXPORT const OotMemoryLeafFunction *oot_memory_leaf_descriptor_{suffix}(void)',
        '{',f'    return &oot_memory_leaf_info_{suffix};','}',''])
