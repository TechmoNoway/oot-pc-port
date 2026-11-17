"""Prove fixed NVN serialized layout queries, separately from hardware limits."""
import hashlib,json
from arm64_decode import Decoder,direct_target,signed
from display_audit import _roles
from graphics_audit import _state_address
from input_formats import require
from sdk_init_audit import _merge_bindings
from unwind_provenance import prove_extents

LAYOUT_QUERIES={15:32,16:32,17:256,18:256,19:4,20:8}
BUILDER_ROLES={
    'nvnMemoryPoolBuilderSetDefaults':[('mov','w8, #0x21'),('stp','xzr, xzr, [x0, #0x10]'),
        ('str','wzr, [x0, #0x20]'),('stp','xzr, xzr, [x0, #0x28]'),('str','w8, [x0, #4]'),('ret','')],
    'nvnMemoryPoolBuilderSetDevice':[('str','x1, [x0, #8]'),('ret','')],
    'nvnMemoryPoolBuilderSetFlags':[('str','w1, [x0, #4]'),('ret','')],
    'nvnMemoryPoolBuilderSetStorage':[('stp','x1, x2, [x0, #0x10]'),('str','wzr, [x0, #0x20]'),('ret','')],
    'nvnMemoryPoolBuilderGetDevice':[('ldr','x0, [x0, #8]'),('ret','')],
    'nvnMemoryPoolBuilderGetFlags':[('ldr','w0, [x0, #4]'),('ret','')],
    'nvnMemoryPoolBuilderGetMemory':[('ldr','x0, [x0, #0x10]'),('ret','')],
    'nvnMemoryPoolBuilderGetSize':[('ldr','x0, [x0, #0x18]'),('ret','')],
}

def prove_memory_pool_builder(module,record):
    require(record['name']in BUILDER_ROLES,'unknown retained NVN memory-pool builder')
    expected=BUILDER_ROLES[record['name']];raw=module.read(record['entry']-module.base,record['size'])
    rows=list(Decoder().engine.disasm(raw,record['entry']))
    require(record['size']==len(expected)*4 and len(rows)==len(expected)and
        hashlib.sha256(raw).hexdigest()==record['body_sha256'],'NVN builder extent or full body differs')
    _roles(rows,dict(enumerate(expected)))
    return record

def prove_constant_cases(module,body):
    d=Decoder();entry=body['entry']
    rows=list(d.engine.disasm(module.read(entry-module.base,body['size']),entry))
    require(body['size']==364 and len(rows)==91,'NVN fixed-layout helper extent differs')
    _roles(rows,{0:('mov','w8, w0'),1:('sub','w9, w8, #2'),2:('mov','w0, wzr'),3:('cmp','w9, #0xb0'),
        7:('mov','w8, #0xe'),9:('ldrb','w12, [x10, x9]'),10:('add','x11, x11, x12, lsl #2'),11:('br','x11'),
        88:('mov','w0, #1'),89:('str','w8, [x1]'),90:('ret','')})
    table=_state_address(module,entry,5,10);lo,hi=module.ranges[1]
    require(lo<=table-module.base and table-module.base+177<=hi,'NVN layout case table leaves original rodata')
    cases=module.read(table-module.base,177);adr=module.unpack('<I',entry-module.base+32)[0]
    require(adr&0x9f00001f==0x1000000b,'NVN layout case base differs')
    case_base=entry+32+signed(((adr>>5&0x7ffff)<<2)|(adr>>29&3),21)
    proofs={}
    for query,value in LAYOUT_QUERIES.items():
        target=case_base+cases[query-2]*4;index=(target-entry)//4
        require(entry<=target<entry+88*4 and (target-entry)%4==0,'NVN layout case leaves its constant body')
        _roles(rows,{index:('mov','w8, #'+(str(value)if value<10 else hex(value)))})
        word=module.unpack('<I',target-module.base+4)[0]
        require(word&0xfc000000==0x14000000 and direct_target(word,target+4)==entry+88*4,
            'NVN layout constant does not reach its ordinary output/return')
        proofs[str(query)]=dict(value=value,case_entry=target)
    return dict(helper=body,table=table,cases_sha256=hashlib.sha256(cases).hexdigest(),queries=proofs)

def extend_nvn_layout_audit(linker,original):
    require(original.get('nvn_runtime')is True and original['display_objects']['declaration']['flags']==7,
        'fixed NVN layout requires the preceding complete NVN profile')
    sdk=next(m for m in linker.modules if m.name=='sdk');domain=original['nvn'];d=Decoder()
    parent=domain['integer_helper'];at=parent['entry']+36;word=sdk.unpack('<I',at-sdk.base)[0]
    require(word&0xfc000000==0x94000000,'NVN original constant helper call differs')
    body=prove_extents(sdk,{direct_target(word,at)})[0];proof=prove_constant_cases(sdk,body)
    # The public helper returns the delegated output unchanged for every selected
    # query. No physical-device fields, guessed driver structures or caps are used.
    from arm64_decode import signed as sign
    table=_state_address(sdk,parent['entry'],12,9);cases=sdk.read(table-sdk.base,170)
    adr=sdk.unpack('<I',parent['entry']-sdk.base+64)[0]
    base=parent['entry']+64+sign(((adr>>5&0x7ffff)<<2)|(adr>>29&3),21)
    rows=list(d.engine.disasm(sdk.read(parent['entry']-sdk.base,parent['size']),parent['entry']))
    _roles(rows,{6:('sub','x1, x29, #4'),8:('stur','wzr, [x29, #-4]'),83:('ldur','w0, [x29, #-4]')})
    tail=sdk.unpack('<I',parent['entry']-sdk.base+84*4)[0]
    require(tail&0xfc000000==0x14000000 and direct_target(tail,parent['entry']+84*4)==parent['entry']+101*4 and
        all(base+cases[q]*4==parent['entry']+83*4 for q in LAYOUT_QUERIES),'NVN public fixed-layout return route differs')
    records={p['name']:p for p in domain['procedures']}
    consumer=records['nvnTexturePoolRegisterTexture']
    require(consumer['size']==372,'NVN texture descriptor consumer extent differs')
    rows=list(d.engine.disasm(sdk.read(consumer['entry']-sdk.base,consumer['size']),consumer['entry']))
    roles={61:('sbfiz','x8, x20, #5, #0x20'),63:('add','x9, x9, x8'),64:('str','w10, [x9]')}
    for n in range(1,8):
        offset=str(n*4)if n*4<10 else hex(n*4);roles[63+n*2]=('ldr','w10, [sp, #'+offset+']');roles[64+n*2]=('str','w10, [x9, #'+offset+']')
    _roles(rows,roles)
    require(next(f for f in original['functions']if f['entry']==consumer['entry'])['handler_id']==31,
        'NVN layout proof must retain its unsupported texture registration guard')
    result=json.loads(json.dumps(original));result['nvn_layout_runtime']=True
    retained=[]
    for name in BUILDER_ROLES:
        p=prove_memory_pool_builder(sdk,records[name]);bindings=[f for f in result['functions']if f['entry']==p['entry']]
        require(len(bindings)==1 and bindings[0]['handler_id']==31 and bindings[0].get('nvn_procedures')==[name],
            'NVN retained builder lacks its preceding closed consumer')
        result['functions'].remove(bindings[0]);retained.append(p)
    result['nvn']['retained_original']=sorted(set(domain['retained_original'])|set(BUILDER_ROLES))
    result['display_objects']['declaration']['flags']=15
    result['nvn']['supported_integer_queries'].update({str(k):v for k,v in LAYOUT_QUERIES.items()})
    result['nvn_layout']=dict(**proof,texture_consumer=consumer,retained_builders=retained,resource_apis_implemented=False,
        scope='fixed serialized SDK ABI geometry only; hardware limits and resource consumers remain guarded')
    require(not any(f['entry']==body['entry']for f in result['functions']),'NVN layout helper conflicts with prior binding')
    result['functions'].append(dict(module='sdk',entry=body['entry'],size=body['size'],body_sha256=body['body_sha256'],
        handler_id=31,returns_value=False,return_register=None,implementation='guard',symbol=None,names=[],
        signature='original private NVN constant-layout backend',source_kind='canonical-unwind-private-entry',private_nvn_proof=body))
    result['functions']=_merge_bindings(result['functions'])
    require(len(result['functions'])<=4096 and all(a['entry']+a['size']<=b['entry']for a,b in zip(result['functions'],result['functions'][1:])),
        'NVN layout registry overlaps or exceeds its unchanged bound')
    return result
