"""Exact-build pool/buffer ABI and closed consumers, separately opt-in."""
import hashlib,json,re
from arm64_decode import Decoder,direct_target
from display_audit import _roles
from display_objects_audit import SUPPORTED_SDK
from input_formats import require
from sdk_init_audit import _merge_bindings
from unwind_provenance import prove_extents
BUFFER_BUILDERS={
'nvnBufferBuilderSetDefaults':[('stp','xzr, xzr, [x0, #0x10]'),('str','xzr, [x0, #0x20]'),('ret','')],
'nvnBufferBuilderSetDevice':[('str','x1, [x0, #8]'),('ret','')],
'nvnBufferBuilderSetStorage':[('stp','x1, x2, [x0, #0x10]'),('str','x3, [x0, #0x20]'),('ret','')],
'nvnBufferBuilderGetDevice':[('ldr','x0, [x0, #8]'),('ret','')],
'nvnBufferBuilderGetMemoryPool':[('ldr','x0, [x0, #0x10]'),('ret','')],
'nvnBufferBuilderGetMemoryOffset':[('ldr','x0, [x0, #0x18]'),('ret','')],
'nvnBufferBuilderGetSize':[('ldr','x0, [x0, #0x20]'),('ret','')],
}
OPERATIONS=[
('nvnMemoryPoolInitialize',466,728,'w0'),('nvnMemoryPoolFinalize',467,188,None),
('nvnMemoryPoolMap',468,24,'x0'),('nvnMemoryPoolGetSize',469,8,'x0'),('nvnMemoryPoolGetFlags',470,12,'w0'),
('nvnMemoryPoolFlushMappedRange',471,4,None),('nvnMemoryPoolInvalidateMappedRange',472,4,None),
('nvnMemoryPoolGetBufferAddress',473,8,'x0'),('nvnBufferInitialize',474,72,'w0'),('nvnBufferFinalize',475,4,None),
('nvnBufferMap',476,40,'x0'),('nvnBufferGetAddress',477,16,'x0'),('nvnBufferGetMemoryPool',478,8,'x0'),
('nvnBufferGetMemoryOffset',479,8,'x0'),('nvnBufferGetSize',480,8,'x0'),
('nvnBufferFlushMappedRange',481,16,None),('nvnBufferInvalidateMappedRange',482,16,None),
('nvnSamplerPoolInitialize',483,252,'w0'),('nvnSamplerPoolFinalize',484,4,None),('nvnSamplerPoolGetMemoryPool',485,8,'x0'),
('nvnSamplerPoolGetMemoryOffset',486,8,'x0'),('nvnSamplerPoolGetSize',487,8,'w0'),('nvnTexturePoolInitialize',488,108,'w0'),
('nvnTexturePoolFinalize',489,4,None),('nvnTexturePoolGetMemoryPool',490,8,'x0'),('nvnTexturePoolGetMemoryOffset',491,8,'x0'),('nvnTexturePoolGetSize',492,8,'w0'),
('nvnSamplerPoolRegisterSampler',493,8,None),('nvnSamplerPoolRegisterSamplerBuilder',494,4,None)]
def prove_body(module,p,size,roles):
    raw=module.read(p['entry']-module.base,p['size']);rows=list(Decoder().engine.disasm(raw,p['entry']))
    require(p['size']==size and len(raw)==size and len(rows)==size//4 and hashlib.sha256(raw).hexdigest()==p['body_sha256'],
        'NVN resource complete body/extent differs')
    _roles(rows,roles);return rows

def prove_sampler_float_getter(module,p,offset):
    return prove_body(module,p,8,{0:('ldr','s0, [x0, #'+hex(offset)+']'),1:('ret','')})

def prove_sampler_method(module,p):
    from sdk_init_instructions import decode_sdk_init_instruction
    name=p['name'];require(name.startswith(('nvnSamplerBuilder','nvnSamplerGet'))or name in('nvnSamplerInitialize','nvnSamplerFinalize'),
        'unknown ordinary sampler method')
    rows=prove_body(module,p,p['size'],{})
    allowed={'adrp','stur','stp','ldp','str','strb','ldr','mov','movk','movi','ret','and','orr','bfi','ubfiz','sbfx','lsr','asr'}
    require(p['size']<=64 and rows[-1].mnemonic=='ret'and all(v.mnemonic!='ret'for v in rows[:-1])and all(v.mnemonic in allowed for v in rows),
        'NVN ordinary sampler method contains an unproved control/driver operation')
    constant=None
    for row in rows:
        decode_sdk_init_instruction(int.from_bytes(row.bytes,'little'),row.address,application=True)
        if '['not in row.op_str:continue
        match=re.search(r'\[(x[0-9]+)(?:, #(-?(?:0x[0-9a-f]+|[0-9]+)))?\]$',row.op_str)
        require(match is not None,'NVN sampler memory form differs')
        base,offset=match.group(1),int(match.group(2)or'0',0)
        registers=row.op_str.split('[')[0].rstrip(', ').split(', ')
        sizes={'w':4,'x':8,'s':4,'d':8,'q':16}
        require(all(register[0]in sizes for register in registers),'NVN sampler memory register differs')
        size=1 if row.mnemonic=='strb'else sum(sizes[register[0]]for register in registers)
        if base=='x8':
            require(name=='nvnSamplerBuilderSetDefaults'and row.address==p['entry']+12 and row.mnemonic=='ldr'and registers==['q0'],
                'NVN sampler global input is not its exact default constant')
            adr=module.unpack('<I',p['entry']-module.base)[0]
            require(adr&0x9f00001f==0x90000008,'NVN sampler default ADRP differs')
            pages=(adr>>29&3)|(adr>>5&0x7ffff)<<2
            if pages&(1<<20):pages-=1<<21
            address=(p['entry']&~4095)+(pages<<12)+offset;lo,hi=module.ranges[1]
            require(lo<=address-module.base and address-module.base+16<=hi,'NVN sampler constant leaves original rodata')
            constant=dict(address=address,size=16,sha256=hashlib.sha256(module.read(address-module.base,16)).hexdigest())
        else:
            limits={'x0':64 if name=='nvnSamplerInitialize'or name.startswith('nvnSamplerGet')else 48,
                'x1':48 if name=='nvnSamplerInitialize'else 16,'x2':4,'x3':4}
            require(base in limits and offset>=0 and offset+size<=limits[base],'NVN sampler memory leaves its reviewed CPU records')
    return dict(record=p,constant=constant,complete_body_verified=True,existing_decoder_only=True)

def extend_nvn_resources_audit(linker,original):
    require(original.get('nvn_layout_runtime')is True and original['display_objects']['declaration']['flags']==15 and
        original['nvn'].get('consumer_closure')is True,'NVN resources require the retained layout/closed consumer profile')
    sdk=next(m for m in linker.modules if m.name=='sdk')
    require(sdk.source_sha256==SUPPORTED_SDK['source_sha256'],'NVN resources require the exact audited SDK')
    result=json.loads(json.dumps(original));records={p['name']:p for p in original['nvn']['procedures']}
    retained=[]
    for name,roles in BUFFER_BUILDERS.items():
        p=records[name];prove_body(sdk,p,len(roles)*4,dict(enumerate(roles)))
        guards=[f for f in result['functions']if f['entry']==p['entry']]
        require(len(guards)==1 and guards[0]['handler_id']==31 and guards[0].get('nvn_procedures')==[name],
            'NVN resource builder aliases changed')
        result['functions'].remove(guards[0]);retained.append(p)
    ordinary=[];ordinary_proofs=[]
    for name,p in records.items():
        if not(name.startswith(('nvnSamplerBuilder','nvnSamplerGet'))or name in ('nvnSamplerInitialize','nvnSamplerFinalize')):continue
        proof=prove_sampler_method(sdk,p)
        guards=[f for f in result['functions']if f['entry']==p['entry']]
        require(len(guards)==1 and guards[0]['handler_id']==31 and guards[0].get('nvn_procedures')==[name],
            'NVN ordinary sampler method aliases changed')
        result['functions'].remove(guards[0]);ordinary.append(p);ordinary_proofs.append(proof)
    for name,offset in (('GetLodBias',16),('GetLodSnap',24),('GetMaxAnisotropy',20)):
        prove_sampler_float_getter(sdk,records['nvnSamplerBuilder'+name],offset)
    prove_body(sdk,records['nvnSamplerBuilderGetLodClamp'],20,{0:('ldr','s0, [x0, #8]'),2:('ldr','s0, [x0, #0xc]')})
    prove_body(sdk,records['nvnSamplerBuilderGetMinMagFilter'],28,{0:('ldr','w8, [x0, #0x2c]'),
        1:('sbfx','w8, w8, #0x10, #4'),4:('sbfx','w8, w8, #0x14, #4')})
    prove_body(sdk,records['nvnSamplerBuilderGetCompare'],28,{0:('ldr','w8, [x0, #0x2c]'),
        1:('sbfx','w8, w8, #0x18, #2'),4:('asr','w8, w8, #0x1a')})
    prove_body(sdk,records['nvnSamplerBuilderGetWrapMode'],40,{0:('ldr','w8, [x0, #0x2c]'),
        1:('sbfx','w8, w8, #0, #4'),4:('sbfx','w8, w8, #4, #4'),7:('sbfx','w8, w8, #8, #4')})
    prove_body(sdk,records['nvnSamplerBuilderGetReductionFilter'],12,{0:('ldr','w8, [x0, #0x2c]'),1:('sbfx','w0, w8, #0xc, #4')})
    border=records['nvnSamplerBuilderGetBorderColor']
    prove_body(sdk,border,36,{2*n:('ldr','s0, [x0, #'+hex(28+4*n)+']')for n in range(4)})
    contracts={}
    for name,handler,size,returns in OPERATIONS:
        p=records[name]
        prove_body(sdk,p,size,{})
        require(p['extent']['source_sha256']==sdk.source_sha256,'NVN resource source extent changed')
        f=next(f for f in result['functions']if f['entry']==p['entry'])
        require(f['handler_id']==31 and f.get('nvn_procedures')==[name],'NVN resource typed consumer aliases changed')
        f.update(handler_id=handler,returns_value=returns is not None,return_register=returns,
            implementation='native_nvn_resources',signature='owned CPU-uncached pool/buffer subset; no driver object serialization')
        contracts[name]=p
    init=contracts['nvnMemoryPoolInitialize']
    rows=prove_body(sdk,init,728,{9:('mov','x21, x1'),10:('mov','x19, x0'),19:('ldr','w8, [x1, #4]'),
        20:('ldr','x20, [x1, #8]'),21:('ldr','x3, [x1, #0x18]'),109:('mov','w0, wzr'),177:('mov','w0, #1'),181:('retab','')})
    for n in range(8):_roles(rows,{11+n:('stp','q0, q0, [x0'+(', #'+hex(n*32)if n else'')+']')})
    buffer=contracts['nvnBufferInitialize']
    prove_body(sdk,buffer,72,{3:('ldr','x8, [x1, #0x10]'),6:('ldr','x8, [x1, #8]'),
        8:('ldr','x8, [x1, #0x10]'),10:('ldr','x8, [x1, #0x18]'),12:('ldr','x8, [x1, #0x20]'),
        14:('mov','w0, #1'),15:('ret',''),16:('mov','w0, wzr'),17:('ret','')})
    sampler=contracts['nvnSamplerPoolInitialize'];texture=contracts['nvnTexturePoolInitialize']
    prove_body(sdk,sampler,252,{7:('ldr','x20, [x1, #8]'),11:('stp','x1, x2, [x0]'),15:('str','w3, [x0, #0x10]'),
        16:('str','xzr, [x0, #0x18]'),17:('mov','w1, wzr'),31:('mov','w1, #1'),44:('mov','w1, #2'),58:('mov','w0, #1'),62:('retab','')})
    prove_body(sdk,texture,108,{0:('stp','x1, x2, [x0]'),1:('str','w3, [x0, #0x10]'),4:('str','xzr, [x0, #0x18]'),
        25:('mov','w0, #1'),26:('ret','')})
    sampler_targets=[]
    for index in (27,40,55):
        pc=sampler['entry']+index*4;word=sdk.unpack('<I',pc-sdk.base)[0]
        require(word&0xfc000000==0x94000000,'NVN reserved sampler recipe route differs')
        sampler_targets.append(direct_target(word,pc))
    require(len(set(sampler_targets))==1,'NVN reserved sampler recipe consumers differ')
    private=[]
    backend_sites=[init['entry']+51*4,init['entry']+54*4,sampler['entry']+27*4,texture['entry']+22*4]
    for at in backend_sites:
        word=sdk.unpack('<I',at-sdk.base)[0]
        require(word&0xfc000000==0x94000000,'NVN pool backend call differs')
        body=prove_extents(sdk,{direct_target(word,at)})[0];private.append(body)
        existing=[f for f in result['functions']if f['entry']==body['entry']]
        if existing:require(len(existing)==1 and existing[0]['handler_id']==31,'NVN pool private backend conflicts')
        else:result['functions'].append(dict(module='sdk',entry=body['entry'],size=body['size'],body_sha256=body['body_sha256'],
            handler_id=31,returns_value=False,return_register=None,implementation='guard',symbol=None,names=[],
            signature='unsupported original pool driver backend',source_kind='canonical-unwind-private-entry',private_nvn_proof=body))
    result['nvn']['retained_original']=sorted(set(result['nvn']['retained_original'])|set(BUFFER_BUILDERS)|{p['name']for p in ordinary})
    result['nvn_resources_runtime']=True;result['display_objects']['declaration']['flags']=31
    result['nvn_resources']=dict(operations=contracts,retained_builders=retained,retained_sampler_methods=ordinary,ordinary_sampler_proofs=ordinary_proofs,guarded_private_backends=private,
        supported_pool_flags=0x22,max_pool_bytes=8*1024*1024,gpu_address_model='owned guest-storage VA; checked shadow/offset resolution; no address/range reuse',
        consumer_closure=True,descriptor_pool_capacity=65536,reserved_sampler_recipes=3,descriptor_binding_implemented=False,sampler_registration_implemented=True,game_draws_implemented=False)
    result['functions']=_merge_bindings(result['functions'])
    require(len(result['functions'])<=4096 and all(a['entry']+a['size']<=b['entry']for a,b in zip(result['functions'],result['functions'][1:])),
        'NVN resource registry overlaps or exceeds bound')
    return result
