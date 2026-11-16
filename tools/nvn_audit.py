"""Original NVN default procedure table, structural routes and closed consumers.

Names describe original table records, never fabricated ELF exports. This audit
alone implements no device, shader or rendering API.
"""
import hashlib,json,re,struct
from arm64_decode import Decoder,direct_target
from arm64_analysis import plt_stubs
from display_audit import _roles,_load_slot
from display_objects_audit import SUPPORTED_SDK,verify_sdk_identity
from graphics_audit import _state_address
from input_formats import require
from sdk_startup_audit import _stage
from sdk_init_audit import _merge_bindings
from unwind_provenance import prove_extents
from vtable_provenance import _metadata
from native_binding import bind_entry_word

RETAINED={'nvnDeviceBuilderSetDefaults','nvnDeviceBuilderSetFlags'}

def merge_nvn_guards(functions,procedures,retained=RETAINED):
    require(set(retained)<={p['name']for p in procedures},'missing retained NVN procedure')
    by_entry={}
    for p in procedures:by_entry.setdefault(p['entry'],[]).append(p)
    result=json.loads(json.dumps(functions))
    for entry,aliases in by_entry.items():
        keep=[p['name']in retained for p in aliases]
        require(all(keep)or not any(keep),'crossed NVN retained aliases')
        require(all((p['size'],p['body_sha256'])==(aliases[0]['size'],aliases[0]['body_sha256'])for p in aliases),
            'NVN procedure aliases disagree on body')
        prior=[r for r in result if r['entry']==entry]
        if prior:
            require(len(prior)==1 and prior[0]['handler_id']==31 and not any(keep)and
                all(prior[0][k]==aliases[0][k]for k in('size','body_sha256')),'NVN guard conflicts with prior binding')
            prior[0]['nvn_procedures']=[p['name']for p in aliases]
        elif not any(keep):
            p=aliases[0]
            result.append(dict(module='sdk',entry=entry,size=p['size'],body_sha256=p['body_sha256'],handler_id=31,
                returns_value=False,return_register=None,implementation='guard',signature='unsupported original NVN procedure',
                symbol=None,names=[],nvn_procedures=[p['name']for p in aliases],
                source_kind='original-nvn-table-and-canonical-unwind',private_nvn_proof=p['extent']))
    result=_merge_bindings(result)
    require(len(result)<=4096 and all(a['entry']+a['size']<=b['entry']for a,b in zip(result,result[1:])),
        'NVN registry overlaps or exceeds its unchanged bound')
    return result

def extend_nvn_audit(linker,original,pristine):
    require(original.get('refresh_runtime')is True and original['display_objects']['declaration']['flags']==3 and
        linker.report().get('link_complete')is True,'NVN requires complete preceding refresh profile')
    sdk=next(m for m in linker.modules if m.name=='sdk');d=Decoder()
    verify_sdk_identity(pristine,sdk,SUPPORTED_SDK);require(_metadata(pristine)==_metadata(sdk),'NVN original metadata differs')
    def stage(name,size):
        p=bind_entry_word(_stage(linker.modules,'nvn_contract','sdk',name,d));require(p['size']==size,'NVN export extent differs');return p
    def rows(p):return list(d.engine.disasm(sdk.read(p['entry']-sdk.base,p['size']),p['entry']))
    loader=stage('nvnBootstrapLoader',96);internal=stage('nvnBootstrapLoaderInternal',12)
    _roles(rows(loader),{5:('mov','x19, x0'),14:('ldr','x2, [x0]'),15:('mov','x1, x19'),
        17:('mov','x0, xzr'),19:('autibsp',''),20:('br','x2'),23:('retab','')})
    _roles(rows(internal),{0:('mov','x1, x0'),1:('mov','x0, xzr')})
    word=sdk.unpack('<I',internal['offset']+8)[0];require(word&0xfc000000==0x14000000,'NVN internal tail differs')
    stub_entry=direct_target(word,internal['entry']+8);stub=prove_extents(sdk,{stub_entry})[0]
    require(stub['size']==16,'NVN resolver thunk extent differs')
    _roles(rows(stub),{2:('ldr','x2, [x8]'),3:('br','x2')})
    resolver_slot=_state_address(sdk,stub_entry,0,8)
    relocations={};cursor=None
    for index,(value,)in enumerate(struct.iter_unpack('<Q',pristine.relr)):
        if value&1:
            require(cursor is not None,'NVN RELR bitmap has no base')
            targets=[cursor+bit*8 for bit in range(63)if value&(1<<(bit+1))];cursor+=63*8
        else:targets=[value];cursor=value+8
        for at in targets:
            require(at%8==0 and at not in relocations,'NVN duplicate/unaligned RELR')
            relocations[at]=dict(index=index,word=value)
    rela=[at for _,data in pristine.rela for at,info,_ in struct.iter_unpack('<QQq',data)if info&0xffffffff]
    def pointer(address):
        off=address-sdk.base
        require(off in relocations and not any(off-4<=at<off+8 for at in rela),'NVN pointer lacks exclusive original RELR')
        value=pristine.unpack('<Q',off)[0]+sdk.base
        require(sdk.unpack('<Q',off)[0]==value and 0<=value<1<<39,'NVN linked pointer reconstruction differs')
        return value,dict(address=address,original_sha256=hashlib.sha256(pristine.read(off,8)).hexdigest(),
            linked_sha256=hashlib.sha256(sdk.read(off,8)).hexdigest(),relocation=relocations[off])
    resolver_entry,resolver_pointer=pointer(resolver_slot);resolver=prove_extents(sdk,{resolver_entry})[0]
    require(resolver['size']==512,'NVN default resolver extent differs')
    _roles(rows(resolver),{9:('mov','x19, x1'),10:('mov','x20, x0'),30:('ldar','x22, [x8]'),
        62:('ldrb','w8, [x19]'),63:('cmp','w8, #0x6e'),65:('ldrb','w8, [x19, #1]'),66:('cmp','w8, #0x76'),
        68:('ldrb','w8, [x19, #2]'),69:('cmp','w8, #0x6e'),71:('mov','w26, #0x2de'),76:('mov','w23, wzr'),
        83:('add','w8, w26, w23'),84:('add','x0, x19, #3'),85:('asr','w20, w8, #1'),
        86:('ldr','w8, [x24, w20, uxtw #2]'),87:('add','x1, x25, x8'),89:('cmp','w0, #1'),
        92:('sub','w26, w20, #1'),104:('cmp','x22, #1'),122:('ldr','x8, [x21]'),
        126:('ldr','x0, [x8, x20, lsl #3]')})
    offsets=_state_address(sdk,resolver_entry,72,24);strings=_state_address(sdk,resolver_entry,74,25)
    table_slot=_load_slot(sdk,resolver_entry,124,8,125);table,table_pointer=pointer(table_slot)
    rlo,rhi=sdk.ranges[1];dlo,dhi=sdk.ranges[2]
    require(rlo<=offsets-sdk.base and offsets-sdk.base+735*4<=rhi and dlo<=table-sdk.base and table-sdk.base+735*8<=dhi,
        'NVN table/offsets leave original ranges')
    records=[];names_bytes=bytearray();pointer_proofs=[]
    for index in range(735):
        delta=sdk.unpack('<I',offsets-sdk.base+index*4)[0];at=strings-sdk.base+delta
        require(rlo<=at<rhi,'NVN name is outside original rodata')
        data=sdk.read(at,min(256,rhi-at));end=data.find(0)
        require(0<end<256,'NVN name is not bounded/terminated');name='nvn'+data[:end].decode('ascii')
        require(re.fullmatch(r'nvn[A-Z][A-Za-z0-9_]*',name)is not None,'NVN procedure name differs')
        target,proof=pointer(table+index*8);require(sdk.is_code(target-sdk.base),'NVN target leaves original code')
        records.append(dict(index=index,name=name,entry=target));names_bytes.extend(data[:end+1]);pointer_proofs.append(proof)
    require(all(a['name']<b['name']for a,b in zip(records,records[1:])),'NVN source name order/uniqueness differs')
    extents={p['entry']:p for p in prove_extents(sdk,{p['entry']for p in records})}
    for p in records:
        raw=sdk.read(p['entry']-sdk.base,4);word=struct.unpack('<I',raw)[0]
        p.update(size=extents[p['entry']]['size'],body_sha256=extents[p['entry']]['body_sha256'],extent=extents[p['entry']],
            entry_word=word,entry_instruction=dict(address=p['entry'],word=word,sha256=hashlib.sha256(raw).hexdigest()))
    kept={p['name']:p for p in records if p['name']in RETAINED|{'nvnDeviceGetProcAddress'}}
    require(kept['nvnDeviceGetProcAddress']['entry']==stub_entry,'NVN table resolver alias differs')
    defaults=kept['nvnDeviceBuilderSetDefaults'];flags=kept['nvnDeviceBuilderSetFlags']
    require(defaults['size']==12 and flags['size']==8,'NVN retained builder extents differ')
    _roles(rows(defaults),{0:('stp','xzr, xzr, [x0]'),1:('str','xzr, [x0, #0x10]'),2:('ret','')})
    _roles(rows(flags),{0:('str','w1, [x0, #4]'),1:('ret','')})
    result=json.loads(json.dumps(original))
    loader_guards=[f for f in result['functions']if f['entry']==loader['entry']]
    require(len(loader_guards)==1 and loader_guards[0]['handler_id']==31 and
        loader_guards[0].get('names')==['nvnBootstrapLoader']and
        all(loader_guards[0][k]==loader[k]for k in('size','body_sha256')),'NVN preceding loader guard differs')
    result['functions']=[f for f in result['functions']if f['entry']!=loader['entry']]
    result['functions']=merge_nvn_guards(result['functions'],records)
    for f in result['functions']:
        matches=[p for p in records if p['entry']==f['entry']]
        if matches:f.update(entry_word=matches[0]['entry_word'],entry_instruction=matches[0]['entry_instruction'])
    device=next(p for p in records if p['name']=='nvnDeviceInitialize')
    require(device['size']==16,'NVN device initializer thunk differs')
    _roles(rows(device),{2:('ldr','x2, [x8]'),3:('br','x2')})
    init_slot=_state_address(sdk,device['entry'],0,8);init_entry,init_pointer=pointer(init_slot)
    init_body=prove_extents(sdk,{init_entry})[0];require(init_body['size']==100,'NVN device initializer wrapper extent differs')
    _roles(rows(init_body),{4:('mov','x20, x1'),5:('mov','x19, x0'),7:('tst','w0, #0xff'),
        9:('mov','x0, x19'),10:('mov','x1, x20'),11:('mov','x2, xzr'),12:('mov','x3, xzr'),13:('mov','x4, xzr'),
        15:('and','w8, w0, #0xff'),17:('mov','w0, #1'),21:('mov','w0, wzr'),24:('retab','')})
    integer=next(p for p in records if p['name']=='nvnDeviceGetInteger')
    require(integer['size']==52,'NVN integer wrapper extent differs')
    _roles(rows(integer),{4:('mov','x19, x2'),5:('mov','x8, x0'),6:('mov','w0, w1'),
        7:('mov','x1, x8'),9:('str','w0, [x19]'),12:('retab','')})
    call=sdk.unpack('<I',integer['entry']-sdk.base+32)[0]
    require(call&0xfc000000==0x94000000,'NVN integer helper call differs')
    integer_body=prove_extents(sdk,{direct_target(call,integer['entry']+32)})[0]
    require(integer_body['size']==436,'NVN integer helper extent differs')
    _roles(rows(integer_body),{5:('mov','x19, x1'),7:('mov','w20, w0'),10:('cmp','w20, #0xa9'),
        14:('mov','w8, w20'),15:('mov','w0, #0xe7'),17:('ldrb','w11, [x9, x8]'),
        18:('add','x10, x10, x11, lsl #2'),19:('br','x10'),47:('mov','w0, #0x28'),
        20:('mov','w0, #1'),100:('mov','w0, wzr'),101:('ldp','x20, x19, [sp, #0x20]'),102:('ldp','x29, x30, [sp, #0x10]'),
        103:('add','sp, sp, #0x30'),104:('retab','')})
    cases=_state_address(sdk,integer_body['entry'],12,9)
    require(rlo<=cases-sdk.base and cases-sdk.base+170<=rhi,'NVN integer cases leave original rodata')
    case_data=sdk.read(cases-sdk.base,170)
    adr=sdk.unpack('<I',integer_body['entry']-sdk.base+64)[0]
    from arm64_decode import signed
    require(adr&0x9f00001f==0x1000000a,'NVN integer case base differs')
    case_base=integer_body['entry']+64+signed(((adr>>5&0x7ffff)<<2)|(adr>>29&3),21)
    require(case_base+case_data[90]*4==integer_body['entry']+100*4 and
        case_base+case_data[42]*4==integer_body['entry']+20*4 and
        direct_target(sdk.unpack('<I',integer_body['entry']-sdk.base+21*4)[0],integer_body['entry']+21*4)==integer_body['entry']+101*4 and
        case_base+case_data[0]*4==integer_body['entry']+101*4 and
        case_base+case_data[1]*4==integer_body['entry']+47*4 and
        direct_target(sdk.unpack('<I',integer_body['entry']-sdk.base+48*4)[0],integer_body['entry']+48*4)==integer_body['entry']+101*4,
        'NVN original API version case routes differ')
    for name,op,operand in (('nvnDeviceSetWindowOriginMode','str','w1, [x0]'),
        ('nvnDeviceGetWindowOriginMode','ldr','w0, [x0]'),('nvnDeviceSetDepthMode','str','w1, [x0, #4]'),
        ('nvnDeviceGetDepthMode','ldr','w0, [x0, #4]')):
        p=next(p for p in records if p['name']==name);require(p['size']==8,'NVN mode accessor extent differs')
        _roles(rows(p),{0:(op,operand),1:('ret','')})
    for name,handler,returns,width in (('nvnDeviceGetProcAddress',458,True,'x0'),
        ('nvnDeviceInitialize',459,True,'w0'),('nvnDeviceFinalize',460,False,None),
        ('nvnDeviceGetInteger',461,False,None),('nvnDeviceSetWindowOriginMode',462,False,None),
        ('nvnDeviceGetWindowOriginMode',463,True,'w0'),('nvnDeviceSetDepthMode',464,False,None),
        ('nvnDeviceGetDepthMode',465,True,'w0')):
        p=next(p for p in records if p['name']==name)
        match=next(r for r in result['functions']if r['entry']==p['entry'])
        require(match['handler_id']==31 and match.get('nvn_procedures')==[name],'NVN typed procedure aliases differ')
        match.update(handler_id=handler,returns_value=returns,return_register=width,implementation='native_nvn_device',
            signature='source-bound owned NVN device/resolver subset')
    for p in (resolver,init_body,integer_body):
        if not any(r['entry']==p['entry']for r in result['functions']):
            result['functions'].append(dict(module='sdk',entry=p['entry'],size=p['size'],body_sha256=p['body_sha256'],
                handler_id=31,returns_value=False,return_register=None,implementation='guard',symbol=None,names=[],
                signature='unsupported original NVN private backend',source_kind='canonical-unwind-private-entry',private_nvn_proof=p))
    result['functions']=_merge_bindings(result['functions'])
    require(len(result['functions'])<=4096 and all(a['entry']+a['size']<=b['entry']for a,b in zip(result['functions'],result['functions'][1:])),
        'NVN typed registry overlaps or exceeds its unchanged bound')
    result.update(format='oot-nvn-bootstrap-audit',nvn_runtime=True)
    result['display_objects']['declaration']['flags']=7
    result['nvn']=dict(loader=loader,internal=internal,resolver_stub=stub,resolver=resolver,
        resolver_pointer=resolver_pointer,table_pointer=table_pointer,table=table,offsets=offsets,strings=strings,
        pointer_proofs=pointer_proofs,offsets_sha256=hashlib.sha256(sdk.read(offsets-sdk.base,735*4)).hexdigest(),
        names_sha256=hashlib.sha256(names_bytes).hexdigest(),table_sha256=hashlib.sha256(sdk.read(table-sdk.base,735*8)).hexdigest(),
        procedures=records,retained_original=sorted(RETAINED),consumer_closure=True,device_initializer=init_body,
        device_initializer_pointer=init_pointer,builder_scope='24-byte original zero/default builder only',
        integer_wrapper=integer,integer_helper=integer_body,integer_cases_sha256=hashlib.sha256(case_data).hexdigest(),
        supported_integer_queries={'0':231,'1':40,'42':0,'90':0},
        astc_scope='explicitly unsupported: no enabled Vulkan ASTC feature or software decoder',
        device_scope='private identity backed by the live parent Vulkan owner; no guest driver fields fabricated',
        device_ready=False,frame_proven=False)
    return result
