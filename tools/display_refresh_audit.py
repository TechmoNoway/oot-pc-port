"""Exact-build public 120 Hz capability declaration, independent of mode setting."""
import json,re
from arm64_analysis import plt_stubs
from arm64_decode import Decoder,direct_target
from display_audit import _roles
from display_objects_audit import SUPPORTED_SDK,verify_sdk_identity
from graphics_audit import _state_address
from input_formats import require
from sdk_startup_audit import _stage
from sdk_init_audit import _merge_bindings
from unwind_provenance import prove_extents
from native_binding import bind_entry_word

PUBLIC='_ZN2nn2vi36SetDisplay120HzRefreshRateCapabilityEPNS0_7DisplayEb'
WRAPPER='_ZN2nn3vi231SetDisplayRefreshRateCapabilityEPNS0_11DisplayTypeENS0_11RefreshRateENS0_21RefreshRateCapabilityE'

def constructed_slots(rows,base_register):
    registers={};slots={}
    for i in rows:
        if i.mnemonic=='adr':
            reg,imm=i.op_str.split(', #');registers[reg]=int(imm,0)
        elif i.mnemonic in ('str','stp'):
            m=re.fullmatch(r'(x\d+)(?:, (x\d+))?, \['+base_register+r', #(0x[0-9a-f]+|[0-9]+)\]',i.op_str)
            if not m:continue
            a,b,offset=m.groups();offset=int(offset,0)
            # Non-ADR writes invalidate earlier materializations of these slots.
            for reg,at in ((a,offset),(b,offset+8)):
                if reg is None:continue
                slots.pop(at,None)
                if reg in registers:slots[at]=registers[reg]
    return slots

def bind_refresh_public(functions,public):
    result=json.loads(json.dumps(functions));matches=[r for r in result if r['entry']==public['entry']]
    require(len(matches)==1 and matches[0].get('names')==[PUBLIC]and matches[0]['handler_id']==31 and
        all(matches[0].get(k)==public.get(k)for k in('module','entry','size','body_sha256','symbol_metadata')),
        'refresh public guard/body/aliases differ')
    matches[0].update(handler_id=457,returns_value=False,return_register=None,
        implementation='native_refresh_capability',signature='void SetDisplay120HzRefreshRateCapability(Display*, bool)')
    return result

def extend_refresh_audit(linker,original,pristine):
    require(original.get('events_runtime')is True and
        original.get('display_objects',{}).get('declaration',{}).get('flags')==1 and
        linker.report().get('link_complete')is True,'refresh requires the complete preceding event profile')
    sdk=next(m for m in linker.modules if m.name=='sdk');d=Decoder()
    verify_sdk_identity(pristine,sdk,SUPPORTED_SDK)
    bridges={sdk.base+o:r for o,r in plt_stubs(sdk).items()}
    def stage(name,size):
        p=_stage(linker.modules,'refresh_contract','sdk',name,d)
        require(p['size']==size,'refresh original extent differs');return p
    def rows(p):return list(d.engine.disasm(sdk.read(p['entry']-sdk.base,p['size']),p['entry']))
    def branch(p,index,target_index):
        word=sdk.unpack('<I',p['entry']-sdk.base+4*index)[0]
        require(direct_target(word,p['entry']+4*index)==p['entry']+4*target_index,
            'refresh original control target differs')
    def call(p,index,name,tail=False):
        word=sdk.unpack('<I',p['entry']-sdk.base+4*index)[0]
        require(word&0xfc000000==(0x14000000 if tail else 0x94000000),'refresh original call kind differs')
        bridge=bridges.get(direct_target(word,p['entry']+4*index))
        require(bridge is not None and bridge['symbol']==name,'refresh original PLT route differs')
        return bridge
    public=stage(PUBLIC,76);wrapper=stage(WRAPPER,32)
    display=original['display_objects']['declaration']['display']
    require(_state_address(sdk,public['entry'],0,8)==_state_address(sdk,public['entry'],9,0)==display,
        'refresh original Display identity differs')
    _roles(rows(public),{2:('cmp','x0, x8'),3:('b.eq',hex(public['entry']+20).replace('0x','#0x')),
        4:('ret',''),11:('mov','w19, w1'),13:('and','w2, w19, #1'),15:('mov','w1, #0x78'),17:('autibsp','')})
    get=stage('_ZN2nn2vi6detail14DefaultDisplay3GetEv',8)
    _roles(rows(get),{0:('add','x0, x0, #0x30'),1:('ret','')})
    routes=[call(public,12,get['symbol']),call(public,18,WRAPPER,True)]
    require(int(routes[0]['resolved_address'],16)==get['entry']and
        int(routes[1]['resolved_address'],16)==wrapper['entry'],'refresh original linked callees differ')
    event=original['system_events'];ctor=event['callback_constructor'];init=event['callback_initializer']
    slots=constructed_slots(rows(ctor)[:-4],'x0')
    require(_state_address(sdk,wrapper['entry'],0,8)==event['callback_table']+0x18,
        'refresh original callback table differs')
    _roles(rows(wrapper),{2:('mov','w3, w2'),3:('mov','w2, w1'),4:('mov','x1, x0'),
        5:('ldr','x4, [x8, #0x180]'),6:('ldr','x0, [x8]'),7:('br','x4')})
    require(0x198 in slots,'refresh callback was not originally constructed')
    callback=prove_extents(sdk,{slots[0x198]})[0]
    require(callback['size']==172,'refresh callback original extent differs')
    cr=rows(callback)
    _roles(cr,{3:('cmp','w2, #0x3c'),5:('tst','w3, #0xff'),7:('cmp','w2, #0x59'),
        9:('cmn','w2, #1'),11:('cmp','w2, #0x3c'),13:('mov','w8, #1'),14:('ands','w9, w3, #0xff'),
        17:('cmp','w2, #0x5a'),19:('cmp','w2, #0x78'),21:('mov','w8, #2'),22:('ands','w9, w3, #0xff'),
        24:('mov','x2, x8'),25:('cmp','w9, #1'),28:('mov','x8, #-0x8000000000000000'),
        29:('ands','w9, w3, #0xff'),31:('and','x2, x3, #0xff'),32:('ldp','x9, x1, [x1, #8]'),
        33:('mov','x3, x8'),34:('ldr','x9, [x9]'),35:('ldr','x4, [x9, #0x130]'),
        36:('ldr','x0, [x9, #0x18]'),38:('autibsp',''),39:('br','x4'),41:('retab','')})
    for index,target in {4:7,6:42,8:17,10:28,12:27,15:24,16:31,18:40,20:27,23:31,26:32,30:24}.items():
        branch(callback,index,target)
    # Reconstruct the lower callback from the original initializer's ADR stores.
    # Its 16-byte table header is proved from the same original base materializations.
    lower_base=_state_address(sdk,init['entry'],46,8);lower_table=_state_address(sdk,init['entry'],31,1)
    require(lower_base==lower_table+16,'refresh lower callback table header differs')
    lower_slots=constructed_slots(rows(init)[46:197],'x8')
    require(0x120 in lower_slots,'refresh lower callback was not originally constructed')
    request=prove_extents(sdk,{lower_slots[0x120]})[0]
    require(request['size']==172,'refresh request original extent differs')
    _roles(rows(request),{6:('mov','x20, x3'),7:('mov','x21, x2'),8:('mov','x22, x1'),9:('mov','x19, x0'),
        11:('ldr','x0, [x19, #0x10]'),13:('mov','x8, #0x13d'),14:('mrs','x23, tpidrro_el0'),
        15:('stp','x21, x20, [x23, #0x10]'),16:('movk','x8, #6, lsl #32'),17:('stp','x8, x22, [x23]'),
        19:('mov','w20, w0'),21:('ldr','w20, [x23, #8]'),22:('mov','x8, #0x13d'),
        23:('movk','x8, #1, lsl #32'),24:('str','x8, [x23]'),37:('mov','w0, w20'),42:('retab','')})
    # All related public consumers already belong to the closed VI/VI2 domain.
    census=[_stage(linker.modules,'refresh_consumer','sdk',s.name,d)for s in sdk.symbols
        if s.section and s.kind==2 and s.name.startswith(('_ZN2nn2vi','_ZN2nn3vi2'))and'RefreshRate'in s.name]
    require(len(census)==22,'complete refresh consumer census differs')
    functions=bind_refresh_public(original['functions'],public)
    for c in census:
        bound=[r for r in functions if r['entry']==c['entry']]
        require(len(bound)==1 and bound[0]['handler_id']==(457 if c['symbol']==PUBLIC else 31)and
            all(bound[0][k]==c[k]for k in('size','body_sha256')),'refresh consumer escaped its exact guard')
    for p in (callback,request):
        prior=[r for r in functions if r['entry']==p['entry']]
        if prior:require(len(prior)==1 and prior[0]['handler_id']==31 and
            all(prior[0][k]==p[k]for k in('size','body_sha256')),'refresh private consumer conflicts')
        else:functions.append(dict(module='sdk',entry=p['entry'],size=p['size'],body_sha256=p['body_sha256'],
            handler_id=31,returns_value=False,return_register=None,implementation='guard',
            signature='unsupported private refresh backend',symbol=None,names=[],
            source_kind='canonical-unwind-private-entry',private_refresh_proof=p))
    # This capability-only profile has no NVN provider. A separate source-audited
    # NVN opt-in retains execution of this original loader instead.
    loader=bind_entry_word(_stage(linker.modules,'refresh_nvn_boundary','sdk','nvnBootstrapLoader',d))
    require(loader['size']==96 and not any(f['entry']==loader['entry']for f in functions),'refresh NVN boundary differs')
    functions.append(dict(loader,handler_id=31,returns_value=False,return_register=None,
        implementation='guard',names=['nvnBootstrapLoader'],signature='NVN requires a separate provider'))
    functions=_merge_bindings(functions)
    require(len(functions)<=4096 and all(a['entry']+a['size']<=b['entry']for a,b in zip(functions,functions[1:])),
        'refresh registry overlaps or exceeds its unchanged limit')
    result=json.loads(json.dumps(original));result.update(format='oot-display-refresh-audit',refresh_runtime=True,functions=functions)
    result['display_objects']['declaration']['flags']=3
    result['display_refresh']=dict(public=public,default_get=get,wrapper=wrapper,routes=routes,callback=callback,
        request=request,consumer_census=census,consumer_closure=True,original_callback_slot=0x198,
        original_request_slot=0x130,request_command=0x13d,enabled_bits=2,update_mask=2,
        source_scope='exact reviewed SDK; default Display public boolean capability only',
        host_scope='owned logical capability; no IPC session or physical mode switch')
    result['display_refresh']['nvn_boundary']=loader
    return result
