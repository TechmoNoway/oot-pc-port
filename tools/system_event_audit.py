"""Exact-build default VSync publication and closed SystemEvent consumers.

The host owns a real physical VBlank source. Original consumer instructions
remain original execution through four narrowly scoped kernel services.
"""
import hashlib,json,re,struct
from arm64_analysis import plt_stubs
from arm64_decode import Decoder,direct_target,signed
from display_audit import _roles
from display_objects_audit import SUPPORTED_SDK,verify_sdk_identity
from graphics_audit import _state_address
from input_formats import require
from sdk_startup_audit import _stage,_instruction
from sdk_init_audit import _merge_bindings
from unwind_provenance import prove_extents

PUBLIC='_ZN2nn2vi20GetDisplayVsyncEventEPNS_2os15SystemEventTypeEPNS0_7DisplayE'
CREATE='_ZN2nn2os17CreateSystemEventEPNS0_15SystemEventTypeENS0_14EventClearModeEb'
ATTACH='_ZN2nn2os33AttachReadableHandleToSystemEventEPNS0_15SystemEventTypeEjbNS0_14EventClearModeE'
INTER_ATTACH='_ZN2nn2os6detail23AttachInterProcessEventEPNS1_21InterProcessEventTypeEjbjbNS0_14EventClearModeE'
HORIZON='_ZN2nn2os6detail30InterProcessEventImplByHorizon'
OPERATIONS=(('Wait',15,21,4,140),('TryWait',18,24,7,136),('Clear',16,22,5,52),('Destroy',18,24,5,56))

def merge_event_consumers(functions,census,retained):
    """Reconcile full original aliases; never relabel a typed provider as a guard."""
    retained=set(retained);entries={r['entry']for r in census if r['symbol']in retained}
    require(len(retained)==sum(r['symbol']in retained for r in census),'missing retained event symbol')
    by_entry={}
    for row in census:
        by_entry.setdefault(row['entry'],[]).append(row)
    for entry,aliases in by_entry.items():
        require(all((r['symbol']in retained)==(entry in entries)for r in aliases),'crossed event alias retention')
    original=json.loads(json.dumps(functions));kept=[]
    for row in original:
        if row['entry']in by_entry:
            aliases=by_entry[row['entry']]
            require(row['handler_id']==31 and all(row[k]==r[k]for r in aliases for k in('size','body_sha256')),
                'event consumer conflicts with an existing typed/body binding')
            if row['entry']in entries:continue
        kept.append(row)
    guards=[]
    for row in census:
        if row['symbol']in retained:continue
        r=dict(row,handler_id=31,names=[row['symbol']],returns_value=False,return_register=None,
            implementation='guard',signature='unsupported SystemEvent producer/consumer',
            entry_word=row['entry_instruction']['word']);guards.append(r)
    merged=_merge_bindings([*kept,*guards])
    require(len(merged)<=4096 and all(a['entry']+a['size']<=b['entry']for a,b in zip(merged,merged[1:])),
        'event registry exceeds its unchanged limit or overlaps')
    return merged

def extend_system_events_audit(linker,original,pristine):
    require(original.get('objects_runtime')is True and original.get('display_objects',{}).get('declaration',{}).get('flags')==0 and
        original['display_objects'].get('original_construction_retained')is True and linker.report().get('link_complete')is True,
        'events require the complete preceding object profile')
    sdk=next(m for m in linker.modules if m.name=='sdk');syntax=Decoder()
    verify_sdk_identity(pristine,sdk,SUPPORTED_SDK)
    bridges={sdk.base+o:r for o,r in plt_stubs(sdk).items()}
    def stage(name,size=None):
        r=_stage(linker.modules,'system_event_contract','sdk',name,syntax)
        require(size is None or r['size']==size,'event source extent differs: '+name);return r
    def rows(r):return list(syntax.engine.disasm(sdk.read(r['offset'],r['size']),r['entry']))
    def target(r,index,tail=False):
        word=sdk.unpack('<I',r['offset']+4*index)[0]
        require(word&0xfc000000==(0x14000000 if tail else 0x94000000),'event call branch kind differs')
        return direct_target(word,r['entry']+index*4)
    def callee(r,index,name,tail=False):
        to=target(r,index,tail);b=bridges.get(to);s=stage(name)
        require(b is not None and b['symbol']==name and int(b['resolved_address'],16)==s['entry'],
            'event original PLT/GOT/callee differs')
        return dict(index=index,callee=s,plt=b)
    public=stage(PUBLIC,44);duplicate=stage('_ZN2nn2vi6detail14DefaultDisplay19DuplicateVsyncEventEPNS_2os15SystemEventTypeE',132)
    display=original['display_objects']['declaration']['display']
    require(_state_address(sdk,public['entry'],0,9)==_state_address(sdk,public['entry'],5,0)==display,
        'event default Display identity differs')
    _roles(rows(public),{2:('cmp','x1, x9'),4:('mov','x8, x0'),7:('mov','x1, x8'),9:('mov','w0, #0xc72'),10:('ret','')})
    routes=[callee(public,8,duplicate['symbol'],True)]
    _roles(rows(duplicate),{5:('ldrb','w8, [x0, #0x170]'),7:('mov','w0, #0xa72'),12:('mov','x19, x0'),
        13:('mov','x20, x1'),14:('add','x0, x0, #0x130'),15:('add','x1, x19, #0x30'),16:('mov','w2, #1'),
        17:('mov','w21, #1'),24:('strb','w21, [x19, #0x170]'),25:('add','x1, x19, #0x130'),
        26:('mov','x0, x20'),28:('mov','w2, #1'),31:('autibsp','')})
    wrappers=(('_ZN2nn3vi216CreateVsyncEventEPNS0_14VsyncEventTypeEPKNS0_11DisplayTypeENS_2os14EventClearModeE',18,False),
        ('_ZN2nn3vi23sdk19DuplicateVsyncEventEPNS_2os15SystemEventTypeEPKNS0_14VsyncEventTypeENS2_14EventClearModeE',32,True))
    routes.extend(callee(duplicate,index,name,tail)for name,index,tail in wrappers)
    # Recover the default callback constructor, not an assumed arbitrary table.
    init=stage('_ZN2nn3vi23sdk10InitializeEv',1060);ir=rows(init)
    local={target(init,n)for n,i in enumerate(ir)if i.mnemonic=='bl'and target(init,n)not in bridges}
    candidates=[]
    for p in prove_extents(sdk,local):
        p['offset']=p['entry']-sdk.base;c=rows(p)
        if c[0].mnemonic=='nop'and c[1].mnemonic=='adr'and c[-1].mnemonic=='ret':candidates.append(p)
    require(len(candidates)==1,'event default callback constructor is missing or ambiguous')
    constructor=candidates[0];c=rows(constructor)
    indices=[n for n,i in enumerate(ir)if i.mnemonic=='bl'and target(init,n)==constructor['entry']]
    require(len(indices)==1,'event default callback constructor route differs');at=indices[0]
    table=_state_address(sdk,init['entry'],at-5,19);context=_state_address(sdk,init['entry'],at-3,1)
    _roles(ir,{at-1:('mov','x0, x19')})
    _roles(c,{len(c)-4:('ldr','x8, [x0, #0x10]'),len(c)-3:('add','x8, x8, #0x76'),
        len(c)-2:('stp','x8, x1, [x0, #0x10]')})
    registers={};constructed={}
    for i in c[:-4]:
        if i.mnemonic=='nop':continue
        if i.mnemonic=='adr':
            register,immediate=i.op_str.split(', #');registers[register]=int(immediate,0);continue
        match=re.fullmatch(r'(x\d+)(?:, (x\d+))?, \[x0, #(0x[0-9a-f]+|[0-9]+)\]',i.op_str)
        require(i.mnemonic in('str','stp')and match is not None,'unknown callback constructor operation')
        a,b,offset=match.groups();offset=int(offset,0)
        require(a in registers and(b is None or b in registers),'callback constructor uses an unknown address')
        constructed[offset]=registers[a]
        if b:constructed[offset+8]=registers[b]
    callbacks=[]
    for (name,_,_),expected_size in zip(wrappers,(260,152)):
        wrapper=stage(name,32);wr=rows(wrapper)
        require(_state_address(sdk,wrapper['entry'],0,8)==table+0x18,'event callback context table differs')
        _roles(wr,{2:('mov','w3, w2'),3:('mov','x2, x1'),4:('mov','x1, x0'),6:('ldr','x0, [x8]'),7:('br','x4')})
        load=sdk.unpack('<I',wrapper['offset']+20)[0]
        require(load&0xffc003ff==0xf9400104,'event callback slot register differs')
        slot=0x18+((load>>10)&4095)*8
        require(slot in constructed,'event callback slot was not originally constructed')
        callback=prove_extents(sdk,{constructed[slot]})[0];callback['offset']=callback['entry']-sdk.base
        require(callback['size']==expected_size,'event callback extent differs')
        if expected_size==152:
            _roles(rows(callback),{6:('ldr','w22, [x2, #8]'),7:('mov','x21, x0'),8:('add','x0, x2, #0x10'),
                9:('mov','w19, w3'),10:('mov','x20, x1'),14:('sub','x1, x29, #4'),15:('mov','w3, w0'),
                16:('mov','w2, w22'),17:('ldr','x9, [x8, #0x58]'),20:('blr','x9'),21:('mov','w21, w0'),
                23:('ldur','w1, [x29, #-4]'),24:('mov','w2, #1'),25:('stur','wzr, [x29, #-4]'),
                26:('mov','x0, x20'),27:('mov','w3, w19'),32:('mov','w0, w21')})
            attachment=callee(callback,28,ATTACH)
        else:
            _roles(rows(callback),{7:('mov','x20, x1'),12:('mov','w19, w3'),46:('mov','w2, wzr'),
                47:('mov','w3, w19'),54:('ldr','w1, [sp, #8]'),56:('str','xzr, [x20, #0x10]!'),
                57:('mov','x0, x20'),59:('mov','w0, wzr')})
            attachment=callee(callback,58,ATTACH)
        callbacks.append(dict(wrapper=wrapper,constructor_slot=slot,callback=callback,attachment=attachment))
    attach=stage(ATTACH,56);inter=stage(INTER_ATTACH,40)
    _roles(rows(attach),{4:('mov','w5, w3'),5:('mov','x19, x0'),6:('mov','w3, wzr'),7:('mov','w4, wzr'),
        9:('mov','w8, #2'),10:('strb','w8, [x19, #0x28]')})
    routes.append(callee(attach,8,INTER_ATTACH))
    _roles(rows(inter),{0:('cmp','w5, #1'),1:('strb','w2, [x0, #0x12]'),2:('stp','w1, w3, [x0, #0x14]'),
        3:('cset','w8, eq'),4:('strb','w4, [x0, #0x13]'),5:('stp','x0, x0, [x0]'),
        6:('strb','w8, [x0, #0x10]'),7:('mov','w8, #1'),8:('strb','w8, [x0, #0x11]'),9:('ret','')})
    # Original tag dispatch and managed close/wait/reset remain guest code.
    retained={CREATE};consumers=[];kernel=[]
    def syscall(caller,index,service):
        address=target(caller,index);size=24 if service==0x18 else 8
        data=sdk.read(address-sdk.base,size);ins=list(syntax.engine.disasm(data,address))
        expected=[('str','x0, [sp, #-0x10]!'),('svc','#0x18'),('ldr','x2, [sp]'),('str','w1, [x2]'),
            ('add','sp, sp, #0x10'),('ret','')]if service==0x18 else[('svc',hex(service)),('ret','')]
        # Capstone uses decimal for single-digit immediates, hexadecimal here.
        require(len(ins)==len(expected),'event syscall sequence length differs')
        for n,(mnemonic,operands)in enumerate(expected):
            require(ins[n].mnemonic==mnemonic and(ins[n].op_str==operands or
                (mnemonic=='svc'and int(ins[n].op_str.lstrip('#'),0)==service)),
                'event syscall register/service/return sequence differs')
        kernel.append(dict(caller=caller,call_index=index,entry=address,size=size,body_sha256=hashlib.sha256(data).hexdigest(),
            service=service,source_kind='call-derived-syscall-sequence',function_identity_proven=False,
            instruction=_instruction(sdk,address+(4 if service==0x18 else 0),syntax)))
    for op,public_len,detail_len,horizon_len,horizon_size in OPERATIONS:
        pub=stage('_ZN2nn2os'+str(public_len)+op+'SystemEventEPNS0_15SystemEventTypeE',48 if op=='Destroy'else 44)
        detail=stage('_ZN2nn2os6detail'+str(detail_len)+op+'InterProcessEventEPNS1_21InterProcessEventTypeE')
        lower=stage(HORIZON+str(horizon_len)+('CloseEj'if op=='Destroy'else op+('Ej'if op=='Clear'else'Ejb')),horizon_size)
        shift=1 if op=='Destroy'else 0
        _roles(rows(pub),{0:('ldrb','w8, [x0, #0x28]'),1+shift:('cmp','w8, #1'),3+shift:('cmp','w8, #2')})
        if op=='Destroy':_roles(rows(pub),{1:('strb','wzr, [x0, #0x28]')})
        routes.append(callee(pub,5+shift,detail['symbol'],True))
        if op in('Wait','TryWait'):
            require(detail['size']==16,'event read/clear-mode consumer extent differs')
            _roles(rows(detail),{0:('ldr','w8, [x0, #0x14]'),1:('ldrb','w1, [x0, #0x10]'),2:('mov','w0, w8')})
            routes.append(callee(detail,3,lower['symbol'],True))
        elif op=='Clear':
            require(detail['size']==24,'event clear consumer extent differs')
            _roles(rows(detail),{1:('ldr','w0, [x0, #0x14]'),4:('ldr','w0, [x8, #0x18]')})
            routes.extend((callee(detail,3,lower['symbol'],True),callee(detail,5,lower['symbol'],True)))
        else:
            require(detail['size']==124,'event managed destroy extent differs')
            _roles(rows(detail),{4:('ldrb','w8, [x0, #0x12]'),6:('strb','wzr, [x0, #0x11]'),
                15:('ldr','w0, [x19, #0x14]'),18:('str','wzr, [x19, #0x14]'),19:('strb','wzr, [x19, #0x12]')})
            routes.append(callee(detail,17,lower['symbol']))
        if op=='Wait':
            _roles(rows(lower),{5:('str','w0, [x29, #0x1c]'),7:('mov','w19, #0xfa01'),
                10:('mov','w2, #1'),11:('mov','x3, #-1'),15:('ldr','w0, [x29, #0x1c]'),
                17:('and','w8, w0, #0x3fffff'),18:('cmp','w8, w19')})
            syscall(lower,13,0x18);syscall(lower,16,0x17)
        elif op=='TryWait':syscall(lower,7,0x17)
        elif op=='Clear':syscall(lower,5,0x12)
        else:syscall(lower,6,0x16)
        wrapper=stage('nnos'+op+'SystemEvent',4);routes.append(callee(wrapper,0,pub['symbol'],True))
        retained.update((pub['symbol'],detail['symbol'],lower['symbol'],wrapper['symbol']));consumers.extend((pub,detail,lower,wrapper))
    create=stage(CREATE,104)
    _roles(rows(create),{4:('mov','x19, x0'),11:('mov','w2, w1'),12:('mov','w1, wzr'),
        14:('mov','w8, #1'),15:('mov','w0, wzr'),16:('strb','w8, [x19, #0x28]')})
    routes.append(callee(create,13,'_ZN2nn2os15InitializeEventEPNS0_9EventTypeEbNS0_14EventClearModeE'))
    census=[stage(s.name)for s in sdk.symbols if s.section and s.kind==2 and any(t in s.name for t in('SystemEvent','InterProcessEvent'))]
    require(len(census)==256 and len({r['entry']for r in census})==254,'complete event symbol census differs')
    result=json.loads(json.dumps(original));functions=merge_event_consumers(result['functions'],census,retained)
    create_word=sdk.unpack('<I',create['offset']+20)[0]
    require(create_word&0xfff8001f==0x36000002 and direct_target(create_word,create['entry']+20)==create['entry']+44,
        'early SystemEvent in-process selection differs')
    kernel_create=target(create,6)
    kernel_create_proof=prove_extents(sdk,{kernel_create})[0]
    if not any(r['entry']==kernel_create for r in functions):
        functions=_merge_bindings([*functions,dict(module='sdk',entry=kernel_create,size=kernel_create_proof['size'],
            body_sha256=kernel_create_proof['body_sha256'],handler_id=31,returns_value=False,return_register=None,
            implementation='guard',signature='unsupported private generic kernel event creator',symbol=None,names=[],
            source_kind='canonical-unwind-private-entry',private_event_proofs=[kernel_create_proof])])
    require(any(r['entry']==kernel_create and r['handler_id']==31 for r in functions),
        'unsupported generic kernel event creation escaped its guard')
    matches=[r for r in functions if PUBLIC in r.get('names',[])]
    require(len(matches)==1 and matches[0]['handler_id']==31 and matches[0]['names']==[PUBLIC],
        'event public binding has conflicting aliases')
    matches[0].update(handler_id=456,returns_value=True,return_register='w0',implementation='native_vsync',signature='Result GetDisplayVsyncEvent(SystemEventType*, Display*)')
    result.update(format='oot-system-event-audit',events_runtime=True,functions=functions)
    result['display_objects']['declaration']['flags']=1
    result['system_events']=dict(public=public,duplicate=duplicate,callback_initializer=init,callback_constructor=constructor,
        callback_table=table,callback_context=context,callbacks=callbacks,attachment=attach,interprocess_attachment=inter,
        routes=routes,kernel_sequences=kernel,consumers=consumers,early_create=create,
        early_inprocess_branch=_instruction(sdk,create['entry']+20,syntax),
        kernel_create_guard=kernel_create_proof,retained_symbols=sorted(retained),
        census=census,consumer_closure=True,source_scope='exact reviewed SDK; default auto-clear managed readable event only',
        original_consumers_retained=True,output_precondition='uninitialized tag zero; nonaliasing checked output')
    return result
