"""Static original VI initializer ABI and closed unsupported consumer domain."""
import hashlib,json,struct
from application_audit import GUARD_ID,_merge_bindings,_stage,_symbol_record
from arm64_analysis import plt_stubs
from arm64_decode import Decoder,direct_target,signed
from graphics_audit import CHECK,_state_address
from input_formats import require

INITIALIZE='_ZN2nn2vi10InitializeEv'
LOWER='_ZN2nn3vi210InitializeEv'
LOCK='_ZN2nn2os9LockMutexEPNS0_9MutexTypeE'
UNLOCK='_ZN2nn2os11UnlockMutexEPNS0_9MutexTypeE'
PREFIXES=tuple(a+b for a in ('_ZN2nn','_ZNK2nn') for b in ('2vi','3vi2'))
CONSTRUCTORS=(
    ('_ZN2nn2vi5LayerC1Ev','_ZN2nn2vi5LayerC2Ev',88,'_ZTVN2nn2vi5LayerE',4),
    ('_ZN2nn2vi5Layer20NativeWindowListenerC1EPS1_',
     '_ZN2nn2vi5Layer20NativeWindowListenerC2EPS1_',20,'_ZTVN2nn2vi5Layer20NativeWindowListenerE',0),
    ('_ZN2nn2vi6detail17LayerNativeWindowC1EPNS1_21INativeWindowListenerE',
     '_ZN2nn2vi6detail17LayerNativeWindowC2EPNS1_21INativeWindowListenerE',28,
     '_ZTVN2nn2vi6detail17LayerNativeWindowE',1))

def _load_slot(sdk,entry,index,rd,load_index=None):
    pc=entry+index*4;adrp=sdk.unpack('<I',pc-sdk.base)[0]
    load=sdk.unpack('<I',entry-sdk.base+(index+1 if load_index is None else load_index)*4)[0]
    require(adrp&0x9f00001f==0x90000008 and load&0xffc003ff==0xf9400100|rd,
            'display full-width global load roles differ')
    return (pc&~4095)+signed(((adrp>>29)&3)|(((adrp>>5)&0x7ffff)<<2),21)*4096+((load>>10)&4095)*8

def _roles(rows,expected):
    require(all((rows[n].mnemonic,rows[n].op_str)==role for n,role in expected.items()),
            'display original register/stack/state roles differ')

def extend_display_audit(linker,original):
    require(original.get('graphics_runtime') is True and
            original.get('graphics_bootstrap',{}).get('skipped_provider_closure') is True and
            linker.report().get('link_complete') is True,'display requires a complete graphics source audit/link')
    sdk=next(m for m in linker.modules if m.name=='sdk');syntax=Decoder()
    for module in linker.modules:
        counts=[]
        if 39 in module.dynamic:
            require(module.dynamic[39]%24==0,'display symbol extent differs');counts.append(module.dynamic[39]//24)
        if 4 in module.dynamic:counts.append(module.unpack('<II',module.dynamic[4])[1])
        if not counts and 0x6ffffef5 in module.dynamic:counts.append(module.gnu_symbol_count())
        require(counts and all(n==len(module.symbols) for n in counts),'display original symbol census differs')
        for index,symbol in enumerate(module.symbols):
            _symbol_record(module,index,symbol)
            require(not (module.name!='sdk' and symbol.section and symbol.name.startswith(PREFIXES)),
                    'display consumer is defined outside the SDK')
    begin,end=sdk.ranges[0]
    require(sdk.header['segments'][0].get('hash_verified') is True and
            hashlib.sha256(sdk.read(begin,end-begin)).hexdigest()==sdk.header['segments'][0]['sha256'],
            'display requires unchanged original verified text')
    bridges={sdk.base+off:r for off,r in plt_stubs(sdk).items()}
    def stage(name):return _stage(linker.modules,'display_'+name,'sdk',name,syntax)
    def rows(s):return list(syntax.engine.disasm(sdk.read(s['offset'],s['size']),s['entry']))
    def callee(ins,name,tail=False):
        word=int.from_bytes(ins.bytes,'little');binding=stage(name)
        require(word&0xfc000000==(0x14000000 if tail else 0x94000000),'display callee branch kind differs')
        route=bridges.get(direct_target(word,ins.address))
        require(route is not None and route['symbol']==name and int(route['resolved_address'],16)==binding['entry'],
                'display original callee PLT/GOT differs')
        return dict(callee=binding,plt=route)
    initialize=stage(INITIALIZE);r=rows(initialize);entry=initialize['entry']
    require(initialize['size']==104 and len(r)==26,'display initializer extent differs')
    _roles(r,{0:('pacibsp',''),1:('stp','x29, x30, [sp, #-0x10]!'),2:('mov','x29, sp'),
        8:('mov','w1, #0x13'),12:('add','x10, x9, #1'),17:('ldp','x29, x30, [sp], #0x10'),
        18:('autibsp',''),23:('ldp','x29, x30, [sp], #0x10'),24:('autibsp','')})
    mutex=_state_address(sdk,entry,3,0)
    require(all(_state_address(sdk,entry,n,0)==mutex for n in (15,21)), 'display mutex routes differ')
    diagnostic=_state_address(sdk,entry,6,0)
    require(sdk.ranges[1][0]<=diagnostic-sdk.base<sdk.ranges[1][1],'display diagnostic is outside original rodata')
    counter=_load_slot(sdk,entry,10,9);load,store=sdk.unpack('<I',initialize['offset']+44)[0],sdk.unpack('<I',initialize['offset']+52)[0]
    require(store&0xffc003ff==0xf900010a and ((store>>10)&4095)==((load>>10)&4095),
            'display refcount store is not the matching full-width field')
    require(counter%8==0 and sdk.writable_start<=counter-sdk.base and counter-sdk.base+8<=sdk.bss_end and
            sdk.writable_start<=mutex-sdk.base<sdk.bss_end and (counter+8<=mutex or mutex+4<=counter),
            'display refcount/mutex are outside separate original data/BSS')
    word=int.from_bytes(r[14].bytes,'little')
    require(word&0xff00001f==0xb4000009 and direct_target(word,r[14].address)==entry+80,
            'display first-reference branch differs')
    calls=[dict(index=n,**callee(r[n],name,tail)) for n,name,tail in
        ((5,LOCK,False),(9,CHECK,False),(19,UNLOCK,True),(20,LOWER,False),(25,UNLOCK,True))]
    # These source-proved constructors run during original module initialization,
    # before VI boot. Keep their real vtable/stores/calls, never native no-ops.
    retained=[];retained_names=set()
    for first,second,size,vtable,at in CONSTRUCTORS:
        a,b=stage(first),stage(second);c=rows(a)
        require(a['size']==size and len(c)==size//4 and all(a[k]==b[k] for k in ('entry','size','body_sha256')),
                'display original constructor aliases/extent differ')
        slot=_load_slot(sdk,a['entry'],at,8,7 if size==88 else at+1)
        definitions=[(i,s) for i,s in enumerate(sdk.symbols) if s.name==vtable and s.section]
        require(len(definitions)==1,'display original vtable definition differs')
        index,symbol=definitions[0];metadata=_symbol_record(sdk,index,symbol)
        require(symbol.kind==1 and symbol.size>=16 and sdk.unpack('<Q',slot-sdk.base)[0]==sdk.base+symbol.value,
                'display original constructor vtable target differs')
        relocations=[(offset,info,addend) for _,table in sdk.rela for offset,info,addend in struct.iter_unpack('<QQq',table)
            if offset==slot-sdk.base]
        require(len(relocations)==1 and relocations[0][1]>>32==index and
                relocations[0][1]&0xffffffff in (257,1025,1026) and relocations[0][2]==0,
                'display original vtable load is not relocation-backed')
        if size==88:
            _roles(c,{0:('pacibsp',''),1:('stp','x29, x30, [sp, #-0x20]!'),2:('str','x19, [sp, #0x10]'),
                3:('mov','x29, sp'),5:('mov','x19, x0'),6:('mov','x1, x19'),8:('add','x8, x8, #0x10'),
                9:('str','x8, [x0]'),10:('add','x0, x0, #0x488'),12:('add','x0, x19, #0x498'),
                13:('add','x1, x19, #0x488'),15:('strh','wzr, [x19, #0x4d0]'),16:('str','xzr, [x19, #0x4c8]'),
                17:('str','xzr, [x19, #0x4c0]'),18:('str','xzr, [x19, #0x4b8]'),19:('ldr','x19, [sp, #0x10]'),
                20:('ldp','x29, x30, [sp], #0x20'),21:('retab','')})
            dependencies=[callee(c[11],CONSTRUCTORS[1][0]),callee(c[14],CONSTRUCTORS[2][0])]
        elif size==20:
            _roles(c,{2:('add','x8, x8, #0x10'),3:('stp','x8, x1, [x0]'),4:('ret','')});dependencies=[]
        else:
            _roles(c,{0:('strb','wzr, [x0, #0x10]'),3:('str','x1, [x0, #0x18]'),
                4:('add','x8, x8, #0x10'),5:('stp','x8, xzr, [x0]'),6:('ret','')});dependencies=[]
        retained.append(dict(wrapper=a,alias=b,vtable=metadata,vtable_slot=slot,callees=dependencies,
            original_execution_retained=True));retained_names.update((first,second))
    records=[];census=0
    for symbol in sdk.symbols:
        if not (symbol.section and symbol.kind==2 and symbol.name.startswith(PREFIXES)):continue
        census+=1
        if symbol.name in retained_names:continue
        row=stage(symbol.name);supported=symbol.name==INITIALIZE
        row.update(handler_id=450 if supported else GUARD_ID,names=[symbol.name],returns_value=False,
            return_register=None,implementation='native_display' if supported else 'guard',
            signature='void VI Initialize()' if supported else 'unsupported VI/VI2 provider consumer',
            entry_word=row['entry_instruction']['word']);records.append(row)
    report=json.loads(json.dumps(original));report['functions']=_merge_bindings([*report['functions'],*records])
    report.update(format='oot-display-sdk-audit',display_runtime=True)
    report['display_initialization']=dict(initialize=initialize,original_mutex=mutex,original_refcount=counter,
        callees=calls,original_constructors=retained,exported_consumers=census,skipped_provider_closure=True,
        return_abi='void; full GPR/vector/FP state preserved',
        ownership='real per-context hidden Win32 window and presentation-supported Vulkan surface; no guest Display/Layer')
    return report
