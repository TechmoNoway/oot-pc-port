"""Exact-build default Display/Layer contracts and closed virtual consumers.

This first object profile deliberately supports one audited original SDK build.
Hashes are input identities, never captured code. A different build must receive
its own ABI review rather than inherit these field/ownership interpretations.
"""
import bisect,hashlib,json,struct
from arm64_decode import Decoder,direct_target,signed
from arm64_analysis import plt_stubs
from display_audit import PREFIXES,_roles,_load_slot
from graphics_audit import _state_address
from sdk_startup_audit import _stage,_instruction
from input_formats import require
from vtable_provenance import prove_vtables
from unwind_provenance import prove_extents

SUPPORTED_SDK=dict(source_sha256='1cf5163c8d0db2d8326559b3ef019b3c28b70d4888d1c4cf00feca76c4162018',
    segments=('75d62ca5f5724bd10627854d2197ee6c1c596b226db837da7e7f3ebf9d769937',
        '250fb013ce8791340dc2c92b7b719511d6954b5c25dcd4e5df1fc4a16923a375',
        '2ffdd29c0b91797eb8e49d7f706b145cd7d205f841a59dc30defb65bf7290c71'))
FUNCTIONS=(
    (451,'_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE',148,True),
    (452,'_ZN2nn2vi12CloseDisplayEPNS0_7DisplayE',8,False),
    (453,'_ZN2nn2vi11CreateLayerEPPNS0_5LayerEPNS0_7DisplayE',196,True),
    (454,'_ZN2nn2vi12DestroyLayerEPNS0_5LayerE',8,False),
    (455,'_ZN2nn2vi15GetNativeWindowEPPvPNS0_5LayerE',48,True))
TABLE_PREFIXES=('_ZTVN2nn2vi','_ZTVN2nn3vi2')

def emit_object_declaration(declaration,image_sha256):
    def constant(value):
        require(type(value)is int and 0<=value<1<<64,'invalid compiled object integer')
        return 'UINT64_C('+str(value)+')'
    def digest(value):
        require(isinstance(value,str)and len(value)==64 and all(c in'0123456789abcdef'for c in value),
            'invalid compiled object digest')
        return '{'+','.join('0x'+value[n:n+2]for n in range(0,64,2))+'}'
    require(declaration['version']==1 and declaration['flags']in(0,1,3,7,15,31)and
        len(declaration['tables'])==8 and len(declaration['vptr_address'])==len(declaration['vptr_value'])==5,
        'invalid compiled object declaration shape')
    lines=['static const OotObjectDeclaration oot_object_declaration={']
    for name in('version','flags','width','height','display','display_size','layer','layer_size','native_window','anchor','anchor_size'):
        lines.append('.'+name+'='+constant(declaration[name])+',')
    for name in('vptr_address','vptr_value'):
        lines.append('.'+name+'={'+','.join(constant(v)for v in declaration[name])+'},')
    lines+=['.image_sha256='+digest(image_sha256)+',','.anchor_sha256='+digest(declaration['anchor_sha256'])+',','.tables={']
    for table in declaration['tables']:
        lines.append('{'+constant(table['address'])+','+constant(table['size'])+',0,'+digest(table['sha256'])+'},')
    return lines+['}};','const OotObjectDeclaration *oot_startup_compiled_objects(void) { return &oot_object_declaration; }']

def verify_sdk_identity(pristine,linked,identity):
    require(pristine.source_sha256==linked.source_sha256==identity['source_sha256'],
        'object ABI requires the explicitly audited SDK build')
    require(len(pristine.ranges)==3 and len(identity['segments'])==3,'object SDK segment census differs')
    for n,(begin,end)in enumerate(pristine.ranges):
        expected=identity['segments'][n]
        require(pristine.header['segments'][n].get('hash_verified')is True and
            pristine.header['segments'][n]['sha256']==expected and
            hashlib.sha256(pristine.read(begin,end-begin)).hexdigest()==expected,
            'object SDK original segment identity differs')
        if n<2:require(linked.read(begin,end-begin)==pristine.read(begin,end-begin),'object SDK linked text/rodata differs')

def merge_private_guards(functions,proof):
    rows={row['entry']:json.loads(json.dumps(row))for row in functions}
    require(len(rows)==len(functions),'object source registry has duplicate entries')
    for target in proof['targets']:
        row=rows.get(target['entry'])
        if row is not None:
            require(row['handler_id']==31 and row['size']==target['size']and
                row['body_sha256']==target['body_sha256']and row['returns_value']is False,
                'private vtable target conflicts with an existing ABI/body binding')
            row.setdefault('private_vtable_proofs',[]).append(target)
        else:
            rows[target['entry']]=dict(module=proof['module'],entry=target['entry'],size=target['size'],
                body_sha256=target['body_sha256'],handler_id=31,returns_value=False,return_register=None,
                implementation='guard',signature='unsupported private VI virtual consumer',
                symbol=None,names=[],source_kind='canonical-unwind-private-entry',
                private_vtable_proofs=[target])
    result=sorted(rows.values(),key=lambda row:row['entry'])
    require(len(result)<=4096 and all(a['entry']+a['size']<=b['entry']for a,b in zip(result,result[1:])),
        'object consumer extents overlap or exceed the unchanged registry limit')
    return result

def extend_objects_audit(linker,original,pristine,events=False):
    require(original.get('display_runtime')is True and
        original.get('display_initialization',{}).get('skipped_provider_closure')is True and
        linker.report().get('link_complete')is True,'objects require the complete preceding display audit')
    require(events is False,'event producer/consumer contract is not yet enabled')
    sdk=next(m for m in linker.modules if m.name=='sdk');syntax=Decoder()
    verify_sdk_identity(pristine,sdk,SUPPORTED_SDK)
    definitions={s.name:s for s in sdk.symbols if s.section and s.kind==1 and s.name.startswith(TABLE_PREFIXES)}
    require(len(definitions)==8 and all(s.size>=24 and s.size%8==0 for s in definitions.values()),
        'complete VI/VI2 original vtable census differs')
    proof=prove_vtables(pristine,linker,{name:(s.size-16)//8 for name,s in definitions.items()})
    require(proof['slot_count']==103 and len(proof['targets'])==85,'audited VI virtual closure differs')
    tables={t['symbol']:t for t in proof['tables']};bridges={sdk.base+o:r for o,r in plt_stubs(sdk).items()}
    def stage(name):return _stage(linker.modules,'object_contract','sdk',name,syntax)
    def instructions(row):return list(syntax.engine.disasm(sdk.read(row['offset'],row['size']),row['entry']))
    def call(row,index,name,tail=False):
        word=sdk.unpack('<I',row['offset']+index*4)[0]
        require(word&0xfc000000==(0x14000000 if tail else 0x94000000),'object callee branch kind differs')
        bridge=bridges.get(direct_target(word,row['entry']+index*4));callee=stage(name)
        require(bridge is not None and bridge['symbol']==name and int(bridge['resolved_address'],16)==callee['entry'],
            'object original callee PLT/GOT differs')
        return dict(index=index,callee=callee,plt=bridge)
    typed=[stage(name)for _,name,_,_ in FUNCTIONS]
    for row,(_,name,size,_)in zip(typed,FUNCTIONS):require(row['size']==size,'object public ABI extent differs: '+name)
    opened,closed,created,destroyed,window=typed
    display=_state_address(sdk,opened['entry'],26,21)
    layer=_state_address(sdk,created['entry'],11,0)
    require(_state_address(sdk,created['entry'],20,20)==layer and
        _state_address(sdk,created['entry'],16,8)==display and
        _state_address(sdk,created['entry'],22,2)==display,'object public static identity routes disagree')
    _roles(instructions(opened),{5:('mov','x19, x0'),6:('str','xzr, [x0]'),9:('mov','x1, x0'),
        28:('mov','x1, x20'),29:('mov','x0, x21'),32:('str','x21, [x19]')})
    _roles(instructions(created),{5:('mov','x19, x0'),7:('mov','x20, x1'),13:('str','xzr, [x19]'),
        18:('cmp','x20, x8'),24:('mov','x0, x20'),27:('mov','x1, sp'),34:('str','x20, [x19]'),
        39:('mov','w0, #0x272'),44:('mov','w0, #0xc72')})
    _roles(instructions(window),{4:('mov','x19, x0'),5:('mov','x0, x1'),7:('str','x0, [x19]'),9:('mov','w0, wzr')})
    dependencies=[call(opened,10,'strcasecmp'),call(opened,17,'strcasecmp'),
        call(opened,30,'_ZN2nn2vi7Display4OpenEPKc'),
        call(created,10,'_ZN2nn2vi21LayerCreationSettingsC1Ev'),
        call(created,14,'_ZNK2nn2vi5Layer6IsOpenEv'),
        call(created,28,'_ZN2nn2vi5Layer4OpenEPKNS0_21LayerCreationSettingsEPNS0_7DisplayEPKc'),
        call(closed,1,'_ZN2nn2vi7Display5CloseEb',True),
        call(destroyed,1,'_ZN2nn2vi5Layer5CloseEb',True),call(window,6,'_ZN2nn2vi5Layer15GetNativeWindowEv')]
    for row in(closed,destroyed):_roles(instructions(row),{0:('mov','w1, wzr')})
    settings=stage('_ZN2nn2vi21LayerCreationSettingsC1Ev')
    require(settings['size']==24,'object default settings extent differs')
    _roles(instructions(settings),{0:('mov','x8, #0x780'),1:('movk','x8, #0x438, lsl #32'),
        2:('str','x8, [x0]'),3:('mov','w8, #2'),4:('str','w8, [x0, #8]'),5:('ret','')})
    member=stage('_ZN2nn2vi5Layer15GetNativeWindowEv');r=instructions(member)
    require(member['size']==8 and len(r)==2,'object native-window member extent differs')
    word=sdk.unpack('<I',member['offset'])[0]
    require(word&0xffc003ff==0x91000000,'object native-window member receiver differs')
    interior=(word>>10)&4095
    tail=bridges.get(direct_target(sdk.unpack('<I',member['offset']+4)[0],member['entry']+4))
    require(tail is not None and tail['symbol'].startswith('_ZN2nn2gs')and 'GetNativeWindowHandle'in tail['symbol'],
        'object native-window identity dependency differs')
    identity=stage(tail['symbol'])
    require(int(tail['resolved_address'],16)==identity['entry']and identity['size']==4 and
        sdk.unpack('<I',identity['offset'])[0]==0xd65f03c0,'object native-window dependency is not identity RET')
    # Find the private original constructor from address materialization, then
    # prove its canonical extent; no observed absolute PC is compiled into tools.
    header=sdk.read(sdk.mod0['exception_start'],sdk.mod0['exception_end']-sdk.mod0['exception_start'])
    begin=sdk.mod0['exception_start'];entries=[sdk.base+begin+x for x,_ in struct.iter_unpack('<ii',header[12:])]
    candidates=set();text_start,text_end=sdk.ranges[0]
    words=sdk.unpack('<'+str((text_end-text_start)//4)+'I',text_start)
    for n,word in enumerate(words[:-1]):
        if word&0x9f00001f!=0x90000014:continue
        other=words[n+1]
        if other&0xffc003ff!=0x91000294:continue
        pc=sdk.base+text_start+n*4
        at=(pc&~4095)+signed(((word>>29)&3)|(((word>>5)&0x7ffff)<<2),21)*4096+((other>>10)&4095)
        if at==display:
            index=bisect.bisect_right(entries,pc)-1
            require(index>=0,'object constructor has no canonical unwind owner');candidates.add(entries[index])
    constructors=[p for p in prove_extents(sdk,candidates)if p['size']==492]
    require(len(constructors)==1,'object static constructor is missing or ambiguous')
    constructor=constructors[0];constructor['offset']=constructor['entry']-sdk.base
    require(_state_address(sdk,constructor['entry'],14,20)==display and
        _state_address(sdk,constructor['entry'],79,21)==layer,'object constructor receivers differ')
    _roles(instructions(constructor),{25:('str','x8, [x20]'),36:('add','x8, x8, #0x10'),
        40:('str','x8, [x20]'),81:('mov','x0, x21'),89:('add','x8, x8, #0x10'),
        90:('str','x8, [x21]'),95:('add','x8, x8, #0x10'),96:('str','x8, [x21, #0x4e0]'),
        109:('add','x0, x20, #0x450')})
    ctor_branch=sdk.unpack('<I',constructor['offset']+82*4)[0]
    ctor_route=bridges.get(direct_target(ctor_branch,constructor['entry']+82*4))
    require(ctor_route is not None and ctor_route['symbol']in('_ZN2nn2vi5LayerC1Ev','_ZN2nn2vi5LayerC2Ev'),
        'object base Layer constructor alias differs')
    constructor_layer=call(constructor,82,ctor_route['symbol'])
    def constructor_table(index,load,name):
        slot=_load_slot(sdk,constructor['entry'],index,8,load)
        require(sdk.unpack('<Q',slot-sdk.base)[0]==tables[name]['entry'],'object final constructor vtable differs')
        relocations=[(at,info,addend)for _,data in sdk.rela for at,info,addend in struct.iter_unpack('<QQq',data)
            if at==slot-sdk.base]
        require(len(relocations)==1 and relocations[0][1]&0xffffffff in(257,1025)and
            relocations[0][1]>>32==tables[name]['symbol_metadata']['index']and relocations[0][2]==0,
            'object constructor vtable slot lacks its original symbol relocation')
        return dict(slot=slot,table=name,relocation=relocations[0])
    constructor_tables=[constructor_table(28,32,'_ZTVN2nn2vi6detail14DefaultDisplayE'),
        constructor_table(83,87,'_ZTVN2nn2vi16LayerWithHistoryE'),
        constructor_table(91,92,'_ZTVN2nn2vi21TimestampRecorderPoolILm8EEE')]
    constructor['required_original_steps']=[_instruction(sdk,constructor['entry']+index*4,syntax)
        for index in (0,40,90,96)]
    require(interior==0x498 and display>layer and display-layer<=16384,'object bounded static layout differs')
    vptr_names=('_ZTVN2nn2vi6detail14DefaultDisplayE','_ZTVN2nn2vi16LayerWithHistoryE',
        '_ZTVN2nn2vi5Layer20NativeWindowListenerE','_ZTVN2nn2vi6detail17LayerNativeWindowE',
        '_ZTVN2nn2vi21TimestampRecorderPoolILm8EEE')
    declaration=dict(version=1,flags=0,width=1920,height=1080,display=display,display_size=0x450,
        layer=layer,layer_size=display-layer,native_window=layer+interior,
        vptr_address=[display,layer,layer+0x488,layer+interior,layer+0x4e0],
        vptr_value=[tables[name]['entry']+16 for name in vptr_names],anchor=opened['entry'],
        anchor_size=opened['size'],anchor_sha256=opened['body_sha256'],
        tables=[dict(address=t['entry'],size=t['size'],sha256=t['linked_sha256'])for t in proof['tables']])
    result=json.loads(json.dumps(original));functions=merge_private_guards(result['functions'],proof)
    for handler,name,size,returns in FUNCTIONS:
        matches=[row for row in functions if name in row.get('names',[])]
        require(len(matches)==1 and matches[0]['names']==[name]and matches[0]['handler_id']==31,
            'object typed public entry has incompatible aliases/handler')
        matches[0].update(handler_id=handler,returns_value=returns,return_register='w0'if returns else None,
            implementation='native_display_objects',signature='source-bound default object public API')
    result.update(format='oot-display-objects-audit',objects_runtime=True,functions=functions)
    result['display_objects']=dict(declaration=declaration,source_identity=SUPPORTED_SDK,
        vtables=proof,constructor=constructor,constructor_tables=constructor_tables,constructor_layer=constructor_layer,
        public_contracts=typed,callees=dependencies,settings=settings,native_window_member=member,
        native_window_identity=identity,skipped_history_and_driver_consumers_guarded=True,
        original_construction_retained=True,source_contract_scope='exact audited SDK build; default public objects only')
    return result
