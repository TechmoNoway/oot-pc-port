"""Original ABI and skipped-provider closure for the opt-in Vulkan bootstrap."""
import hashlib,json
from application_audit import GUARD_ID,_merge_bindings,_stage,_symbol_record
from arm64_decode import Decoder,direct_target
from arm64_analysis import plt_stubs
from input_formats import require

BOOT='_ZN2nn2gs3sdk18BootGraphicsSystemEPvm'
PUBLIC='_ZN2nn2gs10InitializeEPvm'
CHECK='_ZN2nn2gs3sdk30CheckGraphicsSystemInitializedEPKcm'
REMOTE='_ZN2nn2gs3sdk23CanBootWithRemoteMemoryEv'
ALLOCATOR='_ZN2nn2gs3sdk27InitializeGraphicsAllocatorEPFPvmmS2_EPFvS2_S2_EPFS2_S2_mS2_ES2_'
GET_ALLOCATOR='_ZN2nn2gs3sdk20GetGraphicsAllocatorEPPFPvmmS2_EPPFvS2_S2_EPPFS2_S2_mS2_E'
PREFIXES=tuple(a+b for a in ('_ZN2nn','_ZNK2nn') for b in ('2gs','3gsv','5nvsrv','6syncpt','3gpu'))
CALLEES={
    13:'_ZN2nn2os12SdkMutexType4LockEv',
    24:'_ZN2nn3gsv20BootWithRemoteMemoryENS0_12MemoryRegionE',
    25:'_ZN2nn3gsv4shim6detail33InitializeInterModuleImageContextEv',
    29:'_ZN2nn5nvsrv20BootWithRemoteMemoryENS_3gsv12MemoryRegionEPDoFNS_2os17RemoteMemoryUsageEvE',
    34:'_ZN2nn6syncpt3sdk12InitializeExEPvmNS1_14LibraryOptionsE',
    36:'_ZN2nn2gs3sdk26BootNativeMemoryManagementENS_3gsv19MemoryBlockModeBitsE',
    37:'_ZN2nn2gs3sdk27BootGraphicsFrameManagementEv',
    39:'_ZN2nn3gpu3sdk20BootWithRemoteMemoryENS_3gsv12MemoryRegionE',
    44:'_ZN2nn2os12SdkMutexType6UnlockEv',55:'_ZN2nn4diag6detail9AbortImplEv'}

def _state_address(sdk,entry,index,register):
    pc=entry+index*4;adrp,add=sdk.unpack('<II',pc-sdk.base)
    require(adrp&0x9f00001f==0x90000000|register and
            add&0xffc003ff==0x91000000|(register<<5)|register,'graphics state-address roles differ')
    pages=((adrp>>29)&3)|(((adrp>>5)&0x7ffff)<<2)
    if pages&(1<<20):pages-=1<<21
    return (pc&~4095)+(pages<<12)+((add>>10)&4095)

def _conditional(sdk,entry,index,target,condition):
    word=sdk.unpack('<I',entry-sdk.base+index*4)[0];delta=(word>>5)&0x7ffff
    if delta&(1<<18):delta-=1<<19
    require(word&0xff00001f==0x54000000|condition and
            entry+index*4+delta*4==target,'graphics state branch differs')

def extend_graphics_audit(linker,original):
    require(original.get('application_runtime') is True and
            original.get('application_resource_identity',{}).get('exported_am_consumer_closure') is True,
            'graphics requires the complete earlier application audit')
    require(linker.report().get('link_complete') is True,'graphics requires a complete offline link')
    sdk=next(m for m in linker.modules if m.name=='sdk');syntax=Decoder()
    # Check the raw census before filtering. Renaming/removing parsed consumers
    # must not silently reduce the closed provider domain.
    for module in linker.modules:
        counts=[]
        if 39 in module.dynamic:
            require(module.dynamic[39]%24==0,'graphics symbol table extent differs')
            counts.append(module.dynamic[39]//24)
        if 4 in module.dynamic:counts.append(module.unpack('<II',module.dynamic[4])[1])
        if not counts and 0x6ffffef5 in module.dynamic:counts.append(module.gnu_symbol_count())
        require(counts and all(n==len(module.symbols) for n in counts),'graphics original symbol census differs')
        for index,symbol in enumerate(module.symbols):
            _symbol_record(module,index,symbol)
            require(not (module.name!='sdk' and symbol.section and symbol.name.startswith(PREFIXES)),
                    'graphics consumer is defined outside the SDK')
    begin,end=sdk.ranges[0]
    require(sdk.header['segments'][0].get('hash_verified') is True and
            hashlib.sha256(sdk.read(begin,end-begin)).hexdigest()==sdk.header['segments'][0]['sha256'],
            'graphics requires unchanged original verified text')
    stages={name:_stage(linker.modules,'graphics_'+name,'sdk',name,syntax) for name in (BOOT,PUBLIC,CHECK,REMOTE,ALLOCATOR,GET_ALLOCATOR)}
    boot,public,check,remote=(stages[n] for n in (BOOT,PUBLIC,CHECK,REMOTE))
    require((boot['size'],public['size'],check['size'],remote['size'])==(224,4,40,8),'graphics original ABI extent differs')
    bridges={sdk.base+off:row for off,row in plt_stubs(sdk).items()}
    require(public['entry_instruction']['word']&0xfc000000==0x14000000,'graphics public entry is not a B thunk')
    bridge=bridges.get(direct_target(public['entry_instruction']['word'],public['entry']))
    require(bridge is not None and bridge['symbol']==BOOT and int(bridge['resolved_address'],16)==boot['entry'],
            'graphics public thunk does not resolve to the original boot')
    def instructions(stage):return list(syntax.engine.disasm(sdk.read(stage['offset'],stage['size']),stage['entry']))
    b=instructions(boot);c=instructions(check)
    roles={0:('pacibsp',''),7:('mov','x19, x1'),8:('mov','x20, x0'),
        9:('ldapr','w8, [x21]'),10:('cmp','w8, #1'),14:('ldapr','w8, [x21]'),15:('cmp','w8, #1'),
        22:('mov','w22, #1'),40:('stp','x20, x19, [x21, #8]'),41:('stlr','w22, [x21]'),
        47:('ldp','x9, x8, [x8]'),48:('cmp','x9, x20'),49:('ccmp','x8, x19, #0, eq'),54:('retab','')}
    require(len(b)==56 and all((b[n].mnemonic,b[n].op_str)==role for n,role in roles.items()),
            'graphics full-width argument/idempotency/void-return roles differ')
    require([n for n,i in enumerate(b) if i.mnemonic in ('ret','retab','retaa')]==[54] and
            [n for n,i in enumerate(b) if i.mnemonic in ('bl','blr')]==list(CALLEES),
            'graphics return/call control flow differs')
    branch_indices=[n for n,i in enumerate(b) if i.mnemonic.startswith('b.') or
                    i.mnemonic in ('b','br','cbz','cbnz','tbz','tbnz')]
    require(branch_indices==[11,16,50],'graphics conditional control flow differs')
    for at,target,condition in ((11,45,0),(16,42,0),(50,55,1)):
        _conditional(sdk,boot['entry'],at,boot['entry']+target*4,condition)
    state=_state_address(sdk,boot['entry'],5,21)
    require(_state_address(sdk,boot['entry'],45,8)==state+8 and
            _state_address(sdk,check['entry'],0,8)==state,'graphics cached state/pair addresses disagree')
    require(state%8==0 and sdk.writable_start<=state-sdk.base and state-sdk.base+24<=sdk.bss_end,
            'graphics cached state is outside original data/BSS')
    require(len(c)==10 and all((c[n].mnemonic,c[n].op_str)==role for n,role in {
        2:('ldapr','w8, [x8]'),3:('cmp','w8, #1'),5:('ret',''),6:('pacibsp','')}.items()),
        'graphics precondition is not the original void check')
    _conditional(sdk,check['entry'],4,check['entry']+24,1)
    call_proofs=[]
    for index,name in CALLEES.items():
        ins=b[index];word=int.from_bytes(ins.bytes,'little');target=direct_target(word,ins.address)
        route=bridges.get(target);callee=_stage(linker.modules,'graphics_dependency','sdk',name,syntax)
        require(route is not None and route['symbol']==name and int(route['resolved_address'],16)==callee['entry'],
                'graphics original bootstrap callee/PLT changed')
        call_proofs.append(dict(index=index,callee=callee,plt=route))
    require(c[9].mnemonic=='bl' and bridges.get(direct_target(int.from_bytes(c[9].bytes,'little'),c[9].address),{}).get('symbol')==CALLEES[55],
            'graphics precondition failure does not route to the original abort')
    # Preserve this original pure capability query. It runs before the native
    # bootstrap in nv::InitializeGraphics and has no dependency on GS globals.
    require(sdk.unpack('<II',remote['offset'])==(0x52800020,0xd65f03c0),'graphics original pure remote-memory query differs')
    # This initializer precedes BootGraphicsSystem in the original prefix. It
    # still executes its original allocator constructor and guest callbacks;
    # replacing the later GS boot must not replace or suppress this work.
    allocator=stages[ALLOCATOR];a=instructions(allocator)
    require(allocator['size']==28 and len(a)==7 and all((a[n].mnemonic,a[n].op_str)==role for n,role in {
        0:('mov','x4, x3'),1:('mov','x3, x2'),2:('mov','x2, x1'),3:('mov','x1, x0')}.items()),
        'original graphics allocator argument/receiver wrapper differs')
    receiver=_state_address(sdk,allocator['entry'],4,0)
    tail_word=int.from_bytes(a[6].bytes,'little')
    require(tail_word&0xfc000000==0x14000000,'original graphics allocator constructor is not a B tail-call')
    tail=direct_target(tail_word,a[6].address)
    require(sdk.is_code(tail-sdk.base) and
            sdk.writable_start<=receiver-sdk.base and receiver-sdk.base+32<=sdk.bss_end,
            'original graphics allocator receiver/constructor route differs')
    getter=stages[GET_ALLOCATOR];callbacks=instructions(getter);callback_entries=[]
    require(getter['size']==40 and len(callbacks)==10 and (callbacks[9].mnemonic,callbacks[9].op_str)==('ret',''),
            'original graphics allocator callback getter extent/return differs')
    for n in range(3):
        nop,adr,store=callbacks[n*3:n*3+3];word=int.from_bytes(adr.bytes,'little')
        require((nop.mnemonic,nop.op_str)==('nop','') and word&0x9f00001f==0x10000008 and
                (store.mnemonic,store.op_str)==('str',f'x8, [x{n}]'),
                'original graphics allocator callback capture roles differ')
        delta=((word>>29)&3)|(((word>>5)&0x7ffff)<<2)
        if delta&(1<<20):delta-=1<<21
        target=adr.address+delta
        require(target%4==0 and sdk.is_code(target-sdk.base),'original graphics allocator callback is outside SDK code')
        callback_entries.append(target)
    records=[];census=0
    for symbol in sdk.symbols:
        if not (symbol.section and symbol.kind==2 and symbol.name.startswith(PREFIXES)):continue
        census+=1
        if symbol.name in (REMOTE,ALLOCATOR,GET_ALLOCATOR):continue
        row=_stage(linker.modules,'graphics_'+symbol.name,'sdk',symbol.name,syntax)
        handler=448 if symbol.name in (BOOT,PUBLIC) else 449 if symbol.name==CHECK else GUARD_ID
        row.update(handler_id=handler,names=[symbol.name],returns_value=False,return_register=None,
            implementation='native_graphics' if handler!=GUARD_ID else 'guard',
            signature='void graphics bootstrap/precondition' if handler!=GUARD_ID else 'unsupported graphics provider consumer',
            entry_word=row['entry_instruction']['word'])
        records.append(row)
    report=json.loads(json.dumps(original))
    report['functions']=_merge_bindings([*report['functions'],*records])
    report.update(format='oot-graphics-sdk-audit',graphics_runtime=True)
    report['graphics_bootstrap']=dict(boot=boot,public=public,check=check,original_remote_query=remote,
        original_allocator=dict(wrapper=allocator,receiver=receiver,tail_target=tail,original_execution_retained=True),
        original_allocator_getter=dict(wrapper=getter,callbacks=callback_entries,original_execution_retained=True),
        original_state=state,public_plt=bridge,callees=call_proofs,exported_consumers=census,
        skipped_provider_closure=True,return_abi='void; full GPR/vector/FP state preserved',
        ownership='real per-context Vulkan instance/device/graphics queue; no guest SDK objects or supervisor handles')
    return report
