"""Private original-function bindings for the opt-in native SDK logging family."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from arm64_analysis import plt_stubs
from arm64_decode import (CALL, CONDITIONAL, INDIRECT_CALL, INDIRECT_JUMP, JUMP,
                          NORMAL, RETURN, TRAP, Decoder, direct_target, flow_kind)
from capstone.arm64_const import ARM64_OP_MEM
from input_formats import InputError, require
from link_exefs import build_destination, load_prepared
from module_linker import Linker
from sdk_startup_audit import _stage

FORMAT = 'oot-native-sdk-audit'
FUNCTIONS = (
    (1, 'lm_initialize', '_ZN2nn2lm10InitializeEv', 'void Initialize()'),
    (3, 'lm_set_destination', '_ZN2nn2lm14SetDestinationEj', 'void SetDestination(uint32_t)'),
    (5, 'diag_emit', '_ZN2nn4diag6detail18CallAllLogObserverERKNS0_11LogMetaDataERKNS0_7LogBodyE',
     'void CallAllLogObserver(const LogMetaData&, const LogBody&)'),
    (6, 'diag_enable_default', '_ZN2nn4diag24EnableDefaultLogObserverEb',
     'void EnableDefaultLogObserver(bool)'),
    (31, 'guard_register', '_ZN2nn4diag19RegisterLogObserverEPNS0_17LogObserverHolderE', 'unsupported observer registration'),
    (31, 'guard_unregister', '_ZN2nn4diag21UnregisterLogObserverEPNS0_17LogObserverHolderE', 'unsupported observer unregistration'),
    (31, 'guard_replace', '_ZN2nn4diag6detail25ReplaceDefaultLogObserverEPFvRKNS0_11LogMetaDataERKNS0_7LogBodyEPvE',
     'unsupported guest observer callback replacement'),
    (31, 'guard_reset', '_ZN2nn4diag6detail23ResetDefaultLogObserverEv', 'unsupported guest observer reset'),
    (31, 'guard_start_logging', '_ZN2nn2lm12StartLoggingEv', 'unsupported separate log-getter interface'),
    (31, 'guard_stop_logging', '_ZN2nn2lm11StopLoggingEv', 'unsupported separate log-getter interface'),
    (31, 'guard_get_log', '_ZN2nn2lm6GetLogEPcmPlPj', 'unsupported separate log-getter interface'),
    (31, 'guard_log_object', '_ZN2nn2lm22CreateLogServiceByHipcEv', 'unsupported opaque SDK log-service object'),
    (31, 'guard_log_getter', '_ZN2nn2lm21CreateLogGetterByHipcEv', 'unsupported opaque SDK log-getter object'),
)
PUT_SYMBOL = '_ZN2nn4diag6detail7PutImplERKNS0_11LogMetaDataEPKcm'
OE_INITIALIZE_SYMBOL = '_ZN2nn2oe10InitializeEv'
REPLACE_SYMBOL = FUNCTIONS[6][2]
REFERENCES = [
    dict(url='https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/include/stratosphere/diag/diag_log_types.hpp',
         scope='independent structure reference; the inspected original code binds only the consumed metadata prefix'),
    dict(url='https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/source/lm/lm_api.cpp',
         scope='Initialize and SetDestination void API and logging-observer responsibility'),
    dict(url='https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/include/stratosphere/lm/lm_types.hpp',
         scope='destination mask values; host capture does not implement hardware transports'),
]


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _rows(module, entry, size, decoder):
    offset=entry-module.base
    require(0 < size <= 4096 and size % 4 == 0 and module.is_code(offset) and
            module.is_code(offset+size-4), 'native SDK audit has an invalid text extent')
    result=list(decoder.engine.disasm(module.read(offset,size),entry))
    require(len(result)*4==size and all(row.size==4 and row.mnemonic!='.word' for row in result),
            'native SDK audit requires completely decoded original text')
    return result


def _sequence(rows, expected):
    matches=[]
    for start in range(len(rows)-len(expected)+1):
        if all(spec is None or (rows[start+n].mnemonic,rows[start+n].op_str)==spec
               for n,spec in enumerate(expected)):
            matches.append(rows[start:start+len(expected)])
    require(len(matches)==1,'native SDK logging record/observer profile is missing or ambiguous')
    return matches[0]


def _evidence(rows):
    data=b''.join(bytes(row.bytes) for row in rows)
    return dict(entry=rows[0].address,size=len(data),sha256=_sha(data),
                words=[int.from_bytes(row.bytes,'little') for row in rows])


def _direct(row, call):
    word=int.from_bytes(row.bytes,'little')
    require(word & 0xfc000000==(0x94000000 if call else 0x14000000),
            'native SDK audit expected an exact direct branch word')
    return direct_target(word,row.address)


def _observer_roles(rows):
    """Bind field loads to captured input pointers, not matching word sets."""
    pairs=[(row.mnemonic,row.op_str) for row in rows]
    metadata={('ldp','w4, w5, [x20, #0x20]'):(1,0),('ldr','w1, [x20]'):(2,1),
              ('ldr','x21, [x20, #8]'):(4,3),('ldr','x21, [x20, #0x10]'):(8,7),
              ('ldr','x20, [x20, #0x18]'):(16,15)}
    body={('ldrb','w8, [x19, #0x11]'):1,('ldrb','w7, [x19, #0x10]'):2,
          ('ldrb','w8, [x19, #0x10]'):2,('ldp','x1, x2, [x19]'):4}
    require(all(pair in pairs for pair in metadata) and all(pair in pairs for pair in body),
            'native SDK original metadata/body field consumption is unrecognized')
    _sequence(rows,[('ldrb','w8, [x19, #0x10]'),('cmp','w8, #1')])
    indices={row.address:index for index,row in enumerate(rows)}
    # Forward CFG states retain two distinct roles. Once the final metadata
    # field loads through X20 into X20, that role has ended and the register
    # may be reused for a module/thread string. X19 remains the body pointer
    # until the final pointer/length pair. Branch alternatives cannot combine
    # captures and fields from unrelated paths into an apparent proof.
    pending=[(0,False,False,0,0)];seen=set();observed=set();completed=[];capture_sites=set()
    while pending:
        state=pending.pop()
        if state in seen:continue
        seen.add(state)
        require(len(seen)<=65536,'native SDK observer role proof exceeds its bounded state limit')
        index,body_captured,meta_captured,meta_mask,body_mask=state
        require(index<len(rows),'native SDK observer path leaves the profile before body consumption')
        row=rows[index];pair=pairs[index]
        capture_body=not body_captured and pair==('mov','x19, x1')
        capture_meta=not meta_captured and pair==('mov','x20, x0')
        _,modified=row.regs_access()
        modified={row.reg_name(register) for register in modified}
        require(capture_body or not (modified & {'x19','w19'}),
                'native SDK observer body pointer is clobbered before its last field consumption')
        module_load=meta_captured and not (meta_mask&16) and pair==('ldr','x20, [x20, #0x18]')
        require(meta_mask&16 or capture_meta or module_load or not (modified & {'x20','w20'}),
                'native SDK observer metadata pointer is clobbered before its last field consumption')
        if not body_captured:
            require(not (modified & {'x1','w1'}),'native SDK observer body input is clobbered before capture')
        if not meta_captured:
            require(not (modified & {'x0','w0'}),'native SDK observer metadata input is clobbered before capture')
        word=int.from_bytes(row.bytes,'little');flow=flow_kind(word,row.mnemonic)
        if not (body_captured and meta_captured):
            require(flow==NORMAL,
                    'native SDK observer control transfer precedes input capture')
        for operand in row.operands:
            if operand.type!=ARM64_OP_MEM:continue
            base=row.reg_name(operand.mem.base)
            require(not ((base in ('x0','w0') and not meta_captured) or
                         (base in ('x1','w1') and not body_captured)),
                    'native SDK observer dereferences an input before its role capture')
            if base in ('x19','w19'):
                require(body_captured and meta_captured and pair in body,
                        'native SDK observer has an unrecognized body-pointer memory use')
                body_mask|=body[pair];observed.add(pair)
            if base in ('x20','w20'):
                require(body_captured and meta_captured and not(meta_mask&16) and pair in metadata,
                        'native SDK observer has an unrecognized metadata-pointer memory use')
                bit,prerequisites=metadata[pair]
                require(meta_mask&prerequisites==prerequisites,
                        'native SDK observer metadata fields are consumed out of order')
                meta_mask|=bit;observed.add(pair)
        if capture_body:body_captured=True;capture_sites.add(row.address)
        if capture_meta:meta_captured=True;capture_sites.add(row.address)
        if body_mask&4:
            completed.append((meta_mask,body_mask));continue
        require(flow not in (RETURN,TRAP,INDIRECT_JUMP),
                'native SDK observer exits before the proved final body consumption')
        targets=[index+1]
        if flow in (JUMP,CONDITIONAL):
            target=direct_target(word,row.address)
            require(target in indices and indices[target]>index,
                    'native SDK observer role proof requires bounded forward control edges')
            targets=[indices[target]]+([index+1] if flow==CONDITIONAL else [])
        # Calls after capture preserve X19/X20 under the original SDK's AAPCS
        # callee-saved contract; no return or emitted result is inferred here.
        require(flow in (NORMAL,CALL,INDIRECT_CALL,JUMP,CONDITIONAL),
                'native SDK observer has unrecognized control before field consumption')
        pending += [(target,body_captured,meta_captured,meta_mask,body_mask) for target in targets]
    require(len(capture_sites)==2 and set(metadata)<=observed and set(body)<=observed and
            any(meta==31 and data==7 for meta,data in completed),
            'native SDK observer lacks one coherent complete record-consumption path')
    return dict(input_captures=sorted(capture_sites),cfg_states=len(seen),completed_paths=len(completed),
                metadata_consumption=[row.address for row,pair in zip(rows,pairs) if pair in metadata],
                body_consumption=[row.address for row,pair in zip(rows,pairs) if pair in body],
                module_pointer_self_loads=[row.address for row,pair in zip(rows,pairs) if pair==('ldr','x20, [x20, #0x18]')])


def _logging_contract(linker, module, records, decoder):
    bridges={module.base+offset:record for offset,record in plt_stubs(module).items()}
    put=_stage(linker.modules,'put_record','sdk',PUT_SYMBOL,decoder)
    put_rows=_rows(module,put['entry'],put['size'],decoder)
    recipe=_sequence(put_rows,[('mov','w8, #0x101'),('str','x1, [sp, #8]'),
        ('add','x1, sp, #8'),('stp','x2, x8, [sp, #0x10]'),None])
    target=_direct(recipe[-1],True)
    require(target in bridges and bridges[target]['symbol']==FUNCTIONS[2][2] and
            int(bridges[target]['resolved_address'],16)==records['diag_emit']['entry'],
            'native SDK LogBody recipe does not call its bound emission entry')
    before=put_rows[:put_rows.index(recipe[0])]
    for row in before:
        _,modified=row.regs_access()
        require(not ({row.reg_name(reg) for reg in modified} & {'x0','w0','x1','w1','x2','w2'}),
                'native SDK LogBody input roles are changed before capture')
    initialize=_rows(module,records['lm_initialize']['entry'],records['lm_initialize']['size'],decoder)
    candidates=[]
    for index in range(len(initialize)-1):
        row,branch=initialize[index:index+2]
        if row.mnemonic!='adr' or not row.op_str.startswith('x0, #') or branch.mnemonic!='b':continue
        target=_direct(branch,False)
        if target in bridges and bridges[target]['symbol']==REPLACE_SYMBOL:
            require(int(bridges[target]['resolved_address'],16)==records['guard_replace']['entry'],
                    'native SDK observer replacement PLT snapshot differs from its guard')
            candidates.append((row.operands[1].imm,initialize[index:index+2]))
    require(candidates and len({address for address,_ in candidates})==1,
            'native SDK original default-observer installation is unrecognized')
    observer,installation=candidates[0]
    # This is a bounded original-code profile, not a claim of anonymous function
    # identity or a request to translate/run the observer being replaced.
    observer_rows=_rows(module,observer,0x250,decoder)
    role_proof=_observer_roles(observer_rows)
    return dict(body=dict(bytes=24,message_pointer=0,message_size=8,head=16,tail=17,
                         boolean_domain=[0,1],source_recipe=_evidence(recipe)),
        metadata=dict(consumed_prefix_bytes=40,line=0,filename_pointer=8,function_pointer=16,
                      module_pointer=24,severity=32,verbosity=36,severity_domain=[0,1,2,3,4],
                      complete_structure_layout_proven=False,additional_fields_consumed=False),
        original_observer_prefix=_evidence(observer_rows),installation=_evidence(installation),
        observer_register_roles=role_proof,
        all_installations=[_evidence(rows) for _,rows in candidates],
        plt_scope='linked snapshot only; original stubs and runtime actual-target checks remain',
        replacement_scope='native logging owns initialization, destination, enable flag and bounded copies; guest callbacks are guarded')


def audit_native_sdk(linker):
    """Select exact original exports for four native operations and explicit guards."""
    require(linker.report().get('link_complete') is True,'native SDK audit requires a complete offline link')
    owners=[module for module in linker.modules if module.name=='sdk']
    require(len(owners)==1,'native SDK audit requires exactly one SDK module')
    module=owners[0];begin,end=module.ranges[0]
    digest=_sha(module.read(begin,end-begin))
    require(module.header['segments'][0].get('hash_verified') is True and
            digest==module.header['segments'][0].get('sha256'),
            'native SDK audit requires unchanged original text')
    decoder=Decoder();decoder.engine.detail=True
    records={name:_stage(linker.modules,name,'sdk',symbol,decoder) for _,name,symbol,_ in FUNCTIONS}
    contract=_logging_contract(linker,module,records,decoder)
    functions=[]
    for handler,name,_,signature in FUNCTIONS:
        record=dict(records[name],handler_id=handler,signature=signature,returns_value=False,
                    implementation='guard' if handler==31 else 'native-host-logging',
                    original_body_executed=False,native_execution_proven=False)
        record['entry_word']=record['entry_instruction']['word']
        record['names']=[record['symbol']]
        existing=next((row for row in functions if row['entry']==record['entry']),None)
        if existing:
            require((existing['handler_id'],existing['size'],existing['body_sha256'])==
                    (record['handler_id'],record['size'],record['body_sha256']),
                    'native SDK export aliases disagree on contract or complete body')
            existing['names']+=record['names']
        else:functions.append(record)
    functions.sort(key=lambda row:row['entry'])
    require(len(functions)<=64 and all(a['entry']+a['size']<=b['entry'] for a,b in zip(functions,functions[1:])),
            'native SDK selected function extents overlap or exceed the registry limit')
    oe_definitions=[symbol for owner in linker.modules for symbol in owner.symbols
                    if symbol.name==OE_INITIALIZE_SYMBOL and symbol.section]
    oe_initialize=None
    if oe_definitions:
        oe_initialize=dict(_stage(linker.modules,'original_oe_initialize','sdk',OE_INITIALIZE_SYMBOL,decoder),
                           observation_only=True,native_execution=False,
                           original_entry_retirement_required=True)
    return dict(schema_version=1,format=FORMAT,guest_code_executed=False,translation_performed=False,
        native_callbacks_registered=False,runtime_capabilities_granted=False,startup_completed=False,
        sdk_initialization_completed=False,game_entry_reached=False,
        module=dict(name=module.name,base=module.base,source_sha256=module.source_sha256,original_text_sha256=digest),
        functions=functions,logging_contract=contract,original_oe_initialize=oe_initialize,references=REFERENCES,
        scope='explicit native function replacement metadata; no IPC success or whole-SDK initialization proof',
        remaining_platform_scope='OE, applet, account, filesystem, graphics and unknown SDK contracts remain original or deterministic boundaries')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prepared',type=Path);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    try:
        destination=build_destination(args.report)
        require(not destination.exists(),'choose a fresh native SDK report path')
        linker=Linker(load_prepared(args.prepared));linker.apply()
        report=audit_native_sdk(linker)
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open('x',encoding='utf-8') as stream:stream.write(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(report=str(destination),format=FORMAT,functions=len(report['functions']),
            native_operations=sum(row['handler_id']!=31 for row in report['functions']),guest_code_executed=False)))
        return 0
    except (InputError,OSError,ValueError) as error:
        print(f'Native SDK audit failed: {error}',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
