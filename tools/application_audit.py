"""Exact original-export extensions for the separate application-only providers."""
import argparse,hashlib,json,struct
from pathlib import Path
from input_formats import InputError,require
from link_exefs import build_destination,load_prepared
from module_linker import Linker
from sdk_init_audit import audit_sdk_init,GUARD_ID,_merge_bindings
from sdk_startup_audit import _stage,_symbol_record
from arm64_decode import Decoder,direct_target
from arm64_analysis import plt_stubs

CONTRACTS=((320,'graphics_notifications','_ZN2nn2oe42SetGraphicsScaleChangedNotificationEnabledEb',
    'void SetGraphicsScaleChangedNotificationEnabled(bool)',False),
    (321,'desired_language','_ZN2nn2oe18GetDesiredLanguageEv','LanguageCode GetDesiredLanguage()',True))


CONTRACTS += (
    (384, 'romfs_query_cache', '_ZN2nn2fs22QueryMountRomCacheSizeEPm', 'Result QueryMountRomCacheSize(size_t*)', True),
    (385, 'romfs_mount_cache', '_ZN2nn2fs8MountRomEPKcPvm', 'Result MountRom(const char*, void*, size_t)', True),
    (386, 'romfs_mount', '_ZN2nn2fs8MountRomEPKc', 'Result MountRom(const char*)', True),
    (387, 'romfs_unmount', '_ZN2nn2fs7UnmountEPKc', 'void Unmount(const char*)', False),
    (388, 'romfs_open', '_ZN2nn2fs8OpenFileEPNS0_10FileHandleEPKci', 'Result OpenFile(FileHandle*, const char*, int)', True),
    (389, 'romfs_close', '_ZN2nn2fs9CloseFileENS0_10FileHandleE', 'void CloseFile(FileHandle)', False),
    (390, 'romfs_size', '_ZN2nn2fs11GetFileSizeEPlNS0_10FileHandleE', 'Result GetFileSize(int64_t*, FileHandle)', True),
    (391, 'romfs_read_count', '_ZN2nn2fs8ReadFileEPmNS0_10FileHandleElPvm', 'Result ReadFile(size_t*, FileHandle, int64_t, void*, size_t)', True),
    (392, 'romfs_read_exact', '_ZN2nn2fs8ReadFileENS0_10FileHandleElPvm', 'Result ReadFile(FileHandle, int64_t, void*, size_t)', True),
    (393, 'romfs_entry_type', '_ZN2nn2fs12GetEntryTypeEPNS0_18DirectoryEntryTypeEPKc', 'Result GetEntryType(DirectoryEntryType*, const char*)', True),
    (394, 'romfs_read_count_option', '_ZN2nn2fs8ReadFileEPmNS0_10FileHandleElPvmRKNS0_10ReadOptionE', 'Result ReadFile(size_t*, FileHandle, int64_t, void*, size_t, const ReadOption&)', True),
    (395, 'romfs_read_exact_option', '_ZN2nn2fs8ReadFileENS0_10FileHandleElPvmRKNS0_10ReadOptionE', 'Result ReadFile(FileHandle, int64_t, void*, size_t, const ReadOption&)', True),
)

def extend_application_audit(original):
    # JSON copy keeps the earlier audit immutable and records its full identity.
    report=json.loads(json.dumps(original));supported=[]
    for handler,name,symbol,signature,returns in CONTRACTS:
        rows=[row for row in report['functions'] if symbol in row['names']]
        require(len(rows)==1,'application provider export is missing or ambiguous')
        row=rows[0]
        require(row['handler_id']==GUARD_ID and row['names']==[symbol] and row['module']=='sdk',
            'application provider aliases or original guard contract changed')
        row.update(handler_id=handler,id=name,signature=signature,implementation='application_romfs' if handler>=384 else 'application_policy',
            returns_value=returns,return_register='X0' if returns else None)
        supported.append(dict(symbol=symbol,handler_id=handler,entry=row['entry'],size=row['size'],body_sha256=row['body_sha256']))
    report.update(format='oot-application-sdk-audit',application_runtime=True,
        initialization_audit_sha256=hashlib.sha256(json.dumps(original,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        application_providers=supported,
        application_policy='owned notification/language configuration and sealed read-only RomFS file views; no applet/session objects; other consumers remain guarded')
    return report


def extend_application_resource_audit(linker,original):
    """Static original accessor ABI and complete SDK am export guard closure."""
    require(linker.report().get('link_complete') is True,'resource audit requires a complete offline link')
    app='_ZN2nn6applet23GetAppletResourceUserIdEv'
    am='_ZN2nn2am23GetAppletResourceUserIdEv'
    prefix=('_ZN2nn2am','_ZNK2nn2am')
    sdk=next(m for m in linker.modules if m.name=='sdk');syntax=Decoder()
    # Validate the bounded original census and every parsed record before any
    # namespace filter, so a renamed/removed parsed consumer cannot disappear.
    for module in linker.modules:
        counts=[]
        if 39 in module.dynamic:
            require(module.dynamic[39]%24==0,'resource symbol-table size is invalid')
            counts.append(module.dynamic[39]//24)
        if 4 in module.dynamic:counts.append(module.unpack('<II',module.dynamic[4])[1])
        if not counts and 0x6ffffef5 in module.dynamic:counts.append(module.gnu_symbol_count())
        require(counts and all(n==len(module.symbols) for n in counts),'resource original symbol census changed')
        for index,symbol in enumerate(module.symbols):
            _symbol_record(module,index,symbol)
            require(not (module.name!='sdk' and symbol.section and symbol.name.startswith(prefix)),
                    'resource consumer is defined outside the SDK')
    begin,end=sdk.ranges[0]
    require(sdk.header['segments'][0].get('hash_verified') is True and
            hashlib.sha256(sdk.read(begin,end-begin)).hexdigest()==sdk.header['segments'][0]['sha256'],
            'resource audit requires unchanged original text')
    public=_stage(linker.modules,'applet_resource_user_id','sdk',app,syntax)
    getter=_stage(linker.modules,'am_resource_user_id','sdk',am,syntax)
    require(public['size']==4 and public['entry_instruction']['word']&0xfc000000==0x14000000,
            'resource public accessor is not the original B thunk')
    target=direct_target(public['entry_instruction']['word'],public['entry'])
    bridges={sdk.base+off:record for off,record in plt_stubs(sdk).items()}
    bridge=bridges.get(target)
    require(bridge is not None and bridge['symbol']==am and int(bridge['resolved_address'],16)==getter['entry'],
            'resource accessor PLT/GOT does not resolve to its original am getter')
    require(getter['size']==12,'resource getter extent differs')
    adrp,load,ret=sdk.unpack('<3I',getter['offset'])
    require(adrp&0x9f00001f==0x90000008 and load&0xffc003ff==0xf9400100 and ret==0xd65f03c0,
            'resource getter is not the original full-width cached load and return')
    pages=((adrp>>29)&3)|(((adrp>>5)&0x7ffff)<<2)
    if pages&(1<<20):pages-=1<<21
    cache=(getter['entry']&~4095)+pages*4096+((load>>10)&0xfff)*8
    require(cache%8==0 and sdk.writable_start<=cache-sdk.base and cache-sdk.base+8<=sdk.bss_end,
            'resource getter cache is outside original data/BSS')
    report=json.loads(json.dumps(original))
    old=[r for r in report['functions'] if app in r['names']]
    require(len(old)==1 and old[0]['names']==[app] and old[0]['handler_id']==GUARD_ID and
            old[0].get('entry_word')==public['entry_instruction']['word'] and
            old[0].get('returns_value') is False and old[0].get('return_register') is None and
            all(old[0][k]==public[k] for k in ('symbol','module','entry','size','body_sha256','symbol_metadata','entry_instruction')),
            'resource public accessor guard or source binding changed')
    records=[]
    for symbol in sdk.symbols:
        if not symbol.section or symbol.kind!=2 or not symbol.name.startswith(prefix):continue
        row=_stage(linker.modules,'am_resource_user_id' if symbol.name==am else 'guard_'+symbol.name,'sdk',symbol.name,syntax)
        supported=symbol.name==am
        row.update(handler_id=322 if supported else GUARD_ID,signature='uint64_t GetAppletResourceUserId()' if supported else 'unsupported owned-application am consumer',
            returns_value=supported,return_register='X0' if supported else None,implementation='application_resource' if supported else 'guard',
            original_body_executed=False,native_execution_proven=False,entry_word=row['entry_instruction']['word'],names=[symbol.name])
        records.append(row)
    old[0].update(handler_id=322,id='applet_resource_user_id',signature='uint64_t GetAppletResourceUserId()',
                  returns_value=True,return_register='X0',implementation='application_resource')
    report['functions']=_merge_bindings([*report['functions'],*records])
    for row in (old[0],next(r for r in records if r['symbol']==am)):
        report['application_providers'].append({k:row[k] for k in ('symbol','handler_id','entry','size','body_sha256')})
    report['application_resource_identity']=dict(return_bytes=8,return_register='X0',
        public=public,getter=getter,plt_entry=target,plt=bridge,original_cache=cache,
        exported_am_consumers=len(records),exported_am_consumer_closure=True,
        ownership='initialized native platform logical process identity; no console session/object or guest cache initialization')
    return report

def audit_thread_wrappers(linker):
    sdk=next(m for m in linker.modules if m.name=='sdk');begin,end=sdk.ranges[0]
    records=[]
    for number,name,args in ((13,'set_priority',['W0: owned main-thread handle','W1: declared permitted priority']),
                             (15,'set_affinity',['W0: owned main-thread handle','W1: concrete logical core or DontCare (-1)','X2: permitted affinity'])):
        code=struct.pack('<II',0xd4000001|(number<<5),0xd65f03c0)
        matches=[];at=begin
        while (at:=sdk.image.find(code,at,end))>=0:
            if sdk.is_code(at) and sdk.is_code(at+4):matches.append(at)
            at+=1
        require(len(matches)==1,'application thread setter has no unique original SVC/RET wrapper')
        records.append(dict(service=number,operation=name,entry=sdk.base+matches[0],size=8,
            sha256=hashlib.sha256(code).hexdigest(),arguments=args,result='W0 Result',original_body_replaced=False))
    return records

def audit_application(linker):
    report=extend_application_audit(audit_sdk_init(linker))
    # Original wrapper supplies an eight-byte output slot to its service, checks
    # Result, then returns that slot in X0. Do not infer this return ABI solely
    # from its Itanium name or a different console generation's declarations.
    row=next(r for r in report['functions'] if r['handler_id']==321)
    sdk=next(m for m in linker.modules if m.name=='sdk');offset=row['entry']-sdk.base
    checks={16:0xf90007ff,24:0xf9400008,28:0x910023e1,32:0xf9403108,
        36:0xd63f0100,40:0xb90007e0,44:0x350000a0,48:0xf94007e0,60:0xd65f0fff}
    require(row['size']==72 and all(sdk.unpack('<I',offset+at)[0]==word for at,word in checks.items()),
        'desired-language original eight-byte service/result wrapper changed')
    report['desired_language_return']=dict(body_sha256=row['body_sha256'],bytes=8,register='X0',
        original_output_slot_and_result_check=True,policy='explicit owned en-US application preference; not a host or Switch setting')
    report['original_thread_services']=audit_thread_wrappers(linker)
    report['thread_scope']='one owned logical main thread, NPDM-permitted values and observed DontCare affinity; no host scheduling or new thread handles'
    report['thread_service_reference']='https://github.com/switchbrew/libnx/blob/master/nx/include/switch/kernel/svc.h'
    return extend_application_resource_audit(linker,report)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('prepared',type=Path);p.add_argument('--report',type=Path,required=True)
    a=p.parse_args()
    try:
        target=build_destination(a.report);require(not target.exists(),'choose a fresh application audit path')
        linker=Linker(load_prepared(a.prepared));require(linker.apply()['link_complete'],'application audit requires a complete offline link')
        report=audit_application(linker);target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('x',encoding='utf-8') as stream:stream.write(json.dumps(report,indent=2)+'\n')
        return 0
    except (InputError,OSError,ValueError) as error:p.exit(1,f'Application audit failed: {error}\n')
if __name__=='__main__':raise SystemExit(main())
