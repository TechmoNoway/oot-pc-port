"""Exact original-export extensions for the separate application-only providers."""
import argparse,hashlib,json,struct
from pathlib import Path
from input_formats import InputError,require
from link_exefs import build_destination,load_prepared
from module_linker import Linker
from sdk_init_audit import audit_sdk_init,GUARD_ID

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
    return report

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
