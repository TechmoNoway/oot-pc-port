"""Build a private native startup diagnostic executable; execution is explicit."""
import argparse
import hashlib
import gzip
import json
import os
from pathlib import Path
import shutil
import secrets
import subprocess
import sys
import time

from input_formats import InputError, require, inspect_npdm
from lifter_validation import find_cmake
from link_exefs import build_destination, load_prepared
from module_linker import Linker
from prepare_startup import prepare_bundle, owner

ROOT=Path(__file__).resolve().parent.parent


def validated_romfs_input(prepared,index):
    """Bind the private asset seal back to this exact prepared ExeFS catalog."""
    from input_formats import NupCatalog
    from prepare_romfs import HEADER,MAGIC
    index=build_destination(Path(index))
    require(index.stat().st_size<=256*1024*1024,'RomFS index exceeds limit')
    data=index.read_bytes();report=json.loads((index.parent/'manifest.json').read_text(encoding='utf-8'))
    require(len(data)>=HEADER.size and report.get('format')=='oot-prepared-romfs' and
        report.get('payload_hashes_verified') is True and report.get('exefs_catalog_matches_prepared') is True and
        report.get('index_sha256')==hashlib.sha256(data).hexdigest(),'RomFS prepared seal differs')
    header=HEADER.unpack_from(data)
    require(header[0]==MAGIC and header[1:3]==(1,HEADER.size) and header[3]==len(data) and
        header[13]==hashlib.sha256(data[HEADER.size:]).digest() and header[15]==1,'RomFS index header differs')
    manifest=json.loads((prepared/'manifest.json').read_text(encoding='utf-8'))
    source=Path(manifest['source']['path']).resolve()
    require(source==Path(report['source']).resolve(),'RomFS and ExeFS source paths differ')
    catalog=NupCatalog(source);package=manifest['source']['package']
    require(catalog.packages[package['index']]==package and
        hashlib.sha256(catalog.toc).hexdigest()==report['catalog_sha256'],'RomFS original package/catalog differs')
    records={'/'.join(parts):row[3].hex() for parts,row in catalog.files_in(package['exefs_directory'])}
    require(records=={r['name']:r['source_sha256'] for r in manifest['files']},'RomFS original ExeFS hashes differ')
    with source.open('rb') as stream:source_hash=hashlib.sha256(stream.read(128)).digest()
    require(header[12]==source_hash and report['source_header_sha256']==source_hash.hex() and
        header[5]==source.stat().st_size,'RomFS original NUP identity differs')
    program=int(inspect_npdm(prepared_npdm(prepared))['program_id'],16)
    require(header[4]==program==int(report['program_id'],16),'RomFS program identity differs')
    return report


def prepared_npdm(prepared):
    """Read the small metadata object once and bind it to the prepared record."""
    manifest=json.loads((prepared/'manifest.json').read_text(encoding='utf-8'))
    record=next((r for r in manifest['files'] if r['name']=='main.npdm'),None)
    if record is None:return None
    require(type(record['bytes']) is int and 0<=record['bytes']<=32768,'prepared NPDM exceeds size limit')
    path=prepared/'main.npdm'
    require(path.resolve().is_relative_to(prepared.resolve()),'prepared NPDM escapes input directory')
    with path.open('rb') as stream:raw=stream.read(32769)
    require(len(raw)==record['bytes'] and hashlib.sha256(raw).hexdigest()==record['sha256'],'prepared NPDM differs from verified metadata')
    return raw


def build_native(bundle, mode, native_cache=None, sdk_init=False,romfs_sha=None):
    from startup_sources import cached_sources
    started=time.perf_counter()
    native_cache=native_cache or bundle/'native'
    binding=None
    if romfs_sha is not None:
        require(len(romfs_sha)==64 and all(c in '0123456789abcdef' for c in romfs_sha),'invalid RomFS input seal')
        native_cache.mkdir(parents=True,exist_ok=True)
        binding=(native_cache/'romfs_binding.h').resolve()
        content='#define OOT_ROMFS_INPUT_SHA256 "'+romfs_sha+'"\n'
        if not binding.exists() or binding.read_text()!=content:binding.write_text(content,encoding='utf-8')
    before_units={p.name:p.stat().st_mtime_ns for p in (native_cache/'sources').glob('*.c')}
    sources,split=cached_sources(bundle,native_cache)
    source=next(p for p in sources if p.name=='startup.c')
    log=bundle/'compile.log'
    def run(argv):
        with log.open('a',encoding='utf-8') as stream:
            r=subprocess.run(list(map(str,argv)),cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,timeout=900 if sdk_init else 300)
        require(r.returncode==0,f'startup compilation failed; see {log}')
    if mode=='gcc':
        compiler=shutil.which('gcc') or 'C:/msys64/ucrt64/bin/gcc.exe'
        require(Path(compiler).is_file(),'GCC is unavailable')
        exe=bundle/'oot-startup.exe'
        names=('main','startup_cli','startup_context','startup_dispatch','guest_memory',
               'runtime_image','host_win32','pauth','checked_read','sdk_native','native_platform','native_services','native_math','startup_vector','startup_float','startup_init_atomic','application_services','native_romfs','native_graphics')
        if split:
            from concurrent.futures import ThreadPoolExecutor
            import threading
            objects=native_cache/'objects';objects.mkdir(parents=True,exist_ok=True)
            flags=['-std=c17','-O2','-Wall','-Wextra','-Wpedantic','-Werror','-DOOT_HAS_STARTUP_PROGRAM','-D_CRT_SECURE_NO_WARNINGS','-D_WIN32_WINNT=0x0A00','-I',str(ROOT/'src'),'-I',str(ROOT/'third_party/vulkan/include')]
            headers=b''.join(str(p.relative_to(ROOT)).encode()+p.read_bytes() for p in sorted([*(ROOT/'src').glob('*.h'),*(ROOT/'third_party/vulkan/include').rglob('*.h')]))
            lift_headers=b''.join((ROOT/'src'/n).read_bytes() for n in ('arm64_lift.h','guest_memory.h','pauth.h'))
            tool=subprocess.check_output([compiler,'--version'])+hashlib.sha256(Path(compiler).read_bytes()).digest()
            paths=[ROOT/'src'/(n+'.c') for n in names]+sources
            def compile_one(path):
                file_flags=flags+(['-DOOT_ROMFS_BINDING_HEADER="'+binding.as_posix()+'"'] if binding and path.name=='startup_cli.c' else [])
                extra=binding.read_bytes() if binding and path.name=='startup_cli.c' else b''
                key=hashlib.sha256(tool+repr(file_flags).encode()+extra+(lift_headers if path.name.startswith('lift_') else headers)+path.read_bytes()).hexdigest()
                obj=objects/(path.stem+'-'+key+'.o')
                reused=obj.exists()
                if not reused:
                    partial=obj.with_suffix('.'+secrets.token_hex(6)+'.partial')
                    try:
                        run([compiler,*file_flags,'-c',path,'-o',partial]);partial.replace(obj)
                    finally:partial.unlink(missing_ok=True)
                return obj,reused
            with ThreadPoolExecutor(max_workers=4) as pool:compiled=list(pool.map(compile_one,paths))
            objs=[p for p,_ in compiled];reused_objects=sum(hit for _,hit in compiled);compiled_objects=len(compiled)-reused_objects
            response=bundle/'link.rsp'
            response.write_text('\n'.join('"'+p.resolve().as_posix()+'"' for p in objs)+'\n',encoding='utf-8')
            run([compiler,'@'+str(response),'-lbcrypt','-o',exe])
        else:
            run([compiler,'-std=c17','-O2','-Wall','-Wextra','-Wpedantic','-Werror',
                 '-DOOT_HAS_STARTUP_PROGRAM','-D_CRT_SECURE_NO_WARNINGS','-D_WIN32_WINNT=0x0A00',
                 *(['-DOOT_ROMFS_BINDING_HEADER="'+binding.as_posix()+'"'] if binding else []),'-I',ROOT/'src','-I',ROOT/'third_party/vulkan/include',*[ROOT/'src'/(n+'.c') for n in names],*sources,'-lbcrypt','-o',exe])
        identity=subprocess.check_output([compiler,'--version'],text=True).splitlines()[0]
    else:
        cmake=find_cmake();native=native_cache or bundle/'native'
        native.mkdir(parents=True,exist_ok=True)
        names='\n'.join(p.resolve().as_posix() for p in sources if p!=source);delimiter='='
        while ']'+delimiter+']' in names:delimiter+='='
        parts='set(OOT_STARTUP_PARTS\n'+''.join('['+delimiter+'['+p.resolve().as_posix()+']'+delimiter+']\n' for p in sources if p!=source)+')\n'
        parts_file=(native/'startup-parts.cmake').resolve()
        if not parts_file.exists() or parts_file.read_text(encoding='utf-8')!=parts:parts_file.write_text(parts,encoding='utf-8')
        before_objects={str(p):p.stat().st_mtime_ns for p in native.rglob('*.obj')}
        run([cmake,'-S',ROOT,'-B',native,'-G','Visual Studio 17 2022','-A','x64',
             '-DOOT_ROMFS_BINDING_HEADER='+(binding.as_posix() if binding else ''),'-DOOT_STARTUP_SOURCE='+str(source),'-DOOT_STARTUP_PARTS=','-DOOT_STARTUP_PARTS_FILE='+str(parts_file),'-DPython3_EXECUTABLE='+sys.executable])
        run([cmake,'--build',native,'--config','Release','--target','oot-pc-port'])
        exe=native/'Release/oot-pc-port.exe'
        identities=list((native/'CMakeFiles').glob('*/CMakeCCompiler.cmake'))
        require(len(identities)==1,'missing startup compiler identity')
        import re
        identity=' '.join(re.findall(r'set\(CMAKE_C_COMPILER(?:_ID|_VERSION)? "([^"]+)"\)',identities[0].read_text()))
        require('MSVC' in identity,'startup CMake build must exercise MSVC')
        saved=bundle/'oot-startup.exe'
        shutil.copyfile(exe,saved);exe=saved
        after_objects=list(native.rglob('*.obj'))
        compiled_objects=sum(before_objects.get(str(p))!=p.stat().st_mtime_ns for p in after_objects)
        reused_objects=len(after_objects)-compiled_objects
    require(exe.is_file(),'startup executable was not produced')
    stats=dict(format='oot-startup-build',compiler=identity,seconds=time.perf_counter()-started,
        generated_units=len(sources),changed_units=sum(before_units.get(p.name)!=p.stat().st_mtime_ns for p in sources),
        split_sources=split,source_manifest_sha256=hashlib.sha256((bundle/'sources.json').read_bytes()).hexdigest() if split else None,
        compiled_objects=compiled_objects if split or mode!='gcc' else None,
        reused_objects=reused_objects if split or mode!='gcc' else None)
    if romfs_sha:stats.update(romfs_index_sha256=romfs_sha,romfs_binding_sha256=hashlib.sha256(binding.read_bytes()).hexdigest())
    (bundle/'build.json').write_text(json.dumps(stats,indent=2)+'\n',encoding='utf-8')
    return exe,identity


def execute(exe,bundle,limit,quantum,trace_mode='compact',entropy_file=None,fast_functions=False,romfs_index=None):
    trace=bundle/'trace.jsonl'
    args=[str(exe),'--boot-images',str(bundle/'startup.ootmem'),'--trace',str(trace),
          '--limit',str(limit),'--quantum',str(quantum),'--trace-mode',trace_mode]
    if romfs_index is not None:args+=['--romfs-index',str(romfs_index)]
    if fast_functions:args+=['--fast-functions','1']
    if entropy_file is not None:args+=['--entropy-file',str(entropy_file)]
    r=subprocess.run(args,capture_output=True,text=True,timeout=600)
    (bundle/'execution.log').write_text(r.stdout+r.stderr,encoding='utf-8')
    require(r.returncode in (0,1,3) and r.stdout.strip(),'startup execution failed before a diagnostic; see execution.log')
    report=json.loads(r.stdout)
    require(report.get('format')=='oot-startup-run' and report.get('startup_completed') is False,'invalid startup execution report')
    if report.get('application_runtime') is True:
        require(r.returncode!=0 and report.get('error')!=15,'application diagnostic cannot be an initialization-only completion')
    else:require((r.returncode==0)==(report.get('sdk_initialization_completed') is True and report.get('error')==15), 'invalid SDK completion report')
    last=None;step_count=0;digest=hashlib.sha256()
    with trace.open('rb') as stream:
        for line in stream:
            require(last is None,'startup trace contains records after its stop')
            digest.update(line.replace(b'\r\n',b'\n'))
            # The native writer has one fixed numeric-only JSON format. Avoid
            # constructing millions of Python dictionaries for its step rows.
            if b'"event":0,' in line or b'"event":1,' in line or b'"event":3,' in line:step_count+=1
            else:last=json.loads(line)
    require(last is not None and last['event']==2 and last['retired']==report['retired'] and
            report['retired']+report.get('native_calls',0)==report['trace_steps'] and report['trace_rows']==report['trace_steps']+1,
            'startup trace does not reproduce the retired prefix')
    if trace_mode=='full':require(step_count==report['trace_steps'] and digest.hexdigest()==report['trace_sha256'],'full trace digest differs from the native all-row digest')
    else:require(step_count<=report['trace_steps'] and report['trace_mode']=='compact','invalid compact trace')
    report.update(last_transition=last,trace_file=str(trace),stored_trace_sha256=digest.hexdigest(),exit_code=r.returncode)
    return report


def run(prepared,output,compiler='cmake',execute_code=False,expand_targets=0,limit=1000000,quantum=1000,initial_entries=(),trace_mode='compact',sdk=False,entropy_file=None,native_sdk=False,sdk_init=False,host_linked=False,fast_functions=False,native_cache=None,application=False,application_entries=(),romfs_index=None,graphics=False,display=False):
    require(os.name=='nt','native startup builds require Windows')
    output=build_destination(output)
    require(not output.exists(),'choose a fresh startup output directory')
    require(type(expand_targets) is int and 0<=expand_targets<=64,'invalid target expansion limit')
    require(1<=limit<=(1000000000 if sdk else 100000000) and 1<=quantum<=(1000000000 if sdk else 100000000),'invalid startup budget')
    require(trace_mode in ('full','compact'),'invalid startup trace mode')
    require(execute_code or not expand_targets,'target expansion requires explicit execution')
    require(sdk or entropy_file is None,'private SDK entropy requires SDK opt-in')
    require(type(native_sdk) is bool and (not native_sdk or sdk),'native SDK requires SDK opt-in')
    require(type(sdk_init) is bool and (not sdk_init or native_sdk),'SDK initialization requires native SDK opt-in')
    require(not host_linked or sdk_init,'host boot requires SDK init')
    require(not fast_functions or sdk_init,'fast functions require SDK init')
    require(type(application) is bool and (not application or host_linked),'application requires host-linked opt-in')
    require(type(graphics) is bool and (not graphics or application),'graphics requires application opt-in')
    require(type(display) is bool and (not display or graphics),'display requires graphics opt-in')
    require(application or not application_entries,'application roots require application mode')
    romfs_input=None
    if romfs_index is not None:
        require(application,'RomFS requires application mode')
        romfs_index=build_destination(Path(romfs_index))
        romfs_input=validated_romfs_input(prepared,romfs_index)
    if entropy_file is not None:
        entropy_file=build_destination(entropy_file)
        require(len(entropy_file.read_bytes())==32,'SDK entropy input must contain exactly 32 bytes')
    output.mkdir(parents=True)
    if sdk and execute_code and entropy_file is None:
        entropy_file=output/'process-entropy.bin'
        with entropy_file.open('xb') as stream:stream.write(secrets.token_bytes(32))
    native_cache=build_destination(Path(native_cache)) if native_cache is not None else output/'native-cache'
    extras=list(initial_entries);app_extras=list(application_entries);iterations=[]
    from startup_audit import StartupDecodeCache
    decode_cache=StartupDecodeCache() if sdk_init else None
    for index in range(expand_targets+1):
        raw=Linker(load_prepared(prepared))
        bundle=output/f'iteration-{index:02d}'
        npdm=prepared_npdm(prepared)
        metadata=inspect_npdm(npdm) if npdm is not None else None
        sdk_metadata=None
        if sdk:
            from sdk_startup_audit import inspect_sdk_npdm
            require(npdm is not None,'SDK runtime requires verified NPDM metadata')
            sdk_metadata=inspect_sdk_npdm(npdm)
        manifest=prepare_bundle(raw,bundle,extra_entries=extras,
            max_instructions=524288 if sdk_init else 32768 if sdk else 8192,sdk_metadata=sdk_metadata,native_sdk=native_sdk,sdk_init=sdk_init,host_linked=host_linked,
            shared_package=output/'iteration-00/startup.ootmem' if index else None,decode_cache=decode_cache,application=application,application_entries=app_extras,graphics=graphics,display=display,
            **({'stack_size':metadata['main_thread_stack_size']} if metadata else {}))
        if romfs_input:manifest['romfs_input']=dict(romfs_input,index_path=str(romfs_index))
        manifest['npdm']=metadata
        manifest['selection']['stack_size_source']='verified-npdm' if metadata else 'explicit-synthetic-default'
        (bundle/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
        exe,identity=build_native(bundle,compiler,native_cache,sdk_init=sdk_init,romfs_sha=romfs_input['index_sha256'] if romfs_input else None)
        row=dict(iteration=index,compiler=identity,executable=str(exe),bundle=str(bundle),
                 build=json.loads((bundle/'build.json').read_text(encoding='utf-8')),
                 executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
                 additional_entries=list(extras),selection=manifest['selection'])
        if application:row['application_entries']=list(app_extras)
        if execute_code:
            report=execute(exe,bundle,limit,quantum,trace_mode,entropy_file,fast_functions,romfs_index=romfs_index)
            row['execution']=report
        iterations.append(row)
        (output/'run.json').write_text(json.dumps(dict(schema_version=1,format='oot-startup-experiment',
            status='running',process_abi='experimental',iterations=iterations),indent=2)+'\n',encoding='utf-8')
        if not execute_code or index==expand_targets:break
        if report['error']==10:
            target=int(report['last_transition']['next_pc'],16)
        elif report['error']==8 and any(b['address']==int(report['pc'],16) and b['reason'] in ('unselected continuation','unselected SDK goal marker') for b in manifest['selection_boundaries']):
            target=int(report['pc'],16)
        else:break
        if target in (app_extras if application else extras):break
        try:owner(raw.modules,target)
        except InputError:break
        # Keep intermediate evidence losslessly while bounding private disk use.
        # The final diagnostic trace remains directly readable JSON Lines.
        trace=Path(report['trace_file'])
        if trace.stat().st_size>64*1024*1024:
            require(trace.resolve().is_relative_to(output),'startup trace escaped its output directory')
            zipped=trace.with_suffix(trace.suffix+'.gz')
            with trace.open('rb') as source,gzip.open(zipped,'wb',compresslevel=1) as destination:
                shutil.copyfileobj(source,destination,1024*1024)
            trace.unlink();report['trace_file']=str(zipped);report['trace_compression']='gzip'
        # Rebuild from fresh original inputs. Observation selects a code address;
        # it does not approve a callback or resume past a rejected transition.
        (app_extras if application else extras).append(target)
    final=dict(schema_version=1,format='oot-startup-experiment',status='diagnostic-complete',
        process_abi='experimental',switch2_startup_abi_proven=False,
        startup_completed=False,game_code_executed=bool(execute_code and any(r['execution']['retired'] for r in iterations)),
        sdk_runtime=sdk,native_sdk=native_sdk,sdk_init_providers=sdk_init,host_linked=host_linked,fast_functions=fast_functions,sdk_initialization_completed=bool(execute_code and iterations[-1]['execution'].get('sdk_initialization_completed')),
        entropy_input_sha256=hashlib.sha256(entropy_file.read_bytes()).hexdigest() if entropy_file else None,
        iterations=iterations)
    if application:final['application_runtime']=True
    if graphics:final['graphics_runtime']=True
    if display:final['display_runtime']=True
    (output/'run.json').write_text(json.dumps(final,indent=2)+'\n',encoding='utf-8')
    return final


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('prepared',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--compiler',choices=('cmake','gcc'),default='cmake')
    p.add_argument('--execute',action='store_true',help='explicitly execute the compiled experimental startup prefix')
    p.add_argument('--expand-targets',type=int,default=0)
    p.add_argument('--extra-entry',type=lambda s:int(s,0),action='append',default=[],help='explicit prior observed code address to audit again')
    p.add_argument('--limit',type=int,default=1000000);p.add_argument('--quantum',type=int,default=1000)
    p.add_argument('--trace-mode',choices=('compact','full'),default='compact')
    p.add_argument('--sdk',action='store_true',help='explicit opt-in experimental SDK process model and initialization goal')
    p.add_argument('--native-sdk',action='store_true',help='separate original-body-bound native SDK function profile; requires --sdk')
    p.add_argument('--sdk-init',action='store_true',help='explicit native SDK initialization providers; requires --sdk --native-sdk')
    p.add_argument('--host-linked',action='store_true')
    p.add_argument('--fast-functions',action='store_true')
    p.add_argument('--app-entry',type=lambda s:int(s,0),action='append',default=[])
    p.add_argument('--application',action='store_true',help='separate opt-in execution beyond the checked nnMain transition')
    p.add_argument('--graphics',action='store_true',help='separate application profile with a real owned Vulkan bootstrap')
    p.add_argument('--display',action='store_true',help='separate graphics profile with real Win32/Vulkan display resources')
    p.add_argument('--entropy-file',type=Path,help='private 32-byte process entropy under ignored build/')
    p.add_argument('--romfs-index',type=Path,help='private verified read-only RomFS index')
    p.add_argument('--native-cache',type=Path,help='owned incremental compiler cache under ignored build/')
    a=p.parse_args()
    try:
        r=run(a.prepared,a.output,a.compiler,a.execute,a.expand_targets,a.limit,a.quantum,a.extra_entry,a.trace_mode,a.sdk,a.entropy_file,a.native_sdk,a.sdk_init,a.host_linked,a.fast_functions,native_cache=a.native_cache,application=a.application,application_entries=a.app_entry,romfs_index=a.romfs_index,graphics=a.graphics,display=a.display)
        last=r['iterations'][-1]
        print(json.dumps(dict(output=str(a.output),status=r['status'],iterations=len(r['iterations']),
            game_code_executed=r['game_code_executed'],startup_completed=False,
            retired=last.get('execution',{}).get('retired',0),stop_error=last.get('execution',{}).get('error'))))
        return 0
    except (InputError,OSError,ValueError,subprocess.SubprocessError) as error:
        print(f'Startup preparation failed: {error}',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
