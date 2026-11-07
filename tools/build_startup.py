"""Build a private native startup diagnostic executable; execution is explicit."""
import argparse
import hashlib
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from input_formats import InputError, require, inspect_npdm
from lifter_validation import find_cmake
from link_exefs import build_destination, load_prepared
from module_linker import Linker
from prepare_startup import prepare_bundle, owner

ROOT=Path(__file__).resolve().parent.parent


def build_native(bundle, mode, native_cache=None):
    source=bundle/'startup.c'
    log=bundle/'compile.log'
    def run(argv):
        with log.open('a',encoding='utf-8') as stream:
            r=subprocess.run(list(map(str,argv)),cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,timeout=300)
        require(r.returncode==0,f'startup compilation failed; see {log}')
    if mode=='gcc':
        compiler=shutil.which('gcc') or 'C:/msys64/ucrt64/bin/gcc.exe'
        require(Path(compiler).is_file(),'GCC is unavailable')
        exe=bundle/'oot-startup.exe'
        names=('main','startup_cli','startup_context','startup_dispatch','guest_memory',
               'runtime_image','host_win32','pauth','checked_read')
        run([compiler,'-std=c17','-O2','-Wall','-Wextra','-Wpedantic','-Werror',
             '-DOOT_HAS_STARTUP_PROGRAM','-D_CRT_SECURE_NO_WARNINGS','-D_WIN32_WINNT=0x0A00',
             '-I',ROOT/'src',*[ROOT/'src'/(n+'.c') for n in names],source,'-lbcrypt','-o',exe])
        identity=subprocess.check_output([compiler,'--version'],text=True).splitlines()[0]
    else:
        cmake=find_cmake();native=native_cache or bundle/'native'
        run([cmake,'-S',ROOT,'-B',native,'-G','Visual Studio 17 2022','-A','x64',
             '-DOOT_STARTUP_SOURCE='+str(source),'-DPython3_EXECUTABLE='+sys.executable])
        run([cmake,'--build',native,'--config','Release','--target','oot-pc-port'])
        exe=native/'Release/oot-pc-port.exe'
        identities=list((native/'CMakeFiles').glob('*/CMakeCCompiler.cmake'))
        require(len(identities)==1,'missing startup compiler identity')
        import re
        identity=' '.join(re.findall(r'set\(CMAKE_C_COMPILER(?:_ID|_VERSION)? "([^"]+)"\)',identities[0].read_text()))
        require('MSVC' in identity,'startup CMake build must exercise MSVC')
        saved=bundle/'oot-startup.exe'
        shutil.copyfile(exe,saved);exe=saved
    require(exe.is_file(),'startup executable was not produced')
    return exe,identity


def execute(exe,bundle,limit,quantum,trace_mode='compact'):
    trace=bundle/'trace.jsonl'
    r=subprocess.run([str(exe),'--boot-images',str(bundle/'startup.ootmem'),'--trace',str(trace),
                      '--limit',str(limit),'--quantum',str(quantum),'--trace-mode',trace_mode],capture_output=True,text=True,timeout=300)
    (bundle/'execution.log').write_text(r.stdout+r.stderr,encoding='utf-8')
    require(r.returncode in (1,3) and r.stdout.strip(),'startup execution failed before a diagnostic; see execution.log')
    report=json.loads(r.stdout)
    require(report.get('format')=='oot-startup-run' and report.get('startup_completed') is False,'invalid startup execution report')
    last=None;step_count=0;digest=hashlib.sha256()
    with trace.open('rb') as stream:
        for line in stream:
            require(last is None,'startup trace contains records after its stop')
            digest.update(line.replace(b'\r\n',b'\n'))
            # The native writer has one fixed numeric-only JSON format. Avoid
            # constructing millions of Python dictionaries for its step rows.
            if b'"event":0,' in line or b'"event":1,' in line:step_count+=1
            else:last=json.loads(line)
    require(last is not None and last['event']==2 and last['retired']==report['retired']==report['trace_steps'] and report['trace_rows']==report['trace_steps']+1,
            'startup trace does not reproduce the retired prefix')
    if trace_mode=='full':require(step_count==report['retired'] and digest.hexdigest()==report['trace_sha256'],'full trace digest differs from the native all-row digest')
    else:require(step_count<=report['retired'] and report['trace_mode']=='compact','invalid compact trace')
    report.update(last_transition=last,trace_file=str(trace),stored_trace_sha256=digest.hexdigest(),exit_code=r.returncode)
    return report


def run(prepared,output,compiler='cmake',execute_code=False,expand_targets=0,limit=1000000,quantum=1000,initial_entries=(),trace_mode='compact'):
    require(os.name=='nt','native startup builds require Windows')
    output=build_destination(output)
    require(not output.exists(),'choose a fresh startup output directory')
    require(type(expand_targets) is int and 0<=expand_targets<=64,'invalid target expansion limit')
    require(1<=limit<=100000000 and 1<=quantum<=100000000,'invalid startup budget')
    require(trace_mode in ('full','compact'),'invalid startup trace mode')
    require(execute_code or not expand_targets,'target expansion requires explicit execution')
    output.mkdir(parents=True)
    extras=list(initial_entries);iterations=[]
    for index in range(expand_targets+1):
        raw=Linker(load_prepared(prepared))
        bundle=output/f'iteration-{index:02d}'
        metadata=inspect_npdm((prepared/'main.npdm').read_bytes()) if (prepared/'main.npdm').is_file() else None
        manifest=prepare_bundle(raw,bundle,extra_entries=extras,
            shared_package=output/'iteration-00/startup.ootmem' if index else None,
            **({'stack_size':metadata['main_thread_stack_size']} if metadata else {}))
        manifest['npdm']=metadata
        manifest['selection']['stack_size_source']='verified-npdm' if metadata else 'explicit-synthetic-default'
        (bundle/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
        exe,identity=build_native(bundle,compiler,output/'native-cache' if compiler=='cmake' else None)
        row=dict(iteration=index,compiler=identity,executable=str(exe),bundle=str(bundle),
                 executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
                 additional_entries=list(extras),selection=manifest['selection'])
        if execute_code:
            report=execute(exe,bundle,limit,quantum,trace_mode)
            row['execution']=report
        iterations.append(row)
        (output/'run.json').write_text(json.dumps(dict(schema_version=1,format='oot-startup-experiment',
            status='running',process_abi='experimental',iterations=iterations),indent=2)+'\n',encoding='utf-8')
        if not execute_code or index==expand_targets:break
        if report['error']==10:
            target=int(report['last_transition']['next_pc'],16)
        elif report['error']==8 and any(b['address']==int(report['pc'],16) and b['reason']=='unselected continuation' for b in manifest['selection_boundaries']):
            target=int(report['pc'],16)
        else:break
        if target in extras:break
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
        extras.append(target)
    final=dict(schema_version=1,format='oot-startup-experiment',status='diagnostic-complete',
        process_abi='experimental',switch2_startup_abi_proven=False,
        startup_completed=False,game_code_executed=bool(execute_code and any(r['execution']['retired'] for r in iterations)),
        iterations=iterations)
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
    a=p.parse_args()
    try:
        r=run(a.prepared,a.output,a.compiler,a.execute,a.expand_targets,a.limit,a.quantum,a.extra_entry,a.trace_mode)
        last=r['iterations'][-1]
        print(json.dumps(dict(output=str(a.output),status=r['status'],iterations=len(r['iterations']),
            game_code_executed=r['game_code_executed'],startup_completed=False,
            retired=last.get('execution',{}).get('retired',0),stop_error=last.get('execution',{}).get('error'))))
        return 0
    except (InputError,OSError,ValueError,subprocess.SubprocessError) as error:
        print(f'Startup preparation failed: {error}',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
