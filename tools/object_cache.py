"""Shared, content-verified C objects; every caller still links and executes tests.

The compiler preprocesses the real source, including all system headers. Only
line-marker paths are canonicalized for the key; the compiler receives the intact
preprocessed input. Expanded file/time strings remain part of the key. Debug and
unexpanded source-location builtins retain the full line-marker identity as well.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
import hashlib,json,os,re,secrets,shutil,subprocess,tempfile,threading,time
from pathlib import Path
from input_formats import require

ROOT=Path(__file__).resolve().parent.parent
SCHEMA=1
DEFAULT_STORE=ROOT/'build/object-cache/v1'

def digest(data):return hashlib.sha256(data).hexdigest()

def file_digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def destination(path):
    path=Path(path).resolve()
    require((ROOT/'build').resolve().is_relative_to(ROOT.resolve()),'build root escapes checkout')
    require(path.is_relative_to((ROOT/'build').resolve()) and path!= (ROOT/'build').resolve(),
            'object-cache output must remain under build/')
    return path

@lru_cache(maxsize=1)
def _msvc_environment():
    from lifter_validation import find_cmake
    probe=destination(DEFAULT_STORE/'toolchain')
    probe.mkdir(parents=True,exist_ok=True)
    source=probe/'CMakeLists.txt'
    text='cmake_minimum_required(VERSION 3.20)\nproject(oot_cache_toolchain LANGUAGES C)\n'
    if not source.exists() or source.read_text()!=text:source.write_text(text)
    native=probe/'native'
    result=subprocess.run([find_cmake(),'-S',str(probe),'-B',str(native),'-G','Visual Studio 17 2022','-A','x64'],
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
    require(result.returncode==0,'MSVC cache toolchain discovery failed: '+result.stdout.decode(errors='replace')[-2000:])
    metadata=list((native/'CMakeFiles').glob('*/CMakeCCompiler.cmake'))
    require(len(metadata)==1,'ambiguous MSVC cache compiler metadata')
    config=metadata[0].read_text()
    def value(name):
        match=re.search(r'set\('+name+r' "([^"]+)"\)',config)
        require(match is not None,'missing MSVC toolchain '+name);return match.group(1)
    require(value('CMAKE_C_COMPILER_ID')=='MSVC','shared MSVC cache requires Visual Studio cl')
    compiler=Path(value('CMAKE_C_COMPILER')).resolve()
    batch=compiler.parents[7]/'VC/Auxiliary/Build/vcvars64.bat'
    require(batch.is_file(),'MSVC environment setup is missing')
    envrun=subprocess.run('cmd.exe /d /s /c ""'+str(batch)+'" >nul && set"',
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
    require(envrun.returncode==0,'MSVC environment setup failed: '+envrun.stderr.decode(errors='replace')[-1500:])
    captured={}
    for line in envrun.stdout.decode(errors='replace').splitlines():
        if '='in line:
            key,val=line.split('=',1)
            if key and not key.startswith('='):captured[key.upper()]=val
    require(Path(captured['VCTOOLSINSTALLDIR']).resolve()==compiler.parents[3],
        'CMake and vcvars selected different MSVC toolchains')
    return compiler,value('CMAKE_C_COMPILER_VERSION'),captured

@dataclass(frozen=True)
class ObjectResult:
    path:Path
    key:str
    sha256:str
    reused:bool
    cache_object:Path
    preprocess_seconds:float
    compile_seconds:float

class SharedCompiler:
    def __init__(self,mode,store=None,log=None):
        require(mode in ('gcc','cmake'),'invalid shared compiler mode')
        self.mode=mode;self.store=destination(store or DEFAULT_STORE)
        self.store.mkdir(parents=True,exist_ok=True)
        self.log=Path(log) if log else None;self.log_lock=threading.Lock()
        self.env=os.environ.copy()
        if mode=='cmake':
            require(not self.env.get('CL')and not self.env.get('_CL_'),
                'shared MSVC builds require explicit options rather than CL/_CL_ injection')
            self.compiler,version,vc=_msvc_environment()
            for key in ('PATH','INCLUDE','LIB','LIBPATH','VCTOOLSINSTALLDIR','WINDOWSSDKDIR','WINDOWSSDKVERSION'):
                if key in vc:self.env[key]=vc[key]
            self.linker=self.compiler.with_name('link.exe')
            self.description=str(self.compiler)+' MSVC '+version
            self.base=['/nologo','/TC','/std:c17','/O2','/Ob2','/MD','/DNDEBUG','/W4','/WX','/bigobj']
            tools=[self.compiler,self.linker,*[self.compiler.with_name(n)for n in ('c1.dll','c2.dll')]]
        else:
            self.compiler=Path(shutil.which('gcc') or 'C:/msys64/ucrt64/bin/gcc.exe').resolve()
            require(self.compiler.is_file(),'GCC is missing')
            self.env['PATH']=str(self.compiler.parent)+os.pathsep+self.env.get('PATH','')
            self.linker=self.compiler
            self.description=self._capture([self.compiler,'--version']).decode(errors='replace').splitlines()[0]
            self.base=['-std=c17','-O2','-Wall','-Wextra','-Wpedantic','-Werror']
            tools=[self.compiler]
            for name in ('cc1','as'):
                located=self._capture([self.compiler,'-print-prog-name='+name]).decode().strip()
                tool=Path(located)
                if not tool.is_file():tool=Path(shutil.which(located,path=self.env['PATH']) or located)
                require(tool.is_file(),'GCC component is missing: '+name);tools.append(tool.resolve())
        relevant=('CL','_CL_','INCLUDE','LIB','LIBPATH','CPATH','C_INCLUDE_PATH','GCC_EXEC_PREFIX',
                  'COMPILER_PATH','SOURCE_DATE_EPOCH')
        self.toolchain=dict(schema=SCHEMA,mode=mode,description=self.description,
            tools=[dict(path=str(p),sha256=file_digest(p))for p in tools],
            environment_sha256=digest(json.dumps({k:self.env.get(k)for k in relevant},sort_keys=True).encode()))
        if mode=='gcc':
            self.toolchain['driver_specs_sha256']=digest(self._capture([self.compiler,'-dumpspecs']))
            self.toolchain['target']=self._capture([self.compiler,'-dumpmachine']).decode().strip()

    def _capture(self,argv):
        result=subprocess.run(list(map(str,argv)),cwd=ROOT,env=self.env,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,timeout=180)
        require(result.returncode==0,'compiler query failed: '+result.stderr.decode(errors='replace')[-1000:])
        return result.stdout

    def _run(self,argv,timeout=180):
        result=subprocess.run(list(map(str,argv)),cwd=ROOT,env=self.env,stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,timeout=timeout)
        output=result.stdout.decode(errors='replace')
        if self.log:
            with self.log_lock:
                with self.log.open('a',encoding='utf-8')as stream:
                    stream.write(subprocess.list2cmdline(list(map(str,argv)))+'\n'+output)
        require(result.returncode==0,'shared native compilation failed: '+output[-3000:])

    def defines(self,values):
        return [('/D'if self.mode=='cmake'else'-D')+k+('='+str(v)if v is not None else'')for k,v in values.items()]

    def includes(self,paths):
        return [('/I'if self.mode=='cmake'else'-I')+str(Path(p).resolve())for p in paths]

    def _key(self,source,preprocessed,flags):
        # Preserve line numbers, marker flags and file basenames. Actual macro
        # expansion strings are not rewritten. A location builtin or debug build
        # additionally binds the untouched stream to its original full paths.
        sensitive=re.search(rb'\b__builtin_(?:FILE|LINE|FUNCTION|source_location)\b',preprocessed)
        debug=any(f.lower().startswith(('/zi','/z7','-g'))and f.lower()!='-g0'for f in flags)
        debug=debug or bool(re.search(r'/(?:zi|z7)\b',self.env.get('CL','')+' '+self.env.get('_CL_',''),re.I))
        marker=re.compile(rb'^([ \t]*#[ \t]*(?:line[ \t]+)?[0-9]+[ \t]+)"([^"\r\n]+)"([^\r\n]*)(\r?)$',re.M)
        normalized=preprocessed if sensitive or debug else marker.sub(
            lambda m:m[1]+b'"'+m[2].replace(b'\\',b'/').rsplit(b'/',1)[-1]+b'"'+m[3]+m[4],preprocessed)
        descriptor=dict(toolchain=self.toolchain,flags=flags,source_name=source.name,
                        preprocessed_sha256=digest(normalized),schema=SCHEMA)
        return digest(json.dumps(descriptor,sort_keys=True,separators=(',',':')).encode())

    def _read(self,entry,key):
        if not entry.exists():return None
        require(entry.resolve().is_relative_to(self.store),'shared object entry escapes cache')
        obj=entry/('object.obj'if self.mode=='cmake'else'object.o')
        require((entry/'manifest.json').resolve().is_relative_to(self.store),'object seal escapes cache')
        try:
            require(obj.resolve().is_relative_to(self.store),'shared object payload escapes cache')
            record=json.loads((entry/'manifest.json').read_text())
            if not isinstance(record,dict):return None
            if record.get('schema')!=SCHEMA or record.get('key')!=key:return None
            if record.get('toolchain_sha256')!=digest(json.dumps(self.toolchain,sort_keys=True).encode()):return None
            if type(record.get('bytes'))is not int or not 0<record['bytes']<=256*1024*1024:return None
            if obj.stat().st_size!=record['bytes']:return None
            data=obj.read_bytes()
            if digest(data)!=record.get('sha256'):return None
            return data,record,obj
        except (OSError,ValueError,TypeError):return None

    def compile(self,source,output,flags=(),timeout=180):
        source=Path(source).resolve();output=destination(output);output.parent.mkdir(parents=True,exist_ok=True)
        flags=self.base+list(flags);start=time.perf_counter()
        work=self.store/'work';work.mkdir(exist_ok=True)
        require(work.resolve().is_relative_to(self.store),'preprocessing directory escapes cache')
        with tempfile.TemporaryDirectory(prefix='compile-',dir=work)as tmp:
            temp=Path(tmp);pp=temp/'unit.i'
            if self.mode=='cmake':self._run([self.compiler,*flags,'/P','/Fi'+str(pp),source],timeout)
            else:self._run([self.compiler,*flags,'-E',source,'-o',pp],timeout)
            preprocessed=pp.read_bytes();key=self._key(source,preprocessed,flags)
            prep=time.perf_counter()-start
            entries=self.store/'entries';entries.mkdir(exist_ok=True);entry=entries/key
            require(entries.resolve().is_relative_to(self.store),'object directory escapes cache')
            cached=self._read(entry,key);reused=cached is not None;elapsed=0.0
            if cached is None:
                obj=temp/('object.obj'if self.mode=='cmake'else'object.o');start_compile=time.perf_counter()
                if self.mode=='cmake':
                    # Definitions/includes have already been applied. Reintroducing
                    # them would change valid identifiers after an original #undef.
                    compile_flags=[f for f in flags if not f.startswith(('/D','/U','/I','/FI'))]
                    self._run([self.compiler,*compile_flags,'/c',pp,'/Fo'+str(obj)],timeout)
                else:self._run([self.compiler,*flags,'-x','cpp-output','-c',pp,'-o',obj],timeout)
                elapsed=time.perf_counter()-start_compile;data=obj.read_bytes()
                require(0<len(data)<=256*1024*1024,'invalid compiled object size')
                record=dict(schema=SCHEMA,key=key,bytes=len(data),sha256=digest(data),
                            toolchain_sha256=digest(json.dumps(self.toolchain,sort_keys=True).encode()))
                (temp/'manifest.json').write_text(json.dumps(record,sort_keys=True)+'\n')
                # A directory publishes the payload and its seal together. Competing
                # writers may publish equivalent objects; every reader verifies its
                # own byte snapshot before materializing a private run object.
                for attempt in range(3):
                    winner=self._read(entry,key)
                    if winner is not None:cached=winner;break
                    if entry.exists():
                        quarantine=self.store/'quarantine';quarantine.mkdir(exist_ok=True)
                        require(quarantine.resolve().is_relative_to(self.store),'quarantine directory escapes cache')
                        try:entry.rename(quarantine/(key+'-'+secrets.token_hex(6)))
                        except OSError:continue
                    publication=entries/('.'+key+'-'+secrets.token_hex(6))
                    publication.mkdir();(publication/obj.name).write_bytes(data)
                    (publication/'manifest.json').write_text(json.dumps(record,sort_keys=True)+'\n')
                    try:publication.rename(entry)
                    except OSError:
                        require(publication.resolve().is_relative_to(entries.resolve()) and
                            entries.resolve().is_relative_to(self.store),'cache cleanup escaped publication root')
                        shutil.rmtree(publication)
                        continue
                    cached=self._read(entry,key);break
                require(cached is not None,'shared object publication did not stabilize')
            data,record,cache_object=cached
            partial=output.with_name(output.name+'.'+secrets.token_hex(6)+'.partial')
            try:partial.write_bytes(data);partial.replace(output)
            finally:partial.unlink(missing_ok=True)
            return ObjectResult(output,key,record['sha256'],reused,cache_object,prep,elapsed)

    def link(self,objects,output,shared=False,libraries=(),timeout=180):
        output=destination(output);output.parent.mkdir(parents=True,exist_ok=True)
        paths=[]
        for obj in objects:
            require(file_digest(obj.path)==obj.sha256,'object changed before link')
            paths.append(obj.path)
        if self.mode=='cmake':
            args=['/NOLOGO','/INCREMENTAL:NO','/MACHINE:X64','/OUT:'+str(output),
                *(['/DLL','/IMPLIB:'+str(output.with_suffix('.lib'))]if shared else[]),
                *map(str,paths),*[n+'.lib'for n in ('kernel32','user32','gdi32','winspool','comdlg32',
                'advapi32','shell32','ole32','oleaut32','uuid','odbc32','odbccp32',*libraries)]]
        else:args=[*(['-shared']if shared else[]),*[str(p).replace('\\','/')for p in paths],
                   *['-l'+n for n in libraries],'-o',str(output).replace('\\','/')]
        response=output.with_suffix(output.suffix+'.link.rsp')
        response.write_text('\n'.join(subprocess.list2cmdline([a])for a in args)+'\n',encoding='utf-8')
        self._run([self.linker,'@'+str(response)],timeout)
        require(output.is_file(),'link did not produce an output')
        return output

    def build(self,sources,output,flags=(),shared=False,libraries=(),timeout=180,jobs=4):
        started=time.perf_counter()
        output=destination(output);folder=output.parent/'cache-objects';folder.mkdir(parents=True,exist_ok=True)
        def one(pair):
            i,source=pair
            per_file=flags(source)if callable(flags)else flags
            return self.compile(source,folder/(str(i)+('.obj'if self.mode=='cmake'else'.o')),per_file,timeout)
        with ThreadPoolExecutor(max_workers=jobs)as pool:objects=list(pool.map(one,enumerate(sources)))
        linking=time.perf_counter();self.link(objects,output,shared,libraries,timeout)
        return dict(compiled_objects=sum(not o.reused for o in objects),
            reused_objects=sum(o.reused for o in objects),preprocess_seconds=sum(o.preprocess_seconds for o in objects),
            compile_seconds=sum(o.compile_seconds for o in objects),
            link_seconds=time.perf_counter()-linking,seconds=time.perf_counter()-started,
            objects=[dict(key=o.key,sha256=o.sha256)for o in objects],store=str(self.store))
