"""Owned evidence seals and exclusive process lifetime for milestone recovery."""
import hashlib,json,os
from pathlib import Path
from input_formats import require

def sha_file(path):
    with Path(path).open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def identity(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def replace_checkpoint(source,target,timeout=2.0):
    """Windows readers may briefly deny delete-sharing during atomic publication."""
    import time
    deadline=time.monotonic()+timeout
    while True:
        try:source.replace(target);return
        except PermissionError as error:
            if getattr(error,'winerror',None)not in(5,32,33)or time.monotonic()>=deadline:raise
            time.sleep(.01)

def environment_identity(env):
    names={'PATH','INCLUDE','LIB','LIBPATH','CL','_CL_','CFLAGS','CXXFLAGS','CPATH','C_INCLUDE_PATH',
        'PYTHONPATH','PYTHONHOME','PYTHONHASHSEED','LANG','LC_ALL','VSLANG','SOURCE_DATE_EPOCH',
        'CMAKE_GENERATOR','CMAKE_GENERATOR_PLATFORM'}
    return identity({k:v for k,v in env.items()if k.upper()in names or k.upper().startswith('OOT_')})

def seal_native_build(root,native):
    """Seal the mutable CMake build's executable inputs and generated build rules."""
    root=root.resolve();native=Path(native).resolve()
    require(native.is_relative_to(root/'build'),'native checkpoint build escapes build/')
    records={}
    for path in native.rglob('*'):
        if path.is_file()and (path.suffix.lower()in('.exe','.dll','.lib','.vcxproj','.props','.targets','.cmake')
                or path.name=='CMakeCache.txt'):
            require(path.resolve().is_relative_to(native),'native artifact escapes its build')
            records[path.relative_to(root).as_posix()]=dict(bytes=path.stat().st_size,sha256=sha_file(path))
    require(bool(records),'native checkpoint build is empty')
    return records

def verify_native_build(root,records):
    root=root.resolve()
    require(isinstance(records,dict),'invalid native checkpoint artifact table')
    for name,record in records.items():
        path=root/name
        require(not Path(name).is_absolute()and path.resolve().is_relative_to(root/'build'),
            'native checkpoint artifact escapes build/')
        require(path.is_file()and path.stat().st_size==record.get('bytes')and sha_file(path)==record.get('sha256'),
            'native checkpoint artifact changed: '+name)

def execution_binding(root,config,native_only):
    """Content identities of actual inputs; mutable build caches are not inputs."""
    import importlib.metadata,platform,sys
    from object_cache import SharedCompiler
    files={};hashed={}
    def add(path):
        path=Path(path).resolve();require(path.is_file(),'checkpoint input is missing: '+str(path))
        st=path.stat();key=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)
        if key not in hashed:hashed[key]=sha_file(path)
        files[str(path)]=dict(bytes=st.st_size,sha256=hashed[key])
    add(sys.executable)
    add(Path(sys.base_prefix)/'python.exe')
    dll=Path(sys.base_prefix)/('python'+str(sys.version_info.major)+str(sys.version_info.minor)+'.dll')
    if dll.exists():add(dll)
    for package in ('unicorn','capstone'):
        dist=importlib.metadata.distribution(package)
        for record in dist.files or []:
            if Path(str(record)).suffix in('.py','.pyd','.dll'):add(dist.locate_file(record))
    if not native_only:
        for name,value in config.items():
            if name=='native_build' or not isinstance(value,str)or not value.startswith('build/'):continue
            path=(root/value).resolve()
            require(path.is_relative_to((root/'build').resolve()),'checkpoint input escapes build/')
            if path.is_dir():
                for directory,dirs,names in os.walk(path,followlinks=False):
                    dirs[:]=[n for n in dirs if n not in Evidence.EXCLUDED]
                    for filename in names:add(Path(directory)/filename)
            else:add(path)
        prepared=root/config['prepared']
        manifest=json.loads((prepared/'manifest.json').read_text())
        add(manifest['source']['path'])
        if config.get('application_romfs_index'):
            folder=(root/config['application_romfs_index']).parent
            for path in folder.iterdir():
                if path.is_file():add(path)
    return dict(schema=1,config=config,native_only=native_only,python=sys.version,platform=platform.platform(),
        toolchains={mode:SharedCompiler(mode).toolchain for mode in ('cmake','gcc')},files=files)

def process_alive(pid):
    import ctypes
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
    kernel.WaitForSingleObject.restype=wintypes.DWORD
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.OpenProcess(0x100000,False,pid)
    if not handle:return ctypes.get_last_error()!=87
    try:return kernel.WaitForSingleObject(handle,0)==258
    finally:kernel.CloseHandle(handle)

class CommandJob:
    """Gate launch until a kill-on-owner-close Windows job owns the entire tree."""
    def __init__(self,command,cwd,env,log,stderr=None):
        import ctypes,subprocess,sys
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_=[('process_time',ctypes.c_int64),('job_time',ctypes.c_int64),('flags',w.DWORD),
                ('minimum',ctypes.c_size_t),('maximum',ctypes.c_size_t),('processes',w.DWORD),
                ('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
        class Io(ctypes.Structure):
            _fields_=[(n,ctypes.c_uint64)for n in ('reads','writes','other','read_bytes','write_bytes','other_bytes')]
        class Extended(ctypes.Structure):
            _fields_=[('basic',Basic),('io',Io),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),
                ('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
        kernel=ctypes.WinDLL('kernel32',use_last_error=True);self.kernel=kernel;self.handle=None
        kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,w.LPCWSTR];kernel.CreateJobObjectW.restype=w.HANDLE
        kernel.SetInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD]
        kernel.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE]
        kernel.CloseHandle.argtypes=[w.HANDLE]
        self.handle=kernel.CreateJobObjectW(None,None)
        require(bool(self.handle),'cannot create command ownership job')
        child=None
        try:
            info=Extended();info.basic.flags=0x2000 # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            require(kernel.SetInformationJobObject(self.handle,9,ctypes.byref(info),ctypes.sizeof(info))!=0,
                'cannot establish command tree lifetime')
            # The wrapper cannot spawn the command until assignment completes.
            wrapper=('import subprocess,sys; gate=sys.stdin.buffer.read(1); sys.stdin.close(); '
                'sys.exit(subprocess.call(sys.argv[1:],stdin=subprocess.DEVNULL) if gate==b"1" else 125)')
            # Bypass the venv launcher: it can spawn its interpreter before job
            # assignment. This gate uses only the base interpreter's stdlib.
            python=Path(sys.base_prefix)/'python.exe'
            require(python.is_file(),'base interpreter for owned command launch is missing')
            child=subprocess.Popen([str(python),'-B','-c',wrapper,*command],cwd=cwd,env=env,
                stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT if stderr is None else stderr)
            require(kernel.AssignProcessToJobObject(self.handle,int(child._handle))!=0,
                'cannot assign command tree ownership')
            self.child=child
        except BaseException:
            if child is not None:child.kill();child.wait();child.stdin.close()
            self.close();raise

    def start(self):
        self.child.stdin.write(b'1');self.child.stdin.flush();self.child.stdin.close()
        self.child.stdin=None

    def close(self):
        if self.handle:self.kernel.CloseHandle(self.handle);self.handle=None

def owned_run(command,cwd,env,timeout):
    """Capture a direct replay while retaining ownership of all descendants."""
    import subprocess
    job=CommandJob(command,cwd,env,subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        job.start();stdout,stderr=job.child.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command,job.child.returncode,
            stdout.decode('utf-8',errors='replace'),stderr.decode('utf-8',errors='replace'))
    except BaseException:
        job.close();job.child.communicate();raise
    finally:
        job.close();job.child.wait()

class RunOwner:
    def __init__(self,output):
        import msvcrt
        require((output/'run.lock').resolve().is_relative_to(output.resolve()),'run ownership path escapes output')
        self.stream=(output/'run.lock').open('a+b')
        if self.stream.tell()==0:self.stream.write(b'0');self.stream.flush()
        self.stream.seek(0)
        try:msvcrt.locking(self.stream.fileno(),msvcrt.LK_NBLCK,1)
        except OSError:
            self.stream.close();self.stream=None
            require(False,'another process owns this milestone output')
    def close(self):
        if self.stream:
            import msvcrt
            self.stream.seek(0);msvcrt.locking(self.stream.fileno(),msvcrt.LK_UNLCK,1)
            self.stream.close();self.stream=None

class Evidence:
    EXCLUDED={'native-cache','cache-objects','source-verification'}
    def __init__(self,output,records):self.output=output.resolve();self.records=records;self.hashes={}
    def add(self,path):
        path=Path(path)
        if not path.is_file():return
        require(path.resolve().is_relative_to(self.output),'checkpoint evidence escapes output')
        rel=path.relative_to(self.output)
        if any(part in self.EXCLUDED for part in rel.parts)or path.name in('run.json','run.tmp','run.lock'):return
        st=path.stat();key=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)
        if key not in self.hashes:self.hashes[key]=sha_file(path)
        self.records[rel.as_posix()]=dict(bytes=st.st_size,sha256=self.hashes[key])
    def tree(self,folder):
        folder=Path(folder)
        require(folder.resolve().is_relative_to(self.output),'checkpoint tree escapes output')
        for directory,dirs,files in os.walk(folder,followlinks=False):
            dirs[:]=[n for n in dirs if n not in self.EXCLUDED]
            for name in files:self.add(Path(directory)/name)
    def root(self):
        for path in self.output.iterdir():
            if path.suffix in('.json','.xml','.md','.bin','.ootmem','.exe')and path.name not in('run.json','run.tmp'):
                self.add(path)
    def verify(self):
        require(isinstance(self.records,dict),'invalid checkpoint artifact table')
        for name,record in self.records.items():
            path=self.output/name
            require(isinstance(name,str)and not Path(name).is_absolute()and
                path.resolve().is_relative_to(self.output),'checkpoint artifact path escapes output')
            require(isinstance(record,dict)and type(record.get('bytes'))is int and
                path.is_file()and path.stat().st_size==record['bytes']and
                sha_file(path)==record.get('sha256'),'checkpoint artifact changed: '+name)
