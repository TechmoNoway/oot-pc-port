"""Real read-only synthetic backing, file-token lifetimes and whole ABI faults."""
from ctypes import POINTER,Structure,byref,c_char_p,c_int,c_uint8,c_uint32,c_uint64,c_void_p,sizeof
import hashlib,os,struct,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from lifter_validation import compile_library
from lifter_validation_types import State,Memory,Region
from test_native_sdk_runtime import NativeReport
from test_romfs_preparation import fixture,ASSETS,PROGRAM_ID,index_entries
from prepare_romfs import prepare

BASE=0x200000000
class Stats(Structure):
    _fields_=[(name,c_uint64)for name in ('files','directories','cache_bytes','mount_calls','open_calls','read_calls','bytes_read','verified_files','missing_paths')]+[
        ('mounted',c_uint32),('open_handles',c_uint32)]

class NativeRomFsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source=f'#include "{(ROOT/"src/native_romfs.c").as_posix()}"\n'
        source+='OOT_LIFT_EXPORT unsigned oot_romfs_stats_size(void){return sizeof(OotRomFsStats);}\n'
        cls.lib,_=compile_library([],os.environ.get('OOT_LIFTER_COMPILER','cmake'),extra_source=source)
        functions={
            'oot_romfs_open_index':([c_char_p,c_uint64,POINTER(c_uint8)],c_void_p),
            'oot_romfs_close':([c_void_p],None),'oot_romfs_stats':([c_void_p,POINTER(Stats)],c_int),
            'oot_romfs_call':([c_void_p,c_uint32,POINTER(State),POINTER(Memory),POINTER(NativeReport)],c_int),
            'oot_memory_init':([POINTER(Memory),POINTER(Region),c_uint64],c_int),
            'oot_romfs_returns_value':([c_uint32],c_int),'oot_romfs_stats_size':([],c_uint32)}
        for name,(args,result)in functions.items():
            fn=getattr(cls.lib,name);fn.argtypes=args;fn.restype=result
        if cls.lib.oot_romfs_stats_size()!=sizeof(Stats):raise AssertionError('RomFS statistics ABI differs')
    def setup_backing(self,root):
        source,prepared=fixture(root);folder=root/'romfs';prepare(prepared,folder)
        index=folder/'romfs.index';seal=(c_uint8*32).from_buffer_copy(hashlib.sha256(index.read_bytes()).digest())
        fs=self.lib.oot_romfs_open_index(os.fsencode(index),PROGRAM_ID,seal);self.assertTrue(fs)
        backing=(c_uint8*65536)(*([0xa5]*65536));table=(Region*1)(Region(BASE,len(backing),backing,3));memory=Memory()
        self.assertTrue(self.lib.oot_memory_init(byref(memory),table,1))
        return fs,memory,backing,table,index,source
    def stats(self,fs):
        out=Stats();self.assertTrue(self.lib.oot_romfs_stats(fs,byref(out)));return out
    def string(self,backing,offset,text):
        value=text.encode()+b'\0';backing[offset:offset+len(value)]=value;return BASE+offset
    def call(self,fs,memory,handler,args,status=0):
        state=State()
        for n in range(31):state.x[n]=0x1234567800000000+n
        state.pc=0x1000040;state.x[30]=0x1000080;state.sp=0x700001000;state.nzcv=0xd0000000
        for n,value in args.items():state.x[n]=value
        before=State.from_buffer_copy(state);report=NativeReport()
        self.assertEqual(self.lib.oot_romfs_call(fs,handler,byref(state),byref(memory),byref(report)),status)
        self.assertEqual((report.status,report.handler),(status,handler))
        if status:self.assertEqual(state.values(),before.values())
        else:
            before.pc=before.x[30]
            if self.lib.oot_romfs_returns_value(handler):before.x[0]=state.x[0]
            self.assertEqual(state.values(),before.values())
        return state
    def mount(self,fs,memory,backing):
        name=self.string(backing,0x100,'rom')
        self.call(fs,memory,384,{0:BASE+0x40});self.assertEqual(bytes(backing[0x40:0x48]),struct.pack('<Q',64))
        self.call(fs,memory,385,{0:name,1:BASE+0x1000,2:64})
        self.assertEqual(bytes(backing[0x1000:0x1008]),b'OOTMNT1\0');self.assertEqual(self.stats(fs).mounted,1)
    def open(self,fs,memory,backing,name):
        path=self.string(backing,0x200,'rom:/'+name)
        state=self.call(fs,memory,388,{0:BASE+0x60,1:path,2:1});self.assertEqual(state.x[0],0)
        return int.from_bytes(bytes(backing[0x60:0x68]),'little')
    def test_cache_mount_directory_census_missing_paths_and_void_lifetimes(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
            fs,m,b,t,index,source=self.setup_backing(Path(tmp))
            try:
                self.assertEqual((self.stats(fs).files,self.stats(fs).directories),(3,2))
                name=self.string(b,0x100,'rom');before=bytes(b)
                self.call(fs,m,385,{0:name,1:BASE+0x1000,2:63},1);self.assertEqual(bytes(b),before)
                self.mount(fs,m,b)
                for path,kind in (('rom:/',0),('rom:/vacant',0),('rom:/dir',0),('rom:/raw.bin',1)):
                    address=self.string(b,0x200,path);self.call(fs,m,393,{0:BASE+0x40,1:address})
                    self.assertEqual(int.from_bytes(bytes(b[0x40:0x44]),'little'),kind)
                address=self.string(b,0x200,'rom:/missing');before=bytes(b[0x40:0x44])
                self.assertEqual(self.call(fs,m,393,{0:BASE+0x40,1:address}).x[0],0x202);self.assertEqual(bytes(b[0x40:0x44]),before)
                for path in ('sdmc:/raw.bin','rom:/../raw.bin','rom://raw.bin'):
                    address=self.string(b,0x200,path);before=bytes(b)
                    self.call(fs,m,393,{0:BASE+0x40,1:address},1);self.assertEqual(bytes(b),before)
                b[0x1008]^=1;before=bytes(b);self.call(fs,m,384,{0:BASE+0x40},2);self.assertEqual(bytes(b),before);b[0x1008]^=1
                self.call(fs,m,387,{0:name});self.assertEqual(self.stats(fs).mounted,0)
            finally:self.lib.oot_romfs_close(fs)
    def test_raw_compressed_empty_reads_sizes_options_and_stale_handles(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
            fs,m,b,t,index,source=self.setup_backing(Path(tmp))
            try:
                self.mount(fs,m,b)
                for name,data,_ in ASSETS:
                    token=self.open(fs,m,b,name)
                    self.assertGreater(token,1<<39)
                    self.call(fs,m,390,{0:BASE+0x40,1:token});self.assertEqual(int.from_bytes(bytes(b[0x40:0x48]),'little'),len(data))
                    size=min(len(data),20000)
                    self.call(fs,m,391,{0:BASE+0x50,1:token,2:0,3:BASE+0x2000,4:size})
                    self.assertEqual(int.from_bytes(bytes(b[0x50:0x58]),'little'),size)
                    self.assertEqual(bytes(b[0x2000:0x2000+size]),data[:size])
                    b[0x8000:0x8004]=bytes(4)
                    self.call(fs,m,395,{0:token,1:0,2:BASE+0x2000,3:size,4:BASE+0x8000})
                    self.call(fs,m,391,{0:BASE+0x50,1:token,2:len(data),3:BASE+0x2000,4:100})
                    self.assertEqual(int.from_bytes(bytes(b[0x50:0x58]),'little'),0)
                    self.call(fs,m,389,{0:token});self.call(fs,m,390,{0:BASE+0x40,1:token},1)
                    new=self.open(fs,m,b,name);self.assertNotEqual(new,token);self.call(fs,m,389,{0:new})
                self.assertEqual(self.stats(fs).verified_files,3);self.assertEqual(self.stats(fs).open_handles,0)
            finally:self.lib.oot_romfs_close(fs)
    def test_joint_read_outputs_and_open_handles_are_unchanged_on_memory_faults(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
            fs,m,b,t,index,source=self.setup_backing(Path(tmp))
            try:
                self.mount(fs,m,b);path=self.string(b,0x200,'rom:/raw.bin')
                before=bytes(b);self.call(fs,m,388,{0:BASE+65536,1:path,2:1},2)
                self.assertEqual(bytes(b),before);self.assertEqual((self.stats(fs).open_calls,self.stats(fs).verified_files),(0,0))
                token=self.open(fs,m,b,'raw.bin')
                for count,buffer in ((BASE+65536,BASE+0x2000),(BASE+0x2000,BASE+0x2000),(BASE+0x50,BASE+0x1000)):
                    before=bytes(b);reads=self.stats(fs).read_calls
                    self.call(fs,m,391,{0:count,1:token,2:0,3:buffer,4:8},2)
                    self.assertEqual(bytes(b),before);self.assertEqual(self.stats(fs).read_calls,reads)
                self.call(fs,m,387,{0:BASE+0x100},1)
            finally:self.lib.oot_romfs_close(fs)
    def test_compiled_seal_program_source_header_and_payload_corruption_reject(self):
        for mutation in ('seal','program','index','source_header','raw_payload','cached_payload'):
            with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
                root=Path(tmp);source,prepared=fixture(root);folder=root/'romfs';prepare(prepared,folder);index=folder/'romfs.index'
                seal=hashlib.sha256(index.read_bytes()).digest();program=PROGRAM_ID
                if mutation=='seal':seal=bytes(32)
                if mutation=='program':program+=1
                if mutation=='index':raw=bytearray(index.read_bytes());raw[-1]^=1;index.write_bytes(raw)
                if mutation=='source_header':raw=bytearray(source.read_bytes());raw[100]^=1;source.write_bytes(raw)
                if mutation.endswith('payload'):
                    _,entries=index_entries(index);kind,size,offset,_=entries['raw.bin' if mutation=='raw_payload' else 'dir/data.bin']
                    path=source if not kind else folder/'romfs.data';raw=bytearray(path.read_bytes());raw[offset]^=1;path.write_bytes(raw)
                expected=(c_uint8*32).from_buffer_copy(seal);fs=self.lib.oot_romfs_open_index(os.fsencode(index),program,expected)
                if not mutation.endswith('payload'):self.assertFalse(fs,mutation);continue
                self.assertTrue(fs)
                try:
                    b=(c_uint8*65536)();t=(Region*1)(Region(BASE,len(b),b,3));m=Memory();self.lib.oot_memory_init(byref(m),t,1);self.mount(fs,m,b)
                    name='raw.bin' if mutation=='raw_payload' else 'dir/data.bin';path=self.string(b,0x200,'rom:/'+name);before=bytes(b)
                    self.call(fs,m,388,{0:BASE+0x60,1:path,2:1},2);self.assertEqual(bytes(b),before);self.assertEqual(self.stats(fs).open_handles,0)
                finally:self.lib.oot_romfs_close(fs)
