"""Independent artificial image declarations and native object/event lifecycle."""
import hashlib,os,struct,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from module_linker import Linker,Module
from prepare_runtime import make_package,HEADER
from test_module_linker import fixture,change_memory
from object_cache import SharedCompiler
from milestone_checkpoint import owned_run

def synthetic_objects(nvn=False):
    values={}
    for n in range(8):
        values.update({0x2000+n*24:0,0x2008+n*24:0x20f0,0x2010+n*24:0x40})
    if nvn:values.update({0x2100+n*8:0x40+n*4 for n in range(3)})
    raw=change_memory(fixture(values=values,relr=(0x2100,7)if nvn else()),0x40,struct.pack('<II',0xd503201f,0xd65f03c0))
    linker=Linker([Module('main',raw)]);assert linker.apply()['link_complete']
    blob,_=make_package(linker);base=linker.modules[0].base
    def number(value):return 'UINT64_C('+str(value)+')'
    def digest(value):return '{'+','.join('0x'+value[n:n+2]for n in range(0,64,2))+'}'
    lines=['#include "native_objects.h"','static const OotObjectDeclaration object_test_declaration={',
        '.version=1,.flags=OOT_OBJECT_VSYNC,.width=1920,.height=1080,',
        '.display='+number(base+0x2200)+',.display_size=64,.layer='+number(base+0x2400)+',.layer_size=256,',
        '.vptr_address={'+','.join(number(base+x)for x in(0x2200,0x2400,0x2408,0x2410,0x2418))+'},',
        '.vptr_value={'+','.join(number(base+0x2010+n*24)for n in range(5))+'},',
        '.native_window='+number(base+0x2410)+',.anchor='+number(base+0x40)+',.anchor_size=8,',
        '.image_sha256='+digest(HEADER.unpack_from(blob)[-1].hex())+',',
        '.anchor_sha256='+digest(hashlib.sha256(struct.pack('<II',0xd503201f,0xd65f03c0)).hexdigest())+',',
        '.tables={']
    for n in range(8):
        data=linker.modules[0].read(0x2000+n*24,24)
        lines.append('{'+number(base+0x2000+n*24)+',24,0,'+digest(hashlib.sha256(data).hexdigest())+'},')
    lines+=['}};']
    if nvn:
        names=('nvnDeviceFinalize','nvnDeviceGetProcAddress','nvnDeviceInitialize')
        lines+=['#define OOT_NVN_OWNER_TEST 1','static const OotNvnProc object_test_procs[]={']
        lines+=['{"'+name+'",'+number(base+0x40+n*4)+'},'for n,name in enumerate(names)]
        data=linker.modules[0].read(0x2100,24)
        lines+=['};','static const OotNvnDeclaration object_test_nvn={1,3,'+number(base+0x2100)+','+
            digest(hashlib.sha256(data).hexdigest())+',object_test_procs};']
    return blob,'\n'.join(lines)+'\n'

class NativeObjectsTests(unittest.TestCase):
    def test_checked_objects_and_real_event_token_lifetimes(self):
        self.check_objects(False)
    def test_refresh_capability_bool_aliases_faults_and_old_profile_gate(self):
        self.check_objects(True)
    def test_nvn_private_device_identity_lookup_faults_and_finalization(self):
        self.check_objects(True,True)
    def test_nvn_fixed_layout_queries_and_legacy_property_guard(self):
        self.check_objects(True,True,True)
    def check_objects(self,refresh,nvn=False,layout=False):
        parent=ROOT/'build/object-tests';parent.mkdir(parents=True,exist_ok=True)
        folder=Path(tempfile.mkdtemp(dir=parent));blob,declaration=synthetic_objects(nvn)
        if refresh:declaration=declaration.replace('.flags=OOT_OBJECT_VSYNC,','.flags=OOT_OBJECT_VSYNC|OOT_OBJECT_REFRESH'+('|OOT_OBJECT_NVN'if nvn else'')+('|OOT_OBJECT_NVN_LAYOUT'if layout else'')+',')
        image=folder/'synthetic.ootmem';image.write_bytes(blob)
        header=folder/'declaration.h';header.write_text(declaration)
        compiler=SharedCompiler(os.environ.get('OOT_LIFTER_COMPILER','cmake'),log=folder/'build.log')
        flags=compiler.defines({'_WIN32_WINNT':'0x0A00','_CRT_SECURE_NO_WARNINGS':None,
            'OOT_OBJECT_TEST_DECLARATION':'"'+header.as_posix()+'"'})+compiler.includes([ROOT/'src',ROOT/'tests',ROOT/'third_party/vulkan/include'])
        exe=folder/'objects-test.exe'
        compiler.build([ROOT/'tests/native_objects_test.c',ROOT/'tests/objects_vblank_fixture.c',
            ROOT/'src/guest_memory.c',ROOT/'src/runtime_image.c',ROOT/'src/host_win32.c'],exe,flags,
            libraries=['bcrypt','user32'])
        result=owned_run([str(exe),str(image)],ROOT,os.environ.copy(),30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('Object publication, ownership, ABI, event tokens, failures and cleanup passed.',result.stdout)

if __name__=='__main__':unittest.main()
