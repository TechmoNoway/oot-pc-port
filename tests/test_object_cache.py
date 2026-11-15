"""Real compiler checks for immutable shared objects and invalidation."""
import ctypes,json,os,sys,tempfile,unittest
from contextlib import contextmanager
from _ctypes import FreeLibrary
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from object_cache import SharedCompiler
from input_formats import InputError

@contextmanager
def loaded(path):
 lib=ctypes.CDLL(str(path))
 try:yield lib
 finally:FreeLibrary(lib._handle)


class SharedObjectCacheTests(unittest.TestCase):
 def test_preprocessed_definitions_are_not_reintroduced_after_undef(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build')as tmp:
   root=Path(tmp);compiler=SharedCompiler(os.environ.get('OOT_LIFTER_COMPILER','cmake'),store=root/'store')
   source=root/'undef.c';source.write_text('#undef TEST_VALUE\nint TEST_VALUE=41;\n'
       '__declspec(dllexport) int value(void){return TEST_VALUE+1;}\n')
   result=compiler.compile(source,root/'undef.obj',compiler.defines({'TEST_VALUE':9}))
   compiler.link([result],root/'undef.dll',shared=True)
   with loaded(root/'undef.dll')as lib:self.assertEqual(lib.value(),42)

 def test_cross_directory_reuse_header_flags_and_corruption(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
   root=Path(tmp);store=root/'store';inc=root/'include';inc.mkdir()
   header=inc/'value.h';header.write_text('#define HEADER_VALUE 11\n')
   mode=os.environ.get('OOT_LIFTER_COMPILER','cmake')
   compiler=SharedCompiler(mode,store=store)
   flags=compiler.defines({'EXTRA_VALUE':3})+compiler.includes([inc])
   source='#include "value.h"\n__declspec(dllexport) int value(void){return HEADER_VALUE+EXTRA_VALUE;}\n'
   for name in ('a','b'):
    (root/name).mkdir();(root/name/'unit.c').write_text(source)
   first=compiler.compile(root/'a/unit.c',root/'a/unit.obj',flags)
   second=compiler.compile(root/'b/unit.c',root/'b/unit.obj',flags)
   self.assertFalse(first.reused);self.assertTrue(second.reused)
   self.assertEqual(first.key,second.key)
   self.assertEqual(first.sha256,second.sha256)
   library=compiler.link([second],root/'b/value.dll',shared=True)
   with loaded(library)as lib:self.assertEqual(lib.value(),14)
   # Same-size/same-mtime header mutation must still invalidate preprocessing.
   stamp=header.stat();header.write_text('#define HEADER_VALUE 19\n')
   os.utime(header,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
   changed=compiler.compile(root/'a/unit.c',root/'a/changed.obj',flags)
   self.assertFalse(changed.reused);self.assertNotEqual(changed.key,first.key)
   different=compiler.compile(root/'a/unit.c',root/'a/flags.obj',
       compiler.defines({'EXTRA_VALUE':8})+compiler.includes([inc]))
   self.assertFalse(different.reused);self.assertNotEqual(different.key,changed.key)
   obj=Path(changed.cache_object);raw=obj.read_bytes();stamp=obj.stat()
   obj.write_bytes(bytes([raw[0]^1])+raw[1:]);os.utime(obj,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
   repaired=compiler.compile(root/'a/unit.c',root/'a/repaired.obj',flags)
   self.assertFalse(repaired.reused)
   verified=compiler.compile(root/'a/unit.c',root/'a/verified.obj',flags)
   self.assertTrue(verified.reused)
   compiler.link([verified],root/'a/repaired.dll',shared=True)
   with loaded(root/'a/repaired.dll')as fixed:self.assertEqual(fixed.value(),22)
   # Readable but false metadata must not authorize a cached object.
   manifest=Path(verified.cache_object).parent/'manifest.json'
   data=json.loads(manifest.read_text());data['sha256']='0'*64;manifest.write_text(json.dumps(data))
   self.assertFalse(compiler.compile(root/'a/unit.c',root/'a/again.obj',flags).reused)
   # A verified cache read does not authorize later mutation of the run copy.
   private=verified.path;raw=private.read_bytes();private.write_bytes(bytes([raw[0]^1])+raw[1:])
   with self.assertRaises(InputError):compiler.link([verified],root/'a/tampered.dll',shared=True)

 def test_file_macro_identity_and_concurrent_publication(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'build') as tmp:
   root=Path(tmp);compiler=SharedCompiler(os.environ.get('OOT_LIFTER_COMPILER','cmake'),store=root/'store')
   for name in ('a','b'):
    (root/name).mkdir()
    (root/name/'identity.c').write_text('__declspec(dllexport) const char* identity(void){return __FILE__;}\n')
   flags=['/FC']if compiler.mode=='cmake'else[]
   a=compiler.compile(root/'a/identity.c',root/'a/identity.obj',flags)
   b=compiler.compile(root/'b/identity.c',root/'b/identity.obj',flags)
   self.assertNotEqual(a.key,b.key)
   source=root/'parallel.c';source.write_text('static int state; __declspec(dllexport) int parallel(void){return 73;}\n'
       '__declspec(dllexport) int next(void){return ++state;}\n')
   with ThreadPoolExecutor(max_workers=2) as pool:
    results=list(pool.map(lambda i:compiler.compile(source,root/f'parallel-{i}.obj'),range(2)))
   self.assertEqual(results[0].key,results[1].key)
   self.assertTrue(compiler.compile(source,root/'parallel-final.obj').reused)
   compiler.link(results[:1],root/'parallel.dll',shared=True)
   compiler.link(results[:1],root/'independent.dll',shared=True)
   with loaded(root/'parallel.dll')as lib,loaded(root/'independent.dll')as other:
    self.assertEqual(lib.parallel(),73)
    self.assertEqual((lib.next(),lib.next(),other.next()),(1,2,1))

if __name__=='__main__':unittest.main()
