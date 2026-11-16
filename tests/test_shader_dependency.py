"""Synthetic pinned archives verify source integrity and notice retention."""
import hashlib,json,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
import fetch_shader_compiler as compiler
from input_formats import InputError

class ShaderDependencyTests(unittest.TestCase):
    def test_verified_subset_preserves_notices_and_rechecks_cached_sources(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);destination=root/'toolchain/compiler/vendor';destination.parent.mkdir(parents=True)
            files={'LICENSE':b'synthetic license\n','compiler/header.h':b'synthetic header\n'}
            records=[dict(path=p,bytes=len(raw),git_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())for p,raw in files.items()]
            lock=dict(repository='https://github.com/t0masz407/Hookshot',commit='a'*40,files=records)
            path=root/'lock.json';path.write_text(json.dumps(lock))
            archive=destination.parent/('Hookshot-'+'a'*40+'.zip')
            with zipfile.ZipFile(archive,'w')as z:
                for p,raw in files.items():z.writestr('pinned/'+p,raw)
                z.writestr('pinned/renderer.cpp',b'do not import')
            with patch.object(compiler,'ROOT',root),patch.object(compiler.urllib.request,'urlopen',side_effect=AssertionError('unexpected network')):
                result=compiler.fetch(destination,path);self.assertEqual(len(result['files']),2)
                self.assertEqual((destination/'LICENSE').read_bytes(),files['LICENSE']);self.assertFalse((destination/'renderer.cpp').exists())
                (destination/'compiler/header.h').write_bytes(b'tampered')
                compiler.fetch(destination,path);self.assertEqual((destination/'compiler/header.h').read_bytes(),files['compiler/header.h'])
                records[1]['git_sha1']='0'*40;path.write_text(json.dumps(lock))
                with self.assertRaises(InputError):compiler.fetch(destination,path)
    def test_source_paths_duplicates_sizes_and_missing_license_reject_before_fetch(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);path=root/'lock.json';base=dict(path='LICENSE',bytes=0,git_sha1='0'*40)
            for records in([dict(base,path='../LICENSE')],[dict(base,path='C:/LICENSE')],
                [dict(base,path='a/./b')],[dict(base,bytes=-1)],[base,dict(base,path='license')],
                [dict(base,path='compiler.cpp')],[dict(base,git_sha1='x'*40)]):
                path.write_text(json.dumps(dict(repository='https://github.com/t0masz407/Hookshot',commit='a'*40,files=records)))
                with self.subTest(records=records),patch.object(compiler,'ROOT',root),self.assertRaises(InputError):
                    compiler.fetch(root/'toolchain/vendor',path)

if __name__=='__main__':unittest.main()
