"""Owned host timing fixture. Synthetic signals do not grant guest capability."""
import os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from object_cache import SharedCompiler
from milestone_checkpoint import owned_run

class NativeVblankTests(unittest.TestCase):
    def test_edge_level_reset_duplication_failure_and_resource_lifetime(self):
        parent=ROOT/'build/vblank-tests';parent.mkdir(parents=True,exist_ok=True)
        destination=Path(tempfile.mkdtemp(dir=parent))
        compiler=SharedCompiler(os.environ.get('OOT_LIFTER_COMPILER','cmake'),log=destination/'build.log')
        flags=compiler.defines({'_WIN32_WINNT':'0x0A00','_CRT_SECURE_NO_WARNINGS':None})
        exe=destination/'vblank-test.exe'
        compiler.build([ROOT/'tests/native_vblank_test.c'],exe,flags,libraries=['dxguid','user32'])
        result=owned_run([str(exe)],ROOT,os.environ.copy(),20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('Synthetic edge, level signal, reset, ownership, failure and cleanup passed.',result.stdout)

if __name__=='__main__':unittest.main()
