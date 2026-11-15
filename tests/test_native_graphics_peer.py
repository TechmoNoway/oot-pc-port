"""Compile independent synthetic monitor/window/surface ownership checks."""
import os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from object_cache import SharedCompiler
from milestone_checkpoint import owned_run

class GraphicsPeerTests(unittest.TestCase):
    def test_monitor_layer_dpi_rollback_and_parent_lifetimes(self):
        parent=ROOT/'build/graphics-peer-tests';parent.mkdir(exist_ok=True,parents=True)
        folder=Path(tempfile.mkdtemp(dir=parent));compiler=SharedCompiler(os.environ.get('OOT_LIFTER_COMPILER','cmake'),log=folder/'build.log')
        flags=compiler.defines({'_WIN32_WINNT':'0x0A00','_CRT_SECURE_NO_WARNINGS':None})+compiler.includes([ROOT/'third_party/vulkan/include'])
        exe=folder/'peer-test.exe';compiler.build([ROOT/'tests/native_graphics_peer_test.c'],exe,flags,libraries=['user32'])
        result=owned_run([str(exe)],ROOT,os.environ.copy(),20)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('Display monitor and separate layer ownership, DPI, rollback and lifetime passed.',result.stdout)

if __name__=='__main__':unittest.main()
