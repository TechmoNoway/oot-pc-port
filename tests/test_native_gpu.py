"""Compile the independent renderer foundation with synthetic Vulkan dispatch."""
import os,tempfile,unittest
from pathlib import Path
from object_cache import SharedCompiler
from milestone_checkpoint import owned_run
ROOT=Path(__file__).resolve().parents[1]

class NativeGpuTests(unittest.TestCase):
    def test_transfer_barriers_real_owner_lifetimes_and_failure_isolation(self):
        parent=ROOT/'build/gpu-tests';parent.mkdir(parents=True,exist_ok=True);folder=Path(tempfile.mkdtemp(dir=parent))
        compiler=SharedCompiler(os.environ.get('OOT_LIFTER_COMPILER','cmake'),log=folder/'build.log')
        flags=compiler.includes([ROOT/'src',ROOT/'third_party/vulkan/include'])
        exe=folder/'gpu-test.exe';compiler.build([ROOT/'tests/native_gpu_test.c'],exe,flags)
        result=owned_run([str(exe)],ROOT,os.environ.copy(),30)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('GPU buffer transfers, barriers, fences and failure ownership passed',result.stdout)
        self.assertIn('GPU textures and descriptor lifetime checks passed',result.stdout)

if __name__=='__main__':unittest.main()
