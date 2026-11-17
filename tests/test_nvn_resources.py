"""Compile pool/buffer ownership against independent artificial Vulkan dispatch."""
import os,tempfile,unittest
from pathlib import Path
from object_cache import SharedCompiler
from milestone_checkpoint import owned_run
ROOT=Path(__file__).resolve().parents[1]
class NvnResourcesTests(unittest.TestCase):
    def test_pool_buffer_ownership_faults_shadow_recapture_and_snapshot_publication(self):
        parent=ROOT/'build/nvn-resource-tests';parent.mkdir(parents=True,exist_ok=True)
        folder=Path(tempfile.mkdtemp(dir=parent));compiler=SharedCompiler(os.environ.get('OOT_LIFTER_COMPILER','cmake'),log=folder/'build.log')
        exe=folder/'resources.exe';compiler.build([ROOT/'tests/native_nvn_resources_test.c',ROOT/'src/guest_memory.c'],exe,
            compiler.includes([ROOT/'src',ROOT/'tests',ROOT/'third_party/vulkan/include']))
        r=owned_run([str(exe)],ROOT,os.environ.copy(),30)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('logical addresses, recapture, rollback and publication passed',r.stdout)
