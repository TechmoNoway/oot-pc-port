"""The real host CLI runs synthetic code and hashes every full/compact trace row."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from build_startup import build_native
from module_linker import Linker,Module
from prepare_startup import prepare_bundle
from test_arm64_analysis import synthetic_module,branch


class NativeStartupCliTests(unittest.TestCase):
    def test_compact_and_full_preserve_complete_digest_and_stop_with_exclusive_logs(self):
        # B entry; MOV X0,500; ADD X1,1; SUBS X0,1; B.NE; unsupported SVC.
        words={0:branch(0,0x40),0x40:0xd2803e80,0x44:0x91000421,
               0x48:0xf1000400,0x4c:0x54ffffc1,0x50:0xd4000fe1,0x54:0xd65f03c0}
        with tempfile.TemporaryDirectory(dir=ROOT/'build',prefix='startup-cli-test-') as temporary:
            folder=Path(temporary)
            self.assertTrue(folder.resolve().is_relative_to((ROOT/'build').resolve()))
            bundle=folder/'bundle'
            prepare_bundle(Linker([Module('main',synthetic_module(words))]),bundle)
            exe,_=build_native(bundle,os.environ.get('OOT_LIFTER_COMPILER','cmake'))
            package=bundle/'startup.ootmem';before=package.read_bytes();reports={}
            for mode,quantum in (('full',1),('compact',1000)):
                trace=folder/(mode+'.jsonl')
                argv=[str(exe),'--boot-images',str(package),'--trace',str(trace),
                      '--limit','10000','--quantum',str(quantum),'--trace-mode',mode]
                result=subprocess.run(argv,capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,3,result.stderr)
                report=json.loads(result.stdout);reports[mode]=report
                self.assertEqual((report['status'],report['error'],report['service'],report['retired']),
                                 (2,9,0x7f,1502))
                self.assertEqual((report['trace_rows'],report['trace_steps']),(1503,1502))
                data=trace.read_bytes().replace(b'\r\n',b'\n')
                rows=[json.loads(line) for line in data.splitlines()]
                self.assertEqual(rows[-1]['event'],2)
                self.assertEqual(rows[-1]['retired'],1502)
                if mode=='full':
                    self.assertEqual(len(rows),1503)
                    self.assertEqual(hashlib.sha256(data).hexdigest(),report['trace_sha256'])
                else:self.assertEqual(len(rows),65)
                again=subprocess.run(argv,capture_output=True,text=True,timeout=60)
                self.assertEqual(again.returncode,1)
                self.assertEqual(trace.read_bytes().replace(b'\r\n',b'\n'),data)
            self.assertEqual(reports['full']['trace_sha256'],reports['compact']['trace_sha256'])
            self.assertEqual(package.read_bytes(),before)


if __name__=='__main__':unittest.main()
