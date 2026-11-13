"""Generated graphics profile retains the original goal and stays GPU-lazy."""
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from test_application_boot import package,ROOT
from prepare_startup import emit_startup
from startup_sources import write_sources
from build_startup import build_native,execute
from input_formats import InputError

class GraphicsBootTests(unittest.TestCase):
    def test_crossed_graphics_and_application_profiles_reject_before_execution(self):
        blob,sources,_=package(1,True,graphics=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary)
            for label,old in (('program','OOT_STARTUP_GRAPHICS | '),('context',' | OOT_SDK_GRAPHICS')):
                changed=dict(sources);changed['startup.c']=changed['startup.c'].replace(old,'',1)
                self.assertNotEqual(changed['startup.c'],sources['startup.c'])
                folder=root/label;folder.mkdir();write_sources(folder,changed)
                (folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,os.environ.get('OOT_LIFTER_COMPILER','cmake'),root/'cache')
                result=subprocess.run([str(exe),'--boot-images',str(folder/'startup.ootmem'),
                    '--trace',str(folder/'trace.jsonl'),'--limit','1000'],capture_output=True,text=True,timeout=30)
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,'')
                self.assertFalse((folder/'trace.jsonl').exists())

    def test_graphics_emission_requires_application_before_linker_access(self):
        with self.assertRaises(InputError):emit_startup(None,[],{},graphics=True)

    def test_both_explicit_profiles_complete_original_goal_without_booting_gpu(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);outcomes=[]
            for graphics in (False,True):
                blob,sources,_=package(1,True,graphics=graphics)
                folder=root/str(graphics);folder.mkdir();write_sources(folder,sources)
                (folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,os.environ.get('OOT_LIFTER_COMPILER','cmake'),root/'cache')
                report=execute(exe,folder,1000,1,'full');outcomes.append(report)
                self.assertTrue(report['sdk_initialization_completed'])
                self.assertTrue(report['application_entry_retired'])
                if graphics:
                    self.assertIs(report['graphics_runtime'],True)
                    self.assertEqual(report['application_graphics']['ready'],False)
                    self.assertEqual(report['application_graphics']['calls'],0)
                else:self.assertNotIn('application_graphics',report)
            for key in ('retired','post_entry_retired','native_calls','error','trace_sha256'):
                self.assertEqual(outcomes[0][key],outcomes[1][key])

if __name__=='__main__':unittest.main()
