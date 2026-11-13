"""Display opt-in keeps the original goal and rejects crossed program/context flags."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_application_boot import package,ROOT
from prepare_startup import emit_startup
from startup_sources import write_sources
from build_startup import build_native,execute
from input_formats import InputError

class DisplayBootTests(unittest.TestCase):
    def test_requires_graphics_before_linker_access(self):
        with self.assertRaises(InputError):emit_startup(None,[],{},display=True)

    def test_old_and_display_profiles_preserve_goal_and_cold_resources(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary);outcomes=[]
            for display in (False,True):
                blob,sources,_=package(1,True,graphics=True,display=display)
                folder=root/str(display);folder.mkdir();write_sources(folder,sources)
                (folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,os.environ.get('OOT_LIFTER_COMPILER','cmake'),root/'cache')
                report=execute(exe,folder,1000,1,'full');outcomes.append(report)
                self.assertTrue(report['sdk_initialization_completed'] and report['application_entry_retired'])
                self.assertFalse(report['application_graphics']['ready'])
                if display:
                    self.assertIs(report['display_runtime'],True)
                    self.assertEqual(report['application_display'],dict(ready=False,presentation_supported=False,calls=0,initializations=0))
                else:self.assertNotIn('application_display',report)
            for key in ('retired','post_entry_retired','native_calls','error','trace_sha256'):
                self.assertEqual(outcomes[0][key],outcomes[1][key])

    def test_crossed_display_program_and_context_reject_before_execution(self):
        blob,sources,_=package(1,True,graphics=True,display=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as temporary:
            root=Path(temporary)
            for label,old in (('program','OOT_STARTUP_DISPLAY | '),('context',' | OOT_SDK_DISPLAY')):
                changed=dict(sources);changed['startup.c']=changed['startup.c'].replace(old,'',1)
                self.assertNotEqual(changed['startup.c'],sources['startup.c'])
                folder=root/label;folder.mkdir();write_sources(folder,changed)
                (folder/'startup.ootmem').write_bytes(blob)
                exe,_=build_native(folder,os.environ.get('OOT_LIFTER_COMPILER','cmake'),root/'cache')
                result=subprocess.run([str(exe),'--boot-images',str(folder/'startup.ootmem'),
                    '--trace',str(folder/'trace.jsonl'),'--limit','1000'],capture_output=True,text=True,timeout=30)
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,'')
                self.assertFalse((folder/'trace.jsonl').exists())

if __name__=='__main__':unittest.main()
